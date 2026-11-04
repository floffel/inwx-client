//! Pluggable HTTP transport, so the client is testable without a socket.
//!
//! The trait is one method wide: [`Transport::execute`] takes a [`Request`] and
//! returns a [`Response`]. Everything above it — JSON-RPC framing, result-code
//! classification, session cookies, retries — lives in [`crate::client`], so a
//! mock transport can exercise every branch offline.
//!
//! Every request is a `POST` to the JSON-RPC endpoint, so [`Request`] carries no
//! verb field: there is only one.
//!
//! Inbound bodies are bounded. [`read_capped_body`] refuses a response that does
//! not fit the transport's cap before buffering it, first by honouring
//! `Content-Length` and then by a running total over the stream, so neither a
//! huge answer nor a header that lies about its size can make the process
//! allocate without limit.

use std::{fmt, time::Duration};

use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, StatusCode};
use serde_json::Value;

use crate::{Error, Result};

/// A single JSON-RPC call, transport agnostic.
///
/// Headers are owned [`HeaderMap`] entries because the client sets
/// `Content-Type`, `Cookie` and `User-Agent` per call. They never contain the
/// password: the only credential on the wire is the session cookie, and it is
/// opaque.
///
/// ```
/// use inwx_client::transport::Request;
///
/// let body = br#"{"method":"account.check","params":{}}"#;
/// let request = Request::post_json("https://api.domrobot.com/jsonrpc/", body.to_vec())
///     .with_header("Cookie", "session=abc").unwrap()
///     .with_timeout(Some(std::time::Duration::from_secs(5)));
/// assert_eq!(request.header("cookie"), Some("session=abc"));
/// assert_eq!(request.timeout.unwrap().as_secs(), 5);
/// ```
#[derive(Clone)]
pub struct Request<'a> {
    /// Absolute URL of the JSON-RPC endpoint.
    pub url: &'a str,
    /// Serialised JSON body, already valid JSON.
    ///
    /// Stored by value so the transport can hand it to the HTTP client without
    /// copying the whole envelope again.
    pub body: Vec<u8>,
    /// Additional HTTP headers.
    ///
    /// [`HeaderMap`] validates names and values, keeps names case-insensitive,
    /// and retains repeated headers such as `Set-Cookie`.
    pub headers: HeaderMap<HeaderValue>,
    /// Per-request timeout; `None` leaves the transport default in place.
    pub timeout: Option<Duration>,
}

/// `Debug` prints only the destination, header names and body length; header
/// values such as `Cookie` and the body of an `account.login` call never reach
/// a log line.
impl fmt::Debug for Request<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names: Vec<&str> = self.headers.keys().map(HeaderName::as_str).collect();
        formatter
            .debug_struct("Request")
            .field("method", &"POST")
            .field("url", &self.url)
            .field("header_names", &header_names)
            .field("body_len", &self.body.len())
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl<'a> Request<'a> {
    /// A POST with a JSON body and no extra headers.
    ///
    /// The body is accepted as any byte container that can become a `Vec<u8>`,
    /// so a caller can pass an owned serialized request without an extra copy.
    ///
    /// ```
    /// use inwx_client::transport::Request;
    ///
    /// let request = Request::post_json("https://example.test/jsonrpc/", b"{}");
    /// assert!(request.headers.is_empty());
    /// ```
    #[must_use]
    pub fn post_json(url: &'a str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            url,
            body: body.into(),
            headers: HeaderMap::new(),
            timeout: None,
        }
    }

    /// Adds one header, or returns a local transport error for an invalid name
    /// or value.
    ///
    /// ```
    /// use inwx_client::transport::Request;
    ///
    /// let request = Request::post_json("https://example.test/", b"{}")
    ///     .with_header("User-Agent", "inwx-client/0.1").unwrap();
    /// assert_eq!(request.header("user-agent"), Some("inwx-client/0.1"));
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] at [`TransportStage::Local`] when the name or value
    /// is not valid HTTP header syntax, or when the map would exceed the
    /// maintained `http` crate's per-map limit.
    pub fn with_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self> {
        let name = name.into();
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| header_error("invalid request header name", error))?;
        let value = value.into();
        let value = HeaderValue::from_bytes(value.as_bytes())
            .map_err(|error| header_error("invalid request header value", error))?;
        self.headers
            .try_append(name, value)
            .map_err(|error| header_error("too many request headers", error))?;
        Ok(self)
    }

    /// Case-insensitive header lookup.
    ///
    /// ```
    /// use inwx_client::transport::Request;
    ///
    /// let request = Request::post_json("https://example.test/", b"{}")
    ///     .with_header("Content-Type", "application/json").unwrap();
    /// assert_eq!(request.header("CONTENT-TYPE"), Some("application/json"));
    /// assert_eq!(request.header("accept"), None);
    /// ```
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.parse::<HeaderName>().ok()?;
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// Attaches a per-request timeout (no-op for `None`).
    ///
    /// ```
    /// use inwx_client::transport::Request;
    ///
    /// let request = Request::post_json("https://example.test/", b"{}")
    ///     .with_timeout(Some(std::time::Duration::from_secs(2)));
    /// assert_eq!(request.timeout, Some(std::time::Duration::from_secs(2)));
    /// ```
    #[must_use]
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }
}

/// A response as the client needs it: status, headers, body.
///
/// Header names are validated and normalized by [`HeaderMap`], and duplicates
/// are preserved because a `Set-Cookie` per session is normal and the client
/// must see them all. Header values stay as bytes until a caller asks for text,
/// so an opaque cookie or an extension header is not rounded to an empty
/// string.
///
/// ```
/// use inwx_client::transport::Response;
///
/// # fn main() -> inwx_client::Result<()> {
/// let response = Response::new(
///     200,
///     [("Set-Cookie".to_string(), "session=abc; Path=/".to_string())],
///     br#"{"code":1000,"msg":"ok"}"#.to_vec(),
/// )?;
/// assert!(response.is_success());
/// assert_eq!(response.header("set-cookie"), Some("session=abc; Path=/"));
/// assert_eq!(response.json().unwrap()["code"], 1000);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Response {
    inner: http::Response<Vec<u8>>,
}

impl PartialEq for Response {
    fn eq(&self, other: &Self) -> bool {
        self.inner.status() == other.inner.status()
            && self.inner.headers() == other.inner.headers()
            && self.inner.body() == other.inner.body()
    }
}

impl Eq for Response {}

/// `Debug` prints only the status, header names and body length; values such as
/// `Set-Cookie` and response body bytes never reach a log line.
impl fmt::Debug for Response {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names: Vec<&str> = self
            .inner
            .headers()
            .keys()
            .map(HeaderName::as_str)
            .collect();
        formatter
            .debug_struct("Response")
            .field("status", &self.inner.status().as_u16())
            .field("header_names", &header_names)
            .field("body_len", &self.inner.body().len())
            .finish()
    }
}

impl Response {
    /// Builds a response from text header values.
    ///
    /// Header names and values are validated by the maintained `http` crate.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    ///
    /// let response = Response::new(204, std::iter::empty(), Vec::new()).unwrap();
    /// assert_eq!(response.body(), b"");
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] at [`TransportStage::Local`] when the status,
    /// header name or header value is invalid.
    pub fn new(
        status: u16,
        headers: impl IntoIterator<Item = (String, String)>,
        body: Vec<u8>,
    ) -> Result<Self> {
        Self::from_header_bytes(
            status,
            headers
                .into_iter()
                .map(|(name, value)| (name, value.into_bytes())),
            body,
        )
    }

    /// Builds a response from raw header bytes.
    ///
    /// HTTP header values are bytes, not UTF-8 strings. This constructor is
    /// the lossless one for transports that can see opaque values; the client
    /// converts only the headers it needs, and reports an error when one of
    /// those cannot be read as text.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    ///
    /// let response = Response::from_header_bytes(
    ///     200,
    ///     [("X-Opaque".to_string(), vec![0xff, 0xfe])],
    ///     Vec::new(),
    /// ).unwrap();
    /// assert_eq!(response.header("x-opaque"), None);
    /// assert_eq!(response.header_bytes("x-opaque"), Some([0xff, 0xfe].as_slice()));
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] at [`TransportStage::Local`] when the status or a
    /// header name/value is invalid.
    pub fn from_header_bytes(
        status: u16,
        headers: impl IntoIterator<Item = (String, Vec<u8>)>,
        body: Vec<u8>,
    ) -> Result<Self> {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|error| header_error("invalid response header name", error))?;
            let value = HeaderValue::from_bytes(&value)
                .map_err(|error| header_error("invalid response header value", error))?;
            map.try_append(name, value)
                .map_err(|error| header_error("too many response headers", error))?;
        }
        Self::from_header_map(status, map, body)
    }

    fn from_header_map(
        status: u16,
        headers: HeaderMap<HeaderValue>,
        body: Vec<u8>,
    ) -> Result<Self> {
        let status = StatusCode::from_u16(status)
            .map_err(|error| header_error("invalid response status", error))?;
        let mut inner = http::Response::new(body);
        *inner.status_mut() = status;
        *inner.headers_mut() = headers;
        Ok(Self { inner })
    }

    /// HTTP status code.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    /// assert_eq!(Response::new(429, std::iter::empty(), Vec::new()).unwrap().status(), 429);
    /// ```
    #[must_use]
    pub fn status(&self) -> u16 {
        self.inner.status().as_u16()
    }

    /// First value of a header, case-insensitively.
    ///
    /// Returns `None` when the header is absent or when its bytes are not valid
    /// UTF-8; use [`Response::header_bytes`] when an opaque value must be kept
    /// exactly.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    ///
    /// let response = Response::new(200, [("X-Rate".to_string(), "9".to_string())], Vec::new()).unwrap();
    /// assert_eq!(response.header("x-rate"), Some("9"));
    /// ```
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.header_bytes(name)
            .and_then(|value| std::str::from_utf8(value).ok())
    }

    /// Every value of a header, case-insensitively.
    ///
    /// Values that are not valid UTF-8 are skipped. Use
    /// [`Response::header_all_bytes`] to see every value exactly as it was
    /// received.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    ///
    /// let response = Response::new(
    ///     200,
    ///     [
    ///         ("Set-Cookie".to_string(), "a=1".to_string()),
    ///         ("set-cookie".to_string(), "b=2".to_string()),
    ///     ],
    ///     Vec::new(),
    /// ).unwrap();
    /// assert_eq!(response.header_all("set-cookie").count(), 2);
    /// ```
    pub fn header_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.header_all_bytes(name)
            .filter_map(|value| std::str::from_utf8(value).ok())
    }

    /// First value of a header as raw bytes, case-insensitively.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    ///
    /// let response = Response::from_header_bytes(
    ///     200,
    ///     [("X-Trace".to_string(), b"abc".to_vec())],
    ///     Vec::new(),
    /// ).unwrap();
    /// assert_eq!(response.header_bytes("x-trace"), Some(b"abc".as_slice()));
    /// assert_eq!(response.header_bytes("missing"), None);
    /// ```
    #[must_use]
    pub fn header_bytes(&self, name: &str) -> Option<&[u8]> {
        let name = name.parse::<HeaderName>().ok()?;
        self.inner.headers().get(name).map(HeaderValue::as_bytes)
    }

    /// Every value of a header as raw bytes, case-insensitively.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    ///
    /// let response = Response::from_header_bytes(
    ///     200,
    ///     [
    ///         ("Set-Cookie".to_string(), b"a=1".to_vec()),
    ///         ("set-cookie".to_string(), b"b=2".to_vec()),
    ///     ],
    ///     Vec::new(),
    /// ).unwrap();
    /// assert_eq!(
    ///     response.header_all_bytes("set-cookie").collect::<Vec<_>>(),
    ///     [b"a=1".as_slice(), b"b=2".as_slice()],
    /// );
    /// ```
    pub fn header_all_bytes<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        name.parse::<HeaderName>()
            .ok()
            .into_iter()
            .flat_map(move |name| self.inner.headers().get_all(name).iter())
            .map(HeaderValue::as_bytes)
    }

    /// Raw body bytes.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    /// assert_eq!(Response::new(200, std::iter::empty(), b"hi".to_vec()).unwrap().body(), b"hi");
    /// ```
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.inner.body()
    }

    /// Whether the status is 2xx.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    /// assert!(Response::new(200, std::iter::empty(), Vec::new()).unwrap().is_success());
    /// assert!(!Response::new(503, std::iter::empty(), Vec::new()).unwrap().is_success());
    /// ```
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.inner.status().is_success()
    }

    /// Parses the body as JSON; an empty body becomes `null`.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    ///
    /// let response = Response::new(200, std::iter::empty(), br#"{"code":1000}"#.to_vec()).unwrap();
    /// assert_eq!(response.json().unwrap()["code"], 1000);
    /// assert!(Response::new(200, std::iter::empty(), Vec::new()).unwrap().json().unwrap().is_null());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the body is not valid JSON.
    pub fn json(&self) -> Result<Value> {
        if self.body().iter().all(u8::is_ascii_whitespace) {
            return Ok(Value::Null);
        }
        serde_json::from_slice(self.body()).map_err(Error::from)
    }
}

fn header_error(
    message: &'static str,
    error: impl std::error::Error + Send + Sync + 'static,
) -> Error {
    Error::transport_at(TransportStage::Local, message).with_source(error)
}

/// Where a transport failure happened relative to the moment the request bytes
/// left the process.
///
/// The stage is what decides whether a retry is safe: a command that was never
/// written can be replayed freely, one that was written and then lost may
/// already have been executed.
///
/// ```
/// use inwx_client::TransportStage;
///
/// assert!(TransportStage::BeforeSend.is_safe_to_retry());
/// assert!(!TransportStage::AfterSend.is_safe_to_retry());
/// assert!(!TransportStage::Local.is_safe_to_retry());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum TransportStage {
    /// DNS lookup, TCP connect or TLS handshake failed: the request bytes were
    /// never handed to the API, so replaying cannot duplicate anything.
    BeforeSend,
    /// The request had been written when the failure happened — a timeout
    /// waiting for the answer, a reset mid-response, a truncated or
    /// undecodable body. The API may already have processed the command.
    AfterSend,
    /// The transport could not even build the request (bad URL, bad header):
    /// nothing left the process, and a retry cannot help.
    Local,
}

impl TransportStage {
    /// Whether a failure at this stage may be replayed whatever the command
    /// does — `true` only for [`TransportStage::BeforeSend`].
    ///
    /// ```
    /// use inwx_client::TransportStage;
    ///
    /// assert!(TransportStage::BeforeSend.is_safe_to_retry());
    /// assert!(!TransportStage::AfterSend.is_safe_to_retry());
    /// ```
    #[must_use]
    pub fn is_safe_to_retry(self) -> bool {
        matches!(self, Self::BeforeSend)
    }
}

/// Default ceiling for one response body: 4 MiB.
///
/// INWX answers are small. A record list, a zone info or a paginated export
/// page is tens to hundreds of kilobytes, and the JSON-RPC envelope adds
/// nothing worth counting — so 4 MiB leaves room for the largest answer the API
/// documents while capping what a single misbehaving or compromised endpoint can
/// make this process allocate. `nameserver.export` with `zonefile=true` hands
/// back a whole zone in one `text` field and is the one documented shape that
/// could plausibly need more: build that client's transport with
/// `ReqwestTransport::with_max_response_bytes` instead of lowering the default
/// to something a normal answer no longer fits into.
///
/// ```
/// use inwx_client::DEFAULT_MAX_RESPONSE_BYTES;
///
/// assert_eq!(DEFAULT_MAX_RESPONSE_BYTES, 4 * 1024 * 1024);
/// ```
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

/// Where [`read_capped_body`] takes the next piece of a response body.
///
/// `reqwest::Response` implements it, and so can a mock that hands out a body in
/// pieces — which is how the cap is tested without a socket. The trait is not
/// object safe (its method returns a `Future`), so use it generically.
///
/// ```
/// use inwx_client::transport::ChunkSource;
/// use inwx_client::Result;
///
/// /// Hands out a scripted body, one chunk per call.
/// struct Scripted {
///     chunks: Vec<Vec<u8>>,
///     position: usize,
/// }
///
/// impl ChunkSource for Scripted {
///     type Chunk = Vec<u8>;
///
///     fn next_chunk(&mut self) -> impl std::future::Future<Output = Result<Option<Vec<u8>>>> {
///         let next = self.chunks.get(self.position).cloned();
///         self.position += 1;
///         std::future::ready(Ok(next))
///     }
/// }
///
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// let mut source = Scripted { chunks: vec![b"de".to_vec(), b"ad".to_vec()], position: 0 };
/// let body = inwx_client::read_capped_body(&mut source, None, 16).await.unwrap();
/// assert_eq!(body, b"dead");
/// # });
/// ```
#[allow(async_fn_in_trait)]
pub trait ChunkSource {
    /// The chunk type; anything byte-like (`Vec<u8>`, `bytes::Bytes`, …).
    type Chunk: AsRef<[u8]>;

    /// Resolves to the next chunk, or to `None` once the body is done.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] when the next chunk cannot be read.
    fn next_chunk(&mut self) -> impl std::future::Future<Output = Result<Option<Self::Chunk>>>;
}

/// Reads a whole body from `source` without ever buffering more than `limit`
/// bytes allow.
///
/// Two checks, in this order:
///
/// * `declared_len` — the `Content-Length` value, when the endpoint sent one —
///   is compared against `limit` first, so an oversized answer is refused before
///   a single body byte is read and before anything is allocated from it;
/// * while the chunks arrive, a running total is compared against `limit`, so a
///   `Content-Length` that lies too small (or a body with no header at all)
///   still fails fast — at most one chunk past the cap is ever taken.
///
/// An empty body is fine, and so is a `limit` of `0` for one. The returned
/// error carries sizes only, never body bytes.
///
/// ```
/// use inwx_client::transport::ChunkSource;
/// use inwx_client::{read_capped_body, Error, Result};
///
/// # struct One(Option<Vec<u8>>);
/// # impl ChunkSource for One {
/// #     type Chunk = Vec<u8>;
/// #     fn next_chunk(&mut self) -> impl std::future::Future<Output = Result<Option<Vec<u8>>>> {
/// #         std::future::ready(Ok(self.0.take()))
/// #     }
/// # }
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// // Just outside the cap: refused, and the error says how big it was.
/// let error = read_capped_body(&mut One(Some(b"12345".to_vec())), Some(5), 4)
///     .await
///     .unwrap_err();
/// assert!(matches!(error, Error::ResponseTooLarge { limit: 4, observed: Some(5) }));
///
/// // Just inside it — exactly at the cap — is accepted.
/// let body = read_capped_body(&mut One(Some(b"1234".to_vec())), Some(4), 4)
///     .await
///     .unwrap();
/// assert_eq!(body, b"1234");
/// # });
/// ```
///
/// # Errors
///
/// [`Error::ResponseTooLarge`] when the declared or the observed size exceeds
/// `limit`. Whatever the source reports as a read failure is passed through
/// unchanged — a reset or timeout *while reading the body* happens after the
/// request was written, so a source reports it as [`Error::uncertain`] and not
/// as [`Error::transport_before_send`].
pub async fn read_capped_body<S: ChunkSource>(
    source: &mut S,
    declared_len: Option<u64>,
    limit: u64,
) -> Result<Vec<u8>> {
    let mut body: Vec<u8> = Vec::new();
    if let Some(declared) = declared_len {
        if declared > limit {
            return Err(Error::ResponseTooLarge {
                limit,
                observed: Some(declared),
            });
        }
        // The declared size is within the cap here, so reserving from it cannot
        // be talked into an allocation the cap does not allow. Where `usize` is
        // too small to hold it, nothing is reserved and the running total does
        // the work.
        if let Ok(size) = usize::try_from(declared) {
            body.reserve(size);
        }
    }

    while let Some(chunk) = source.next_chunk().await? {
        let seen = u64::try_from(body.len()).unwrap_or(u64::MAX);
        let total = seen.saturating_add(u64::try_from(chunk.as_ref().len()).unwrap_or(u64::MAX));
        if total > limit {
            return Err(Error::ResponseTooLarge {
                limit,
                observed: Some(total),
            });
        }
        body.extend_from_slice(chunk.as_ref());
    }
    Ok(body)
}

/// Parses a `Content-Length` value. Anything that is not a plain unsigned
/// number — absent, `-1`, `42x`, two values in one header, bigger than
/// `u64` — becomes `None`, which leaves enforcement to the running total.
#[cfg(feature = "http")]
fn parse_content_length(value: Option<&[u8]>) -> Option<u64> {
    let value = std::str::from_utf8(value?).ok()?;
    value.trim().parse().ok()
}

/// Performs one HTTP request. Implement it for your own stack, or use
/// `ReqwestTransport`.
///
/// Implementations must:
///
/// * send exactly the headers in [`Request::headers`] (including `Cookie`),
/// * return the raw status, headers and body even for non-2xx (the client
///   decides what is retryable),
/// * never transparently re-send the request body — in particular, do not
///   follow 3xx redirects for this `POST`; a 3xx answer must become a terminal
///   transport or HTTP error, not a successful [`Response`],
/// * classify a failure that happened before the request was written (DNS,
///   connect, TLS) as [`Error::transport_before_send`], or — when the stage is
///   at hand — as [`Error::transport_at`], which picks the variant from it,
///   handing the failure that was caught to
///   [`Error::transport_at_caused_by`] so it survives as the `source`: a
///   flattened message destroys the chain below it,
/// * classify a failure that happened after it was written (a timeout waiting
///   for the answer, a reset mid-response, a truncated body) as
///   [`Error::uncertain`](Error::uncertain) — the API may have executed the
///   command, and the client will not replay it for a mutating method. There is
///   no one-string constructor that would silently make this retryable,
/// * bound the body they buffer — [`read_capped_body`] does that for a chunked
///   source, and a transport that reads differently must still refuse a body
///   over its cap with [`Error::ResponseTooLarge`],
/// * never log the body of a `account.login` call: it carries the password.
///
/// ```
/// use inwx_client::transport::{Request, Response, Transport};
/// use inwx_client::Result;
///
/// struct AlwaysOk;
///
/// impl Transport for AlwaysOk {
///     async fn execute(&self, request: Request<'_>) -> Result<Response> {
///         assert!(request.url.starts_with("https://"));
///         Response::new(
///             200,
///             std::iter::empty(),
///             br#"{"code":1000,"msg":"ok"}"#.to_vec(),
///         )
///     }
/// }
/// ```
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Executes `request` and returns the response, whatever its status.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] when the request never reached the API,
    /// [`Error::Uncertain`] when it was written but no usable answer came back.
    fn execute(&self, request: Request<'_>) -> impl std::future::Future<Output = Result<Response>>;
}

/// `reqwest`-based transport, enabled by default via the `http` feature.
///
/// The inner client is cheap to clone and safe to share across tasks.
///
/// Bodies are capped at [`DEFAULT_MAX_RESPONSE_BYTES`], which is enforced while
/// the response streams (see [`read_capped_body`]); a body over the cap becomes
/// [`Error::ResponseTooLarge`] and nothing of it is returned or logged.
///
/// ```no_run
/// # #[cfg(feature = "http")]
/// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
///
/// let client = InwxClient::new(ReqwestTransport::new())
///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
/// let records = client.list_records(&DomainName::parse("example.com")?).await?;
/// println!("{} records", records.len());
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "http")]
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: Option<reqwest::Client>,
    max_response_bytes: u64,
}

#[cfg(feature = "http")]
impl Default for ReqwestTransport {
    fn default() -> Self {
        Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .ok(),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

#[cfg(feature = "http")]
impl ReqwestTransport {
    /// Creates a transport with a default client (rustls, redirects refused)
    /// and the [`DEFAULT_MAX_RESPONSE_BYTES`] cap.
    ///
    /// ```
    /// # #[cfg(feature = "http")]
    /// let transport = inwx_client::ReqwestTransport::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the ceiling for one response body, in bytes.
    ///
    /// A smaller value protects the process harder; a bigger one is what a
    /// caller reading a huge export needs. `0` accepts an empty body and
    /// nothing else, which is a legitimate way to refuse every answer.
    ///
    /// The cap is checked against `Content-Length` before the body is read and
    /// against a running total while it streams, so it holds even when the
    /// endpoint lies about the size. Going over it is
    /// [`Error::ResponseTooLarge`], which is terminal on purpose: repeating the
    /// request could run the same command twice.
    ///
    /// ```
    /// # #[cfg(feature = "http")]
    /// # {
    /// use inwx_client::{ReqwestTransport, DEFAULT_MAX_RESPONSE_BYTES};
    ///
    /// let transport = ReqwestTransport::new().with_max_response_bytes(64 * 1024);
    /// assert_eq!(transport.max_response_bytes(), 64 * 1024);
    /// assert_eq!(ReqwestTransport::new().max_response_bytes(), DEFAULT_MAX_RESPONSE_BYTES);
    /// # }
    /// ```
    #[must_use]
    pub fn with_max_response_bytes(mut self, max_response_bytes: u64) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    /// The configured ceiling for one response body, in bytes.
    ///
    /// ```
    /// # #[cfg(feature = "http")]
    /// use inwx_client::{ReqwestTransport, DEFAULT_MAX_RESPONSE_BYTES};
    ///
    /// assert_eq!(ReqwestTransport::new().max_response_bytes(), DEFAULT_MAX_RESPONSE_BYTES);
    /// ```
    #[must_use]
    pub fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }
}

#[cfg(feature = "http")]
impl ChunkSource for reqwest::Response {
    type Chunk = bytes::Bytes;

    async fn next_chunk(&mut self) -> Result<Option<Self::Chunk>> {
        self.chunk().await.map_err(describe_reqwest_error)
    }
}

#[cfg(feature = "http")]
impl Transport for ReqwestTransport {
    async fn execute(&self, request: Request<'_>) -> Result<Response> {
        let Some(client) = self.client.as_ref() else {
            return Err(Error::transport_at(
                TransportStage::Local,
                "could not build the reqwest client",
            ));
        };
        let Request {
            url,
            body,
            headers,
            timeout,
        } = request;
        let mut builder = client.post(url);
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        for (name, value) in &headers {
            builder = builder.header(name, value);
        }

        let mut response = builder
            .body(body)
            .send()
            .await
            .map_err(describe_reqwest_error)?;
        if let Some(error) = redirect_refusal(response.status().as_u16()) {
            return Err(error);
        }
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
            .collect::<Vec<_>>();
        // The declared size is only a hint: `read_capped_body` checks it and
        // then counts what actually arrives, so a lying header cannot buy a
        // bigger allocation.
        let declared_len = parse_content_length(
            response
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .map(reqwest::header::HeaderValue::as_bytes),
        );
        let body = read_capped_body(&mut response, declared_len, self.max_response_bytes).await?;

        Response::from_header_bytes(status, headers, body)
    }
}

/// Where a `reqwest` failure sits relative to the moment the request was
/// written, with the short description that goes into the error message.
///
/// The description names the kind of failure only. What actually went wrong —
/// the resolve error, the refused connection, the TLS handshake — stays in the
/// `reqwest::Error` that becomes the `source`, rather than being flattened into
/// the message as text nobody can match on.
///
/// The `reqwest` kind flags are exclusive and a connect timeout is reported as
/// [`reqwest::Error::is_timeout`], not [`reqwest::Error::is_connect`], so the
/// timeout is checked first and read as "already sent" — the fail-closed side
/// of an ambiguous classification.
#[cfg(feature = "http")]
fn classify_reqwest_error(error: &reqwest::Error) -> (&'static str, TransportStage) {
    if error.is_timeout() {
        (
            "timed out waiting for the answer",
            TransportStage::AfterSend,
        )
    } else if error.is_connect() {
        ("could not connect", TransportStage::BeforeSend)
    } else if error.is_builder() {
        ("could not build the request", TransportStage::Local)
    } else if error.is_body() || error.is_decode() {
        (
            "could not read the response body",
            TransportStage::AfterSend,
        )
    } else {
        ("request failed", TransportStage::AfterSend)
    }
}

/// Maps a `reqwest` failure to the error for its stage, keeping the failure
/// itself as the `source`.
///
/// The message stays short and header-free: `reqwest::Error` renders the URL
/// but never request headers, and the cookie header must not reach a log line
/// even through a cause chain.
#[cfg(feature = "http")]
fn describe_reqwest_error(error: reqwest::Error) -> Error {
    let (description, stage) = classify_reqwest_error(&error);
    Error::transport_at_caused_by(stage, description, error)
}

/// Refuses a status that would tell a client to replay the request elsewhere.
///
/// The reqwest transport disables automatic redirects for exactly this reason.
/// A custom transport that still sees a 3xx must not hand it back as a normal
/// response: the client would parse the redirect body as an envelope, and a
/// transparent replay would duplicate a mutating `POST` outside the
/// [`TransportStage`] model.
#[cfg(feature = "http")]
fn redirect_refusal(status: u16) -> Option<Error> {
    (300..400)
        .contains(&status)
        .then(|| Error::http(status, crate::HttpBody::from_bytes(&[])))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body handed out chunk by chunk. `polled` records how many chunks the
    /// reader took, which is how the tests tell "refused before reading" from
    /// "read everything and complained afterwards".
    struct Scripted {
        chunks: Vec<Vec<u8>>,
        position: usize,
    }

    impl Scripted {
        fn new(chunks: &[&[u8]]) -> Self {
            Self {
                chunks: chunks.iter().map(|chunk| chunk.to_vec()).collect(),
                position: 0,
            }
        }

        fn polled(&self) -> usize {
            self.position.min(self.chunks.len())
        }
    }

    impl ChunkSource for Scripted {
        type Chunk = Vec<u8>;

        fn next_chunk(&mut self) -> impl std::future::Future<Output = Result<Option<Vec<u8>>>> {
            let next = self.chunks.get(self.position).cloned();
            self.position += 1;
            std::future::ready(Ok(next))
        }
    }

    /// A source that fails on the second chunk, as a reset connection does.
    /// A reset while the body is being read happens after the request was
    /// written, so it is uncertain, not retryable.
    struct Breaks;

    impl ChunkSource for Breaks {
        type Chunk = Vec<u8>;

        fn next_chunk(&mut self) -> impl std::future::Future<Output = Result<Option<Vec<u8>>>> {
            std::future::ready(Err(Error::uncertain("connection reset")))
        }
    }

    fn is_too_large(error: &Error, limit: u64, observed: Option<u64>) -> bool {
        matches!(
            error,
            Error::ResponseTooLarge { limit: seen, observed: seen_observed }
                if *seen == limit && *seen_observed == observed
        )
    }

    #[test]
    fn the_default_cap_is_four_mebibytes() {
        assert_eq!(DEFAULT_MAX_RESPONSE_BYTES, 4 * 1024 * 1024);
    }

    #[tokio::test]
    async fn a_body_exactly_at_the_cap_is_accepted() {
        let body = vec![b'x'; 64];
        let mut source = Scripted::new(&[&body]);
        let read = read_capped_body(&mut source, None, 64).await.unwrap();
        assert_eq!(read.len(), 64);
    }

    #[tokio::test]
    async fn one_byte_over_the_cap_is_refused() {
        let body = vec![b'x'; 65];
        let mut source = Scripted::new(&[&body]);
        let error = read_capped_body(&mut source, None, 64).await.unwrap_err();
        assert!(is_too_large(&error, 64, Some(65)));
    }

    #[tokio::test]
    async fn chunks_are_summed_and_the_cap_is_crossed_mid_stream() {
        // 40 + 40 against a cap of 64: the second chunk is the one that
        // crosses, and the read stops there.
        let part = vec![b'y'; 40];
        let mut source = Scripted::new(&[&part, &part, b"never read".as_slice()]);
        let error = read_capped_body(&mut source, None, 64).await.unwrap_err();
        assert!(is_too_large(&error, 64, Some(80)));
        assert_eq!(source.polled(), 2, "the rest of the body must stay unread");
    }

    #[tokio::test]
    async fn many_small_chunks_add_up_to_the_whole_body() {
        let mut source = Scripted::new(&[b"dead".as_slice(), b"be".as_slice(), b"ef".as_slice()]);
        let read = read_capped_body(&mut source, None, 8).await.unwrap();
        assert_eq!(read, b"deadbeef");
    }

    #[tokio::test]
    async fn a_declared_length_exactly_at_the_cap_is_accepted() {
        let body = vec![b'x'; 64];
        let mut source = Scripted::new(&[&body]);
        let read = read_capped_body(&mut source, Some(64), 64).await.unwrap();
        assert_eq!(read.len(), 64);
    }

    #[tokio::test]
    async fn a_declared_length_one_over_the_cap_is_refused_before_reading() {
        let body = vec![b'x'; 128];
        let mut source = Scripted::new(&[&body]);
        let error = read_capped_body(&mut source, Some(65), 64)
            .await
            .unwrap_err();
        assert!(is_too_large(&error, 64, Some(65)));
        assert_eq!(source.polled(), 0, "Content-Length alone must refuse");
    }

    #[tokio::test]
    async fn a_lying_declared_length_still_fails_while_streaming() {
        // Declares 8 bytes, sends 80. The header cannot buy a bigger read than
        // the cap, and the running total catches the lie.
        let part = vec![b'z'; 40];
        let mut source = Scripted::new(&[&part, &part]);
        let error = read_capped_body(&mut source, Some(8), 64)
            .await
            .unwrap_err();
        assert!(is_too_large(&error, 64, Some(80)));
        assert_eq!(source.polled(), 2);
    }

    #[tokio::test]
    async fn an_empty_body_is_accepted_with_a_header_without_one_and_at_a_zero_cap() {
        let mut no_header = Scripted::new(&[]);
        assert_eq!(
            read_capped_body(&mut no_header, None, 64)
                .await
                .unwrap()
                .len(),
            0
        );

        let mut declared_empty = Scripted::new(&[]);
        assert_eq!(
            read_capped_body(&mut declared_empty, Some(0), 64)
                .await
                .unwrap()
                .len(),
            0
        );

        let mut zero_cap = Scripted::new(&[]);
        assert_eq!(
            read_capped_body(&mut zero_cap, None, 0)
                .await
                .unwrap()
                .len(),
            0
        );

        // A zero cap still refuses one byte.
        let mut one_byte = Scripted::new(&[b"x".as_slice()]);
        let error = read_capped_body(&mut one_byte, None, 0).await.unwrap_err();
        assert!(is_too_large(&error, 0, Some(1)));
    }

    #[tokio::test]
    async fn the_error_never_carries_body_bytes() {
        let secret = br#"{"password":"hunter2","token":"s3cr3t"}"#;
        let mut source = Scripted::new(&[secret]);
        let error = read_capped_body(&mut source, None, 8).await.unwrap_err();
        let rendered = format!("{error}");
        let debug = format!("{error:?}");
        assert!(rendered.contains('8'), "the cap belongs in the message");
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("s3cr3t"));
        assert!(!debug.contains("hunter2"));
        assert!(!debug.contains("s3cr3t"));
    }

    #[tokio::test]
    async fn a_reset_while_reading_the_body_passes_through_as_uncertain() {
        let mut source = Breaks;
        let error = read_capped_body(&mut source, None, 64).await.unwrap_err();
        assert!(error.is_uncertain());
        assert!(!error.is_retryable());
        assert!(matches!(error, Error::Uncertain { .. }));
    }

    #[test]
    #[cfg(feature = "http")]
    fn only_a_plain_number_counts_as_a_declared_length() {
        assert_eq!(parse_content_length(Some(b"64")), Some(64));
        assert_eq!(parse_content_length(Some(b" 64 ")), Some(64));
        assert_eq!(parse_content_length(Some(b"0")), Some(0));
        assert_eq!(parse_content_length(None), None);
        assert_eq!(parse_content_length(Some(b"")), None);
        assert_eq!(parse_content_length(Some(b"-1")), None);
        assert_eq!(parse_content_length(Some(b"64x")), None);
        assert_eq!(parse_content_length(Some(b"64, 64")), None);
        assert_eq!(parse_content_length(Some(b"99999999999999999999999")), None);
        assert_eq!(parse_content_length(Some(&[0xff, 0xfe])), None);
    }

    #[test]
    #[cfg(feature = "http")]
    fn redirects_are_refused_as_terminal_http_errors() {
        for status in [300, 307, 308, 399] {
            let error = redirect_refusal(status).expect("a 3xx status must be refused");
            assert!(
                matches!(error, Error::Http { status: seen, .. } if seen == status),
                "{error:?}"
            );
            assert!(!error.is_retryable(), "{status}");
            assert!(!error.is_uncertain(), "{status}");
        }

        assert!(redirect_refusal(299).is_none());
        assert!(redirect_refusal(400).is_none());
        assert!(redirect_refusal(503).is_none());
    }

    #[test]
    fn headers_are_case_insensitive_and_duplicates_survive() {
        let response = Response::new(
            200,
            [
                ("Set-Cookie".to_string(), "a=1".to_string()),
                ("Set-Cookie".to_string(), "b=2".to_string()),
            ],
            Vec::new(),
        )
        .unwrap();
        assert_eq!(response.header("SET-COOKIE"), Some("a=1"));
        assert_eq!(
            response.header_all("set-cookie").collect::<Vec<_>>(),
            ["a=1", "b=2"]
        );
    }

    #[test]
    fn header_bytes_keep_opaque_values_and_text_lookup_stays_lossless() {
        let valid = Response::from_header_bytes(
            200,
            [("X-Text".to_string(), "café".as_bytes().to_vec())],
            Vec::new(),
        )
        .unwrap();
        assert_eq!(valid.header("x-text"), Some("café"));
        assert_eq!(valid.header_bytes("x-text"), Some("café".as_bytes()));

        let opaque = Response::from_header_bytes(
            200,
            [("X-Opaque".to_string(), vec![0xff, 0xfe])],
            Vec::new(),
        )
        .unwrap();
        assert_eq!(opaque.header("x-opaque"), None);
        assert_eq!(opaque.header_all("x-opaque").next(), None);
        assert_eq!(
            opaque.header_bytes("x-opaque"),
            Some([0xff, 0xfe].as_slice())
        );
        assert_eq!(
            opaque.header_all_bytes("x-opaque").collect::<Vec<_>>(),
            [[0xff, 0xfe].as_slice()]
        );
    }

    #[test]
    fn json_on_garbage_is_an_error() {
        let response = Response::new(200, std::iter::empty(), b"{not json".to_vec()).unwrap();
        assert!(matches!(response.json(), Err(Error::Json { .. })));
    }

    #[test]
    fn whitespace_only_body_is_null() {
        let response = Response::new(200, std::iter::empty(), b"  \n\t".to_vec()).unwrap();
        assert!(response.json().unwrap().is_null());
    }

    #[test]
    fn request_headers_are_validated_and_repeated() {
        let request = Request::post_json("https://example.test/", b"{}")
            .with_header("X-Trace", "abc")
            .unwrap()
            .with_header("x-trace", "def")
            .unwrap();
        assert_eq!(request.header("X-TRACE"), Some("abc"));

        let bad_name =
            Request::post_json("https://example.test/", b"{}").with_header("bad name", "abc");
        assert!(matches!(bad_name, Err(Error::Transport { .. })));

        let bad_value =
            Request::post_json("https://example.test/", b"{}").with_header("X-Bad", "a\nb");
        assert!(matches!(bad_value, Err(Error::Transport { .. })));

        assert_eq!(request.header("bad name"), None);
    }

    #[test]
    fn response_construction_rejects_invalid_status_and_headers() {
        let bad_status = Response::new(99, std::iter::empty(), Vec::new());
        assert!(matches!(bad_status, Err(Error::Transport { .. })));

        let bad_name = Response::new(
            200,
            [("bad name".to_string(), "abc".to_string())],
            Vec::new(),
        );
        assert!(matches!(bad_name, Err(Error::Transport { .. })));

        let bad_value = Response::new(200, [("X-Bad".to_string(), "a\nb".to_string())], Vec::new());
        assert!(matches!(bad_value, Err(Error::Transport { .. })));

        let bad_bytes_status = Response::from_header_bytes(1000, std::iter::empty(), Vec::new());
        assert!(matches!(bad_bytes_status, Err(Error::Transport { .. })));

        let response = Response::new(200, std::iter::empty(), Vec::new()).unwrap();
        assert_eq!(response.header("bad name"), None);
        assert_eq!(response.header_bytes("bad name"), None);
        assert_eq!(response.header_all("bad name").next(), None);
        assert_eq!(response.header_all_bytes("bad name").next(), None);
    }

    #[test]
    fn only_a_failure_before_the_request_was_written_is_safe_to_retry() {
        assert!(TransportStage::BeforeSend.is_safe_to_retry());
        assert!(!TransportStage::AfterSend.is_safe_to_retry());
        assert!(!TransportStage::Local.is_safe_to_retry());

        // The stage decides the error, and the error decides the retry.
        for stage in [
            TransportStage::BeforeSend,
            TransportStage::AfterSend,
            TransportStage::Local,
        ] {
            let error = Error::transport_at(stage, "boom");
            assert_eq!(error.is_retryable(), stage.is_safe_to_retry());
            assert_eq!(error.is_uncertain(), stage == TransportStage::AfterSend);
        }
    }

    /// A `reqwest` failure becomes the `source` of the error, not text inside
    /// its message: the description names the kind, and the error itself — with
    /// whatever it wraps — stays walkable.
    #[cfg(feature = "http")]
    #[test]
    fn a_reqwest_failure_is_kept_as_the_cause() {
        let failure = reqwest::Client::new()
            .post("://not a url")
            .body(Vec::new())
            .build()
            .expect_err("a malformed URL cannot be built");
        assert!(
            failure.is_builder(),
            "a malformed URL must fail before anything is sent"
        );

        let error = describe_reqwest_error(failure);

        assert_eq!(
            error.to_string(),
            "transport error: could not build the request"
        );
        // A request that was never built is a local mistake: terminal, and
        // certainly not an ambiguous outcome.
        assert!(!error.is_retryable());
        assert!(!error.is_uncertain());
        assert!(
            std::error::Error::source(&error).is_some(),
            "the reqwest error is kept as the cause"
        );
    }
}
