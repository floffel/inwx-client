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

use std::time::Duration;

use serde_json::Value;

use crate::{Error, Result};

/// A single JSON-RPC call, transport agnostic.
///
/// Headers are owned pairs because the client sets `Content-Type`, `Cookie` and
/// `User-Agent` per call. They never contain the password: the only credential
/// on the wire is the session cookie, and it is opaque.
///
/// ```
/// use inwx_client::transport::Request;
///
/// let body = br#"{"method":"account.check","params":{}}"#;
/// let request = Request::post_json("https://api.domrobot.com/jsonrpc/", body)
///     .with_header("Cookie", "session=abc")
///     .with_timeout(Some(std::time::Duration::from_secs(5)));
/// assert_eq!(request.header("cookie"), Some("session=abc"));
/// assert_eq!(request.timeout.unwrap().as_secs(), 5);
/// ```
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// Absolute URL of the JSON-RPC endpoint.
    pub url: &'a str,
    /// Serialised JSON body, already valid JSON.
    pub body: &'a [u8],
    /// Additional headers, as `(name, value)` pairs in insertion order.
    pub headers: Vec<(String, String)>,
    /// Per-request timeout; `None` leaves the transport default in place.
    pub timeout: Option<Duration>,
}

impl<'a> Request<'a> {
    /// A POST with a JSON body and no extra headers.
    ///
    /// ```
    /// use inwx_client::transport::Request;
    ///
    /// let request = Request::post_json("https://example.test/jsonrpc/", b"{}");
    /// assert!(request.headers.is_empty());
    /// ```
    #[must_use]
    pub fn post_json(url: &'a str, body: &'a [u8]) -> Self {
        Self {
            url,
            body,
            headers: Vec::new(),
            timeout: None,
        }
    }

    /// Adds one header.
    ///
    /// ```
    /// use inwx_client::transport::Request;
    ///
    /// let request = Request::post_json("https://example.test/", b"{}")
    ///     .with_header("User-Agent", "inwx-client/0.1");
    /// assert_eq!(request.header("user-agent"), Some("inwx-client/0.1"));
    /// ```
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Case-insensitive header lookup.
    ///
    /// ```
    /// use inwx_client::transport::Request;
    ///
    /// let request = Request::post_json("https://example.test/", b"{}")
    ///     .with_header("Content-Type", "application/json");
    /// assert_eq!(request.header("CONTENT-TYPE"), Some("application/json"));
    /// assert_eq!(request.header("accept"), None);
    /// ```
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
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
/// Header names are lower-cased on construction and duplicates are preserved,
/// because a `Set-Cookie` per session is normal and the client must see them
/// all.
///
/// ```
/// use inwx_client::transport::Response;
///
/// let response = Response::new(
///     200,
///     [("Set-Cookie".to_string(), "session=abc; Path=/".to_string())],
///     br#"{"code":1000,"msg":"ok"}"#.to_vec(),
/// );
/// assert!(response.is_success());
/// assert_eq!(response.header("set-cookie"), Some("session=abc; Path=/"));
/// assert_eq!(response.json().unwrap()["code"], 1000);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    /// Builds a response, lower-casing header names.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    ///
    /// let response = Response::new(204, std::iter::empty(), Vec::new());
    /// assert_eq!(response.body(), b"");
    /// ```
    pub fn new(
        status: u16,
        headers: impl IntoIterator<Item = (String, String)>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            status,
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), value))
                .collect(),
            body,
        }
    }

    /// HTTP status code.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    /// assert_eq!(Response::new(429, std::iter::empty(), Vec::new()).status(), 429);
    /// ```
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// First value of a header, case-insensitively.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    ///
    /// let response = Response::new(200, [("X-Rate".to_string(), "9".to_string())], Vec::new());
    /// assert_eq!(response.header("x-rate"), Some("9"));
    /// ```
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Every value of a header, case-insensitively.
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
    /// );
    /// assert_eq!(response.header_all("set-cookie").count(), 2);
    /// ```
    pub fn header_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Raw body bytes.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    /// assert_eq!(Response::new(200, std::iter::empty(), b"hi".to_vec()).body(), b"hi");
    /// ```
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Whether the status is 2xx.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    /// assert!(Response::new(200, std::iter::empty(), Vec::new()).is_success());
    /// assert!(!Response::new(503, std::iter::empty(), Vec::new()).is_success());
    /// ```
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Parses the body as JSON; an empty body becomes `null`.
    ///
    /// ```
    /// use inwx_client::transport::Response;
    ///
    /// let response = Response::new(200, std::iter::empty(), br#"{"code":1000}"#.to_vec());
    /// assert_eq!(response.json().unwrap()["code"], 1000);
    /// assert!(Response::new(200, std::iter::empty(), Vec::new()).json().unwrap().is_null());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the body is not valid JSON.
    pub fn json(&self) -> Result<Value> {
        if self.body.iter().all(u8::is_ascii_whitespace) {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&self.body).map_err(Error::from)
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
/// unchanged.
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
fn parse_content_length(value: Option<&str>) -> Option<u64> {
    value?.trim().parse().ok()
}

/// Performs one HTTP request. Implement it for your own stack, or use
/// `ReqwestTransport`.
///
/// Implementations must:
///
/// * send exactly the headers in [`Request::headers`] (including `Cookie`),
/// * return the raw status, headers and body even for non-2xx (the client
///   decides what is retryable),
/// * classify connection failures as [`Error::transport`],
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
///         Ok(Response::new(
///             200,
///             std::iter::empty(),
///             br#"{"code":1000,"msg":"ok"}"#.to_vec(),
///         ))
///     }
/// }
/// ```
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Executes `request` and returns the response, whatever its status.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] when no response could be obtained.
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
    client: reqwest::Client,
    max_response_bytes: u64,
}

#[cfg(feature = "http")]
impl Default for ReqwestTransport {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

#[cfg(feature = "http")]
impl ReqwestTransport {
    /// Creates a transport with a default client (rustls, redirects followed)
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
        self.chunk()
            .await
            .map_err(|error| describe_reqwest_error(&error))
    }
}

#[cfg(feature = "http")]
impl Transport for ReqwestTransport {
    async fn execute(&self, request: Request<'_>) -> Result<Response> {
        let mut builder = self.client.post(request.url);
        if let Some(timeout) = request.timeout {
            builder = builder.timeout(timeout);
        }
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        let mut response = builder
            .body(request.body.to_vec())
            .send()
            .await
            .map_err(|error| describe_reqwest_error(&error))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect::<Vec<_>>();
        // The declared size is only a hint: `read_capped_body` checks it and
        // then counts what actually arrives, so a lying header cannot buy a
        // bigger allocation.
        let declared_len = parse_content_length(
            response
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
        );
        let body = read_capped_body(&mut response, declared_len, self.max_response_bytes).await?;

        Ok(Response::new(status, headers, body))
    }
}

/// Maps a `reqwest` failure to a retryable transport error without echoing
/// headers (the cookie header must never reach a log line).
#[cfg(feature = "http")]
fn describe_reqwest_error(error: &reqwest::Error) -> Error {
    let kind = if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() || error.is_decode() {
        "body"
    } else {
        "request"
    };
    // `reqwest::Error` renders the URL but never request headers.
    Error::transport(format!("{kind}: {error}"))
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
    struct Breaks;

    impl ChunkSource for Breaks {
        type Chunk = Vec<u8>;

        fn next_chunk(&mut self) -> impl std::future::Future<Output = Result<Option<Vec<u8>>>> {
            std::future::ready(Err(Error::transport("connection reset")))
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
    async fn a_failing_source_is_reported_as_the_transport_error_it_gave() {
        let mut source = Breaks;
        let error = read_capped_body(&mut source, None, 64).await.unwrap_err();
        assert!(matches!(
            error,
            Error::Transport {
                retryable: true,
                ..
            }
        ));
    }

    #[test]
    #[cfg(feature = "http")]
    fn only_a_plain_number_counts_as_a_declared_length() {
        assert_eq!(parse_content_length(Some("64")), Some(64));
        assert_eq!(parse_content_length(Some(" 64 ")), Some(64));
        assert_eq!(parse_content_length(Some("0")), Some(0));
        assert_eq!(parse_content_length(None), None);
        assert_eq!(parse_content_length(Some("")), None);
        assert_eq!(parse_content_length(Some("-1")), None);
        assert_eq!(parse_content_length(Some("64x")), None);
        assert_eq!(parse_content_length(Some("64, 64")), None);
        assert_eq!(parse_content_length(Some("99999999999999999999999")), None);
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
        );
        assert_eq!(response.header("SET-COOKIE"), Some("a=1"));
        assert_eq!(
            response.header_all("set-cookie").collect::<Vec<_>>(),
            ["a=1", "b=2"]
        );
    }

    #[test]
    fn json_on_garbage_is_an_error() {
        let response = Response::new(200, std::iter::empty(), b"{not json".to_vec());
        assert!(matches!(response.json(), Err(Error::Json { .. })));
    }

    #[test]
    fn whitespace_only_body_is_null() {
        let response = Response::new(200, std::iter::empty(), b"  \n\t".to_vec());
        assert!(response.json().unwrap().is_null());
    }
}
