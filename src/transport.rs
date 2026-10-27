//! Pluggable HTTP transport, so the client is testable without a socket.
//!
//! The trait is one method wide: [`Transport::execute`] takes a [`Request`] and
//! returns a [`Response`]. Everything above it — JSON-RPC framing, result-code
//! classification, session cookies, retries — lives in [`crate::client`], so a
//! mock transport can exercise every branch offline.
//!
//! Every request is a `POST` to the JSON-RPC endpoint, so [`Request`] carries no
//! verb field: there is only one.

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

/// Default ceiling for a single inbound response body: 4 MiB.
///
/// INWX answers are small. The bulkiest documented calls — a `nameserver.info`
/// over a large zone, a 1000-row accounting page, a `nameserver.exportrecords`
/// CSV — are tens of kilobytes, so 4 MiB sits roughly two orders of magnitude
/// above the largest answer the API is known to produce. That is enough
/// headroom for growth while still bounding what a misbehaving or compromised
/// endpoint can make this process allocate before the JSON parser sees a byte.
///
/// ```
/// use inwx_client::DEFAULT_MAX_RESPONSE_BYTES;
///
/// assert_eq!(DEFAULT_MAX_RESPONSE_BYTES, 4 * 1024 * 1024);
/// // Roomy for a whole zone file, small enough to bound the damage.
/// assert!(DEFAULT_MAX_RESPONSE_BYTES >= 1024 * 1024);
/// ```
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Grows a response body one chunk at a time and refuses to cross a size cap.
///
/// A transport must not buffer a body first and measure it afterwards: the cap
/// has to be checked *before* every allocation. This guard does that in two
/// steps. [`BoundedBody::with_content_length`] rejects an announced length that
/// already exceeds the cap, so nothing is read at all, and [`BoundedBody::push`]
/// enforces a running total, so an endpoint that announces 12 bytes and then
/// streams gigabytes still fails on the first chunk that crosses the line —
/// never more than one chunk past it.
///
/// Crossing the cap yields [`Error::ResponseTooLarge`], which is terminal: the
/// endpoint did answer, so repeating a non-idempotent command could duplicate
/// work that already happened.
///
/// The guard bounds size only. A body that stops *short* of its announced
/// length is not an over-cap error; it simply fails to parse as JSON.
///
/// ```
/// use inwx_client::{BoundedBody, DEFAULT_MAX_RESPONSE_BYTES};
///
/// // What `ReqwestTransport` does with every chunk it receives.
/// let mut body = BoundedBody::new(DEFAULT_MAX_RESPONSE_BYTES)?
///     .with_content_length(Some(24))?;
/// body.push(br#"{"code":1000,"#)?;
/// body.push(br#""msg":"ok"}"#)?;
/// assert_eq!(body.bytes_seen(), 24);
/// assert_eq!(body.limit(), DEFAULT_MAX_RESPONSE_BYTES);
/// assert_eq!(body.finish(), br#"{"code":1000,"msg":"ok"}"#.to_vec());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedBody {
    limit: u64,
    seen: u64,
    declared: Option<u64>,
    buffer: Vec<u8>,
}

impl BoundedBody {
    /// Creates an empty guard that allows `limit` bytes in total.
    ///
    /// A limit of `0` is refused: no HTTP answer this crate can use is zero
    /// bytes, so it is far more likely to be an uninitialised value than an
    /// intentional choice. Use [`DEFAULT_MAX_RESPONSE_BYTES`] unless a
    /// legitimate answer is known to be bigger.
    ///
    /// ```
    /// use inwx_client::{BoundedBody, DEFAULT_MAX_RESPONSE_BYTES};
    ///
    /// assert!(BoundedBody::new(1).is_ok());
    /// assert!(BoundedBody::new(DEFAULT_MAX_RESPONSE_BYTES).is_ok());
    /// assert!(BoundedBody::new(0).is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `limit` is `0`.
    pub fn new(limit: usize) -> Result<Self> {
        if limit == 0 {
            return Err(Error::validation(
                "transport.max_response_bytes",
                "must be at least 1 byte; the default is \
                 {DEFAULT_MAX_RESPONSE_BYTES} (4 MiB), which covers every \
                 documented INWX answer",
            ));
        }
        Ok(Self {
            limit: u64::try_from(limit).unwrap_or(u64::MAX),
            seen: 0,
            declared: None,
            buffer: Vec::new(),
        })
    }

    /// Records the `Content-Length` the endpoint announced and checks it against
    /// the cap before a single body byte is read.
    ///
    /// `None` is the normal case for a chunked answer: without a declaration the
    /// running total in [`BoundedBody::push`] is the only line of defence, and
    /// it still holds.
    ///
    /// ```
    /// use inwx_client::BoundedBody;
    ///
    /// // Just inside the cap, and one byte over it.
    /// assert!(BoundedBody::new(8)?.with_content_length(Some(8)).is_ok());
    /// assert!(BoundedBody::new(8)?.with_content_length(Some(9)).is_err());
    /// // Chunked responses announce nothing.
    /// assert!(BoundedBody::new(8)?.with_content_length(None).is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::ResponseTooLarge`] with `observed: 0` when the announced length
    /// exceeds the cap.
    pub fn with_content_length(mut self, declared: Option<u64>) -> Result<Self> {
        if let Some(announced) = declared {
            if announced > self.limit {
                return Err(Error::ResponseTooLarge {
                    limit: self.limit,
                    declared: Some(announced),
                    observed: 0,
                });
            }
        }
        self.declared = declared;
        Ok(self)
    }

    /// Adds one chunk, rejecting the body *before* extending the buffer.
    ///
    /// ```
    /// use inwx_client::BoundedBody;
    ///
    /// let mut body = BoundedBody::new(8)?;
    /// body.push(b"1234")?;
    /// body.push(b"5678")?; // exactly at the cap: fine
    /// assert!(body.push(b"9").is_err()); // one byte over
    /// assert_eq!(body.bytes_seen(), 8);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::ResponseTooLarge`] when the running total would exceed the cap.
    pub fn push(&mut self, chunk: &[u8]) -> Result<()> {
        let total = self
            .seen
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if total > self.limit {
            return Err(Error::ResponseTooLarge {
                limit: self.limit,
                declared: self.declared,
                observed: total,
            });
        }
        self.buffer.extend_from_slice(chunk);
        self.seen = total;
        Ok(())
    }

    /// The cap in bytes.
    ///
    /// ```
    /// use inwx_client::BoundedBody;
    /// assert_eq!(BoundedBody::new(1024)?.limit(), 1024);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn limit(&self) -> usize {
        usize::try_from(self.limit).unwrap_or(usize::MAX)
    }

    /// Bytes accepted so far.
    ///
    /// ```
    /// use inwx_client::BoundedBody;
    ///
    /// let mut body = BoundedBody::new(1024)?;
    /// body.push(b"abc")?;
    /// assert_eq!(body.bytes_seen(), 3);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn bytes_seen(&self) -> usize {
        usize::try_from(self.seen).unwrap_or(usize::MAX)
    }

    /// The announced `Content-Length`, when there was one.
    ///
    /// ```
    /// use inwx_client::BoundedBody;
    ///
    /// let body = BoundedBody::new(1024)?.with_content_length(Some(42))?;
    /// assert_eq!(body.declared_length(), Some(42));
    /// assert_eq!(BoundedBody::new(1024)?.declared_length(), None);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn declared_length(&self) -> Option<u64> {
        self.declared
    }

    /// Hands over the buffered body.
    ///
    /// ```
    /// use inwx_client::BoundedBody;
    ///
    /// let mut body = BoundedBody::new(1024)?;
    /// body.push(br#"{"code":1000}"#)?;
    /// assert_eq!(body.finish(), br#"{"code":1000}"#.to_vec());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }
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
/// Response bodies are streamed through a [`BoundedBody`], so an endpoint that
/// is misbehaving or compromised cannot make this process allocate without
/// bound: a `Content-Length` above
/// [`max_response_bytes`](Self::max_response_bytes) is rejected before the body
/// is read, and the running total is enforced chunk by chunk. The default cap is
/// [`DEFAULT_MAX_RESPONSE_BYTES`].
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
    max_response_bytes: usize,
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
    /// and the default response cap.
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
    /// The limit is enforced while the body arrives, never after it has been
    /// buffered: an announced `Content-Length` above the cap fails before the
    /// first byte is read, and a lying or missing declaration is caught by the
    /// running total, which stops within one chunk of crossing the line.
    ///
    /// `0` is refused — no usable INWX answer is empty, so a zero cap is a
    /// misconfiguration. `usize::MAX` effectively switches the guard off and is
    /// only defensible against an endpoint you control yourself.
    ///
    /// Crossing the cap is terminal, not retryable ([`Error::ResponseTooLarge`]):
    /// the server did answer, so repeating a non-idempotent command could
    /// duplicate work that already happened.
    ///
    /// ```
    /// # #[cfg(feature = "http")]
    /// # fn main() -> Result<(), inwx_client::Error> {
    /// use inwx_client::{ReqwestTransport, DEFAULT_MAX_RESPONSE_BYTES};
    ///
    /// let transport = ReqwestTransport::new().with_max_response_bytes(64 * 1024)?;
    /// assert_eq!(transport.max_response_bytes(), 64 * 1024);
    /// assert_eq!(
    ///     ReqwestTransport::new().max_response_bytes(),
    ///     DEFAULT_MAX_RESPONSE_BYTES
    /// );
    /// assert!(ReqwestTransport::new().with_max_response_bytes(0).is_err());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `bytes` is `0`.
    pub fn with_max_response_bytes(mut self, bytes: usize) -> Result<Self> {
        // One rule for the limit, checked in one place.
        BoundedBody::new(bytes)?;
        self.max_response_bytes = bytes;
        Ok(self)
    }

    /// The configured ceiling for one response body, in bytes.
    ///
    /// ```
    /// # #[cfg(feature = "http")]
    /// # fn main() {
    /// use inwx_client::{ReqwestTransport, DEFAULT_MAX_RESPONSE_BYTES};
    ///
    /// assert_eq!(
    ///     ReqwestTransport::new().max_response_bytes(),
    ///     DEFAULT_MAX_RESPONSE_BYTES
    /// );
    /// assert_eq!(
    ///     ReqwestTransport::new()
    ///         .with_max_response_bytes(2048)
    ///         .unwrap()
    ///         .max_response_bytes(),
    ///     2048
    /// );
    /// # }
    /// ```
    #[must_use]
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
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

        // Never `response.bytes()`: that buffers first and only then measures,
        // so a lying endpoint decides how much we allocate. Check what was
        // announced, then enforce the total chunk by chunk instead.
        let declared = response.content_length();
        let mut body = BoundedBody::new(self.max_response_bytes)?.with_content_length(declared)?;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| describe_reqwest_error(&error))?
        {
            body.push(&chunk)?;
        }

        Ok(Response::new(status, headers, body.finish()))
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
