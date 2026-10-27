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

/// Performs one HTTP request. Implement it for your own stack, or use
/// `ReqwestTransport`.
///
/// Implementations must:
///
/// * send exactly the headers in [`Request::headers`] (including `Cookie`),
/// * return the raw status, headers and body even for non-2xx (the client
///   decides what is retryable),
/// * classify failures that happened before the request was sent as
///   [`Error::transport`],
/// * classify timeouts and failures after sending as [`Error::ambiguous`],
///   because the command may already have run,
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
    /// [`Error::Transport`] when the request definitely was not sent, or
    /// [`Error::Ambiguous`] when it may have reached the API and the outcome was
    /// lost. The client retries safe transport failures, but never replays a
    /// mutating command after an ambiguous outcome.
    fn execute(&self, request: Request<'_>) -> impl std::future::Future<Output = Result<Response>>;
}

/// `reqwest`-based transport, enabled by default via the `http` feature.
///
/// The inner client is cheap to clone and safe to share across tasks.
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
#[derive(Debug, Clone, Default)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

#[cfg(feature = "http")]
impl ReqwestTransport {
    /// Creates a transport with a default client (rustls, redirects followed).
    ///
    /// ```
    /// # #[cfg(feature = "http")]
    /// let transport = inwx_client::ReqwestTransport::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

        let response = builder
            .body(request.body.to_vec())
            .send()
            .await
            .map_err(|error| describe_reqwest_send_error(&error))?;
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
        let body = response
            .bytes()
            .await
            .map_err(|error| describe_reqwest_body_error(&error))?
            .to_vec();

        Ok(Response::new(status, headers, body))
    }
}

/// Maps a failure while sending. A connection that was never established is
/// safe to retry; a timeout or any later failure may follow a sent command and
/// is therefore ambiguous. The rendering never includes request headers, so the
/// cookie cannot reach a log line.
#[cfg(feature = "http")]
fn describe_reqwest_send_error(error: &reqwest::Error) -> Error {
    describe_send_failure(
        error,
        error.is_timeout(),
        error.is_builder(),
        error.is_connect(),
    )
}

/// Classifies a send failure from the properties a transport can observe.
#[cfg(feature = "http")]
fn describe_send_failure(
    error: &(impl std::fmt::Display + ?Sized),
    is_timeout: bool,
    is_builder: bool,
    is_connect: bool,
) -> Error {
    if is_timeout {
        // A connection timeout is also reported as a timeout. Since reqwest
        // does not expose whether bytes left the host, fail closed rather than
        // risk a duplicate command.
        return Error::ambiguous(format!("timeout: {error}"));
    }
    if is_builder {
        return Error::Transport {
            message: format!("request setup: {error}"),
            retryable: false,
        };
    }
    if is_connect {
        return Error::transport(format!("connect: {error}"));
    }
    // `reqwest::Error` renders the URL but never request headers.
    Error::ambiguous(format!("request: {error}"))
}

/// Once response bytes are being read, the server has necessarily received the
/// command. Any failure here leaves its outcome unknown.
#[cfg(feature = "http")]
fn describe_reqwest_body_error(error: &reqwest::Error) -> Error {
    describe_body_failure(error)
}

/// A failure after response bytes started arriving leaves the command outcome
/// unknown regardless of the concrete transport error type.
#[cfg(feature = "http")]
fn describe_body_failure(error: &(impl std::fmt::Display + ?Sized)) -> Error {
    Error::ambiguous(format!("response body: {error}"))
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

    #[cfg(feature = "http")]
    #[tokio::test]
    async fn request_setup_errors_are_terminal() {
        let result = ReqwestTransport::new()
            .execute(Request::post_json("not a url", b"{}"))
            .await;

        assert!(matches!(
            result,
            Err(Error::Transport {
                retryable: false,
                ..
            })
        ));
    }

    #[cfg(feature = "http")]
    #[test]
    fn send_failure_classification_is_fail_closed() {
        assert!(describe_send_failure("timeout", true, true, true).is_ambiguous());

        let setup = describe_send_failure("bad header", false, true, true);
        assert!(matches!(
            setup,
            Error::Transport {
                retryable: false,
                ..
            }
        ));

        let connect = describe_send_failure("refused", false, false, true);
        assert!(connect.is_retryable());
        assert!(!connect.is_ambiguous());

        assert!(describe_send_failure("reset", false, false, false).is_ambiguous());
    }

    #[cfg(feature = "http")]
    #[test]
    fn a_failure_while_reading_the_body_is_ambiguous() {
        assert!(describe_body_failure("connection reset").is_ambiguous());
    }
}
