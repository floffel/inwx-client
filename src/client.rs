//! The client: session handling, retries and the JSON-RPC loop.
//!
//! INWX authenticates with a cookie session, not a bearer token: `account.login`
//! returns a `Set-Cookie` header and every later call has to replay it. This
//! module owns that dance — lazy login on the first call, one re-login when the
//! API reports an expired session, and cookie collection that never touches the
//! `Debug` representation of anything.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::rpc::{RpcRequest, RpcResponse};
use crate::transport::{Request, Response, Transport};
use crate::types::de;

/// Production endpoint, as documented (`api.domrobot.com`).
pub const DEFAULT_BASE_URL: &str = "https://api.domrobot.com/jsonrpc/";

/// Free test environment (OTE), where registrations cost nothing.
pub const SANDBOX_BASE_URL: &str = "https://api.ote.domrobot.com/jsonrpc/";

/// Default number of attempts for a retryable failure (the first try plus two
/// retries).
pub const DEFAULT_ATTEMPTS: u32 = 3;

/// Default delay before the first retry.
pub const DEFAULT_BASE_DELAY: Duration = Duration::from_millis(500);

/// Default ceiling for the backoff.
pub const DEFAULT_MAX_DELAY: Duration = Duration::from_secs(8);

/// Language the API uses for `msg` and `reason`.
///
/// ```
/// use inwx_client::Language;
///
/// assert_eq!(Language::default().as_str(), "en");
/// assert_eq!(Language::De.as_str(), "de");
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Language {
    /// English messages.
    #[default]
    En,
    /// German messages.
    De,
}

impl Language {
    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::Language;
    /// assert_eq!(Language::En.as_str(), "en");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::De => "de",
        }
    }
}

impl std::str::FromStr for Language {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "en" => Ok(Self::En),
            "de" => Ok(Self::De),
            other => Err(Error::validation(
                "lang",
                format!("{other:?} is not a supported language (en, de)"),
            )),
        }
    }
}

/// Account credentials for `account.login`.
///
/// Both fields are checked at construction: an empty username or password would
/// make every call fail with a confusing API error, and a control character
/// would let a value escape its JSON string into a header.
///
/// ```
/// use inwx_client::Credentials;
///
/// let credentials = Credentials::new("florian", "s3cret")?;
/// assert_eq!(credentials.username(), "florian");
/// assert!(Credentials::new("", "s3cret").is_err());
/// assert!(Credentials::new("florian", "with\nnewline").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    /// Validates and stores credentials.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when either value is empty or contains control
    /// characters (the username is `text64` on the wire, the password is
    /// unbounded — neither is truncated here).
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Result<Self> {
        let username = username.into();
        let password = password.into();
        if username.trim().is_empty() {
            return Err(Error::validation(
                "credentials.username",
                "must not be empty",
            ));
        }
        if password.is_empty() {
            return Err(Error::validation(
                "credentials.password",
                "must not be empty",
            ));
        }
        if username.chars().any(char::is_control) || password.chars().any(char::is_control) {
            return Err(Error::validation(
                "credentials",
                "must not contain control characters",
            ));
        }
        Ok(Self { username, password })
    }

    /// The username.
    ///
    /// ```
    /// use inwx_client::Credentials;
    /// assert_eq!(Credentials::new("user", "pass")?.username(), "user");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }
}

/// `Debug` redacts the password: a credential that reaches a log line is a
/// credential leak.
impl fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// How many times a retryable failure is retried, and how long to wait.
///
/// Backoff is exponential from [`DEFAULT_BASE_DELAY`] and clamped to
/// [`DEFAULT_MAX_DELAY`]. Only failures that happened before the request was
/// written, HTTP 429/5xx and API code `2300` (object pending transfer) are
/// retried; everything else is terminal — retrying a rejected command would
/// just duplicate the rejection.
///
/// An [`Error::Uncertain`] (a timeout, a reset mid-response) is out of reach
/// here: the command may already have run, so it is replayed only for a
/// read-only method, never for a mutating one. See
/// [`is_read_only_method`].
///
/// ```
/// use std::time::Duration;
/// use inwx_client::RetryPolicy;
///
/// let policy = RetryPolicy::default();
/// assert_eq!(policy.delay(1), Some(Duration::from_millis(500)));
/// assert_eq!(policy.delay(2), Some(Duration::from_secs(1)));
/// assert_eq!(policy.delay(3), None); // three attempts in total
///
/// let impatient = RetryPolicy::new(4).with_base_delay(Duration::ZERO).with_max_delay(Duration::ZERO);
/// assert_eq!(impatient.delay(3), Some(Duration::ZERO));
/// assert_eq!(impatient.attempts(), 4);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    attempts: u32,
    base_delay: Duration,
    max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: DEFAULT_ATTEMPTS,
            base_delay: DEFAULT_BASE_DELAY,
            max_delay: DEFAULT_MAX_DELAY,
        }
    }
}

impl RetryPolicy {
    /// A policy with `attempts` total attempts (clamped to at least one) and
    /// the default delays.
    ///
    /// ```
    /// use inwx_client::RetryPolicy;
    ///
    /// assert_eq!(RetryPolicy::new(0).attempts(), 1);
    /// assert_eq!(RetryPolicy::new(5).attempts(), 5);
    /// ```
    #[must_use]
    pub fn new(attempts: u32) -> Self {
        Self {
            attempts: attempts.max(1),
            ..Self::default()
        }
    }

    /// Sets the delay before the first retry.
    ///
    /// ```
    /// use std::time::Duration;
    /// use inwx_client::RetryPolicy;
    ///
    /// let policy = RetryPolicy::default().with_base_delay(Duration::from_millis(10));
    /// assert_eq!(policy.delay(1), Some(Duration::from_millis(10)));
    /// ```
    #[must_use]
    pub fn with_base_delay(mut self, delay: Duration) -> Self {
        self.base_delay = delay;
        self
    }

    /// Sets the ceiling for the backoff.
    ///
    /// ```
    /// use std::time::Duration;
    /// use inwx_client::RetryPolicy;
    ///
    /// let policy = RetryPolicy::new(6)
    ///     .with_base_delay(Duration::from_secs(1))
    ///     .with_max_delay(Duration::from_secs(2));
    /// assert_eq!(policy.delay(4), Some(Duration::from_secs(2)));
    /// ```
    #[must_use]
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Total number of attempts, including the first one.
    ///
    /// ```
    /// use inwx_client::RetryPolicy;
    /// assert_eq!(RetryPolicy::default().attempts(), 3);
    /// ```
    #[must_use]
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// How long to wait after failure number `attempt` (1-based), or `None`
    /// when the attempts are exhausted.
    ///
    /// ```
    /// use inwx_client::RetryPolicy;
    /// assert!(RetryPolicy::new(2).delay(2).is_none());
    /// ```
    #[must_use]
    pub fn delay(&self, attempt: u32) -> Option<Duration> {
        if attempt >= self.attempts {
            return None;
        }
        let factor = 1u32
            .checked_shl(attempt.saturating_sub(1))
            .unwrap_or(u32::MAX);
        Some(self.base_delay.saturating_mul(factor).min(self.max_delay))
    }
}

/// Subset of `account.info` this crate models.
///
/// The full response has more than sixty fields, most of them billing detail
/// this client has no use for; unknown fields are ignored.
///
/// ```
/// use inwx_client::AccountInfo;
///
/// let info: AccountInfo = serde_json::from_str(
///     r#"{"accountId":61140,"customerId":10069,"customerNo":110069,"username":"florian"}"#,
/// )?;
/// assert_eq!(info.account_id, Some(61140));
/// assert!(info.two_factor.is_none());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct AccountInfo {
    /// Account id.
    #[serde(rename = "accountId", default, deserialize_with = "de::opt_i64")]
    pub account_id: Option<i64>,
    /// Customer id.
    #[serde(rename = "customerId", default, deserialize_with = "de::opt_i64")]
    pub customer_id: Option<i64>,
    /// Customer number.
    #[serde(rename = "customerNo", default, deserialize_with = "de::opt_i64")]
    pub customer_no: Option<i64>,
    /// Login name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub username: Option<String>,
    /// Two-factor method, `"0"` when disabled.
    #[serde(rename = "tfa", default, deserialize_with = "de::opt_string")]
    pub two_factor: Option<String>,
}

/// A JSON-RPC client for the INWX `DomRobot` API.
///
/// The client is generic over [`Transport`], so tests and binaries can plug in
/// their own HTTP stack. It is cheap to clone only by wrapping in [`Arc`]; the
/// session is shared through an internal `Arc<Mutex<_>>`, so 32 tasks can share
/// one client (see the `concurrency` integration test).
///
/// ```
/// use inwx_client::{InwxClient, RetryPolicy, transport::{Request, Response, Transport}, Result};
/// # use std::sync::Arc;
/// # use std::sync::Mutex;
///
/// #[derive(Clone)]
/// struct Scripted(Arc<Mutex<Vec<&'static str>>>);
///
/// impl Transport for Scripted {
///     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
///         let body = self.0.lock().unwrap().remove(0);
///         Ok(Response::new(200, std::iter::empty(), body.as_bytes().to_vec()))
///     }
/// }
///
/// # async fn demo() -> Result<()> {
/// let transport = Scripted(Arc::new(Mutex::new(vec![
///     r#"{"code":1000,"msg":"ok","resData":{"accountId":1}}"#,
///     r#"{"code":1000,"msg":"ok","resData":{}}"#,
/// ])));
/// let client = InwxClient::new(transport)
///     .with_credentials("user", "pass")?
///     .with_retry(RetryPolicy::default());
/// let info = client.account_info().await?;
/// assert_eq!(info.account_id, Some(1));
/// # Ok(())
/// # }
/// ```
pub struct InwxClient<T> {
    transport: T,
    base_url: String,
    credentials: Option<Credentials>,
    session: Arc<Mutex<Option<String>>>,
    policy: RetryPolicy,
    timeout: Option<Duration>,
    language: Option<Language>,
}

impl<T: Transport> InwxClient<T> {
    /// A client without credentials, pointed at production.
    ///
    /// Add credentials with [`InwxClient::with_credentials`], or a cookie with
    /// [`InwxClient::with_session`], before calling any authenticated method.
    ///
    /// ```
    /// use inwx_client::{InwxClient, transport::{Request, Response, Transport}, Result};
    ///
    /// struct Never;
    ///
    /// impl Transport for Never {
    ///     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    ///         unreachable!("no call is made here")
    ///     }
    /// }
    ///
    /// let client = InwxClient::new(Never);
    /// assert!(!client.is_authenticated());
    /// ```
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            base_url: DEFAULT_BASE_URL.to_owned(),
            credentials: None,
            session: Arc::new(Mutex::new(None)),
            policy: RetryPolicy::default(),
            timeout: Some(Duration::from_secs(30)),
            language: None,
        }
    }

    /// A client pointed at the free OTE sandbox instead of production.
    ///
    /// ```
    /// use inwx_client::{InwxClient, SANDBOX_BASE_URL, transport::{Request, Response, Transport}, Result};
    ///
    /// struct Never;
    ///
    /// impl Transport for Never {
    ///     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    ///         unreachable!()
    ///     }
    /// }
    ///
    /// assert_eq!(InwxClient::sandbox(Never).base_url(), SANDBOX_BASE_URL);
    /// ```
    pub fn sandbox(transport: T) -> Self {
        Self {
            base_url: SANDBOX_BASE_URL.to_owned(),
            ..Self::new(transport)
        }
    }

    /// Sets the username and password used for the lazy `account.login`.
    ///
    /// ```
    /// use inwx_client::{InwxClient, transport::{Request, Response, Transport}, Result};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!()
    /// #     }
    /// # }
    /// let client = InwxClient::new(Never).with_credentials("user", "pass")?;
    /// assert!(!client.is_authenticated()); // logs in on first use
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`Credentials::new`].
    pub fn with_credentials(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self> {
        self.credentials = Some(Credentials::new(username, password)?);
        Ok(self)
    }

    /// Reuses an existing session cookie instead of logging in.
    ///
    /// The value is what the API returned in `Set-Cookie`, without the
    /// attributes — `session=abc123`. It is rejected if it would not survive as
    /// a header value.
    ///
    /// ```
    /// use inwx_client::{InwxClient, transport::{Request, Response, Transport}, Result};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!()
    /// #     }
    /// # }
    /// let client = InwxClient::new(Never).with_session("domrobot=abc123")?;
    /// assert!(client.is_authenticated());
    ///
    /// // A newline would smuggle a second header.
    /// assert!(InwxClient::new(Never).with_session("a=b\r\nX-Evil: 1").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the cookie is empty or contains control
    /// characters.
    pub fn with_session(self, cookie: impl Into<String>) -> Result<Self> {
        let cookie = cookie.into();
        // Checked before trimming: a trailing newline would otherwise be
        // trimmed away and the header it could smuggle would go unnoticed.
        if cookie.chars().any(char::is_control) {
            return Err(Error::validation(
                "session",
                "must not contain control characters (header injection)",
            ));
        }
        let trimmed = cookie.trim();
        if trimmed.is_empty() {
            return Err(Error::validation("session", "must not be empty"));
        }
        *self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(trimmed.to_owned());
        Ok(self)
    }

    /// Overrides the endpoint. Tests use this to point at a mock host.
    ///
    /// ```
    /// use inwx_client::{InwxClient, transport::{Request, Response, Transport}, Result};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!()
    /// #     }
    /// # }
    /// let client = InwxClient::new(Never).with_base_url("https://inwx.test/jsonrpc/");
    /// assert_eq!(client.base_url(), "https://inwx.test/jsonrpc/");
    /// ```
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Replaces the retry policy.
    ///
    /// ```
    /// use inwx_client::{InwxClient, RetryPolicy, transport::{Request, Response, Transport}, Result};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!()
    /// #     }
    /// # }
    /// let client = InwxClient::new(Never).with_retry(RetryPolicy::new(1));
    /// ```
    #[must_use]
    pub fn with_retry(mut self, policy: RetryPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Sets the per-request timeout (`None` uses the transport default).
    ///
    /// ```
    /// use inwx_client::{InwxClient, transport::{Request, Response, Transport}, Result};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!()
    /// #     }
    /// # }
    /// let client = InwxClient::new(Never).with_timeout(None);
    /// assert_eq!(client.timeout(), None);
    /// ```
    #[must_use]
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the `lang` parameter sent with every call.
    ///
    /// ```
    /// use inwx_client::{InwxClient, Language, transport::{Request, Response, Transport}, Result};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!()
    /// #     }
    /// # }
    /// let client = InwxClient::new(Never).with_language(Language::De);
    /// ```
    #[must_use]
    pub fn with_language(mut self, language: Language) -> Self {
        self.language = Some(language);
        self
    }

    /// The endpoint in use.
    ///
    /// ```
    /// # use inwx_client::{InwxClient, DEFAULT_BASE_URL, transport::{Request, Response, Transport}, Result};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!()
    /// #     }
    /// # }
    /// assert_eq!(InwxClient::new(Never).base_url(), DEFAULT_BASE_URL);
    /// ```
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The configured timeout.
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use inwx_client::{InwxClient, transport::{Request, Response, Transport}, Result};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!()
    /// #     }
    /// # }
    /// assert_eq!(InwxClient::new(Never).timeout(), Some(Duration::from_secs(30)));
    /// ```
    #[must_use]
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Whether a session cookie is present.
    ///
    /// ```
    /// # use inwx_client::{InwxClient, transport::{Request, Response, Transport}, Result};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!()
    /// #     }
    /// # }
    /// assert!(!InwxClient::new(Never).is_authenticated());
    /// assert!(InwxClient::new(Never).with_session("s=1")?.is_authenticated());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }

    /// Drops the session cookie without telling the server.
    ///
    /// ```
    /// # use inwx_client::{InwxClient, transport::{Request, Response, Transport}, Result};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!()
    /// #     }
    /// # }
    /// let client = InwxClient::new(Never).with_session("s=1")?;
    /// client.clear_session();
    /// assert!(!client.is_authenticated());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn clear_session(&self) {
        *self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// Logs in with the configured credentials and stores the session cookie.
    ///
    /// The client does this automatically before the first authenticated call,
    /// so an explicit call is only needed to fail fast at startup.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.login().await?;
    /// assert!(client.is_authenticated());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::NotAuthenticated`] without credentials, [`Error::Api`] when the
    /// API rejects the login, [`Error::Authentication`] when it accepts the
    /// login but sends no cookie.
    pub async fn login(&self) -> Result<()> {
        let credentials = self.credentials.as_ref().ok_or(Error::NotAuthenticated)?;
        let mut params = Map::new();
        params.insert(
            "user".to_owned(),
            Value::String(credentials.username.clone()),
        );
        params.insert(
            "pass".to_owned(),
            Value::String(credentials.password.clone()),
        );
        self.add_language(&mut params);

        let response = self.send("account.login", params).await?;
        let envelope = RpcResponse::parse(response.body())?;
        envelope.into_result()?;

        let cookie = collect_cookies(&response);
        if cookie.is_empty() {
            return Err(Error::Authentication {
                message: "login succeeded but the response carried no session cookie".to_owned(),
            });
        }
        *self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cookie);
        Ok(())
    }

    /// Ends the session server-side and forgets the cookie locally.
    ///
    /// The local cookie is dropped even when the API call fails, so a broken
    /// connection cannot leave the client holding a session it cannot use.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.logout().await?;
    /// assert!(!client.is_authenticated());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Whatever the `account.logout` call returned; the session is cleared
    /// either way.
    pub async fn logout(&self) -> Result<()> {
        let result = if self.is_authenticated() {
            self.call("account.logout", Value::Null).await.map(|_| ())
        } else {
            Ok(())
        };
        self.clear_session();
        result
    }

    /// Reads the account behind the credentials (`account.info`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let info = client.account_info().await?;
    /// println!("customer {:?}", info.customer_no);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn account_info(&self) -> Result<AccountInfo> {
        let data = self.call("account.info", json!({ "wide": 0 })).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Calls any method and returns its `resData`.
    ///
    /// This is the escape hatch for the parts of the API this crate does not
    /// model (accounting, certificates, hosting, `DynDNS`, DNSSEC, tags). It still
    /// handles login, cookies, retries and error envelopes.
    ///
    /// ```
    /// # use inwx_client::{InwxClient, transport::{Request, Response, Transport}, Result};
    /// # use std::sync::{Arc, Mutex};
    /// # #[derive(Clone)]
    /// # struct Scripted(Arc<Mutex<Vec<&'static str>>>);
    /// # impl Transport for Scripted {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         let body = self.0.lock().unwrap().remove(0);
    /// #         Ok(Response::new(200, std::iter::empty(), body.as_bytes().to_vec()))
    /// #     }
    /// # }
    /// # async fn demo() -> Result<()> {
    /// let transport = Scripted(Arc::new(Mutex::new(vec![
    ///     r#"{"code":1000,"msg":"ok","resData":{"x":1}}"#,
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":2}}"#,
    /// ])));
    /// let client = InwxClient::new(transport).with_session("s=1")?;
    /// let data = client.call("accounting.accountBalance", serde_json::json!({})).await?;
    /// assert_eq!(data["count"], 2);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Retries follow [`RetryPolicy`], with one extra rule: an
    /// [`Error::Uncertain`] — the request was written and the answer never
    /// arrived — is replayed only when [`is_read_only_method`] says the command
    /// cannot have side effects. For a mutating method the error is returned
    /// as-is, because a second attempt could register twice.
    ///
    /// The same rule covers HTTP: a 429 or a 5xx is replayed only for a
    /// read-only method. For a mutating method the status says nothing about
    /// whether the command already ran, so the call answers
    /// [`Error::Uncertain`] after a single attempt instead of retrying.
    ///
    /// # Errors
    ///
    /// [`Error::NotAuthenticated`], [`Error::Api`], [`Error::Transport`],
    /// [`Error::Uncertain`], [`Error::Json`] or [`Error::Http`].
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        if !is_public_method(method) {
            self.ensure_session().await?;
        }
        let mut relogged_in = false;
        let mut attempt = 1u32;

        loop {
            let outcome = self
                .send(method, params.as_object().cloned().unwrap_or_default())
                .await;
            match outcome {
                Ok(response) if response.is_success() => {
                    let envelope = RpcResponse::parse(response.body())?;
                    if envelope.is_authentication() && !relogged_in && self.credentials.is_some() {
                        relogged_in = true;
                        self.clear_session();
                        self.login().await?;
                        continue;
                    }
                    // `2300` means the object is mid-transfer: the command did
                    // not fail, it is simply too early.
                    if envelope.code == 2300 {
                        if let Some(delay) = self.policy.delay(attempt) {
                            sleep_for(delay).await;
                            attempt += 1;
                            continue;
                        }
                    }
                    return envelope.into_result();
                }
                Ok(response) => {
                    // HTTP 401/403 means the session died; 429 and 5xx are
                    // worth another try for a method that cannot have done
                    // anything yet; anything else is terminal.
                    let status = response.status();
                    if matches!(status, 401 | 403) && !relogged_in && self.credentials.is_some() {
                        relogged_in = true;
                        self.clear_session();
                        self.login().await?;
                        continue;
                    }
                    if status_replay_allowed(status, method) {
                        if let Some(delay) = self.policy.delay(attempt) {
                            sleep_for(delay).await;
                            attempt += 1;
                            continue;
                        }
                    }
                    return match RpcResponse::parse(response.body()) {
                        // The API did answer with a verdict, so the verdict
                        // outranks the status and is never repeated.
                        Ok(envelope) if !envelope.is_success() => envelope.into_result(),
                        // Nothing readable answered behind a transient status.
                        // The request was written, so on a command that mutates
                        // the outcome is unknown and a replay could duplicate
                        // the work.
                        _ if status_is_uncertain(status, method) => Err(Error::uncertain(format!(
                            "`{method}` answered HTTP {status}; the command may have been \
                             executed, check the current state before retrying"
                        ))),
                        Ok(envelope) => envelope.into_result(),
                        Err(_) => Err(Error::Http {
                            status,
                            body: String::from_utf8_lossy(response.body())
                                .chars()
                                .take(512)
                                .collect(),
                        }),
                    };
                }
                Err(error) if replay_allowed(&error, method) => {
                    if let Some(delay) = self.policy.delay(attempt) {
                        sleep_for(delay).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Opens a session when the next call needs one.
    async fn ensure_session(&self) -> Result<()> {
        if self.is_authenticated() {
            return Ok(());
        }
        if self.credentials.is_none() {
            return Err(Error::NotAuthenticated);
        }
        self.login().await
    }

    /// One HTTP round trip, no retries and no session logic.
    async fn send(&self, method: &str, params: Map<String, Value>) -> Result<Response> {
        let mut params = params;
        self.add_language(&mut params);
        let body = RpcRequest::new(method, &Value::Object(params)).to_bytes()?;

        let cookie = self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut request = Request::post_json(&self.base_url, &body)
            .with_header("Content-Type", "application/json")
            .with_header("Accept", "application/json")
            .with_header(
                "User-Agent",
                concat!("inwx-client/", env!("CARGO_PKG_VERSION")),
            );
        if let Some(cookie) = &cookie {
            request = request.with_header("Cookie", cookie.clone());
        }
        request = request.with_timeout(self.timeout);
        self.transport.execute(request).await
    }

    fn add_language(&self, params: &mut Map<String, Value>) {
        if let Some(language) = self.language {
            params
                .entry("lang".to_owned())
                .or_insert_with(|| Value::String(language.as_str().to_owned()));
        }
    }
}

/// Methods that only read: calling one twice cannot charge, create or delete
/// anything.
///
/// Kept sorted and lowercase; [`is_read_only_method`] compares after trimming
/// and ASCII folding. Everything that is not in here counts as mutating, which
/// is the safe direction — an omission costs a missing retry, never a
/// duplicated registration.
const READ_ONLY_METHODS: &[&str] = &[
    "account.check",
    "account.info",
    "accounting.accountbalance",
    "accounting.creditlogbyid",
    "accounting.getinvoice",
    "accounting.getpreviewinvoice",
    "accounting.getreceipt",
    "accounting.getstatement",
    "accounting.listinvoices",
    "accounting.lockedfunds",
    "accounting.log",
    "authinfo2.getprice",
    "certificate.getproduct",
    "certificate.info",
    "certificate.list",
    "certificate.listproducts",
    "certificate.listremainingneededdata",
    "certificate.log",
    "contact.info",
    "contact.list",
    "dnssec.info",
    "dnssec.listkeys",
    "domain.check",
    "domain.getdomainprice",
    "domain.getprices",
    "domain.info",
    "domain.list",
    "domain.whois",
    "dyndns.check",
    "dyndns.info",
    "dyndns.list",
    "dyndns.log",
    "dyndnssubscription.list",
    "dyndnssubscription.listproducts",
    "hosting.controlpanel",
    "hosting.getprices",
    "hosting.issuspended",
    "hosting.list",
    "nameserver.check",
    "nameserver.export",
    "nameserver.exportlist",
    "nameserver.exportrecords",
    "nameserver.info",
    "nameserver.list",
    "nameserverset.info",
    "nameserverset.list",
    "tag.info",
    "tag.list",
];

/// Whether a method only reads, so replaying it after an
/// [`Error::Uncertain`] cannot duplicate a mutation.
///
/// The comparison trims surrounding whitespace and folds ASCII case; the match
/// itself is exact, so `domain.infos` is not `domain.info`. Everything unknown
/// counts as mutating, including any method reached through
/// [`InwxClient::call`] that this table does not cover — fail closed.
///
/// ```
/// use inwx_client::is_read_only_method;
///
/// assert!(is_read_only_method("domain.info"));
/// assert!(is_read_only_method("  DOMAIN.LIST  "));
/// assert!(!is_read_only_method("domain.create"));
/// // One character short of a known method is still unknown.
/// assert!(!is_read_only_method("domain.inf"));
/// ```
#[must_use]
pub fn is_read_only_method(method: &str) -> bool {
    let trimmed = method.trim();
    if trimmed.is_empty() {
        return false;
    }
    let folded = trimmed.to_ascii_lowercase();
    READ_ONLY_METHODS.binary_search(&folded.as_str()).is_ok()
}

/// Whether `error` may be answered with another attempt of `method`.
///
/// Everything known to happen before the request was written is retried as
/// before. An [`Error::Uncertain`] happened afterwards, so it is only replayed
/// when the command cannot have side effects.
fn replay_allowed(error: &Error, method: &str) -> bool {
    match error {
        Error::Uncertain { .. } => is_read_only_method(method),
        other => other.is_retryable(),
    }
}

/// Methods that may be called without a session.
fn is_public_method(method: &str) -> bool {
    matches!(method, "account.login" | "account.logout" | "account.check")
}

/// HTTP statuses worth another attempt.
fn is_retryable_status(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

/// Whether an HTTP status may be answered with another attempt of `method`.
///
/// A transient status is only worth replaying when the command cannot have
/// done anything yet. For a mutating method the status alone says nothing
/// about whether the order already happened.
fn status_replay_allowed(status: u16, method: &str) -> bool {
    is_retryable_status(status) && is_read_only_method(method)
}

/// Whether a status leaves the outcome of `method` unknown: the request was
/// written, the answer is a transient failure, and a second attempt could
/// duplicate the mutation.
fn status_is_uncertain(status: u16, method: &str) -> bool {
    is_retryable_status(status) && !is_read_only_method(method)
}

/// Collects every `Set-Cookie` header into a single `Cookie` value.
///
/// Attributes (`Path`, `Domain`, `HttpOnly`, …) are dropped: only the
/// `name=value` pair belongs in the request header. Duplicate names keep the
/// last value, which is what a browser cookie jar would do.
fn collect_cookies(response: &Response) -> String {
    let mut pairs: Vec<String> = Vec::new();
    for header in response.header_all("set-cookie") {
        let pair = header.split(';').next().unwrap_or("").trim();
        if pair.is_empty() || pair.contains('\n') || pair.contains('\r') {
            continue;
        }
        let Some((name, _)) = pair.split_once('=') else {
            // A cookie without a value is not a cookie.
            continue;
        };
        if name.trim().is_empty() {
            continue;
        }
        pairs.retain(|existing: &String| !existing.starts_with(&format!("{name}=")));
        pairs.push(pair.to_owned());
    }
    pairs.join("; ")
}

#[cfg(feature = "http")]
async fn sleep_for(delay: Duration) {
    tokio::time::sleep(delay).await;
}

/// Without the `http` feature there is no timer to await, so retries happen
/// immediately — bring your own pacing.
#[cfg(not(feature = "http"))]
#[allow(clippy::unused_async)]
async fn sleep_for(_delay: Duration) {}

/// `Debug` shows the endpoint and whether a session exists, never the cookie or
/// the credentials.
impl<T> fmt::Debug for InwxClient<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InwxClient")
            .field("base_url", &self.base_url)
            .field(
                "authenticated",
                &self
                    .session
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_some(),
            )
            .field("credentials", &self.credentials.is_some())
            .field("retry", &self.policy)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TransportStage;

    #[test]
    fn credentials_debug_redacts_password() {
        let credentials = Credentials::new("user", "hunter2").unwrap();
        let rendered = format!("{credentials:?}");
        assert!(rendered.contains("user"));
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn credentials_reject_control_characters() {
        assert!(Credentials::new("us\ner", "pass").is_err());
        assert!(Credentials::new("user", "pa\rss").is_err());
        assert!(Credentials::new("  ", "pass").is_err());
    }

    #[test]
    fn delay_is_exponential_and_capped() {
        let policy = RetryPolicy::new(6)
            .with_base_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_millis(500));
        assert_eq!(policy.delay(1), Some(Duration::from_millis(100)));
        assert_eq!(policy.delay(2), Some(Duration::from_millis(200)));
        assert_eq!(policy.delay(3), Some(Duration::from_millis(400)));
        assert_eq!(policy.delay(4), Some(Duration::from_millis(500)));
        assert_eq!(policy.delay(6), None);
        assert_eq!(policy.delay(0), Some(Duration::from_millis(100)));
    }

    #[test]
    fn cookie_attributes_are_dropped_and_duplicates_collapse() {
        let response = Response::new(
            200,
            [
                (
                    "Set-Cookie".to_string(),
                    "domrobot=s1; Path=/; HttpOnly".to_string(),
                ),
                ("Set-Cookie".to_string(), "other=x; Secure".to_string()),
                ("Set-Cookie".to_string(), "domrobot=s2; Path=/".to_string()),
                ("Set-Cookie".to_string(), "garbage".to_string()),
            ],
            Vec::new(),
        );
        assert_eq!(collect_cookies(&response), "other=x; domrobot=s2");
    }

    #[test]
    fn retryable_status_classification() {
        for status in [429, 500, 502, 503, 504] {
            assert!(is_retryable_status(status), "{status}");
        }
        for status in [200, 400, 401, 404, 422] {
            assert!(!is_retryable_status(status), "{status}");
        }
    }

    #[test]
    fn language_round_trips() {
        assert_eq!("DE".parse::<Language>().unwrap(), Language::De);
        assert!("fr".parse::<Language>().is_err());
    }

    #[test]
    fn public_methods_need_no_session() {
        assert!(is_public_method("account.login"));
        assert!(!is_public_method("domain.list"));
    }

    #[test]
    fn read_only_table_is_sorted_and_unique() {
        // `is_read_only_method` binary-searches, which is only correct while
        // the table is sorted and free of duplicates.
        assert!(
            READ_ONLY_METHODS.contains(&"domain.info"),
            "the table must not be empty"
        );
        for pair in READ_ONLY_METHODS.windows(2) {
            assert!(
                pair[0] < pair[1],
                "out of order or duplicated: {:?} .. {:?}",
                pair[0],
                pair[1]
            );
        }
        for method in READ_ONLY_METHODS {
            assert!(method.contains('.'), "{method} is not namespaced");
            assert_eq!(*method, method.to_ascii_lowercase(), "{method}");
        }
    }

    #[test]
    fn read_only_lookup_sits_on_the_boundary() {
        // In the table, just outside it by one character, and one character
        // short of it.
        assert!(is_read_only_method("domain.info"));
        assert!(!is_read_only_method("domain.infos"));
        assert!(is_read_only_method("tag.list"));
        assert!(!is_read_only_method("tag.listx"));
        assert!(!is_read_only_method("domain.inf"));
        assert!(!is_read_only_method("tag.update"));
        assert!(!is_read_only_method("domain.create"));
        // The two authinfo2 methods sit on both sides of the line: the price
        // query reads, the order spends money.
        assert!(is_read_only_method("authinfo2.getprice"));
        assert!(!is_read_only_method("authinfo2.create"));

        // Case and padding are folded away; a bare namespace is not a method.
        assert!(is_read_only_method("  DOMAIN.INFO\t"));
        assert!(!is_read_only_method(""));
        assert!(!is_read_only_method("   "));
        assert!(!is_read_only_method("list"));
    }

    #[test]
    fn a_transient_status_is_only_replayed_for_a_read_only_method() {
        // Inside the retryable band on a read method: replay. The same status
        // on an order: never. Just outside the band: terminal either way.
        assert!(status_replay_allowed(500, "domain.list"));
        assert!(status_replay_allowed(429, "domain.list"));
        assert!(!status_replay_allowed(500, "authinfo2.create"));
        assert!(!status_replay_allowed(429, "authinfo2.create"));
        assert!(!status_replay_allowed(400, "domain.list"));
        assert!(!status_replay_allowed(404, "domain.list"));
    }

    #[test]
    fn a_transient_status_on_an_order_leaves_the_outcome_unknown() {
        assert!(status_is_uncertain(500, "authinfo2.create"));
        assert!(status_is_uncertain(429, "authinfo2.create"));
        assert!(!status_is_uncertain(500, "domain.list"));
        // A terminal status is an answer, not an missing one.
        assert!(!status_is_uncertain(404, "authinfo2.create"));
        assert!(!status_is_uncertain(400, "authinfo2.create"));
        // The two classifications are mutually exclusive and together cover
        // exactly the retryable statuses.
        for status in 0u16..600 {
            assert!(
                !(status_replay_allowed(status, "authinfo2.create")
                    && status_is_uncertain(status, "authinfo2.create"))
            );
            assert_eq!(
                status_replay_allowed(status, "domain.list")
                    || status_is_uncertain(status, "authinfo2.create"),
                is_retryable_status(status)
            );
        }
    }

    #[test]
    fn only_uncertain_failures_depends_on_the_method() {
        let uncertain = Error::uncertain("timeout");
        assert!(replay_allowed(&uncertain, "domain.info"));
        assert!(!replay_allowed(&uncertain, "domain.create"));
        assert!(!replay_allowed(&uncertain, "some.future.method"));

        // Everything before the request was written is replayed regardless.
        let connect = Error::transport_at(TransportStage::BeforeSend, "dns");
        assert!(replay_allowed(&connect, "domain.create"));
        let local = Error::transport_at(TransportStage::Local, "bad url");
        assert!(!replay_allowed(&local, "domain.info"));

        assert!(!replay_allowed(
            &Error::validation("domain", "empty"),
            "domain.info"
        ));
    }
}
