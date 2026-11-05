//! The client: session handling, retries and the JSON-RPC loop.
//!
//! INWX authenticates with a cookie session, not a bearer token: `account.login`
//! returns a `Set-Cookie` header and every later call has to replay it. This
//! module owns that dance — lazy login on the first call, one re-login when the
//! API reports an expired session, and cookie collection that never touches the
//! `Debug` representation of anything.

use std::fmt;
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use serde_json::{json, Map, Value};
use subtle::ConstantTimeEq;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::{retry_after_at, Error, HttpBody, Result};
use crate::rpc::{not_an_object, RpcRequest, RpcResponse};
use crate::session::{SessionGate, Turn};
use crate::transport::{Request, Response, Transport, TransportStage};
use crate::types::de;

/// Longest account username accepted by the `account.login` `text64` field.
const MAX_USERNAME_LEN: usize = 64;

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
/// would let a value escape its JSON string into a header. The username is the
/// API's `text64`, so it is limited to 64 characters; validation happens on the
/// borrowed input before either value is copied into owned storage.
///
/// The password is kept in a private wrapper that is deliberately not
/// `Clone`, is zeroed when the credentials are dropped, and compares in
/// constant time. This means credentials cannot be duplicated accidentally and
/// equality checks do not leak the position of the first differing byte.
///
/// ```
/// use inwx_client::Credentials;
///
/// let credentials = Credentials::new("florian", "s3cret")?;
/// assert_eq!(credentials.username(), "florian");
/// assert_eq!(credentials, Credentials::new("florian", "s3cret")?);
/// assert_ne!(credentials, Credentials::new("florian", "other")?);
/// assert!(Credentials::new("", "s3cret").is_err());
/// assert!(Credentials::new("florian", "with\nnewline").is_err());
///
/// let longest = "u".repeat(64);
/// let too_long = "u".repeat(65);
/// assert!(Credentials::new(longest.as_str(), "s3cret").is_ok());
/// assert!(Credentials::new(too_long.as_str(), "s3cret").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
///
/// Cloning is intentionally unavailable:
///
/// ```compile_fail
/// # fn main() -> Result<(), inwx_client::Error> {
/// use inwx_client::Credentials;
///
/// let credentials = Credentials::new("florian", "s3cret")?;
/// let duplicate = credentials.clone();
/// # Ok(())
/// # }
/// ```
pub struct Credentials {
    username: String,
    password: Password,
}

impl Credentials {
    /// Validates and stores credentials.
    ///
    /// ```
    /// use inwx_client::Credentials;
    ///
    /// let credentials = Credentials::new("user", "pass")?;
    /// assert_eq!(credentials.username(), "user");
    /// assert!(Credentials::new("user", "").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when either value is empty, the username is longer
    /// than 64 characters, or either value contains control characters. The
    /// username is `text64` on the wire; the password is unbounded. Neither is
    /// truncated here.
    pub fn new(
        username: impl Into<String> + AsRef<str>,
        password: impl Into<String> + AsRef<str>,
    ) -> Result<Self> {
        validate_credentials(username.as_ref(), password.as_ref())?;
        Ok(Self {
            username: username.into(),
            password: Password::new(password.into()),
        })
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

/// Compares both fields. The password comparison is constant-time and always
/// runs, regardless of whether the usernames match.
impl PartialEq for Credentials {
    fn eq(&self, other: &Self) -> bool {
        let usernames_match = self.username == other.username;
        let passwords_match = self.password == other.password;
        usernames_match && passwords_match
    }
}

impl Eq for Credentials {}

/// Password storage that cannot be cloned and erases its contents on drop.
struct Password(Zeroizing<String>);

impl Password {
    fn new(password: String) -> Self {
        Self(Zeroizing::new(password))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for Password {}

impl ZeroizeOnDrop for Password {}

/// Checks borrowed credentials before either value is converted into a `String`.
fn validate_credentials(username: &str, password: &str) -> Result<()> {
    if username.trim().is_empty() {
        return Err(Error::validation(
            "credentials.username",
            "must not be empty",
        ));
    }
    if username.chars().count() > MAX_USERNAME_LEN {
        return Err(Error::validation(
            "credentials.username",
            format!("must be at most {MAX_USERNAME_LEN} characters"),
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
    Ok(())
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
/// written, HTTP 429/5xx and API code `2300` (object pending transfer) on a
/// read-only method are retried; everything else is terminal — retrying a
/// rejected command would just duplicate the rejection, and replaying a
/// mutation after a transient status or `2300` would duplicate the work.
///
/// The wait is the *ceiling*, not the value slept: [`InwxClient`] draws a
/// uniform sample from `[0, delay]` for every retry ([`RetryPolicy::delay_with_jitter`]),
/// because thirty-two tasks sharing one client fail at the same instant and a
/// fixed delay sends all thirty-two retries back at the same instant, in a
/// burst that hits a rate-limited API harder than the original load did.
/// The ceiling itself stays deterministic, so it is what a caller reads to
/// reason about the worst case, and what the tests pin.
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
/// // The jittered value is never above the ceiling, and both ends are reachable.
/// assert_eq!(policy.delay_with_jitter(1, 0.0), Some(Duration::ZERO));
/// assert_eq!(policy.delay_with_jitter(1, 1.0), Some(Duration::from_millis(500)));
/// assert_eq!(policy.delay_with_jitter(2, 0.5), Some(Duration::from_millis(500)));
/// assert_eq!(policy.delay_with_jitter(3, 0.5), None);
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
    /// This is the deterministic ceiling of the backoff — what a caller reads
    /// to reason about the worst case — not the value [`InwxClient`] sleeps,
    /// which is [`Self::delay_with_jitter`] of this.
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

    /// How long to wait after failure number `attempt` (1-based) when the
    /// random sample is `unit`: a value uniform in `[0, delay(attempt)]`, or
    /// `None` when the attempts are exhausted.
    ///
    /// This is full jitter: the sample is drawn over the whole interval rather
    /// than spread around a mean, so two clients that failed at the same moment
    /// are as far apart as the ceiling allows. It stays a pure function of
    /// `unit` — the caller owns the randomness, exactly as it owns the clock —
    /// so the retry decision can be tested without a fake generator.
    ///
    /// `unit` is clamped to `[0, 1]`; a `NaN` sample counts as `0`, so a broken
    /// generator collapses the wait to "immediately" instead of panicking
    /// inside a retry loop.
    ///
    /// # Why this is not a call into a backoff crate
    ///
    /// `exponential-backoff` and its kin are generators: `next_backoff` takes
    /// `&mut self`, so a policy that owned one could not be read through
    /// `&self` — and this client is shared by `Arc` across thirty-two tasks and
    /// holds no lock on the retry path. Their state would also make the wait a
    /// function of how often it was asked, not of `(policy, attempt)`, while
    /// the retry decision here has to stay a pure function. What remains is the
    /// clamp and one multiplication.
    ///
    /// ```
    /// use std::time::Duration;
    /// use inwx_client::RetryPolicy;
    ///
    /// let policy = RetryPolicy::new(4).with_base_delay(Duration::from_secs(1));
    ///
    /// // Both ends of the interval, and the middle.
    /// assert_eq!(policy.delay_with_jitter(1, 0.0), Some(Duration::ZERO));
    /// assert_eq!(policy.delay_with_jitter(1, 1.0), Some(Duration::from_secs(1)));
    /// assert_eq!(policy.delay_with_jitter(2, 0.5), Some(Duration::from_secs(1)));
    ///
    /// // Outside the interval, and no sample at all for the last attempt.
    /// assert_eq!(policy.delay_with_jitter(1, -1.0), Some(Duration::ZERO));
    /// assert_eq!(policy.delay_with_jitter(1, 2.0), Some(Duration::from_secs(1)));
    /// assert_eq!(policy.delay_with_jitter(1, f64::NAN), Some(Duration::ZERO));
    /// assert_eq!(policy.delay_with_jitter(4, 0.5), None);
    /// ```
    #[must_use]
    pub fn delay_with_jitter(&self, attempt: u32, unit: f64) -> Option<Duration> {
        let ceiling = self.delay(attempt)?;
        // `f64::clamp` returns `NaN` for a `NaN` input, and `Duration::mul_f64`
        // panics on it: normalise first, then multiply.
        let unit = if unit.is_nan() {
            0.0
        } else {
            unit.clamp(0.0, 1.0)
        };
        if unit >= 1.0 {
            return Some(ceiling);
        }
        if unit <= 0.0 {
            return Some(Duration::ZERO);
        }
        Some(ceiling.mul_f64(unit))
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
/// their own HTTP stack. It is cheap to clone only by wrapping in
/// `std::sync::Arc`; the session is shared through one internal gate, so 32
/// tasks can share one client (see the `concurrency` integration test) — and a
/// session that dies under them costs one `account.login`, not one per task.
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
///         Response::new(200, std::iter::empty(), body.as_bytes().to_vec())
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
    session: SessionGate,
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
            session: SessionGate::new(),
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
        username: impl Into<String> + AsRef<str>,
        password: impl Into<String> + AsRef<str>,
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
        self.session.install(trimmed.to_owned());
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
        self.session.is_authenticated()
    }

    /// Drops the session cookie without telling the server.
    ///
    /// A login that is already on the wire does not resurrect the session
    /// afterwards: the drop wins, and the next call logs in again.
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
        self.session.clear();
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
    /// # One transition at a time
    ///
    /// A login never replaces a session that is already installed: a second
    /// `account.login` invalidates the cookie of the first server-side, so the
    /// installed one is reused and this call returns `Ok`. Use
    /// [`Self::logout`] or [`Self::clear_session`] first to replace a session
    /// on purpose.
    ///
    /// Concurrent callers do not each post credentials. The transition is
    /// single-flight: one caller runs the login, the others wait for its cookie
    /// and then use it, so a session that expired under thirty-two tasks costs
    /// one `account.login` instead of thirty-two — every one of which would be
    /// invalidated by the next and would count against an account that locks
    /// after repeated failures.
    ///
    /// Retries follow [`RetryPolicy`] — including the ones [`InwxClient::call`]
    /// refuses for a mutating command. `account.login` is the one command that
    /// is replayed although it writes: it opens a session and nothing else, so a
    /// 429, a 5xx or an answer that never arrived costs a repeat, not a
    /// duplicate domain, order or charge. A second login only replaces the
    /// session the first one opened.
    ///
    /// A login the API rejects is terminal, as everywhere else: an error
    /// envelope on a `2xx` is the verdict, and repeating it would only repeat
    /// the rejection.
    ///
    /// # Errors
    ///
    /// [`Error::NotAuthenticated`] without credentials, [`Error::Api`] when the
    /// API rejects the login, [`Error::Authentication`] when it accepts the
    /// login but sends no cookie.
    pub async fn login(&self) -> Result<()> {
        if self.credentials.is_none() {
            return Err(Error::NotAuthenticated);
        }
        // `None` for the generation: any session that is installed will do.
        self.transition_session(None).await
    }

    /// One session transition: reuse the session somebody else installed, or
    /// run the one `account.login` that may be on the wire.
    ///
    /// `seen` is the generation whose cookie the caller found dead, or `None`
    /// when any session will do. Whoever claims the transition installs the
    /// cookie it obtains — and only while the state is still the one it claimed
    /// it for, so a concurrent [`Self::clear_session`] is not undone.
    async fn transition_session(&self, seen: Option<u64>) -> Result<()> {
        match self.session.begin(seen).await {
            Turn::Fresh => Ok(()),
            Turn::Login(claim) => {
                let outcome = self.login_request().await;
                claim.resolve(outcome.as_ref().ok().cloned());
                outcome.map(|_| ())
            }
        }
    }

    /// The `account.login` round trip, cookie included.
    ///
    /// Callers must hold the login claim (see [`Self::transition_session`]):
    /// this writes no session state itself, so the decision where the cookie
    /// belongs stays in one place.
    async fn login_request(&self) -> Result<String> {
        let credentials = self.credentials.as_ref().ok_or(Error::NotAuthenticated)?;
        let mut params = Map::new();
        params.insert(
            "user".to_owned(),
            Value::String(credentials.username.clone()),
        );
        params.insert(
            "pass".to_owned(),
            Value::String(credentials.password.expose().to_owned()),
        );
        self.add_language(&mut params);

        let mut attempt = 1u32;
        let response = loop {
            match self.send("account.login", params.clone()).await {
                // A success, or a status no repeat could improve on: the
                // envelope below reports what the API said, whether or not this
                // was the last attempt.
                Ok(response)
                    if response.is_success() || !is_retryable_status(response.status()) =>
                {
                    break response;
                }
                Ok(response) => {
                    if let Some(delay) = self.policy.delay_with_jitter(attempt, jitter_unit()) {
                        sleep_for(delay).await;
                        attempt += 1;
                        continue;
                    }
                    break response;
                }
                Err(error) if !login_replay_allowed(&error) => return Err(error),
                Err(error) => {
                    if let Some(delay) = self.policy.delay_with_jitter(attempt, jitter_unit()) {
                        sleep_for(delay).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(error);
                }
            }
        };
        // The login request was written too: a body that cannot be read leaves
        // it open whether a session was opened server-side.
        let envelope = RpcResponse::parse_answer(response.body())?;
        envelope.into_result()?;

        let cookie = collect_cookies(&response)?;
        if cookie.is_empty() {
            return Err(Error::Authentication {
                message: "login succeeded but the response carried no session cookie".to_owned(),
                source: None,
            });
        }
        Ok(cookie)
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
            self.call("account.logout", json!({})).await.map(|_| ())
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
    /// #         Response::new(200, std::iter::empty(), body.as_bytes().to_vec())
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
    /// A `2xx` answer whose body cannot be read as an envelope is
    /// [`Error::Undecodable`]: the exchange completed, so the command may have
    /// run, and the call answers that at once instead of replaying — whatever
    /// the method, because the body carries nothing that would tell a duplicate
    /// write from a first one.
    ///
    /// The same rule covers HTTP: a 429 or a 5xx is replayed only for a
    /// read-only method. For a mutating method the status says nothing about
    /// whether the command already ran, so the call answers
    /// [`Error::HttpUncertain`] after a single attempt instead of retrying.
    ///
    /// API code `2300` (object pending transfer) is gated the same way: a read
    /// is replayed once the object is out of the transfer, a mutation is
    /// answered with that code at once. The command reached the object, and a
    /// second `domain.transfer` after the pending transfer settled would be a
    /// second order.
    ///
    /// A non-`2xx` answer whose body is not an envelope is [`Error::Http`], and
    /// the reason it could not be read is kept as that error's `source`: a
    /// proxy page and a JSON document of the wrong shape produce the same
    /// status, and only the parse error tells them apart.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `params` is not a JSON object, before
    /// anything is sent and before a session is opened: a method that takes no
    /// parameters passes `{}`. Silently sending an empty object instead would
    /// drop the caller's payload — a mutating call whose fields are all optional
    /// would go out with nothing set, and a read without its required filter
    /// would come back as a server-side rejection that looks like an API
    /// problem.
    ///
    /// [`Error::NotAuthenticated`], [`Error::Api`], [`Error::Transport`],
    /// [`Error::Uncertain`], [`Error::Undecodable`], [`Error::Json`] or
    /// [`Error::Http`].
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let Value::Object(params) = params else {
            return Err(not_an_object());
        };
        if !is_public_method(method) {
            self.ensure_session().await?;
        }
        let mut relogged_in = false;
        let mut attempt = 1u32;

        loop {
            // Read before the request goes out: a session that dies during the
            // round trip is then this generation, and one a concurrent caller
            // replaced in the meantime is not.
            let generation = self.session.generation();
            let outcome = self.send(method, params.clone()).await;
            match outcome {
                Ok(response) if response.is_success() => {
                    // The request was written and a 2xx came back, so a body
                    // that cannot be read leaves the outcome open: the parser
                    // reports `Undecodable`, not a local decode failure.
                    let envelope = RpcResponse::parse_answer(response.body())?;
                    if envelope.is_authentication() && !relogged_in && self.credentials.is_some() {
                        relogged_in = true;
                        self.transition_session(Some(generation)).await?;
                        continue;
                    }
                    // `2300` means the object is mid-transfer: the command did
                    // not fail, it is simply too early. Only a read is replayed
                    // — the code says the object was already reached, so a
                    // second mutating attempt could order, charge or delete
                    // once more.
                    if code_replay_allowed(envelope.code, method) {
                        if let Some(delay) = self.policy.delay_with_jitter(attempt, jitter_unit()) {
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
                        self.transition_session(Some(generation)).await?;
                        continue;
                    }
                    if status_replay_allowed(status, method) {
                        if let Some(delay) = self.policy.delay_with_jitter(attempt, jitter_unit()) {
                            sleep_for(delay).await;
                            attempt += 1;
                            continue;
                        }
                    }
                    let parse = RpcResponse::parse_body(response.body());
                    return match parse {
                        // The API did answer with a verdict, so the verdict
                        // outranks the status and is never repeated.
                        Ok(envelope) if !envelope.is_success() => envelope.into_result(),
                        // Nothing readable answered behind a transient status.
                        // The request was written, so on a command that mutates
                        // the outcome is unknown and a replay could duplicate
                        // the work.
                        _ if status_is_uncertain(status, method) => match parse {
                            Err(source) => Err(Error::http_uncertain(
                                method,
                                status,
                                HttpBody::from_bytes(response.body()),
                            )
                            .with_source(source)),
                            Ok(_) => Err(Error::http_uncertain(
                                method,
                                status,
                                HttpBody::from_bytes(response.body()),
                            )),
                        },
                        Ok(envelope) => envelope.into_result(),
                        // The body is unreadable, and the parse error is the
                        // only thing that separates "not JSON at all" — a proxy
                        // page, a cut-off answer — from "JSON in a shape no
                        // envelope has". Keeping it as the cause makes that
                        // difference walkable instead of flattening both into
                        // the same status with a body fragment.
                        Err(cause) => Err(http_error(&response).with_source(cause)),
                    };
                }
                Err(error) if replay_allowed(&error, method) => {
                    if let Some(delay) = self.policy.delay_with_jitter(attempt, jitter_unit()) {
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
    ///
    /// Concurrent callers coalesce here: the first one claims the login, the
    /// rest wait for its cookie and then find the session installed. Thirty-two
    /// tasks that start together therefore cost one `account.login`, not
    /// thirty-two — a second login invalidates the cookie of the first
    /// server-side, so posting them in parallel is how a client ends up holding
    /// a session the server has already dropped.
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
    ///
    /// `params` is already a map: the shape is decided in [`Self::call`], so
    /// there is no second coercion here.
    async fn send(&self, method: &str, params: Map<String, Value>) -> Result<Response> {
        let mut params = params;
        self.add_language(&mut params);
        let body = RpcRequest::from_map(method, params).to_bytes()?;

        let cookie = self.session.cookie();
        let mut request = Request::post_json(&self.base_url, body)
            .with_header("Content-Type", "application/json")?
            .with_header("Accept", "application/json")?
            .with_header(
                "User-Agent",
                concat!("inwx-client/", env!("CARGO_PKG_VERSION")),
            )?;
        if let Some(cookie) = &cookie {
            request = request.with_header("Cookie", cookie.clone())?;
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
    "account.getroles",
    "account.info",
    "account.list",
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
    "domain.getalldomainprices",
    "domain.getdomainprice",
    "domain.getextradatarules",
    "domain.getprices",
    "domain.getpromos",
    "domain.info",
    "domain.list",
    "domain.pricechanges",
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
    "request.info",
    "request.list",
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
/// when the command cannot have side effects. An [`Error::Undecodable`] never
/// reaches this gate: `call` reports an unreadable `2xx` answer at once, since
/// the body says nothing about whether the command ran.
fn replay_allowed(error: &Error, method: &str) -> bool {
    match error {
        Error::Uncertain { .. } => is_read_only_method(method),
        other => other.is_retryable(),
    }
}

/// Whether a failed `account.login` attempt may be answered with another one.
///
/// `account.login` is the only command that writes and is still replay-safe: it
/// opens a session, and a second login replaces that session instead of
/// duplicating a domain, an order or a charge. So the gate is wider than
/// [`replay_allowed`] in exactly one place — an [`Error::Uncertain`], the
/// timeout whose answer was lost, is retried too, where the same failure on
/// [`InwxClient::create_domain`] would be handed back to the caller.
///
/// An [`Error::Undecodable`] never reaches this gate: a `2xx` whose body cannot
/// be read is reported by [`InwxClient::login`] at once, since the missing
/// cookie says nothing about whether a repeat would open a second session.
fn login_replay_allowed(error: &Error) -> bool {
    match error {
        Error::Uncertain { .. } => true,
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

/// Whether API code `code` may be answered with another attempt of `method`.
///
/// `2300` (object pending transfer) is the only code worth a replay: the object
/// exists and is mid-transfer, so the same command can work once the registry
/// caught up. That is only true for a method that cannot have changed anything.
/// For a mutating method the code is the answer — the command already reached
/// the object — and repeating it once the transfer settled would register,
/// charge or delete a second time, so it is handed back as-is.
fn code_replay_allowed(code: Option<i32>, method: &str) -> bool {
    code == Some(2300) && is_read_only_method(method)
}

/// Whether a status leaves the outcome of `method` unknown: the request was
/// written, the answer is a transient failure, and a second attempt could
/// duplicate the mutation.
fn status_is_uncertain(status: u16, method: &str) -> bool {
    is_retryable_status(status) && !is_read_only_method(method)
}

/// The [`Error::Http`] for a non-2xx answer whose body is not an INWX
/// envelope, carrying the `Retry-After` the endpoint asked for.
///
/// The delay is attached as data. Nothing here waits: whether a caller honours
/// it, and for how long, is that caller's decision — the status is what
/// decides whether a replay is allowed at all.
fn http_error(response: &Response) -> Error {
    let error = Error::http(response.status(), HttpBody::from_bytes(response.body()));
    match retry_after_in(response) {
        Some(delay) => error.with_retry_after(delay),
        None => error,
    }
}

/// The delay the answer's `Retry-After` header asks for, if it carried a
/// usable one and more than one such header agrees.
fn retry_after_in(response: &Response) -> Option<Duration> {
    // One clock reading for every header on this answer, so a repeated value
    // cannot disagree with itself.
    let now = SystemTime::now();
    let mut values = response
        .header_all("retry-after")
        .map(|value| retry_after_at(value, now));
    let first = values.next()??;
    // A gateway that repeats the header contradicts itself; refuse to guess
    // and fall back to the caller's own backoff.
    if values.all(|other| other == Some(first)) {
        Some(first)
    } else {
        None
    }
}

/// Collects every `Set-Cookie` header into a single `Cookie` value.
///
/// Attributes (`Path`, `Domain`, `HttpOnly`, …) are dropped: only the
/// `name=value` pair belongs in the request header. Duplicate names keep the
/// last value, which is what a browser cookie jar would do. A `Set-Cookie`
/// value that is not valid UTF-8 is a typed transport error: the real value is
/// not text, and silently dropping it would install no session.
fn collect_cookies(response: &Response) -> Result<String> {
    let mut pairs: Vec<String> = Vec::new();
    for header in response.header_all_bytes("set-cookie") {
        let header = std::str::from_utf8(header).map_err(|_| {
            Error::transport_at(
                TransportStage::AfterSend,
                "login response carried a Set-Cookie header that is not valid UTF-8",
            )
        })?;
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
    Ok(pairs.join("; "))
}

/// A uniform sample from `[0, 1)` that scales this retry's backoff.
///
/// One draw per retry, from the thread-local generator: thirty-two tasks on one
/// client fail together, and the sample is what pulls their retries apart. It
/// is read synchronously, so no generator ever crosses an `.await`.
#[cfg(feature = "http")]
fn jitter_unit() -> f64 {
    rand::random()
}

/// Without a timer there is nothing to smear out: the retries happen
/// immediately, so the sample is the lower end of the interval and the wait
/// stays exactly zero.
#[cfg(not(feature = "http"))]
fn jitter_unit() -> f64 {
    0.0
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
            .field("authenticated", &self.session.is_authenticated())
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
    fn credentials_are_validated_before_conversion() {
        use std::cell::Cell;

        struct Tracked<'a> {
            text: &'a str,
            conversions: &'a Cell<usize>,
        }

        impl AsRef<str> for Tracked<'_> {
            fn as_ref(&self) -> &str {
                self.text
            }
        }

        impl From<Tracked<'_>> for String {
            fn from(value: Tracked<'_>) -> Self {
                value.conversions.set(value.conversions.get() + 1);
                value.text.to_owned()
            }
        }

        let username_conversions = Cell::new(0);
        let password_conversions = Cell::new(0);
        let too_long = "u".repeat(MAX_USERNAME_LEN + 1);
        let error = Credentials::new(
            Tracked {
                text: &too_long,
                conversions: &username_conversions,
            },
            Tracked {
                text: "pass",
                conversions: &password_conversions,
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::Validation {
                field: "credentials.username",
                ..
            }
        ));
        assert_eq!(username_conversions.get(), 0);
        assert_eq!(password_conversions.get(), 0);

        let error = Credentials::new(
            Tracked {
                text: "user",
                conversions: &username_conversions,
            },
            Tracked {
                text: "with\nnewline",
                conversions: &password_conversions,
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::Validation {
                field: "credentials",
                ..
            }
        ));
        assert_eq!(username_conversions.get(), 0);
        assert_eq!(password_conversions.get(), 0);

        Credentials::new(
            Tracked {
                text: "user",
                conversions: &username_conversions,
            },
            Tracked {
                text: "pass",
                conversions: &password_conversions,
            },
        )
        .unwrap();
        assert_eq!(username_conversions.get(), 1);
        assert_eq!(password_conversions.get(), 1);
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
    fn jittered_delay_sits_inside_the_ceiling() {
        let policy = RetryPolicy::new(4)
            .with_base_delay(Duration::from_millis(400))
            .with_max_delay(Duration::from_secs(2));

        // Both ends of the interval are reachable, and every sample in between
        // stays at or below the deterministic ceiling.
        for attempt in 1..policy.attempts() {
            let ceiling = policy.delay(attempt).unwrap();
            assert_eq!(policy.delay_with_jitter(attempt, 0.0), Some(Duration::ZERO));
            assert_eq!(policy.delay_with_jitter(attempt, 1.0), Some(ceiling));
            for step in 1..100 {
                let unit = f64::from(step) / 100.0;
                let waited = policy
                    .delay_with_jitter(attempt, unit)
                    .expect("the attempt is inside the budget");
                assert!(waited <= ceiling, "attempt {attempt} unit {unit}");
            }
        }

        // One step outside the interval at each end, and a sample that is not a
        // number at all: clamped rather than `NaN` reaching `Duration`.
        assert_eq!(policy.delay_with_jitter(1, -0.5), Some(Duration::ZERO));
        assert_eq!(
            policy.delay_with_jitter(1, 1.5),
            Some(Duration::from_millis(400))
        );
        assert_eq!(policy.delay_with_jitter(1, f64::NAN), Some(Duration::ZERO));
        assert_eq!(
            policy.delay_with_jitter(1, f64::NEG_INFINITY),
            Some(Duration::ZERO)
        );
        assert_eq!(
            policy.delay_with_jitter(1, f64::INFINITY),
            Some(Duration::from_millis(400))
        );

        // The budget boundary: the last attempt has a wait, one more has none.
        assert_eq!(
            policy.delay_with_jitter(3, 0.5),
            Some(Duration::from_millis(800))
        );
        assert_eq!(policy.delay_with_jitter(4, 0.5), None);
        assert_eq!(policy.delay_with_jitter(5, 0.5), None);
    }

    #[test]
    fn jitter_is_monotone_in_the_sample() {
        let policy = RetryPolicy::new(3).with_base_delay(Duration::from_secs(8));
        let mut previous = Duration::ZERO;
        for step in 0..=100 {
            let unit = f64::from(step) / 100.0;
            let waited = policy.delay_with_jitter(1, unit).unwrap();
            assert!(waited >= previous, "unit {unit} went backwards");
            previous = waited;
        }
        assert_eq!(previous, Duration::from_secs(8));
    }

    /// The point of the jitter: thirty-two tasks that failed together do not
    /// come back together.
    #[cfg(feature = "http")]
    #[test]
    fn the_retry_sample_does_not_collapse_onto_one_value() {
        let mut samples: Vec<f64> = (0..32).map(|_| jitter_unit()).collect();
        assert!(
            samples.iter().all(|unit| (0.0..1.0).contains(unit)),
            "every sample is drawn from [0, 1): {samples:?}"
        );
        samples.sort_by(f64::total_cmp);
        samples.dedup();
        assert!(
            samples.len() > 1,
            "32 draws must not land on one value: {samples:?}"
        );
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
        )
        .unwrap();
        assert_eq!(collect_cookies(&response).unwrap(), "other=x; domrobot=s2");
    }

    #[test]
    fn a_non_utf8_cookie_is_a_typed_uncertain_error() {
        let response = Response::from_header_bytes(
            200,
            [("Set-Cookie".to_string(), vec![0xff, 0xfe])],
            Vec::new(),
        )
        .unwrap();
        let error = collect_cookies(&response).unwrap_err();
        assert!(matches!(error, Error::Uncertain { .. }), "{error:?}");
        assert!(error.is_uncertain());
        assert!(!error.is_retryable());
        assert!(error.to_string().contains("Set-Cookie"), "{error}");
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

        // Reading roles may be replayed; granting or revoking one may not.
        assert!(is_read_only_method("account.getroles"));
        assert!(!is_read_only_method("account.getrole"));
        assert!(!is_read_only_method("account.addrole"));
        assert!(!is_read_only_method("account.removerole"));

        // The account namespace: reads may be replayed, every mutation may
        // not. `account.check` and `account.list` only observe state.
        assert!(is_read_only_method("account.check"));
        assert!(is_read_only_method("account.list"));
        assert!(!is_read_only_method("account.update"));
        assert!(!is_read_only_method("account.create"));
        assert!(!is_read_only_method("account.delete"));

        // The price endpoints added for issue #63 sit exactly on the line:
        // neighbour spellings that the API does not have stay mutating.
        for method in [
            "domain.getalldomainprices",
            "domain.getextradatarules",
            "domain.getpromos",
            "domain.pricechanges",
        ] {
            assert!(is_read_only_method(method), "{method} only reads");
            assert!(
                !is_read_only_method(&format!("{method}x")),
                "{method}x must stay outside the table"
            );
            assert!(
                !is_read_only_method(method.trim_end_matches('s')),
                "{method} without its last character must stay outside"
            );
        }

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

    #[test]
    fn login_replay_is_wider_than_the_read_only_table() {
        // The pre-write failures a `RetryPolicy` covers.
        let before = Error::transport_at(TransportStage::BeforeSend, "dns lookup failed");
        assert!(login_replay_allowed(&before));
        // The lost answer: the one write a second login cannot duplicate.
        let uncertain = Error::uncertain("timeout waiting for the answer");
        assert!(login_replay_allowed(&uncertain));
        // Terminal stays terminal: a local mistake, a rejection, a bad input.
        let local = Error::transport_at(TransportStage::Local, "unsupported scheme");
        assert!(!login_replay_allowed(&local));
        assert!(!login_replay_allowed(&Error::validation("user", "empty")));
        // An unreadable `2xx` is `Undecodable`, which never reaches this gate.
        let cut = serde_json::from_str::<Value>("<html>502</html>").unwrap_err();
        assert!(!login_replay_allowed(&Error::Undecodable { source: cut }));
        // The gate is login-specific because the method is not read-only.
        assert!(!is_read_only_method("account.login"));
    }

    #[test]
    fn unlocking_is_never_read_only() {
        // In the table next to it, and the new method just outside it.
        assert!(is_read_only_method("account.info"));
        assert!(!is_read_only_method("account.unlock"));
        assert!(!is_read_only_method("account.unlockx"));
        assert!(!is_read_only_method("ACCOUNT.UNLOCK"));
    }

    #[test]
    fn change_password_is_not_read_only() {
        // It writes, so an unconfirmed attempt must never be replayed.
        assert!(!is_read_only_method("account.changepassword"));
        assert!(is_read_only_method("account.info"));
    }

    #[test]
    fn an_uncertain_unlock_is_not_replayed() {
        let uncertain = Error::uncertain("timeout");
        assert!(replay_allowed(&uncertain, "account.info"));
        assert!(!replay_allowed(&uncertain, "account.unlock"));
    }

    /// The header lookup: absent, present once, repeated consistently, and
    /// repeated inconsistently.
    #[test]
    fn retry_after_reads_the_header_case_insensitively() {
        let response = |headers: Vec<(&str, &str)>| {
            Response::new(
                429,
                headers
                    .into_iter()
                    .map(|(name, value)| (name.to_owned(), value.to_owned())),
                b"slow down".to_vec(),
            )
            .unwrap()
        };

        assert_eq!(retry_after_in(&response(Vec::new())), None);
        assert_eq!(
            retry_after_in(&response(vec![("Retry-After", "30")])),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            retry_after_in(&response(vec![("retry-after", "  45 ")])),
            Some(Duration::from_secs(45))
        );
        // Two headers that agree are one answer.
        assert_eq!(
            retry_after_in(&response(vec![
                ("Retry-After", "30"),
                ("retry-after", "30"),
            ])),
            Some(Duration::from_secs(30))
        );
        // Two that disagree are no answer at all.
        assert_eq!(
            retry_after_in(&response(vec![
                ("Retry-After", "30"),
                ("retry-after", "60"),
            ])),
            None
        );
        // An unreadable value is not a zero delay.
        assert_eq!(
            retry_after_in(&response(vec![("Retry-After", "soon")])),
            None
        );
        // A different header never stands in for it.
        assert_eq!(
            retry_after_in(&response(vec![("X-Retry-After", "30")])),
            None
        );
    }

    /// The error a non-envelope 429 produces carries the header, and the one
    /// without a header says so instead of guessing.
    #[test]
    fn the_http_error_carries_the_retry_after_it_saw() {
        let throttled = Response::new(
            429,
            [("Retry-After".to_owned(), "90".to_owned())],
            b"<html>slow down</html>".to_vec(),
        )
        .unwrap();
        let error = http_error(&throttled);
        assert_eq!(error.retry_after(), Some(Duration::from_secs(90)));
        assert!(error.is_retryable());
        assert_eq!(error.to_string(), "http 429: <html>slow down</html>");

        let plain = Response::new(503, std::iter::empty(), b"unavailable".to_vec()).unwrap();
        assert_eq!(http_error(&plain).retry_after(), None);
        assert!(http_error(&plain).is_retryable());
    }
}
