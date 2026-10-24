//! Everything the client can fail with.
//!
//! One enum, `#[non_exhaustive]`, with a source chain: JSON failures keep the
//! `serde_json::Error` as `source`, so `err.source()` still reports the line and
//! column.

use thiserror::Error;

use crate::rpc::Detail;

/// Error type returned by every fallible operation in this crate.
///
/// The enum is `#[non_exhaustive]`: new failure modes can be added without a
/// breaking release, so match with a trailing `_` arm.
///
/// ```
/// use inwx_client::{Error, RecordSpec};
///
/// let err = RecordSpec::a("www", "2001:db8::1").unwrap_err();
/// match err {
///     Error::Validation { field, .. } => assert_eq!(field, "record.content"),
///     other => panic!("unexpected: {other}"),
/// }
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The API answered with a non-success result code.
    ///
    /// INWX puts the result code in the JSON body and still answers HTTP 200,
    /// so this is the normal way a rejected command surfaces. `code` is the
    /// numeric result code, `message` the human readable `msg`; `reason_code`
    /// and `reason` are the optional machine readable extras, `details` the
    /// optional per-parameter list.
    ///
    /// ```
    /// use inwx_client::{Error, RpcResponse};
    ///
    /// let response = RpcResponse::parse(
    ///     br#"{"code":2303,"msg":"Object does not exist","reasonCode":"NOT_FOUND"}"#,
    /// )?;
    /// let err = response.into_result().unwrap_err();
    /// assert!(matches!(err, Error::Api { code: 2303, .. }));
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[error("INWX API error {code}: {message}")]
    Api {
        /// Numeric result code, for example `2303` (`Object does not exist`).
        code: i32,
        /// The `msg` field, as sent by the API.
        message: String,
        /// Short error tag such as `MISSING_ID`, when the API sent one.
        reason_code: Option<String>,
        /// Longer explanation, when the API sent one.
        reason: Option<String>,
        /// Per-parameter detail entries, when the API sent any.
        details: Vec<Detail>,
    },

    /// A response body was not valid JSON, or a `resData` field had the wrong
    /// type. `serde_json`'s line/column information is kept as `source`.
    #[error("invalid JSON: {source}")]
    Json {
        /// The underlying `serde_json` error.
        #[from]
        source: serde_json::Error,
    },

    /// The HTTP call never produced a usable response: DNS, TLS, timeout,
    /// connection reset.
    ///
    /// `retryable` is `true` for everything except local configuration
    /// mistakes, so callers can decide whether to hand the request back to
    /// [`RetryPolicy`](crate::RetryPolicy) themselves.
    #[error("transport error: {message}")]
    Transport {
        /// Description from the transport.
        message: String,
        /// `true` when another attempt could plausibly succeed.
        retryable: bool,
    },

    /// The API rejected the session (`2200`, `2201`, `2202`) and the client
    /// could not recover by logging in again — usually because it has no
    /// credentials.
    #[error("authentication failed: {message}")]
    Authentication {
        /// The API message, or a description of why re-login was impossible.
        message: String,
    },

    /// The client was asked to call an authenticated method with no session and
    /// no credentials to open one.
    #[error("not authenticated: log in first or supply credentials")]
    NotAuthenticated,

    /// An argument would be rejected by the API, or is unsafe to put on the
    /// wire. The request is never sent.
    #[error("invalid {field}: {message}")]
    Validation {
        /// Dotted path of the offending field, for example `record.content`.
        field: &'static str,
        /// What is wrong and what the accepted shape is.
        message: String,
    },

    /// A successful response was missing a field the client needs.
    #[error("response for `{method}` is missing `{field}`")]
    MissingField {
        /// The method that was called.
        method: &'static str,
        /// The field that should have been there.
        field: &'static str,
    },

    /// The server answered with a non-2xx status and a body that is not an
    /// INWX error envelope.
    #[error("http {status}: {body}")]
    Http {
        /// HTTP status code.
        status: u16,
        /// Body, truncated to 512 characters.
        body: String,
    },
}

impl Error {
    /// Builds a validation error. `field` is the dotted path, `message` the
    /// human readable detail.
    ///
    /// ```
    /// use inwx_client::Error;
    ///
    /// let err = Error::validation("record.ttl", "must be 0..=2147483647");
    /// assert!(err.is_validation());
    /// ```
    #[must_use]
    pub fn validation(field: &'static str, message: impl Into<String>) -> Self {
        Self::Validation {
            field,
            message: message.into(),
        }
    }

    /// Builds a retryable transport error.
    ///
    /// ```
    /// use inwx_client::Error;
    /// assert!(Error::transport("connection reset").is_retryable());
    /// ```
    #[must_use]
    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport {
            message: message.into(),
            retryable: true,
        }
    }

    /// Result code of an [`Error::Api`], or `None` for every other variant.
    ///
    /// ```
    /// use inwx_client::Error;
    ///
    /// let err = Error::Api {
    ///     code: 2302,
    ///     message: "Object exists".into(),
    ///     reason_code: None,
    ///     reason: None,
    ///     details: Vec::new(),
    /// };
    /// assert_eq!(err.code(), Some(2302));
    /// ```
    #[must_use]
    pub fn code(&self) -> Option<i32> {
        match self {
            Self::Api { code, .. } => Some(*code),
            _ => None,
        }
    }

    /// Whether another attempt could succeed.
    ///
    /// Transport failures carry their own flag; an API error is retryable only
    /// for `2300` (object pending transfer), everything else is terminal.
    /// Validation, decoding and authentication errors are never retryable.
    ///
    /// ```
    /// use inwx_client::{Error, RetryPolicy};
    ///
    /// assert!(Error::transport("dns").is_retryable());
    /// assert!(!Error::validation("domain", "empty").is_retryable());
    /// assert_eq!(RetryPolicy::default().delay(1), Some(std::time::Duration::from_millis(500)));
    /// ```
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { retryable, .. } => *retryable,
            Self::Api { code, .. } => *code == 2300,
            _ => false,
        }
    }

    /// Whether this is a rejected session rather than a rejected command.
    ///
    /// The client uses this to decide whether a single re-login is worth it;
    /// callers can use it to prompt for new credentials.
    ///
    /// ```
    /// use inwx_client::{Error, RpcResponse};
    ///
    /// let response = RpcResponse::parse(br#"{"code":2200,"msg":"Authentication error"}"#)?;
    /// let err = response.into_result().unwrap_err();
    /// assert!(err.is_authentication());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn is_authentication(&self) -> bool {
        match self {
            Self::Api { code, .. } => matches!(code, 2200..=2202),
            Self::Authentication { .. } | Self::NotAuthenticated => true,
            _ => false,
        }
    }

    /// Whether this came from argument validation, before any request was sent.
    ///
    /// ```
    /// use inwx_client::Error;
    /// assert!(Error::validation("domain", "empty").is_validation());
    /// ```
    #[must_use]
    pub fn is_validation(&self) -> bool {
        matches!(self, Self::Validation { .. })
    }
}

/// Convenience alias used across the crate.
///
/// ```
/// fn ok() -> inwx_client::Result<u8> {
///     Ok(1)
/// }
/// assert_eq!(ok().unwrap(), 1);
/// ```
pub type Result<T> = std::result::Result<T, Error>;
