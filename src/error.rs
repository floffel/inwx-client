//! Everything the client can fail with.
//!
//! One enum, `#[non_exhaustive]`, with a source chain: JSON failures keep the
//! `serde_json::Error` as `source`, so `err.source()` still reports the line and
//! column.

use thiserror::Error;

use crate::rpc::Detail;
use crate::transport::TransportStage;

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

    /// The HTTP call never produced a usable response, and the command
    /// definitely did not run: DNS lookup, TCP connect or TLS handshake failed,
    /// or the request could not even be built locally.
    ///
    /// A failure after the request had been written — a timeout waiting for the
    /// answer, a reset mid-response, a truncated body — is [`Error::Uncertain`]
    /// instead, because replaying it could duplicate a mutation.
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

    /// The request had already been written when the transport failed: a
    /// timeout waiting for the answer, a reset mid-flight, a truncated or
    /// undecodable body.
    ///
    /// The API may have executed the command, so the outcome is unknown rather
    /// than merely unsuccessful, and replaying it can duplicate a mutation.
    /// [`InwxClient::call`](crate::InwxClient::call) therefore never retries
    /// this for a mutating command; read-only ones are replayed, see
    /// [`is_read_only_method`](crate::is_read_only_method).
    ///
    /// ```
    /// use inwx_client::Error;
    ///
    /// let err = Error::uncertain("timeout waiting for response");
    /// assert!(err.is_uncertain());
    /// assert!(!err.is_retryable());
    /// ```
    #[error("uncertain transport failure: {message} (the command may have been executed)")]
    Uncertain {
        /// Description from the transport.
        message: String,
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
    ///
    /// The status decides whether another attempt could plausibly succeed:
    /// `429` (rate limit) and the gateway/overload answers `502`, `503`, `504`
    /// are retryable, every other status (`400`, `401`, `403`, `404`, `500`,
    /// `505`, …) is terminal — see [`is_retryable`](Self::is_retryable).
    ///
    /// That is classification only. Nothing here retries anything by itself, and
    /// whether a *mutating* command is actually replayed stays governed by the
    /// idempotency rules around [`RetryPolicy`](crate::RetryPolicy)
    /// ([issue #2](https://github.com/floffel/inwx-client/issues/2)):
    /// [`InwxClient::call`](crate::InwxClient::call) backs off on 429 and 5xx,
    /// and never replays an ambiguous outcome for a method that can write.
    ///
    /// ```
    /// use inwx_client::Error;
    ///
    /// let gateway = Error::Http {
    ///     status: 502,
    ///     body: "bad gateway".into(),
    /// };
    /// assert!(gateway.is_retryable());
    ///
    /// let gone = Error::Http {
    ///     status: 404,
    ///     body: "no such page".into(),
    /// };
    /// assert!(!gone.is_retryable());
    /// ```
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

    /// Builds a retryable transport error: a failure that happened before the
    /// request was written, so replaying the command cannot duplicate anything.
    /// Use [`Error::transport_at`] when the stage is known, and
    /// [`Error::uncertain`] when the request had already been written.
    ///
    /// ```
    /// use inwx_client::Error;
    ///
    /// let err = Error::transport("dns lookup failed");
    /// assert!(err.is_retryable());
    /// assert!(!err.is_uncertain());
    /// ```
    #[must_use]
    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport {
            message: message.into(),
            retryable: true,
        }
    }

    /// Builds the error for a transport failure that happened at `stage`.
    ///
    /// A failure before the request was written ([`TransportStage::BeforeSend`])
    /// becomes a retryable [`Error::Transport`]; one after it
    /// ([`TransportStage::AfterSend`]) becomes [`Error::Uncertain`], because the
    /// command may already have run; a local mistake that never left the
    /// process ([`TransportStage::Local`]) becomes a terminal
    /// [`Error::Transport`].
    ///
    /// ```
    /// use inwx_client::{Error, TransportStage};
    ///
    /// let before = Error::transport_at(TransportStage::BeforeSend, "dns lookup failed");
    /// assert!(before.is_retryable());
    /// assert!(!before.is_uncertain());
    ///
    /// let after = Error::transport_at(TransportStage::AfterSend, "timeout");
    /// assert!(after.is_uncertain());
    /// assert!(!after.is_retryable());
    ///
    /// let local = Error::transport_at(TransportStage::Local, "unsupported scheme");
    /// assert!(!local.is_retryable());
    /// assert!(!local.is_uncertain());
    /// ```
    #[must_use]
    pub fn transport_at(stage: TransportStage, message: impl Into<String>) -> Self {
        let message = message.into();
        match stage {
            TransportStage::BeforeSend => Self::Transport {
                message,
                retryable: true,
            },
            TransportStage::AfterSend => Self::Uncertain { message },
            TransportStage::Local => Self::Transport {
                message,
                retryable: false,
            },
        }
    }

    /// Builds an [`Error::Uncertain`] for a failure that happened after the
    /// request had been written, so the command may already have run.
    ///
    /// Use this from a [`Transport`](crate::transport::Transport) implementation
    /// for a timeout, a reset mid-response or a truncated body. Prefer
    /// [`Error::transport_at`] when the stage is already known, and
    /// [`Error::transport`] when the request was demonstrably never written.
    ///
    /// ```
    /// use inwx_client::Error;
    ///
    /// let err = Error::uncertain("timeout after 30s");
    /// assert!(err.is_uncertain());
    /// // Never blindly replayed: the API may have registered the domain.
    /// assert!(!err.is_retryable());
    /// ```
    #[must_use]
    pub fn uncertain(message: impl Into<String>) -> Self {
        Self::Uncertain {
            message: message.into(),
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

    /// Whether another attempt could succeed without risking a second write.
    ///
    /// Transport failures carry their own flag; an API error is retryable only
    /// for `2300` (object pending transfer), everything else is terminal.
    /// Validation, decoding and authentication errors are never retryable. An
    /// [`Error::Http`] is classified by its status: `429`, `502`, `503` and
    /// `504` are retryable, all other non-2xx statuses (`400`, `401`, `403`,
    /// `404`, …) are terminal.
    ///
    /// This is classification, not a retry. Retrying a *mutating* command is
    /// still governed by the idempotency rules of
    /// [`RetryPolicy`](crate::RetryPolicy)
    /// ([issue #2](https://github.com/floffel/inwx-client/issues/2)): a
    /// transient status says another attempt *could* work, not that replaying
    /// `domain.create` is safe.
    ///
    /// [`Error::Uncertain`] is *not* retryable here: the command may already
    /// have been executed. [`InwxClient::call`](crate::InwxClient::call) still
    /// replays it for a read-only method, where a second attempt cannot
    /// duplicate anything — see
    /// [`is_read_only_method`](crate::is_read_only_method).
    ///
    /// ```
    /// use inwx_client::{Error, RetryPolicy};
    ///
    /// assert!(Error::transport("dns lookup failed").is_retryable());
    /// assert!(!Error::uncertain("timeout").is_retryable());
    /// assert!(!Error::validation("domain", "empty").is_retryable());
    ///
    /// // A gateway hiccup is transient, a rejected request is not.
    /// let gateway = Error::Http { status: 503, body: "unavailable".into() };
    /// assert!(gateway.is_retryable());
    /// let denied = Error::Http { status: 403, body: "forbidden".into() };
    /// assert!(!denied.is_retryable());
    /// assert_eq!(RetryPolicy::default().delay(1), Some(std::time::Duration::from_millis(500)));
    /// ```
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        // Spelled out rather than left to the catch-all arm: an uncertain
        // failure means the command may already have run, so a blind replay
        // could duplicate a mutation. `InwxClient::call` still replays it for a
        // read-only method, where that is provably harmless.
        if self.is_uncertain() {
            return false;
        }
        match self {
            Self::Transport { retryable, .. } => *retryable,
            Self::Api { code, .. } => *code == 2300,
            Self::Http { status, .. } => is_transient_status(*status),
            _ => false,
        }
    }

    /// Whether the transport failed after the request had been written, so the
    /// outcome of the command is unknown.
    ///
    /// ```
    /// use inwx_client::Error;
    ///
    /// assert!(Error::uncertain("timeout").is_uncertain());
    /// assert!(!Error::transport("dns lookup failed").is_uncertain());
    /// ```
    #[must_use]
    pub fn is_uncertain(&self) -> bool {
        matches!(self, Self::Uncertain { .. })
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

/// Statuses worth another attempt when the answer was not an INWX envelope.
///
/// `429` says the caller is being rate limited and `502`/`503`/`504` say a
/// gateway or the server itself is temporarily unable to answer; both usually
/// go away on their own. Any other non-2xx status rejects the request or the
/// session, so a replay fails the same way.
///
/// Deliberately narrower than the statuses [`InwxClient::call`](crate::InwxClient::call)
/// backs off on internally (429 and all of 5xx): that loop additionally weighs
/// whether a replay is safe for the method it is calling, while this
/// classification only answers "could another attempt succeed?".
fn is_transient_status(status: u16) -> bool {
    matches!(status, 429 | 502 | 503 | 504)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(status: u16) -> Error {
        Error::Http {
            status,
            body: String::from("gateway trouble"),
        }
    }

    #[test]
    fn transient_http_statuses_are_retryable() {
        for status in [429, 502, 503, 504] {
            assert!(http(status).is_retryable(), "{status} must be retryable");
        }
    }

    #[test]
    fn every_other_status_stays_terminal() {
        for status in [
            0,
            100,
            200,
            204,
            301,
            400,
            401,
            402,
            403,
            404,
            405,
            408,
            418,
            422,
            425,
            428,
            430,
            500,
            501,
            505,
            507,
            599,
            u16::MAX,
        ] {
            assert!(!http(status).is_retryable(), "{status} must stay terminal");
        }
    }

    /// Boundary pair: every retryable status sits between two terminal ones.
    #[test]
    fn the_http_boundary_is_exact() {
        assert!(!http(428).is_retryable());
        assert!(http(429).is_retryable());
        assert!(!http(430).is_retryable());

        assert!(!http(501).is_retryable());
        assert!(http(502).is_retryable());
        assert!(http(503).is_retryable());
        assert!(http(504).is_retryable());
        assert!(!http(505).is_retryable());
    }

    #[test]
    fn the_body_never_changes_the_verdict() {
        let long = "x".repeat(600);
        for body in ["", "rate limited", &long] {
            let error = Error::Http {
                status: 503,
                body: body.to_owned(),
            };
            assert!(error.is_retryable());
            let terminal = Error::Http {
                status: 404,
                body: body.to_owned(),
            };
            assert!(!terminal.is_retryable());
        }
    }

    /// No behavior change for the other variants.
    #[test]
    fn other_variants_classify_as_before() {
        assert!(Error::transport("dns lookup failed").is_retryable());
        assert!(!Error::Transport {
            message: String::from("unsupported scheme"),
            retryable: false,
        }
        .is_retryable());

        let api = |code| Error::Api {
            code,
            message: String::from("boom"),
            reason_code: None,
            reason: None,
            details: Vec::new(),
        };
        assert!(api(2300).is_retryable());
        assert!(!api(2302).is_retryable());
        assert!(!api(2200).is_retryable());

        assert!(!Error::uncertain("timeout").is_retryable());
        assert!(!Error::validation("domain", "empty").is_retryable());
        assert!(!Error::NotAuthenticated.is_retryable());
        assert!(!Error::Authentication {
            message: String::from("no cookie"),
        }
        .is_retryable());
        assert!(!Error::MissingField {
            method: "domain.info",
            field: "resData.id",
        }
        .is_retryable());
    }
}
