//! Everything the client can fail with.
//!
//! One enum, `#[non_exhaustive]`, with a source chain that survives the
//! boundary: JSON failures keep the `serde_json::Error` as `source`, so
//! `err.source()` still reports the line and column, and every failure that had
//! a cause — a `reqwest`, TLS or `io` error from a transport, a login that
//! produced no cookie — keeps that cause in `source` instead of flattening its
//! text into the message. The short `message` is what `Display` prints;
//! [`Error::with_source`] is how a cause is attached.
//!
//! Certainty is part of the type. A failure that happened after the request was
//! written leaves the outcome of the command unknown, and it is spelled two
//! ways: [`Error::Uncertain`] for the transport (a timeout, a reset) and
//! [`Error::Undecodable`] for decoding (an answer whose body cannot be read).
//! Both answer [`Error::is_uncertain`] with `true` and are never replayed for a
//! mutating command; [`Error::Json`] is the other side of that line — a payload
//! that arrived intact and does not fit the model, behind a command that ran.

use std::fmt;
use std::ops::Deref;
use std::time::{Duration, SystemTime};

use thiserror::Error;

use crate::rpc::Detail;
use crate::transport::TransportStage;

/// A boxed cause carried by one of the transport-shaped [`enum@Error`]
/// variants, so `err.source()` walks down to the failure that really happened:
/// the `reqwest` error behind a failed request, the TLS error behind that, the
/// `io` error behind a truncated body.
///
/// It is `Send + Sync + 'static` because [`enum@Error`] is: the error travels
/// out of the task and thread the client ran on, like the client itself.
///
/// ```rust
/// use inwx_client::{Error, ErrorSource, TransportStage};
///
/// let cause: ErrorSource = Box::new(std::io::Error::other("connection reset"));
/// let err = Error::transport_at(TransportStage::AfterSend, "could not read the answer")
///     .with_source(cause);
/// assert!(err.is_uncertain());
/// ```
pub type ErrorSource = Box<dyn std::error::Error + Send + Sync + 'static>;

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

    /// A body that arrived intact could not be decoded: it was not JSON, or a
    /// `resData` field had the wrong type. `serde_json`'s line/column
    /// information is kept as `source`.
    ///
    /// This is the *certain* decoding failure — local data with a shape the
    /// model does not have, or a payload the caller parsed out of an answer it
    /// already received. When the body of a written request cannot be read at
    /// all, the outcome of the command is unknown instead and the error is
    /// [`Error::Undecodable`].
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
    ///
    /// The flag is not a free choice. It must never be `true` once the request
    /// bytes left the process: that outcome is [`Error::Uncertain`], because a
    /// replay could duplicate a mutation. So the variant is
    /// `#[non_exhaustive]` — outside this crate it cannot be written as a
    /// struct literal — and the only ways in are [`Error::transport_at`] and
    /// [`Error::transport_before_send`], which derive the flag from
    /// [`TransportStage`] instead of taking it from the caller.
    ///
    /// The underlying transport failure is kept in `source`
    /// ([`Error::with_source`], or [`Error::transport_at_caused_by`]), so the
    /// cause is still walkable instead of having been flattened into `message`.
    #[non_exhaustive]
    #[error("transport error: {message}")]
    Transport {
        /// Short description from the transport, the one `Display` prints.
        message: String,
        /// `true` when another attempt could plausibly succeed: only ever set
        /// for a failure at [`TransportStage::BeforeSend`], never after the
        /// request was written.
        retryable: bool,
        /// The failure behind the description — the `reqwest`, TLS or `io`
        /// error — when the transport had one to hand in.
        #[source]
        source: Option<ErrorSource>,
    },

    /// The request had already been written when the transport failed: a
    /// timeout waiting for the answer, a reset mid-flight, a read that stopped
    /// early.
    ///
    /// An answer that arrives but cannot be decoded is the decode-side sibling
    /// with the same verdict: [`Error::Undecodable`].
    ///
    /// The API may have executed the command, so the outcome is unknown rather
    /// than merely unsuccessful, and replaying it can duplicate a mutation.
    /// [`InwxClient::call`](crate::InwxClient::call) therefore never retries
    /// this for a mutating command; read-only ones are replayed, see
    /// [`is_read_only_method`](crate::is_read_only_method).
    ///
    /// ```rust
    /// use inwx_client::Error;
    ///
    /// let err = Error::uncertain("timeout waiting for response");
    /// assert!(err.is_uncertain());
    /// assert!(!err.is_retryable());
    /// ```
    #[error("uncertain transport failure: {message} (the command may have been executed)")]
    Uncertain {
        /// Short description from the transport, the one `Display` prints.
        message: String,
        /// The failure behind the description, or `None` when the transport
        /// built this from a description alone. See [`Error::with_source`].
        #[source]
        source: Option<ErrorSource>,
    },

    /// The request had been written and an answer arrived, but its body could
    /// not be read as a response envelope: a proxy error page, a cut-off `200`,
    /// or a document that is JSON without being the object an envelope is.
    ///
    /// Kept apart from [`Error::Json`] on purpose. `Json` is a decode failure on
    /// data that arrived intact — a `resData` payload in a shape the model does
    /// not have, or a body the caller parsed itself; the command behind it is
    /// known to have run. Here nothing is known: the exchange completed and the
    /// bytes are unreadable, so the command *may* have been executed and the
    /// caller must not read this as a local decoding bug.
    ///
    /// This is the decode-side sibling of [`Error::Uncertain`] and carries the
    /// same verdict: [`is_uncertain`](Error::is_uncertain) is `true`,
    /// [`is_retryable`](Error::is_retryable) is `false`, and
    /// [`InwxClient::call`](crate::InwxClient::call) does not replay it. A
    /// caller decides whether the current state can be checked instead.
    ///
    /// The `serde_json` error stays the `source`, so the line and column of the
    /// cut are still reported.
    ///
    /// ```rust
    /// use inwx_client::Error;
    ///
    /// let source = serde_json::from_str::<serde_json::Value>("<html>502 Bad Gateway</html>")
    ///     .expect_err("a gateway page is not JSON");
    /// let err = Error::Undecodable { source };
    ///
    /// assert!(err.is_uncertain());
    /// assert!(!err.is_retryable());
    /// assert!(err.to_string().contains("may have been executed"));
    /// ```
    #[error("undecodable answer: {source} (the command may have been executed)")]
    Undecodable {
        /// The parser error, with the line and column where reading stopped.
        #[source]
        source: serde_json::Error,
    },

    /// The API rejected the session (`2200`, `2201`, `2202`) and the client
    /// could not recover by logging in again — usually because it has no
    /// credentials.
    #[error("authentication failed: {message}")]
    Authentication {
        /// The API message, or a description of why re-login was impossible.
        message: String,
        /// The failure that produced this, when there was one — for example the
        /// session error a transport reported. See [`Error::with_source`].
        #[source]
        source: Option<ErrorSource>,
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

    /// A successful response carried a field the client needs, but in a shape
    /// the documented answer does not have: a scalar where a list belongs, or a
    /// list entry that does not parse.
    ///
    /// Kept apart from [`Error::MissingField`] on purpose. The field *is*
    /// there, so the shape was renamed, reshaped, or the row was mangled — and
    /// a silent default here would turn a failed check into a passing one.
    /// `detail` names what was expected and, for a list, which entry failed.
    ///
    /// ```
    /// use inwx_client::Error;
    ///
    /// let err = Error::unexpected_answer(
    ///     "nameserver.check",
    ///     "details",
    ///     "expected an array with one entry per checked nameserver",
    /// );
    /// assert!(err.to_string().contains("unexpected `details`"));
    /// assert!(!err.is_retryable());
    /// ```
    #[error("response for `{method}` has an unexpected `{field}`: {detail}")]
    UnexpectedAnswer {
        /// The method that was called.
        method: &'static str,
        /// The field whose shape was wrong.
        field: &'static str,
        /// What was expected, and which entry failed when the list itself was
        /// the right shape.
        detail: String,
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
    /// The body comes from a gateway or a misconfigured endpoint, so it can be
    /// arbitrarily large and can echo the request back. It is therefore kept as
    /// an [`HttpBody`], which bounds it to [`MAX_HTTP_BODY_CHARS`] characters on
    /// a character boundary and redacts known secrets before the error ever
    /// exists — `Display` and `Debug` print that same safe text.
    ///
    /// A transient status is often accompanied by a `Retry-After` header saying
    /// how long the endpoint wants to be left alone. That delay is kept in
    /// `retry_after` and read back through [`Error::retry_after`]: seeing it
    /// after the fact is what lets a caller pace its own retry instead of
    /// guessing, since the client never sleeps on a header it did not read.
    ///
    /// ```rust
    /// use inwx_client::Error;
    ///
    /// let gateway = Error::http(502, "bad gateway");
    /// assert!(gateway.is_retryable());
    /// assert_eq!(gateway.retry_after(), None);
    ///
    /// let gone = Error::http(404, "no such page");
    /// assert!(!gone.is_retryable());
    ///
    /// let throttled = Error::http(429, "slow down").with_retry_after(
    ///     std::time::Duration::from_secs(30),
    /// );
    /// assert_eq!(
    ///     throttled.retry_after(),
    ///     Some(std::time::Duration::from_secs(30)),
    /// );
    /// ```
    #[error("http {status}: {body}")]
    Http {
        /// HTTP status code.
        status: u16,
        /// Body, bounded to [`MAX_HTTP_BODY_CHARS`] characters and with
        /// sensitive values redacted — see [`HttpBody`].
        body: HttpBody,
        /// Delay the endpoint asked for in a `Retry-After` header, or `None`
        /// when the answer carried no usable one.
        ///
        /// Both header forms are understood: delay-seconds (`120`) and an
        /// HTTP-date (`Sun, 06 Nov 1994 08:49:37 GMT`, read relative to the
        /// moment the answer arrived, so a date in the past becomes
        /// [`Duration::ZERO`]). The value is advisory and unbounded — the
        /// crate never sleeps on it, so a caller that waits should cap it
        /// against its own deadline.
        retry_after: Option<Duration>,
        /// The failure behind the answer, when there was one — a decode or
        /// framing error from a custom transport, say. `None` for a plain
        /// non-2xx answer, whose detail is `body`. See [`Error::with_source`].
        #[source]
        source: Option<ErrorSource>,
    },

    /// A response body crossed the transport's size cap, so it was discarded
    /// before the JSON parser ever saw a byte.
    ///
    /// The reqwest transport refuses a body larger than
    /// [`DEFAULT_MAX_RESPONSE_BYTES`](crate::DEFAULT_MAX_RESPONSE_BYTES) — or
    /// whatever `ReqwestTransport::with_max_response_bytes` was given — by
    /// honouring `Content-Length` first and then watching a running total while
    /// the body streams in, so a lying header still fails fast. The message
    /// carries sizes only: a body from a misbehaving endpoint must never reach a
    /// log line.
    ///
    /// Terminal by design, not retryable. The cap is a property of the answer,
    /// not a transient fault, so another attempt would fetch the same oversized
    /// body; worse, the command may already have been executed server-side
    /// before the read was cut short, and repeating a non-idempotent request
    /// duplicates the work. Raise the cap deliberately or let the call fail.
    ///
    /// ```
    /// use inwx_client::{Error, DEFAULT_MAX_RESPONSE_BYTES};
    ///
    /// let err = Error::ResponseTooLarge {
    ///     limit: 4 * 1024 * 1024,
    ///     observed: Some(4 * 1024 * 1024 + 1),
    /// };
    /// assert_eq!(err.to_string(), "response body exceeds the 4194304-byte cap");
    /// assert!(!err.is_retryable());
    /// assert!(DEFAULT_MAX_RESPONSE_BYTES >= 4 * 1024 * 1024);
    /// ```
    #[error("response body exceeds the {limit}-byte cap")]
    ResponseTooLarge {
        /// Cap that was crossed, in bytes.
        limit: u64,
        /// How much of the body is accounted for: the declared
        /// `Content-Length` when the header alone broke the cap, otherwise the
        /// bytes read before the abort (the true body may be larger — reading
        /// stopped). `None` when no size was ever measured.
        observed: Option<u64>,
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

    /// Builds an [`Error::UnexpectedAnswer`] for a field that is present but has
    /// the wrong shape. `field` is the response path, `detail` says what was
    /// expected and what was found instead.
    ///
    /// ```
    /// use inwx_client::Error;
    ///
    /// let err = Error::unexpected_answer(
    ///     "nameserver.check",
    ///     "details",
    ///     "expected an array with one entry per checked nameserver",
    /// );
    /// assert!(!err.is_retryable());
    /// assert_eq!(
    ///     err.to_string(),
    ///     "response for `nameserver.check` has an unexpected `details`: \
    ///      expected an array with one entry per checked nameserver",
    /// );
    /// ```
    #[must_use]
    pub fn unexpected_answer(
        method: &'static str,
        field: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self::UnexpectedAnswer {
            method,
            field,
            detail: detail.into(),
        }
    }

    /// Builds a retryable transport error: a failure that happened before the
    /// request was written, so replaying the command cannot duplicate anything.
    ///
    /// The name is the point. There is deliberately no `Error::transport(msg)`
    /// one-string constructor: it was the shortest call for a transport author
    /// to reach for, and it produced a retryable error even for a timeout that
    /// may already have executed the command. A failure after the request had
    /// been written is [`Error::uncertain`]; when the stage is known, prefer
    /// [`Error::transport_at`], which picks the variant from it.
    ///
    /// The message is all this form takes. When the transport still holds the
    /// failure it caught, use [`Error::transport_at_caused_by`] instead — the
    /// cause then stays walkable through `source`.
    ///
    /// ```
    /// use inwx_client::Error;
    ///
    /// let err = Error::transport_before_send("dns lookup failed");
    /// assert!(err.is_retryable());
    /// assert!(!err.is_uncertain());
    ///
    /// // The unsafe call is no longer available: this does not compile.
    /// // let _ = Error::transport("timeout");
    /// ```
    #[must_use]
    pub fn transport_before_send(message: impl Into<String>) -> Self {
        Self::transport_at(TransportStage::BeforeSend, message)
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
    /// The message is all this form takes. When the transport still holds the
    /// failure it caught, use [`Error::transport_at_caused_by`] instead — the
    /// cause then stays walkable through `source` instead of existing only as
    /// text.
    ///
    /// ```rust
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
                source: None,
            },
            TransportStage::AfterSend => Self::Uncertain {
                message,
                source: None,
            },
            TransportStage::Local => Self::Transport {
                message,
                retryable: false,
                source: None,
            },
        }
    }

    /// Builds the error for a transport failure at `stage` and keeps `source`
    /// as its cause.
    ///
    /// Same classification as [`Error::transport_at`] — the retry flag still
    /// comes from the stage, never from the caller — with the failure the
    /// transport caught attached as the `source`. That is the form a real
    /// transport should use: flattening a `reqwest` or `io` error into the
    /// message destroys everything below it, so a caller can neither walk the
    /// chain nor match on what actually failed.
    ///
    /// ```rust
    /// use inwx_client::{Error, TransportStage};
    /// use std::error::Error as _;
    ///
    /// let failure = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
    /// let err = Error::transport_at_caused_by(
    ///     TransportStage::BeforeSend,
    ///     "could not connect",
    ///     failure,
    /// );
    ///
    /// assert!(err.is_retryable());
    /// assert_eq!(
    ///     err.source().map(ToString::to_string),
    ///     Some(String::from("refused")),
    /// );
    /// // The message stays short: the cause is not duplicated into it.
    /// assert_eq!(err.to_string(), "transport error: could not connect");
    ///
    /// // A failure after the request was written keeps its cause too, but is
    /// // never retryable.
    /// let reset = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
    /// let err = Error::transport_at_caused_by(TransportStage::AfterSend, "reset", reset);
    /// assert!(err.is_uncertain());
    /// assert!(err.source().is_some());
    /// ```
    #[must_use]
    pub fn transport_at_caused_by(
        stage: TransportStage,
        message: impl Into<String>,
        source: impl Into<ErrorSource>,
    ) -> Self {
        Self::transport_at(stage, message).with_source(source)
    }

    /// Builds an [`Error::Uncertain`] for a failure that happened after the
    /// request had been written, so the command may already have run.
    ///
    /// Use this from a [`Transport`](crate::transport::Transport) implementation
    /// for a timeout, a reset mid-response or a truncated body. Prefer
    /// [`Error::transport_at`] when the stage is already known, and
    /// [`Error::transport_before_send`] when the request was demonstrably never
    /// written.
    ///
    /// This form takes only the description. When the transport still holds the
    /// error it caught (a reset from `reqwest`, an `io` error from a truncated
    /// read), chain [`Error::with_source`] onto it so the cause survives.
    ///
    /// ```rust
    /// use inwx_client::Error;
    ///
    /// let err = Error::uncertain("timeout waiting for response");
    /// assert!(err.is_uncertain());
    /// assert!(!err.is_retryable());
    ///
    /// let caused = Error::uncertain("connection reset")
    ///     .with_source(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
    /// assert!(std::error::Error::source(&caused).is_some());
    /// ```
    #[must_use]
    pub fn uncertain(message: impl Into<String>) -> Self {
        Self::Uncertain {
            message: message.into(),
            source: None,
        }
    }

    /// Builds an [`Error::Http`] for a non-2xx answer whose body is not an INWX
    /// envelope. The body is bounded and redacted by [`HttpBody`] on the way in,
    /// so the error stays safe to log whatever the endpoint sent.
    ///
    /// The `Retry-After` of the answer is not part of this call site — add it
    /// with [`with_retry_after`](Self::with_retry_after) when the transport saw
    /// one.
    ///
    /// ```
    /// use inwx_client::Error;
    ///
    /// let err = Error::http(503, "<html>service unavailable</html>");
    /// assert_eq!(err.to_string(), "http 503: <html>service unavailable</html>");
    /// assert!(err.is_retryable());
    ///
    /// // Whatever the page echoes back, the password does not reach the message.
    /// let echoed = Error::http(400, r#"{"password":"hunter2"}"#);
    /// assert!(!echoed.to_string().contains("hunter2"));
    /// ```
    #[must_use]
    pub fn http(status: u16, body: impl Into<HttpBody>) -> Self {
        Self::Http {
            status,
            body: body.into(),
            retry_after: None,
            source: None,
        }
    }

    /// Attaches `source` as the cause of this error, so `err.source()` walks
    /// into it instead of the failure existing only as text in `message`.
    ///
    /// This is the way in for a transport: hand over the `reqwest`, TLS or `io`
    /// error that was caught, not its `Display` string. Everything below it —
    /// the resolve error under a connect failure, the TLS error under that —
    /// stays reachable, and a caller can match on the concrete type rather than
    /// parse a message.
    ///
    /// Supported on [`Error::Transport`], [`Error::Uncertain`],
    /// [`Error::Authentication`] and [`Error::Http`]. On any other variant it is
    /// a no-op, like [`with_retry_after`](Self::with_retry_after), so a path
    /// that builds an error without matching first stays readable.
    ///
    /// `message` is not rewritten: it is what `Display` prints, and keeping the
    /// cause out of it is what stops the same text (and any URL in it) from
    /// appearing twice in a logged chain.
    ///
    /// ```rust
    /// use inwx_client::Error;
    /// use std::error::Error as _;
    ///
    /// let failure = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
    /// let err = Error::transport_before_send("could not connect").with_source(failure);
    ///
    /// assert_eq!(err.source().map(ToString::to_string), Some("refused".to_owned()));
    /// assert_eq!(err.to_string(), "transport error: could not connect");
    ///
    /// // A variant with no cause slot ignores it rather than inventing one.
    /// let plain = Error::validation("record.ttl", "out of range")
    ///     .with_source(std::io::Error::other("unreachable"));
    /// assert!(plain.source().is_none());
    /// ```
    #[must_use]
    pub fn with_source(mut self, source: impl Into<ErrorSource>) -> Self {
        let source = source.into();
        match &mut self {
            Self::Transport { source: slot, .. }
            | Self::Uncertain { source: slot, .. }
            | Self::Authentication { source: slot, .. }
            | Self::Http { source: slot, .. } => *slot = Some(source),
            _ => {}
        }
        self
    }

    /// Records the delay a `Retry-After` header asked for on an
    /// [`Error::Http`].
    ///
    /// The header is advisory input from the network, so it is carried as data
    /// and never turned into a sleep here: a caller that decides to wait reads
    /// it back with [`retry_after`](Self::retry_after) and caps it itself.
    /// Calling this on any other variant is a no-op, so a path that builds an
    /// error without matching first stays readable.
    ///
    /// ```rust
    /// use inwx_client::Error;
    /// use std::time::Duration;
    ///
    /// let err = Error::http(429, "too many requests").with_retry_after(Duration::from_secs(120));
    /// assert_eq!(err.retry_after(), Some(Duration::from_secs(120)));
    /// // The classification does not change: 429 was retryable already.
    /// assert!(err.is_retryable());
    ///
    /// // Attaching a delay never overrides the status: 404 stays terminal.
    /// let gone = Error::http(404, "no such page").with_retry_after(Duration::from_secs(5));
    /// assert_eq!(gone.retry_after(), Some(Duration::from_secs(5)));
    /// assert!(!gone.is_retryable());
    /// assert_eq!(Error::validation("domain", "empty").retry_after(), None);
    /// ```
    #[must_use]
    pub fn with_retry_after(mut self, retry_after: Duration) -> Self {
        if let Self::Http {
            retry_after: slot, ..
        } = &mut self
        {
            *slot = Some(retry_after);
        }
        self
    }

    /// Delay the endpoint asked for before the next attempt, if it asked for
    /// one.
    ///
    /// `Some` only for an [`Error::Http`] that carried a usable `Retry-After`
    /// header: either delay-seconds (`120`) or an HTTP-date, which is turned
    /// into a delay relative to the moment the answer arrived — a date already
    /// in the past yields [`Duration::ZERO`], meaning "retry now". Every other
    /// failure, and an `Http` without the header, answers `None`, so the
    /// caller's own backoff applies.
    ///
    /// This is the server's wish, not a recommendation: the value is unbounded
    /// and says nothing about whether the failed command may be replayed — for
    /// a mutating method that decision is [`is_retryable`](Self::is_retryable)
    /// and [`is_uncertain`](Self::is_uncertain).
    ///
    /// ```rust
    /// use inwx_client::{retry_after_from_header, Error};
    /// use std::time::Duration;
    ///
    /// // The two forms the header is allowed to take.
    /// let seconds = retry_after_from_header("30");
    /// assert_eq!(seconds, Some(Duration::from_secs(30)));
    ///
    /// let throttled = Error::http(429, "too many requests")
    ///     .with_retry_after(seconds.unwrap_or_default());
    /// assert_eq!(throttled.retry_after(), Some(Duration::from_secs(30)));
    /// assert!(throttled.is_retryable());
    ///
    /// // No header seen: the caller's backoff decides.
    /// assert_eq!(Error::http(503, "unavailable").retry_after(), None);
    /// assert_eq!(Error::uncertain("timeout").retry_after(), None);
    /// ```
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Http { retry_after, .. } => *retry_after,
            _ => None,
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
    /// Validation, decoding and authentication errors are never retryable, and
    /// neither is [`Error::ResponseTooLarge`]: a body over the cap is a property
    /// of the answer, and the command behind it may already have run. An
    /// [`Error::Undecodable`] is not retryable either — like
    /// [`Error::Uncertain`] it means the command may have been executed, so it
    /// is uncertain rather than merely failed. An
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
    /// A `Retry-After` header carried on the error never changes the answer
    /// here — it only says *when* a retry would be polite, never *whether* one
    /// is allowed; see [`Error::retry_after`].
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
    /// assert!(Error::transport_before_send("dns lookup failed").is_retryable());
    /// assert!(!Error::uncertain("timeout").is_retryable());
    /// assert!(!Error::validation("domain", "empty").is_retryable());
    ///
    /// // A gateway hiccup is transient, a rejected request is not.
    /// let gateway = Error::http(503, "unavailable");
    /// assert!(gateway.is_retryable());
    /// let denied = Error::http(403, "forbidden");
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
            // Terminal by design — validation, decoding, authentication, HTTP,
            // a missing field, and `ResponseTooLarge` (a body over the cap is a
            // property of the answer, and the command behind it may already have
            // run, so repeating it would duplicate work).
            _ => false,
        }
    }

    /// Whether the outcome of the command is unknown: the request was written
    /// and the exchange then broke, either in transport (a timeout, a reset
    /// mid-response, a truncated body) or in decoding (an answer whose body
    /// cannot be read as an envelope).
    ///
    /// Both cases mean the API may already have executed the command, so a
    /// replay can duplicate a mutation.
    ///
    /// ```rust
    /// use inwx_client::Error;
    ///
    /// assert!(Error::uncertain("timeout").is_uncertain());
    /// assert!(!Error::transport_before_send("dns lookup failed").is_uncertain());
    ///
    /// // The decode side of the same ambiguity: the answer arrived, the body
    /// // did not survive it.
    /// let cut = serde_json::from_str::<serde_json::Value>("{\"code\":10")
    ///     .expect_err("the document is cut off");
    /// assert!(Error::Undecodable { source: cut }.is_uncertain());
    ///
    /// // A payload with the wrong shape is certain instead: the command ran.
    /// let payload = serde_json::from_value::<u8>(serde_json::json!("held"))
    ///     .expect_err("a string is not a number");
    /// assert!(!Error::Json { source: payload }.is_uncertain());
    /// ```
    #[must_use]
    pub fn is_uncertain(&self) -> bool {
        matches!(self, Self::Uncertain { .. } | Self::Undecodable { .. })
    }

    /// Whether this is a rejected session rather than a rejected command.
    ///
    /// The client uses this to decide whether a single re-login is worth it;
    /// callers can use it to prompt for new credentials. That decision is only
    /// sound for errors a login can cure, so this covers the API codes
    /// `2200`–`2202` and [`Error::Authentication`]. [`Error::NotAuthenticated`]
    /// is deliberately excluded: it means the client has neither a session nor
    /// credentials, so a re-login cannot succeed and the caller has to supply
    /// credentials first — see [`Error::is_missing_credentials`].
    ///
    /// ```
    /// use inwx_client::{Error, RpcResponse};
    ///
    /// let response = RpcResponse::parse(br#"{"code":2200,"msg":"Authentication error"}"#)?;
    /// let err = response.into_result().unwrap_err();
    /// assert!(err.is_authentication());
    ///
    /// // Nothing to log in with: a configuration gap, not an expired session.
    /// assert!(!Error::NotAuthenticated.is_authentication());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn is_authentication(&self) -> bool {
        match self {
            Self::Api { code, .. } => matches!(code, 2200..=2202),
            Self::Authentication { .. } => true,
            _ => false,
        }
    }

    /// Whether the client never had credentials to authenticate with.
    ///
    /// [`Error::NotAuthenticated`] is returned when an authenticated method is
    /// called on a client that has neither a session nor credentials to open
    /// one, so the fix is to configure credentials rather than to retry or to
    /// log in again. Not part of [`Error::is_authentication`] for that reason.
    ///
    /// ```
    /// use inwx_client::Error;
    ///
    /// assert!(Error::NotAuthenticated.is_missing_credentials());
    /// // An expired session is a different problem: a login can cure it.
    /// assert!(!Error::Authentication {
    ///     message: "session expired".into(),
    ///     source: None,
    /// }
    /// .is_missing_credentials());
    /// assert!(!Error::validation("domain", "empty").is_missing_credentials());
    /// ```
    #[must_use]
    pub fn is_missing_credentials(&self) -> bool {
        matches!(self, Self::NotAuthenticated)
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

/// Most characters of an HTTP error body that an [`Error::Http`] keeps.
///
/// Long enough for a gateway page or a short INWX complaint, short enough that
/// a log line stays a log line.
///
/// ```
/// use inwx_client::{HttpBody, MAX_HTTP_BODY_CHARS};
///
/// let short = HttpBody::new("bad gateway");
/// assert_eq!(short.as_str(), "bad gateway");
///
/// let long = HttpBody::new(&"x".repeat(MAX_HTTP_BODY_CHARS + 1));
/// assert!(long.as_str().starts_with(&"x".repeat(MAX_HTTP_BODY_CHARS)));
/// assert!(long.as_str().ends_with("[truncated]"));
/// ```
pub const MAX_HTTP_BODY_CHARS: usize = 512;

/// Appended when a body had to be cut, so truncation is visible in a log.
const TRUNCATION_MARKER: &str = " [truncated]";

/// Stands in for the value of a sensitive key.
const REDACTED_VALUE: &str = "<redacted>";

/// Keys whose values must not reach a log line, compared case-insensitively
/// against the whole key so that `mypassword` stays untouched.
const SENSITIVE_KEYS: &[&str] = &[
    "apikey",
    "api_key",
    "authcode",
    "auth_code",
    "newpassword",
    "oldpassword",
    "pass",
    "passwd",
    "password",
    "secret",
    "sessionid",
    "session_id",
    "token",
];

/// The body of an [`Error::Http`], bounded and redacted at construction time.
///
/// A non-2xx answer that is not an INWX envelope comes from a gateway, a proxy
/// or a misconfigured endpoint, and it can be arbitrarily large — or echo back
/// the request, credentials included, which is how the API reports bad
/// parameters. Handing that to a caller verbatim would put an unbounded and
/// possibly secret-bearing page into every log line the caller writes.
///
/// So a body enters the error only through this type, and every constructor
/// enforces the same two rules:
///
/// * at most [`MAX_HTTP_BODY_CHARS`] characters survive, cut on a character
///   boundary and followed by `" [truncated]"` when anything was dropped;
/// * the value of a known sensitive key (`password`, `passwd`, `pass`,
///   `authcode`, `secret`, `token`, `sessionid`, `apikey`, and the
///   `new`/`old` password forms — JSON `"key": "value"` and form/query
///   `key=value` alike) becomes `<redacted>`.
///
/// [`Display`](fmt::Display) labels the body and [`Debug`](fmt::Debug) quotes
/// it, but both print exactly that bounded, redacted text — there is no path
/// that emits the raw string.
///
/// ```
/// use inwx_client::HttpBody;
///
/// let echoed = HttpBody::new(r#"{"password":"hunter2","user":"bob"}"#);
/// assert_eq!(echoed.as_str(), r#"{"password":"<redacted>","user":"bob"}"#);
///
/// // Form-encoded answers are the same: the secret goes, the rest stays.
/// let form = HttpBody::new("user=bob&pass=hunter2&action=login");
/// assert_eq!(form.as_str(), "user=bob&pass=<redacted>&action=login");
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HttpBody(String);

impl HttpBody {
    /// Bounds and redacts `body`.
    ///
    /// The text is redacted first and cut afterwards, so a redaction that
    /// lengthens a value can never push the result past
    /// [`MAX_HTTP_BODY_CHARS`].
    ///
    /// ```
    /// use inwx_client::HttpBody;
    ///
    /// let body = HttpBody::new("relay said no");
    /// assert_eq!(body.to_string(), "relay said no");
    /// ```
    #[must_use]
    pub fn new(body: &str) -> Self {
        Self(bounded(&redact(body)))
    }

    /// Bounds and redacts a raw response body.
    ///
    /// Only the bytes that can still matter are decoded: four bytes per kept
    /// character is the widest a UTF-8 code point gets, so the whole page is
    /// never copied into a `String` first. Invalid UTF-8 becomes `U+FFFD` as
    /// usual, and a replacement character produced by cutting a sequence at the
    /// byte cap is removed again by the character truncation that follows.
    ///
    /// ```
    /// use inwx_client::HttpBody;
    ///
    /// let body = HttpBody::from_bytes(b"\xff<html>bad request</html>");
    /// assert!(body.as_str().ends_with("<html>bad request</html>"));
    /// ```
    #[must_use]
    pub fn from_bytes(body: &[u8]) -> Self {
        let cap = MAX_HTTP_BODY_CHARS.saturating_mul(4);
        let prefix = body.get(..body.len().min(cap)).unwrap_or_default();
        Self::new(&String::from_utf8_lossy(prefix))
    }

    /// The bounded, redacted text — the only view of the body this type offers.
    ///
    /// ```
    /// use inwx_client::HttpBody;
    ///
    /// let body = HttpBody::new("nope");
    /// assert_eq!(body.as_str(), "nope");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HttpBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Quotes the bounded text, so a derived `Debug` on [`enum@Error`] stays readable.
impl fmt::Debug for HttpBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, formatter)
    }
}

impl From<String> for HttpBody {
    fn from(body: String) -> Self {
        Self::new(&body)
    }
}

impl From<&str> for HttpBody {
    fn from(body: &str) -> Self {
        Self::new(body)
    }
}

impl AsRef<str> for HttpBody {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for HttpBody {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

/// Cuts `text` to [`MAX_HTTP_BODY_CHARS`] characters, one character at a time so
/// the result can never split a code point.
fn bounded(text: &str) -> String {
    let capacity = text
        .len()
        .min(MAX_HTTP_BODY_CHARS * 4 + TRUNCATION_MARKER.len());
    let mut kept = String::with_capacity(capacity);
    for (index, character) in text.chars().enumerate() {
        if index == MAX_HTTP_BODY_CHARS {
            kept.push_str(TRUNCATION_MARKER);
            return kept;
        }
        kept.push(character);
    }
    kept
}

/// Replaces the value of every known sensitive key with `<redacted>`.
fn redact(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut redacted = String::with_capacity(text.len());
    let mut copied = 0;
    let mut cursor = 0;
    while cursor < bytes.len() {
        match sensitive_value_at(text, cursor) {
            Some((value_start, value_end)) => {
                // Every offset here sits on an ASCII byte of the key or of its
                // separator, so the range is a valid character boundary.
                redacted.push_str(text.get(copied..value_start).unwrap_or_default());
                redacted.push_str(REDACTED_VALUE);
                copied = value_end;
                cursor = value_end;
            }
            None => cursor += 1,
        }
    }
    redacted.push_str(text.get(copied..).unwrap_or_default());
    redacted
}

/// Span of the value of a sensitive key starting at `start`, quotes excluded.
///
/// Returns `None` when `start` is not the beginning of a whole sensitive key
/// followed by `:` or `=` and a value.
fn sensitive_value_at(text: &str, start: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    if let Some(previous) = start.checked_sub(1).and_then(|index| bytes.get(index)) {
        // Only a whole key counts: `mypassword` is a different key.
        if previous.is_ascii_alphanumeric() || *previous == b'_' {
            return None;
        }
    }
    let key_end = key_end(bytes, start)?;
    let key = text.get(start..key_end)?;
    if !SENSITIVE_KEYS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(key))
    {
        return None;
    }
    // A JSON key is wrapped in quotes; the separator follows the closing one.
    let mut cursor = key_end;
    if let Some(&quote @ (b'"' | b'\'')) = start.checked_sub(1).and_then(|index| bytes.get(index)) {
        if bytes.get(cursor) != Some(&quote) {
            return None;
        }
        cursor += 1;
    }
    let cursor = skip_ascii_whitespace(bytes, cursor);
    let cursor = match bytes.get(cursor) {
        Some(b':' | b'=') => cursor + 1,
        _ => return None,
    };
    let cursor = skip_ascii_whitespace(bytes, cursor);
    value_span(bytes, cursor)
}

/// Index just past the identifier at `start`, or `None` when there is none.
fn key_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut end = start;
    while let Some(byte) = bytes.get(end) {
        if byte.is_ascii_alphanumeric() || *byte == b'_' {
            end += 1;
        } else {
            break;
        }
    }
    (end > start).then_some(end)
}

fn skip_ascii_whitespace(bytes: &[u8], mut cursor: usize) -> usize {
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    cursor
}

/// Span of the value at `cursor`: inside the quotes when there are some, up to
/// the next separator otherwise.
fn value_span(bytes: &[u8], cursor: usize) -> Option<(usize, usize)> {
    match bytes.get(cursor) {
        Some(&quote @ (b'"' | b'\'')) => {
            let value_start = cursor + 1;
            let mut end = value_start;
            while let Some(&byte) = bytes.get(end) {
                if byte == b'\\' {
                    // An escaped character is data, including an escaped quote.
                    end += 2;
                    continue;
                }
                if byte == quote {
                    return Some((value_start, end));
                }
                end += 1;
            }
            Some((value_start, bytes.len().min(end)))
        }
        Some(_) => {
            let mut end = cursor;
            while let Some(&byte) = bytes.get(end) {
                if byte.is_ascii_whitespace() || matches!(byte, b'&' | b',' | b';' | b'}' | b']') {
                    break;
                }
                end += 1;
            }
            Some((cursor, end.min(bytes.len())))
        }
        None => None,
    }
}

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

/// Delay a `Retry-After` header asks for, in the header's own terms.
///
/// The header has two forms (RFC 9110 §10.2.3): delay-seconds, a non-negative
/// integer, and an HTTP-date. A date is measured against the current instant —
/// so a date in the past, the endpoint saying "immediately", yields
/// [`Duration::ZERO`] instead of a negative wait. Anything else (empty,
/// negative, fractional, out of range, not a date) answers `None`: a value the
/// client cannot read must not become a made-up delay.
///
/// Attach the result with [`Error::with_retry_after`], or read it back from an
/// error with [`Error::retry_after`]. This is the parser the client itself uses
/// on every non-envelope answer, exposed because a caller with its own
/// [`Transport`](crate::transport::Transport) or HTTP stack needs the same
/// reading.
///
/// ```rust
/// use inwx_client::retry_after_from_header;
/// use std::time::Duration;
///
/// // Delay-seconds, padded or not.
/// assert_eq!(retry_after_from_header("120"), Some(Duration::from_secs(120)));
/// assert_eq!(retry_after_from_header(" 0 "), Some(Duration::ZERO));
///
/// // A date in the past means "now", never a negative delay.
/// assert_eq!(
///     retry_after_from_header("Sun, 06 Nov 1994 08:49:37 GMT"),
///     Some(Duration::ZERO),
/// );
///
/// // Not a delay: nothing is invented.
/// assert_eq!(retry_after_from_header("soon"), None);
/// assert_eq!(retry_after_from_header("-1"), None);
/// assert_eq!(retry_after_from_header(""), None);
/// ```
#[must_use]
pub fn retry_after_from_header(value: &str) -> Option<Duration> {
    retry_after_at(value, SystemTime::now())
}

/// [`retry_after_from_header`] against an explicit instant, so the date form
/// stays a pure function: the caller decides what "now" is.
pub(crate) fn retry_after_at(value: &str, now: SystemTime) -> Option<Duration> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    // Delay-seconds: digits only. `parse::<u64>` would also accept `+5` and
    // `1_000`, neither of which the grammar allows, and an overflow must not
    // wrap into a short delay.
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        return value.parse::<u64>().ok().map(Duration::from_secs);
    }
    let deadline = httpdate::parse_http_date(value).ok()?;
    Some(deadline.duration_since(now).unwrap_or(Duration::ZERO))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(status: u16) -> Error {
        Error::Http {
            status,
            body: "gateway trouble".into(),
            retry_after: None,
            source: None,
        }
    }

    /// The cause of an error, read through the trait the chain is walked with.
    fn cause(error: &Error) -> Option<String> {
        std::error::Error::source(error).map(ToString::to_string)
    }

    /// Everything an error reports about itself, as one comparable value: the
    /// classification, the authentication reading and the message.
    fn verdict(error: &Error) -> (bool, bool, bool, String) {
        (
            error.is_retryable(),
            error.is_uncertain(),
            error.is_authentication(),
            error.to_string(),
        )
    }

    /// A cause handed in stays reachable through `source`, and `Display` keeps
    /// printing the short message: the failure is not flattened into text that
    /// a caller would have to parse.
    #[test]
    fn a_cause_survives_as_the_source_instead_of_text() {
        let err = Error::transport_at_caused_by(
            TransportStage::BeforeSend,
            "could not connect",
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"),
        );

        assert_eq!(cause(&err), Some(String::from("refused")));
        assert_eq!(err.to_string(), "transport error: could not connect");
        assert!(!err.to_string().contains("refused"));
        // The verdict still comes from the stage, not from the cause.
        assert!(err.is_retryable());
        assert!(!err.is_uncertain());
    }

    /// The chain is walked past the first cause: an error that wraps another
    /// keeps its own `source` reachable through the boxed one.
    #[test]
    fn the_chain_walks_below_the_first_cause() {
        #[derive(Debug)]
        struct Wrapped {
            message: &'static str,
            inner: std::io::Error,
        }

        impl fmt::Display for Wrapped {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.message)
            }
        }

        impl std::error::Error for Wrapped {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.inner)
            }
        }

        let err = Error::transport_at_caused_by(
            TransportStage::AfterSend,
            "connection reset",
            Wrapped {
                message: "hyper connection reset",
                inner: std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset by peer"),
            },
        );

        let first = std::error::Error::source(&err).expect("the wrapper is the first cause");
        assert_eq!(first.to_string(), "hyper connection reset");
        let second = first.source().expect("the wrapper has a cause of its own");
        assert_eq!(second.to_string(), "reset by peer");
        assert!(second.source().is_none(), "the chain ends where it ends");
    }

    /// Every variant that has a cause slot accepts one, and `with_source`
    /// replaces an earlier cause rather than stacking a second one.
    #[test]
    fn with_source_reaches_every_variant_that_carries_a_cause() {
        let cause_of = |text: &'static str| std::io::Error::other(text);

        for error in [
            Error::transport_before_send("dns lookup failed").with_source(cause_of("cause")),
            Error::uncertain("timeout").with_source(cause_of("cause")),
            Error::http(503, "unavailable").with_source(cause_of("cause")),
            Error::Authentication {
                message: String::from("no cookie"),
                source: None,
            }
            .with_source(cause_of("cause")),
        ] {
            assert_eq!(cause(&error), Some(String::from("cause")), "{error}");
        }

        let replaced = Error::uncertain("timeout")
            .with_source(cause_of("first"))
            .with_source(cause_of("second"));
        assert_eq!(cause(&replaced), Some(String::from("second")));
    }

    /// A variant without a cause slot ignores a cause instead of growing a
    /// second field, and `Json` keeps the parser error it already carries.
    #[test]
    fn variants_without_a_cause_slot_stay_chainless() {
        let builders: [fn() -> Error; 6] = [
            || Error::validation("domain", "empty"),
            || Error::NotAuthenticated,
            || Error::MissingField {
                method: "domain.info",
                field: "resData.id",
            },
            || Error::unexpected_answer("nameserver.check", "details", "expected an array"),
            || Error::ResponseTooLarge {
                limit: 8,
                observed: Some(9),
            },
            || Error::Api {
                code: 2300,
                message: String::from("object pending transfer"),
                reason_code: None,
                reason: None,
                details: Vec::new(),
            },
        ];

        for build in builders {
            let plain = build();
            assert!(cause(&plain).is_none(), "{plain}");
            let late = build().with_source(std::io::Error::other("late"));
            assert!(cause(&late).is_none(), "{late}");
            assert_eq!(
                verdict(&plain),
                verdict(&late),
                "attaching a cause changed the verdict for {plain}"
            );
        }

        let json: Error = serde_json::from_str::<serde_json::Value>("{not json")
            .expect_err("garbage is not JSON")
            .into();
        let parsed = cause(&json);
        assert!(parsed.is_some(), "the parser error is the source");
        assert_eq!(
            cause(&json.with_source(std::io::Error::other("late"))),
            parsed,
            "a later cause must not replace the line/column of the parser"
        );

        // The decode-side sibling carries its parser error the same way, and
        // refuses a replacement just as firmly.
        let cut = || Error::Undecodable {
            source: serde_json::from_str::<serde_json::Value>("{not json")
                .expect_err("garbage is not JSON"),
        };
        assert!(cause(&cut()).is_some(), "the parser error is the source");
        assert_eq!(
            cause(&cut().with_source(std::io::Error::other("late"))),
            cause(&cut()),
            "a later cause must not replace the line/column of the parser"
        );
    }

    /// The decode side of an ambiguous outcome: the answer arrived, the body did
    /// not survive it. Same verdict as a transport failure after the write —
    /// uncertain, never retryable — with the parser error walkable as the cause.
    #[test]
    fn an_undecodable_answer_is_uncertain_and_never_retryable() {
        let error = Error::Undecodable {
            source: serde_json::from_str::<serde_json::Value>(r#"{"code":1000,"msg":"ok""#)
                .expect_err("the document is cut off"),
        };

        assert!(error.is_uncertain());
        assert!(!error.is_retryable());
        assert!(!error.is_authentication());
        assert!(!error.is_missing_credentials());
        assert!(!error.is_validation());
        assert!(cause(&error).is_some(), "the parser error is the cause");
        assert!(error.to_string().contains("may have been executed"));
        assert_eq!(error.code(), None);
        assert_eq!(error.retry_after(), None);

        // An empty answer is the same: the exchange completed, nothing came
        // back that could be read.
        let empty = Error::Undecodable {
            source: serde_json::from_slice::<serde_json::Value>(b"")
                .expect_err("an empty body is not JSON"),
        };
        assert!(empty.is_uncertain());
        assert!(!empty.is_retryable());
    }

    /// Boundary pair around the certainty of a decode failure: the same
    /// unreadable-looking bytes, once cut off behind a written request (unknown
    /// outcome) and once complete but in the wrong shape (certain failure).
    #[test]
    fn the_certainty_boundary_is_cut_off_versus_merely_unexpected() {
        let cut = Error::Undecodable {
            source: serde_json::from_str::<serde_json::Value>("{\"code\":10")
                .expect_err("cut off mid-document"),
        };
        // One byte more closes the object: valid JSON, still not an envelope.
        let whole = Error::Json {
            source: serde_json::from_str::<serde_json::Map<String, serde_json::Value>>("[1,2,3]")
                .expect_err("a sequence is not an envelope"),
        };

        assert!(cut.is_uncertain());
        assert!(!whole.is_uncertain());
        // Neither may be replayed, but for different reasons: the one may have
        // run, the other is a shape the client does not model.
        assert!(!cut.is_retryable());
        assert!(!whole.is_retryable());
        assert_ne!(cut.to_string(), whole.to_string());
    }

    /// The message-only constructors invent nothing: no cause means no source,
    /// so a caller can rely on `source()` being `Some` only when there was a
    /// real failure behind the error.
    #[test]
    fn the_message_only_constructors_have_no_source() {
        for error in [
            Error::transport_before_send("dns lookup failed"),
            Error::transport_at(TransportStage::AfterSend, "timeout"),
            Error::uncertain("timeout"),
            Error::http(503, "unavailable"),
        ] {
            assert!(cause(&error).is_none(), "{error}");
        }
    }

    /// The boxed cause does not cost the error its thread safety: it still
    /// travels out of the task it was created in.
    #[test]
    fn the_error_stays_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
    }

    /// The retry flag of a transport failure is derived from the stage, never
    /// passed in: the free-form `Error::transport(msg)` that always produced a
    /// retryable error is gone, and the variant takes no `retryable` argument.
    /// Edge pair: the last stage that may be replayed and the first one that
    /// may not.
    #[test]
    fn only_the_before_send_stage_is_retryable() {
        let before = Error::transport_before_send("dns lookup failed");
        assert!(before.is_retryable());
        assert!(!before.is_uncertain());

        let after = Error::transport_at(TransportStage::AfterSend, "timeout");
        assert!(!after.is_retryable());
        assert!(after.is_uncertain());

        assert!(!Error::transport_at(TransportStage::Local, "unsupported scheme").is_retryable());
        assert!(!Error::transport_at(TransportStage::Local, "unsupported scheme").is_uncertain());

        // Building the same stage through the stage-driven constructor and the
        // named one must not diverge, whatever the message.
        for message in ["", "x", "timeout waiting for the answer"] {
            assert_eq!(
                Error::transport_before_send(message).is_retryable(),
                Error::transport_at(TransportStage::BeforeSend, message).is_retryable()
            );
            assert_eq!(
                Error::transport_before_send(message).to_string(),
                Error::transport_at(TransportStage::BeforeSend, message).to_string()
            );
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
                body: body.to_owned().into(),
                retry_after: None,
                source: None,
            };
            assert!(error.is_retryable());
            let terminal = Error::Http {
                status: 404,
                body: body.to_owned().into(),
                retry_after: None,
                source: None,
            };
            assert!(!terminal.is_retryable());
        }
    }

    /// The header is data, not a verdict: attaching, carrying and reading it
    /// back says nothing about whether the status may be replayed. Edge pair:
    /// no header seen and the smallest delay that is not zero.
    #[test]
    fn the_retry_after_header_is_carried_without_changing_the_verdict() {
        assert_eq!(http(429).retry_after(), None);

        let immediate = http(429).with_retry_after(Duration::ZERO);
        assert_eq!(immediate.retry_after(), Some(Duration::ZERO));
        assert!(immediate.is_retryable());

        let throttled = http(429).with_retry_after(Duration::from_secs(120));
        assert_eq!(throttled.retry_after(), Some(Duration::from_secs(120)));
        assert!(throttled.is_retryable());

        // Attaching it to a terminal status does not make that status retryable.
        let denied = http(403).with_retry_after(Duration::from_secs(120));
        assert_eq!(denied.retry_after(), Some(Duration::from_secs(120)));
        assert!(!denied.is_retryable());

        // The largest expressible delay survives the round trip unchanged.
        let huge = http(503).with_retry_after(Duration::from_secs(u64::MAX));
        assert_eq!(huge.retry_after(), Some(Duration::from_secs(u64::MAX)));

        // Neither the body nor the delay reaches the message; the verdict is
        // the only thing `Display` is allowed to leak.
        assert_eq!(throttled.to_string(), "http 429: gateway trouble");
        assert!(!throttled.to_string().contains("120"));
    }

    /// Every other variant answers `None`, whatever the builder was handed.
    #[test]
    fn only_an_http_error_carries_a_retry_after() {
        for error in [
            Error::uncertain("timeout"),
            Error::validation("domain", "empty"),
            Error::transport_before_send("dns lookup failed"),
            Error::NotAuthenticated,
            Error::Api {
                code: 2300,
                message: String::from("object pending transfer"),
                reason_code: None,
                reason: None,
                details: Vec::new(),
            },
        ] {
            assert_eq!(error.retry_after(), None, "{error}");
            assert_eq!(
                error.with_retry_after(Duration::from_secs(1)).retry_after(),
                None
            );
        }
    }

    /// 1994-11-06T08:49:37Z, the date RFC 9110 uses in its own example.
    const FIXDATE: &str = "Sun, 06 Nov 1994 08:49:37 GMT";
    const FIXDATE_EPOCH_SECS: u64 = 784_111_777;

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    /// Delay-seconds: zero, a typical value, and the largest value that still
    /// fits — with one past the edge and the shapes a `u64` parser would
    /// wrongly accept.
    #[test]
    fn retry_after_seconds_parse_exactly() {
        let now = at(FIXDATE_EPOCH_SECS);
        assert_eq!(retry_after_at("0", now), Some(Duration::ZERO));
        assert_eq!(retry_after_at("120", now), Some(Duration::from_secs(120)));
        assert_eq!(
            retry_after_at(" 120\t", now),
            Some(Duration::from_secs(120))
        );
        // Leading zeros are still a number.
        assert_eq!(retry_after_at("0007", now), Some(Duration::from_secs(7)));
        // One past `u64::MAX` must not wrap into a short delay.
        assert_eq!(retry_after_at("18446744073709551616", now), None);
        assert_eq!(
            retry_after_at("18446744073709551615", now),
            Some(Duration::from_secs(u64::MAX))
        );

        for rejected in ["", "  ", "-1", "+5", "1.5", "1s", "12 0", "abc", "0x10"] {
            assert_eq!(retry_after_at(rejected, now), None, "{rejected:?}");
        }
    }

    /// A date is measured against `now`: in the future it is the distance, at
    /// or before `now` it is "retry now". All three formats a recipient must
    /// accept are read.
    #[test]
    fn retry_after_dates_are_measured_against_now() {
        let deadline = at(FIXDATE_EPOCH_SECS);

        // Just inside: one second before the date.
        assert_eq!(
            retry_after_at(FIXDATE, at(FIXDATE_EPOCH_SECS - 1)),
            Some(Duration::from_secs(1))
        );
        // The date itself and anything older mean "now", never a negative wait.
        assert_eq!(retry_after_at(FIXDATE, deadline), Some(Duration::ZERO));
        assert_eq!(
            retry_after_at(FIXDATE, at(FIXDATE_EPOCH_SECS + 86_400)),
            Some(Duration::ZERO)
        );
        // Same instant, spelled the other two ways a recipient must accept.
        for spelling in ["Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994"] {
            assert_eq!(
                retry_after_at(spelling, at(FIXDATE_EPOCH_SECS - 5)),
                Some(Duration::from_secs(5)),
                "{spelling}"
            );
        }

        // Not a date, not a number: no delay rather than a made-up one.
        for rejected in [
            "Sun, 32 Nov 1994 08:49:37 GMT",
            "Sun, 06 Foo 1994 08:49:37 GMT",
            "1994-11-06T08:49:37Z",
            "Sun, 06 Nov 1994 08:49:37",
        ] {
            assert_eq!(retry_after_at(rejected, deadline), None, "{rejected}");
        }
    }

    /// The public entry point reads the clock for the date form: a date long
    /// past is "now", a date far ahead is a long wait, a number is the number.
    #[test]
    fn the_public_parser_reads_the_clock_for_dates() {
        assert_eq!(
            retry_after_from_header(FIXDATE),
            Some(Duration::ZERO),
            "a 1994 date is long past"
        );
        assert_eq!(retry_after_from_header("90"), Some(Duration::from_secs(90)));
        assert!(
            retry_after_from_header("Mon, 06 Nov 2400 08:49:37 GMT")
                .is_some_and(|delay| delay > Duration::from_secs(3_000_000_000)),
            "a date centuries ahead is a long wait"
        );
    }

    /// No behavior change for the other variants.
    #[test]
    fn other_variants_classify_as_before() {
        assert!(Error::transport_before_send("dns lookup failed").is_retryable());
        assert!(!Error::transport_at(TransportStage::Local, "unsupported scheme").is_retryable());

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
            source: None,
        }
        .is_retryable());
        assert!(!Error::MissingField {
            method: "domain.info",
            field: "resData.id",
        }
        .is_retryable());
        assert!(
            !Error::unexpected_answer("nameserver.check", "details", "expected an array")
                .is_retryable()
        );
    }

    /// Only errors a login can cure are reported as re-login-able; a missing
    /// credential is a different, terminal condition.
    #[test]
    fn relogin_classification_stops_at_the_credential_gap() {
        let api = |code| Error::Api {
            code,
            message: String::from("Authentication error"),
            reason_code: None,
            reason: None,
            details: Vec::new(),
        };

        // Just outside and just inside both ends of the 2200..=2202 window.
        assert!(!api(2199).is_authentication());
        assert!(api(2200).is_authentication());
        assert!(api(2201).is_authentication());
        assert!(api(2202).is_authentication());
        assert!(!api(2203).is_authentication());

        // A recovery that could not log in again stays re-login-able: the
        // caller may hold fresh credentials.
        assert!(Error::Authentication {
            message: String::from("no cookie"),
            source: None,
        }
        .is_authentication());

        // The one error a login cannot cure.
        assert!(!Error::NotAuthenticated.is_authentication());
        assert!(Error::NotAuthenticated.is_missing_credentials());

        // Everything else is neither.
        for error in [
            api(2300),
            api(2203),
            Error::validation("domain", "empty"),
            Error::transport_before_send("dns lookup failed"),
            Error::uncertain("timeout"),
            Error::MissingField {
                method: "domain.info",
                field: "resData.id",
            },
        ] {
            assert!(!error.is_authentication());
            assert!(!error.is_missing_credentials());
        }
    }

    /// Boundary pair on the documented cap: an exact fit is kept verbatim, one
    /// character more is cut and marked.
    #[test]
    fn the_body_bound_is_exact() {
        let inside = "x".repeat(MAX_HTTP_BODY_CHARS);
        let kept = HttpBody::new(&inside);
        assert_eq!(kept.as_str(), inside);
        assert!(!kept.as_str().contains("[truncated]"));

        let outside = "x".repeat(MAX_HTTP_BODY_CHARS + 1);
        let cut = HttpBody::new(&outside);
        assert_eq!(
            cut.as_str(),
            format!("{}{TRUNCATION_MARKER}", "x".repeat(MAX_HTTP_BODY_CHARS))
        );
    }

    /// The cut lands on a character boundary: no half code point and no
    /// replacement character at the seam.
    #[test]
    fn truncation_keeps_multibyte_characters_whole() {
        let body = HttpBody::new(&"ä".repeat(MAX_HTTP_BODY_CHARS + 100));
        assert!(body.as_str().starts_with(&"ä".repeat(MAX_HTTP_BODY_CHARS)));
        assert!(body.as_str().ends_with(TRUNCATION_MARKER));
        assert!(!body.as_str().contains('\u{FFFD}'));
        assert_eq!(
            body.as_str().chars().count(),
            MAX_HTTP_BODY_CHARS + TRUNCATION_MARKER.len()
        );
    }

    /// Raw bytes are cut before they are decoded, so an oversized page never
    /// becomes a full `String`; invalid UTF-8 is still rendered lossily.
    #[test]
    fn raw_bytes_are_bounded_before_decoding() {
        let huge = vec![b'x'; 8 * 1024 * 1024];
        assert_eq!(
            HttpBody::from_bytes(&huge).as_str().chars().count(),
            MAX_HTTP_BODY_CHARS + TRUNCATION_MARKER.len()
        );

        let invalid = HttpBody::from_bytes(b"\xff\xfe<html>bad request</html>");
        assert!(invalid.as_str().ends_with("<html>bad request</html>"));
    }

    /// A body echoing the request loses its secrets in JSON and in form
    /// encoding, whatever the case of the key, and keeps everything else.
    #[test]
    fn known_secret_values_are_redacted() {
        let json = HttpBody::new(
            r#"{"user":"bob","password":"hunter2","reason":"bad login","apiKey":"k-1"}"#,
        );
        assert_eq!(
            json.as_str(),
            r#"{"user":"bob","password":"<redacted>","reason":"bad login","apiKey":"<redacted>"}"#
        );

        let form = HttpBody::new("user=bob&PASSWORD=hunter2&authcode=ABC-DEF&action=login");
        assert_eq!(
            form.as_str(),
            "user=bob&PASSWORD=<redacted>&authcode=<redacted>&action=login"
        );

        // A whole key only: `mypassword` is a different field.
        let other = HttpBody::new(r#"{"mypassword":"kept"}"#);
        assert_eq!(other.as_str(), r#"{"mypassword":"kept"}"#);

        // An escaped quote is data, so the value ends where JSON ends it.
        let escaped = HttpBody::new(r#"{"password":"a\"b","user":"bob"}"#);
        assert_eq!(
            escaped.as_str(),
            r#"{"password":"<redacted>","user":"bob"}"#
        );

        // Prose without a key/value separator is left alone.
        assert_eq!(
            HttpBody::new("password is required").as_str(),
            "password is required"
        );
    }

    /// `Display` and `Debug` print the bounded, redacted text and nothing else,
    /// so neither a huge page nor a secret reaches a log line.
    #[test]
    fn display_and_debug_stay_within_the_bound() {
        let long = Error::http(500, "y".repeat(50_000));
        assert_eq!(
            long.to_string().chars().count(),
            "http 500: ".len() + MAX_HTTP_BODY_CHARS + TRUNCATION_MARKER.len()
        );
        assert!(format!("{long:?}").chars().count() < 1_000);
        assert!(format!("{long:?}").contains("[truncated]"));

        let echoed = Error::http(400, format!(r#"{{"password":"{}"}}"#, "s".repeat(10_000)));
        assert!(!echoed.to_string().contains("ssssssssss"));
        assert!(echoed.to_string().contains("<redacted>"));
        assert!(format!("{echoed:?}").contains("<redacted>"));
    }
}
