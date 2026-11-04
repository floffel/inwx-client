//! JSON-RPC framing: the request envelope and the response envelope.
//!
//! INWX speaks a small, unversioned dialect of JSON-RPC: a `method` plus a
//! `params` object goes out, a `code` plus an optional `resData` comes back,
//! and **transport success is not command success** — a rejected command is
//! still HTTP 200 with a non-`1000` code, and an asynchronous command can answer
//! with `1001`/`1300`/`1301` before it has completed. [`RpcResponse::into_result`]
//! is the single place that distinction is made.

use std::fmt;

use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::types::de;

/// Result code for "command completed successfully".
pub const CODE_SUCCESS: i32 = 1000;

/// The documented outcome class of a command result code.
///
/// ```
/// use inwx_client::rpc::{classify_code, ResultCode};
///
/// assert_eq!(classify_code(1000), Some(ResultCode::Success));
/// assert_eq!(classify_code(1001), Some(ResultCode::Pending));
/// assert_eq!(classify_code(1300), Some(ResultCode::Queued));
/// assert_eq!(classify_code(2303), None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResultCode {
    /// The command completed. `1000` is the usual code, and `1500` closes a
    /// session successfully.
    Success,
    /// The command has been accepted but not completed, such as an
    /// asynchronous registration or transfer (`1001`).
    Pending,
    /// The command entered a message queue (`1300`, `1301`).
    Queued,
}

/// Classifies an INWX numeric result code.
///
/// `None` means the code is not one of the documented non-error outcomes and
/// therefore belongs in [`Error::Api`] unless the caller has
/// another meaning for it.
///
/// ```
/// use inwx_client::rpc::{classify_code, ResultCode};
///
/// assert_eq!(classify_code(1000), Some(ResultCode::Success));
/// assert_eq!(classify_code(1001), Some(ResultCode::Pending));
/// assert_eq!(classify_code(1301), Some(ResultCode::Queued));
/// assert_eq!(classify_code(1500), Some(ResultCode::Success));
/// assert_eq!(classify_code(1501), None);
/// ```
#[must_use]
pub fn classify_code(code: i32) -> Option<ResultCode> {
    match code {
        1000 | 1500 => Some(ResultCode::Success),
        1001 => Some(ResultCode::Pending),
        1300 | 1301 => Some(ResultCode::Queued),
        _ => None,
    }
}

/// Codes the API uses for a command that did not fail outright.
///
/// `1001` is "action pending" (asynchronous registration or transfer), `1300`
/// and `1301` are the message-queue variants of success, and `1500` closes a
/// session successfully. Treating only `1000` as success — as a naive client
/// does — turns a pending registration into an error.
///
/// This predicate only says the code is not an API error. A caller that needs to
/// know whether the command completed should use [`classify_code`].
///
/// ```
/// use inwx_client::rpc;
///
/// assert!(rpc::is_success_code(1000));
/// assert!(rpc::is_success_code(1001));
/// assert!(rpc::is_success_code(1300));
/// assert!(!rpc::is_success_code(2303));
/// ```
#[must_use]
pub fn is_success_code(code: i32) -> bool {
    classify_code(code).is_some()
}

/// One entry of the optional `details` array on an error response.
///
/// ```
/// use inwx_client::rpc::Detail;
///
/// let detail = Detail {
///     code: "PARAM_MISSING".into(),
///     msg: "id is missing".into(),
///     ..Detail::default()
/// };
/// assert_eq!(detail.code, "PARAM_MISSING");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detail {
    /// Short machine readable code.
    #[serde(default)]
    pub code: String,
    /// Human readable explanation.
    #[serde(default)]
    pub msg: String,
    /// Additional fields returned by the API.
    ///
    /// Kept so a permissively parsed response survives a serialize/parse round
    /// trip even when the API adds a new detail member.
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
}

/// A JSON-RPC request.
///
/// Parameters are a `serde_json::Map`, so the caller decides the shape; the
/// typed builders in [`crate::domain`], [`crate::record`], [`crate::contact`]
/// and [`crate::price`] all end up here.
///
/// ```
/// use inwx_client::rpc::RpcRequest;
///
/// let request = RpcRequest::new("account.check", &serde_json::json!({}))?;
/// let bytes = request.to_bytes()?;
/// assert_eq!(
///     String::from_utf8(bytes).unwrap(),
///     r#"{"method":"account.check","params":{}}"#
/// );
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct RpcRequest {
    /// Method name, for example `nameserver.createRecord`.
    pub method: String,
    /// Method parameters; the API documents one object per method.
    pub params: Map<String, Value>,
}

/// The error a non-object `params` produces.
///
/// One message for both entry points — [`RpcRequest::new`] and
/// [`crate::InwxClient::call`] — so a caller cannot tell which layer refused,
/// only that the shape is wrong.
pub(crate) fn not_an_object() -> Error {
    Error::validation(
        "params",
        "must be a JSON object; a method without parameters passes `{}`",
    )
}

impl RpcRequest {
    /// Builds a request from a method name and a JSON object.
    ///
    /// ```
    /// use inwx_client::rpc::RpcRequest;
    ///
    /// let params = serde_json::json!({"domain": ["example.com"]});
    /// let request = RpcRequest::new("domain.check", &params)?;
    /// assert_eq!(request.params["domain"][0], "example.com");
    /// // `params` is borrowed, so the caller keeps its object.
    /// assert_eq!(params["domain"][0], "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `params` is not a JSON object — `null`, an
    /// array, a string, a number. The API takes one object per method, so any
    /// other shape would arrive as an empty parameter set: a mutation whose
    /// fields are all optional would go out with nothing set, and a listing
    /// without its required filter would fail server-side in a way that looks
    /// like an API problem. A method that takes no parameters passes `{}`.
    ///
    /// ```
    /// use inwx_client::rpc::RpcRequest;
    ///
    /// // Just inside: an object, empty or not, is the documented shape.
    /// assert!(RpcRequest::new("account.logout", &serde_json::json!({})).is_ok());
    ///
    /// // Just outside: `null` is not an object.
    /// let error = RpcRequest::new("account.logout", &serde_json::Value::Null).unwrap_err();
    /// assert!(error.is_validation());
    /// ```
    pub fn new(method: impl Into<String>, params: &Value) -> Result<Self> {
        match params {
            Value::Object(map) => Ok(Self {
                method: method.into(),
                params: map.clone(),
            }),
            _ => Err(not_an_object()),
        }
    }

    /// Builds a request from a parameter map that is already an object.
    ///
    /// Used by the client's request path, which holds the map itself and would
    /// otherwise have to wrap it in a [`Value`] only to unpack it again.
    #[must_use]
    pub(crate) fn from_map(method: impl Into<String>, params: Map<String, Value>) -> Self {
        Self {
            method: method.into(),
            params,
        }
    }

    /// Serialises the envelope.
    ///
    /// # Errors
    ///
    /// [`Error::Json`] in the (unreachable) case that the value cannot be
    /// serialised.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(Error::from)
    }
}

/// A JSON-RPC response, parsed permissively.
///
/// Every field is optional on the wire: errors carry `reasonCode`/`reason`,
/// successes carry `resData`, and a `nameserver.createRecord` answer has neither
/// `svTRID` nor `runtime`. Unknown fields are kept in [`extra`](Self::extra), so
/// a new API field never breaks parsing and does not disappear if the response
/// is serialized again.
///
/// ```
/// use inwx_client::RpcResponse;
///
/// let response = RpcResponse::parse(
///     br#"{"code":1000,"msg":"Command completed successfully","resData":{"id":42},"runtime":0.05}"#,
/// )?;
/// assert!(response.is_success());
/// assert_eq!(response.into_result()?["id"], 42);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct RpcResponse {
    /// Result code; `None` when the field was absent or unusable.
    #[serde(default, deserialize_with = "de::opt_i32")]
    pub code: Option<i32>,
    /// Result message, for example `Command completed successfully`.
    ///
    /// A `null` or absent value becomes an empty string.
    #[serde(default, deserialize_with = "de::string_with_default")]
    pub msg: String,
    /// Short machine readable error tag, for example `MISSING_ID`.
    #[serde(default, rename = "reasonCode", deserialize_with = "de::opt_string")]
    pub reason_code: Option<String>,
    /// Longer error explanation.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub reason: Option<String>,
    /// Payload of a successful command.
    #[serde(default, rename = "resData")]
    pub res_data: Option<Value>,
    /// Server transaction id, useful in support requests.
    #[serde(default, rename = "svTRID", deserialize_with = "de::opt_string")]
    pub sv_trid: Option<String>,
    /// Server-side runtime in seconds.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub runtime: Option<f64>,
    /// Per-parameter error details.
    ///
    /// A `null` or absent value becomes an empty list.
    #[serde(default, deserialize_with = "de::rows")]
    pub details: Vec<Detail>,
    /// Additional fields returned by the API.
    ///
    /// Kept so a permissively parsed response survives a serialize/parse round
    /// trip even when the API adds a new envelope member.
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
}

impl RpcResponse {
    /// Parses a response body.
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the bytes are not a JSON object of the expected
    /// shape, or when the envelope states `code` or `resData` more than once.
    /// The original `serde_json` error stays available as `source`.
    ///
    /// This function cannot know whether a request preceded `bytes`, so an
    /// unreadable body is reported as a decode failure. Code that parses the
    /// answer to a request it has already sent must not use that classification
    /// to conclude the command never ran: the client re-classifies that case and
    /// answers [`Error::Undecodable`] for exactly that reason — the command may
    /// have been executed.
    ///
    /// ```
    /// use inwx_client::RpcResponse;
    ///
    /// let err = RpcResponse::parse(b"<html>502 Bad Gateway</html>").unwrap_err();
    /// assert!(matches!(err, inwx_client::Error::Json { .. }));
    /// ```
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(Error::from)
    }

    /// Parses the body of an answer to a request that had already been written.
    ///
    /// The framing rules are [`parse`](Self::parse)'s. The difference is what a
    /// failure means: here the request is known to have left the process, so a
    /// body that cannot be read is [`Error::Undecodable`] — the command may
    /// already have run — instead of the local decode failure
    /// [`Error::Json`]. Both keep the `serde_json` error as `source`.
    pub(crate) fn parse_answer(bytes: &[u8]) -> Result<Self> {
        Self::parse(bytes).map_err(|error| match error {
            Error::Json { source } => Error::Undecodable { source },
            other => other,
        })
    }

    /// Whether the code is one of the documented non-error codes.
    ///
    /// This is deliberately wider than "completed": [`classify_code`] says
    /// whether a code is [`ResultCode::Success`], [`ResultCode::Pending`] or
    /// [`ResultCode::Queued`].
    ///
    /// ```
    /// use inwx_client::rpc::{classify_code, ResultCode};
    /// use inwx_client::RpcResponse;
    ///
    /// let pending = RpcResponse::parse(br#"{"code":1001,"msg":"pending"}"#)?;
    /// assert!(pending.is_success());
    /// assert_eq!(
    ///     pending.code.and_then(classify_code),
    ///     Some(ResultCode::Pending)
    /// );
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.code.is_some_and(is_success_code)
    }

    /// `msg` plus `reason`, when the API sent one.
    ///
    /// ```
    /// use inwx_client::RpcResponse;
    ///
    /// let response = RpcResponse::parse(
    ///     br#"{"code":2003,"msg":"Required parameter missing","reason":"id"}"#,
    /// )?;
    /// assert_eq!(response.error_message(), "Required parameter missing: id");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn error_message(&self) -> String {
        match &self.reason {
            Some(reason) if !reason.is_empty() => format!("{}: {reason}", self.msg),
            _ => self.msg.clone(),
        }
    }

    /// Whether the code is a rejected session (`2200`, `2201`, `2202`).
    ///
    /// The client uses this to decide whether one re-login is worth trying.
    ///
    /// ```
    /// use inwx_client::RpcResponse;
    ///
    /// let expired = RpcResponse::parse(br#"{"code":2200,"msg":"Authentication error"}"#)?;
    /// assert!(expired.is_authentication());
    /// assert!(!expired.is_success());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn is_authentication(&self) -> bool {
        self.code.is_some_and(|code| matches!(code, 2200..=2202))
    }

    /// Turns the envelope into `resData`, or into the matching [`Error`].
    ///
    /// ```
    /// use inwx_client::{Error, RpcResponse};
    ///
    /// let response = RpcResponse::parse(br#"{"code":1000,"msg":"ok"}"#)?;
    /// assert!(response.into_result()?.is_null());
    ///
    /// let pending = RpcResponse::parse(
    ///     br#"{"code":1001,"msg":"action pending","svTRID":"trid-1"}"#,
    /// )?;
    /// assert!(matches!(
    ///     pending.into_result(),
    ///     Err(Error::Pending {
    ///         code: 1001,
    ///         sv_trid: Some(ref trid),
    ///         ..
    ///     }) if trid == "trid-1"
    /// ));
    ///
    /// let failure = RpcResponse::parse(br#"{"code":2200,"msg":"Authentication error"}"#)?;
    /// assert!(matches!(
    ///     failure.into_result(),
    ///     Err(Error::Api { code: 2200, .. })
    /// ));
    ///
    /// let malformed = RpcResponse::parse(br#"{"msg":"no code"}"#)?;
    /// assert!(matches!(malformed.into_result(), Err(Error::Uncertain { .. })));
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Pending`] for an accepted but not completed command, carrying
    /// the `svTRID` when the API sent one. [`Error::Api`] for a rejected
    /// command, or [`Error::Uncertain`] when the response does not carry a
    /// usable result code.
    pub fn into_result(self) -> Result<Value> {
        match self.code {
            Some(code) => match classify_code(code) {
                Some(ResultCode::Success) => Ok(self.res_data.unwrap_or(Value::Null)),
                Some(ResultCode::Pending | ResultCode::Queued) => Err(Error::Pending {
                    code,
                    message: self.error_message(),
                    sv_trid: self.sv_trid,
                }),
                None => Err(Error::Api {
                    code,
                    message: self.error_message(),
                    reason_code: self.reason_code,
                    reason: self.reason,
                    details: self.details,
                }),
            },
            None => Err(Error::uncertain(
                "response envelope carried no usable result code; the command may have been executed",
            )),
        }
    }
}

impl<'de> Deserialize<'de> for RpcResponse {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RpcResponseVisitor)
    }
}

struct RpcResponseVisitor;

impl<'de> Visitor<'de> for RpcResponseVisitor {
    type Value = RpcResponse;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a map of JSON-RPC response fields")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut response = RpcResponse {
            code: None,
            msg: String::new(),
            reason_code: None,
            reason: None,
            res_data: None,
            sv_trid: None,
            runtime: None,
            details: Vec::new(),
            extra: Map::new(),
        };
        let mut code_seen = false;
        let mut msg_seen = false;
        let mut reason_code_seen = false;
        let mut reason_seen = false;
        let mut res_data_seen = false;
        let mut sv_trid_seen = false;
        let mut runtime_seen = false;
        let mut details_seen = false;

        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value::<Value>()?;
            match key.as_str() {
                "code" => {
                    if code_seen {
                        return Err(A::Error::custom("duplicate field `code`"));
                    }
                    code_seen = true;
                    response.code = de::opt_i32(value).map_err(A::Error::custom)?;
                }
                "msg" => {
                    if msg_seen {
                        return Err(A::Error::custom("duplicate field `msg`"));
                    }
                    msg_seen = true;
                    response.msg = de::string_with_default(value).map_err(A::Error::custom)?;
                }
                "reasonCode" => {
                    if reason_code_seen {
                        return Err(A::Error::custom("duplicate field `reasonCode`"));
                    }
                    reason_code_seen = true;
                    response.reason_code = de::opt_string(value).map_err(A::Error::custom)?;
                }
                "reason" => {
                    if reason_seen {
                        return Err(A::Error::custom("duplicate field `reason`"));
                    }
                    reason_seen = true;
                    response.reason = de::opt_string(value).map_err(A::Error::custom)?;
                }
                "resData" => {
                    if res_data_seen {
                        return Err(A::Error::custom("duplicate field `resData`"));
                    }
                    res_data_seen = true;
                    response.res_data = match value {
                        Value::Null => None,
                        value => Some(value),
                    };
                }
                "svTRID" => {
                    if sv_trid_seen {
                        return Err(A::Error::custom("duplicate field `svTRID`"));
                    }
                    sv_trid_seen = true;
                    response.sv_trid = de::opt_string(value).map_err(A::Error::custom)?;
                }
                "runtime" => {
                    if runtime_seen {
                        return Err(A::Error::custom("duplicate field `runtime`"));
                    }
                    runtime_seen = true;
                    response.runtime = de::opt_f64(value).map_err(A::Error::custom)?;
                }
                "details" => {
                    if details_seen {
                        return Err(A::Error::custom("duplicate field `details`"));
                    }
                    details_seen = true;
                    response.details = de::rows::<Detail, _>(value).map_err(A::Error::custom)?;
                }
                _ => {
                    response.extra.insert(key, value);
                }
            }
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unknown_fields_are_kept() {
        let response = RpcResponse::parse(
            br#"{"code":1000,"msg":"ok","brandNewField":{"a":1},"resData":{"id":"7"}}"#,
        )
        .unwrap();
        assert!(response.is_success());
        assert_eq!(response.extra["brandNewField"]["a"], 1);
        assert_eq!(response.into_result().unwrap()["id"], "7");
    }

    #[test]
    fn unknown_fields_survive_a_round_trip() {
        let body = br#"{"code":2003,"msg":"Required parameter missing","reason":"id","svTRID":"abc","vendorField":{"nested":[1,2,3]},"details":[{"code":"PARAM_MISSING","msg":"id","vendor":"detail extra","detailField":{"x":true}}]}"#;
        let response = RpcResponse::parse(body).unwrap();
        let original = serde_json::from_slice::<Value>(body).unwrap();

        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["vendorField"], original["vendorField"]);
        assert_eq!(
            value["details"][0]["vendor"],
            original["details"][0]["vendor"]
        );
        assert_eq!(
            value["details"][0]["detailField"],
            original["details"][0]["detailField"]
        );
    }

    #[test]
    fn duplicate_code_is_rejected_in_either_order() {
        for body in [
            br#"{"code":2303,"msg":"not found","code":1000}"#.as_slice(),
            br#"{"code":1000,"msg":"not found","code":2303}"#.as_slice(),
        ] {
            let label = String::from_utf8_lossy(body);
            let public = RpcResponse::parse(body).unwrap_err();
            let answered = RpcResponse::parse_answer(body).unwrap_err();

            assert!(matches!(public, Error::Json { .. }), "{label}");
            assert!(!public.is_uncertain(), "{label}");
            assert!(answered.is_uncertain(), "{label}");
            assert!(!answered.is_retryable(), "{label}");
        }
    }

    #[test]
    fn duplicate_res_data_is_rejected_in_either_order() {
        for body in [
            br#"{"code":1000,"resData":{"id":1},"resData":{"id":2}}"#.as_slice(),
            br#"{"resData":{"id":2},"resData":{"id":1},"code":1000}"#.as_slice(),
        ] {
            assert!(matches!(RpcResponse::parse(body), Err(Error::Json { .. })));
        }
    }

    #[test]
    fn missing_code_is_uncertain_and_not_api() {
        let response = RpcResponse::parse(br#"{"msg":"?"}"#).unwrap();
        assert_eq!(response.code, None);
        assert!(!response.is_success());
        let error = response.into_result().unwrap_err();
        assert!(matches!(error, Error::Uncertain { .. }));
        assert!(error.is_uncertain());
        assert!(!error.is_retryable());
        assert_eq!(error.code(), None);
    }

    #[test]
    fn unusable_codes_are_uncertain_and_not_api() {
        for body in [
            br#"{"code":null,"msg":"?"}"#.as_slice(),
            br#"{"code":true,"msg":"?"}"#.as_slice(),
            br#"{"code":{},"msg":"?"}"#.as_slice(),
            br#"{"code":1000.0,"msg":"?"}"#.as_slice(),
            br#"{"code":2147483648,"msg":"?"}"#.as_slice(),
            br#"{"code":-2147483649,"msg":"?"}"#.as_slice(),
            br#"{"code":"not a number","msg":"?"}"#.as_slice(),
        ] {
            let response = RpcResponse::parse(body).unwrap();
            assert_eq!(response.code, None, "{}", String::from_utf8_lossy(body));

            let error = response.into_result().unwrap_err();
            assert!(matches!(error, Error::Uncertain { .. }));
            assert!(error.is_uncertain());
            assert!(!error.is_retryable());
            assert_eq!(error.code(), None);
        }
    }

    #[test]
    fn code_boundaries_keep_the_nearest_representable_values() {
        let inside = RpcResponse::parse(br#"{"code":2147483647,"msg":"?"}"#).unwrap();
        assert_eq!(inside.code, Some(i32::MAX));
        assert!(matches!(
            inside.into_result(),
            Err(Error::Api { code: i32::MAX, .. })
        ));

        let outside = RpcResponse::parse(br#"{"code":2147483648,"msg":"?"}"#).unwrap();
        assert_eq!(outside.code, None);
        assert!(matches!(
            outside.into_result(),
            Err(Error::Uncertain { .. })
        ));
    }

    #[test]
    fn null_msg_and_details_are_permissive_on_success() {
        let response = RpcResponse::parse(
            br#"{"code":1000,"msg":null,"details":null,"resData":{"id":7},"svTRID":"abc"}"#,
        )
        .unwrap();

        assert_eq!(response.msg, "");
        assert_eq!(response.details, [] as [Detail; 0]);
        assert_eq!(response.sv_trid.as_deref(), Some("abc"));
        assert_eq!(response.into_result().unwrap()["id"], 7);
    }

    #[test]
    fn null_msg_and_details_are_permissive_on_error() {
        let response = RpcResponse::parse(
            br#"{"code":2303,"msg":null,"reasonCode":"PENDING","reason":"later","details":null,"svTRID":"abc"}"#,
        )
        .unwrap();

        assert_eq!(response.msg, "");
        assert_eq!(response.details, [] as [Detail; 0]);
        assert_eq!(response.sv_trid.as_deref(), Some("abc"));
        assert!(matches!(
            response.into_result(),
            Err(Error::Api {
                code: 2303,
                reason_code: Some(reason_code),
                reason: Some(reason),
                details,
                ..
            }) if reason_code == "PENDING" && reason == "later" && details.is_empty()
        ));
    }

    #[test]
    fn a_request_without_params_is_built_from_an_empty_object() {
        let request = RpcRequest::new("account.logout", &json!({})).unwrap();
        assert!(request.params.is_empty());
        assert_eq!(
            std::str::from_utf8(&request.to_bytes().unwrap()).unwrap(),
            r#"{"method":"account.logout","params":{}}"#
        );
    }

    #[test]
    fn a_non_object_request_params_is_refused() {
        // Just inside: an object with one field keeps that field.
        let inside = RpcRequest::new("domain.info", &json!({"domain": "example.com"})).unwrap();
        assert_eq!(inside.params.len(), 1);

        // Just outside: every non-object shape is a validation error, not an
        // empty parameter set that would drop the caller's payload.
        for params in [
            Value::Null,
            json!([]),
            json!([1, 2, 3]),
            json!("domain"),
            json!(7),
            json!(true),
        ] {
            let error = RpcRequest::new("domain.info", &params).unwrap_err();
            assert!(error.is_validation(), "{params} should be refused");
            assert!(error.to_string().contains("params"), "{error}");
            assert!(
                error.to_string().contains("JSON object"),
                "the message names the expected shape: {error}"
            );
        }
    }

    #[test]
    fn scalar_shapes_are_accepted() {
        let response =
            RpcResponse::parse(br#"{"code":"1000","svTRID":12345,"runtime":"0.25"}"#).unwrap();
        // The API sends the code as a number, but a string is tolerated the
        // same way every other scalar is.
        assert_eq!(response.code, Some(1000));
        assert!(response.is_success());
        assert_eq!(response.sv_trid.as_deref(), Some("12345"));
        assert_eq!(response.runtime, Some(0.25));
    }

    #[test]
    fn every_documented_non_error_code_is_classified() {
        for code in [1000, 1001, 1300, 1301, 1500] {
            assert!(is_success_code(code), "{code}");
            assert!(classify_code(code).is_some(), "{code}");
        }
        for code in [0, 1200, 2003, 2200, 2303] {
            assert!(!is_success_code(code), "{code}");
            assert_eq!(classify_code(code), None, "{code}");
        }

        assert_eq!(classify_code(1000), Some(ResultCode::Success));
        assert_eq!(classify_code(1500), Some(ResultCode::Success));
        assert_eq!(classify_code(1001), Some(ResultCode::Pending));
        assert_eq!(classify_code(1300), Some(ResultCode::Queued));
        assert_eq!(classify_code(1301), Some(ResultCode::Queued));
    }

    #[test]
    fn pending_and_queued_codes_are_typed_not_plain_success() {
        for (code, expected_trid) in [(1001, "trid-1"), (1300, "trid-2"), (1301, "trid-3")] {
            let body = format!(
                r#"{{"code":{code},"msg":"accepted","reasonCode":"QUEUED","reason":"later","svTRID":"{expected_trid}","resData":{{"roId":42}}}}"#
            );
            let response = RpcResponse::parse(body.as_bytes()).unwrap();
            assert!(response.is_success(), "{code}");

            let error = response.into_result().unwrap_err();
            assert!(matches!(
                error,
                Error::Pending {
                    code: actual,
                    sv_trid: Some(ref trid),
                    ..
                } if actual == code && trid == expected_trid
            ));
            assert_eq!(error.code(), Some(code));
            assert!(!error.is_retryable());
            assert!(!error.is_uncertain());
            assert!(!error.is_authentication());
        }
    }

    #[test]
    fn completed_codes_still_return_payload_or_null() {
        let with_payload =
            RpcResponse::parse(br#"{"code":1000,"msg":"ok","resData":{"id":7},"svTRID":"trid-1"}"#)
                .unwrap();
        assert_eq!(with_payload.into_result().unwrap()["id"], 7);

        let no_payload = RpcResponse::parse(br#"{"code":1500,"msg":"logout"}"#).unwrap();
        assert!(no_payload.into_result().unwrap().is_null());
    }

    #[test]
    fn codes_just_outside_the_pending_classes_are_api_errors() {
        for code in [1002, 1299, 1302, 1501] {
            let body = format!(r#"{{"code":{code},"msg":"boom"}}"#);
            let response = RpcResponse::parse(body.as_bytes()).unwrap();
            assert!(!response.is_success(), "{code}");
            assert!(matches!(
                response.into_result(),
                Err(Error::Api { code: actual, .. }) if actual == code
            ));
        }
    }

    /// A body the client cannot read after its request has gone out is an
    /// `Undecodable` answer — the outcome is unknown — while the public parser,
    /// which cannot know whether a request preceded the bytes, keeps reporting
    /// the local decode failure.
    #[test]
    fn an_unreadable_answer_after_a_write_is_undecodable() {
        for body in [
            b"<html>502 Bad Gateway</html>".as_slice(),
            b"".as_slice(),
            b"   ".as_slice(),
            b"[1,2,3]".as_slice(),
            br#"{"code":1000,"msg":"ok""#.as_slice(),
        ] {
            let label = String::from_utf8_lossy(body);
            let public = RpcResponse::parse(body).unwrap_err();
            let answered = RpcResponse::parse_answer(body).unwrap_err();

            assert!(matches!(public, Error::Json { .. }), "{label}");
            assert!(!public.is_uncertain(), "{label}");
            assert!(answered.is_uncertain(), "{label}");
            assert!(!answered.is_retryable(), "{label}");
            assert!(
                std::error::Error::source(&answered).is_some(),
                "{label}: the parser error stays the cause"
            );
        }
    }

    /// The classification moves the failure only, never the success. Edge pair:
    /// the smallest readable envelope, and the same document one brace short of
    /// it.
    #[test]
    fn a_readable_answer_is_parsed_the_same_way_after_a_write() {
        let readable = br#"{"code":1000}"#;
        assert_eq!(
            RpcResponse::parse_answer(readable).unwrap().code,
            Some(CODE_SUCCESS)
        );
        assert_eq!(
            RpcResponse::parse(readable).unwrap().code,
            Some(CODE_SUCCESS)
        );

        let cut = br#"{"code":1000"#;
        assert!(RpcResponse::parse(cut).is_err());
        assert!(RpcResponse::parse_answer(cut).is_err());
    }
}
