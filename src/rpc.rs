//! JSON-RPC framing: the request envelope and the response envelope.
//!
//! INWX speaks a small, unversioned dialect of JSON-RPC: a `method` plus a
//! `params` object goes out, a `code` plus an optional `resData` comes back,
//! and **transport success is not command success** — a rejected command is
//! still HTTP 200 with a non-`1000` code. [`RpcResponse::into_result`] is the
//! single place that distinction is made.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::types::de;

/// Result code for "command completed successfully".
pub const CODE_SUCCESS: i32 = 1000;

/// Codes the API uses for a command that did not fail outright.
///
/// `1001` is "action pending" (asynchronous registration or transfer), `1300`
/// and `1301` are the message-queue variants of success, and `1500` closes a
/// session successfully. Treating only `1000` as success — as a naive client
/// does — turns a pending registration into an error.
///
/// ```
/// use inwx_client::rpc;
///
/// assert!(rpc::is_success_code(1000));
/// assert!(rpc::is_success_code(1001));
/// assert!(!rpc::is_success_code(2303));
/// ```
#[must_use]
pub fn is_success_code(code: i32) -> bool {
    matches!(code, 1000 | 1001 | 1300 | 1301 | 1500)
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    /// Result code; `0` when the field was absent (a malformed answer).
    #[serde(default, deserialize_with = "de::i32_with_default")]
    pub code: i32,
    /// Result message, for example `Command completed successfully`.
    #[serde(default)]
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
    #[serde(default)]
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
    /// shape. The original `serde_json` error stays available as `source`.
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
        // `serde` happily fills a struct from a JSON *array* (fields in order),
        // which would turn `[]` into "code 0, message empty" instead of an
        // error. Parsing the object first keeps that accident out.
        let object: Map<String, Value> = serde_json::from_slice(bytes).map_err(Error::from)?;
        serde_json::from_value(Value::Object(object)).map_err(Error::from)
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

    /// Whether the code is one of the documented success codes.
    ///
    /// ```
    /// use inwx_client::RpcResponse;
    ///
    /// let pending = RpcResponse::parse(br#"{"code":1001,"msg":"pending"}"#)?;
    /// assert!(pending.is_success());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn is_success(&self) -> bool {
        is_success_code(self.code)
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
        matches!(self.code, 2200..=2202)
    }

    /// Turns the envelope into `resData`, or into the matching [`Error`].
    ///
    /// ```
    /// use inwx_client::{Error, RpcResponse};
    ///
    /// let response = RpcResponse::parse(br#"{"code":1000,"msg":"ok"}"#)?;
    /// assert!(response.into_result()?.is_null());
    ///
    /// let failure = RpcResponse::parse(br#"{"code":2200,"msg":"Authentication error"}"#)?;
    /// assert!(matches!(
    ///     failure.into_result(),
    ///     Err(Error::Api { code: 2200, .. })
    /// ));
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Api`] for a non-success code.
    pub fn into_result(self) -> Result<Value> {
        if self.is_success() {
            Ok(self.res_data.unwrap_or(Value::Null))
        } else {
            Err(Error::Api {
                code: self.code,
                message: self.error_message(),
                reason_code: self.reason_code,
                reason: self.reason,
                details: self.details,
            })
        }
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
    fn missing_code_is_zero_and_not_success() {
        let response = RpcResponse::parse(br#"{"msg":"?"}"#).unwrap();
        assert_eq!(response.code, 0);
        assert!(!response.is_success());
        assert!(matches!(
            response.into_result(),
            Err(Error::Api { code: 0, .. })
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
        assert_eq!(response.code, 1000);
        assert!(response.is_success());
        assert_eq!(response.sv_trid.as_deref(), Some("12345"));
        assert_eq!(response.runtime, Some(0.25));
    }

    #[test]
    fn every_documented_success_code_is_success() {
        for code in [1000, 1001, 1300, 1301, 1500] {
            assert!(is_success_code(code), "{code}");
        }
        for code in [0, 1200, 2003, 2200, 2303] {
            assert!(!is_success_code(code), "{code}");
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
            CODE_SUCCESS
        );
        assert_eq!(RpcResponse::parse(readable).unwrap().code, CODE_SUCCESS);

        let cut = br#"{"code":1000"#;
        assert!(RpcResponse::parse(cut).is_err());
        assert!(RpcResponse::parse_answer(cut).is_err());
    }
}
