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
/// let detail = Detail { code: "PARAM_MISSING".into(), msg: "id is missing".into() };
/// assert_eq!(detail.code, "PARAM_MISSING");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detail {
    /// Short machine readable code.
    #[serde(default)]
    pub code: String,
    /// Human readable explanation.
    #[serde(default)]
    pub msg: String,
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
/// let request = RpcRequest::new("account.check", &serde_json::json!({}));
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

impl RpcRequest {
    /// Builds a request from a method name and any JSON value that is an
    /// object.
    ///
    /// ```
    /// use inwx_client::rpc::RpcRequest;
    ///
    /// let request = RpcRequest::new("domain.check", &serde_json::json!({"domain": ["example.com"]}));
    /// assert_eq!(request.params["domain"][0], "example.com");
    /// ```
    ///
    /// A non-object `params` is treated as empty rather than rejected: the
    /// methods that take no parameters (`account.logout`) are called with
    /// `null` often enough that panicking would be unkind.
    #[must_use]
    pub fn new(method: impl Into<String>, params: &Value) -> Self {
        Self {
            method: method.into(),
            params: params.as_object().cloned().unwrap_or_default(),
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
/// `svTRID` nor `runtime`. Unknown fields are ignored, so a new API field never
/// breaks parsing.
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
}

impl RpcResponse {
    /// Parses a response body.
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the bytes are not a JSON object of the expected
    /// shape. The original `serde_json` error stays available as `source`.
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

    #[test]
    fn unknown_fields_are_ignored() {
        let response = RpcResponse::parse(
            br#"{"code":1000,"msg":"ok","brandNewField":{"a":1},"resData":{"id":"7"}}"#,
        )
        .unwrap();
        assert!(response.is_success());
        assert_eq!(response.into_result().unwrap()["id"], "7");
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
    fn request_with_non_object_params_is_empty() {
        let request = RpcRequest::new("account.logout", &Value::Null);
        assert!(request.params.is_empty());
        assert_eq!(
            std::str::from_utf8(&request.to_bytes().unwrap()).unwrap(),
            r#"{"method":"account.logout","params":{}}"#
        );
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
}
