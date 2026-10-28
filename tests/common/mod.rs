//! Shared recording transport for the integration tests.
//!
//! Every request is captured — URL, method, params, headers — and replies come
//! from a scripted queue, so a test can assert both what the client sent and how
//! it reacted to a sequence of statuses. Nothing here opens a socket.

#![allow(dead_code)]
// `ok(json!({...}))` reads better than `ok(&json!({...}))`; the helpers copy the
// value into the scripted queue anyway.
#![allow(clippy::needless_pass_by_value)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use inwx_client::transport::{Request, Response, Transport};
use inwx_client::{Error, InwxClient, Result};
use serde_json::{json, Value};

/// One recorded call.
#[derive(Clone, Debug)]
pub struct Call {
    /// Endpoint the client posted to.
    pub url: String,
    /// JSON-RPC method from the body.
    pub method: String,
    /// JSON-RPC params from the body.
    pub params: Value,
    /// Request headers, in the order the client set them.
    pub headers: Vec<(String, String)>,
}

impl Call {
    /// A header value, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A scripted reply.
#[derive(Clone)]
pub enum Reply {
    /// A 200 with this body.
    Body(String),
    /// A 200 with `Set-Cookie` headers and a success envelope.
    Login {
        /// The cookie pair, for example `domrobot=abc`.
        cookie: String,
    },
    /// A full response, status and all.
    Response(Response),
    /// A transport-level failure.
    Failure {
        /// Message for [`Error::Transport`].
        message: String,
        /// Whether a retry could help.
        retryable: bool,
    },
    /// The request was written and the answer never arrived.
    Uncertain {
        /// Message for [`Error::Uncertain`].
        message: String,
    },
}

/// Records calls and replays scripted replies.
///
/// When the queue runs dry every call answers `{"code":1000,"msg":"ok"}`, so
/// tests that do not care about a response can stay short.
#[derive(Clone, Default)]
pub struct MockTransport {
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    calls: Vec<Call>,
    queue: VecDeque<Reply>,
}

impl MockTransport {
    /// An empty transport.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues a reply.
    pub fn push(&self, reply: Reply) {
        self.state.lock().unwrap().queue.push_back(reply);
    }

    /// Queues a `200` with a success envelope carrying `data` as `resData`.
    pub fn ok(&self, data: Value) {
        self.push(Reply::Body(
            json!({ "code": 1000, "msg": "Command completed successfully", "resData": data })
                .to_string(),
        ));
    }

    /// Queues a `200` with a success envelope and no `resData`.
    pub fn ok_empty(&self) {
        self.push(Reply::Body(
            json!({ "code": 1000, "msg": "Command completed successfully" }).to_string(),
        ));
    }

    /// Queues an API error envelope (still HTTP 200).
    pub fn api_error(&self, code: i32, message: &str) {
        self.push(Reply::Body(
            json!({ "code": code, "msg": message }).to_string(),
        ));
    }

    /// Queues a login that sets `cookie`.
    pub fn login(&self, cookie: &str) {
        self.push(Reply::Login {
            cookie: cookie.to_owned(),
        });
    }

    /// Queues an HTTP status with `body`.
    pub fn status(&self, status: u16, body: &str) {
        self.push(Reply::Response(Response::new(
            status,
            std::iter::empty(),
            body.as_bytes().to_vec(),
        )));
    }

    /// Queues a retryable transport failure.
    pub fn transport_failure(&self, message: &str) {
        self.push(Reply::Failure {
            message: message.to_owned(),
            retryable: true,
        });
    }

    /// Queues a terminal transport failure.
    pub fn terminal_failure(&self, message: &str) {
        self.push(Reply::Failure {
            message: message.to_owned(),
            retryable: false,
        });
    }

    /// Queues a failure that happened after the request was written.
    pub fn uncertain_failure(&self, message: &str) {
        self.push(Reply::Uncertain {
            message: message.to_owned(),
        });
    }

    /// Every recorded call.
    pub fn calls(&self) -> Vec<Call> {
        self.state.lock().unwrap().calls.clone()
    }

    /// Number of recorded calls.
    pub fn call_count(&self) -> usize {
        self.state.lock().unwrap().calls.len()
    }

    /// The single recorded call; panics unless there is exactly one.
    pub fn only_call(&self) -> Call {
        let calls = self.calls();
        assert_eq!(calls.len(), 1, "expected one call, got {calls:#?}");
        calls.into_iter().next().unwrap()
    }
}

impl Transport for MockTransport {
    async fn execute(&self, request: Request<'_>) -> Result<Response> {
        // Keep this a real coroutine: the trait method is `async`.
        std::future::ready(()).await;

        let body: Value = serde_json::from_slice(request.body).unwrap_or(Value::Null);
        let call = Call {
            url: request.url.to_owned(),
            method: body
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            params: body.get("params").cloned().unwrap_or(Value::Null),
            headers: request.headers.clone(),
        };

        let reply = {
            let mut state = self.state.lock().unwrap();
            state.calls.push(call);
            state.queue.pop_front()
        };

        match reply {
            Some(Reply::Body(body)) => Ok(json_response(&body)),
            Some(Reply::Login { cookie }) => Ok(Response::new(
                200,
                [(
                    "Set-Cookie".to_owned(),
                    format!("{cookie}; Path=/; HttpOnly; Secure"),
                )],
                br#"{"code":1000,"msg":"Login successful","resData":{"accountId":61140}}"#.to_vec(),
            )),
            Some(Reply::Response(response)) => Ok(response),
            Some(Reply::Failure { message, retryable }) => Err(if retryable {
                Error::transport(message)
            } else {
                Error::Transport {
                    message,
                    retryable: false,
                }
            }),
            Some(Reply::Uncertain { message }) => Err(Error::uncertain(message)),
            None => Ok(json_response(r#"{"code":1000,"msg":"ok"}"#)),
        }
    }
}

/// A `200 application/json` response with `body`.
pub fn json_response(body: &str) -> Response {
    Response::new(
        200,
        [("content-type".to_owned(), "application/json".to_owned())],
        body.as_bytes().to_vec(),
    )
}

/// A client with a session cookie, so tests about commands need no login step.
pub fn client(transport: MockTransport) -> InwxClient<MockTransport> {
    InwxClient::new(transport)
        .with_session("domrobot=test-session")
        .expect("test cookie is valid")
        .with_base_url("https://inwx.test/jsonrpc/")
        .with_retry(no_wait())
}

/// A client with credentials and no session: the first call logs in.
pub fn anonymous_client(transport: MockTransport) -> InwxClient<MockTransport> {
    InwxClient::new(transport)
        .with_credentials("test-user", "test-pass")
        .expect("test credentials are valid")
        .with_base_url("https://inwx.test/jsonrpc/")
        .with_retry(no_wait())
}

/// Three attempts that do not sleep, so retry tests stay fast.
pub fn no_wait() -> inwx_client::RetryPolicy {
    inwx_client::RetryPolicy::new(3)
        .with_base_delay(std::time::Duration::ZERO)
        .with_max_delay(std::time::Duration::ZERO)
}

/// A client with retries disabled, so a failure surfaces immediately.
pub fn client_without_retries(transport: MockTransport) -> InwxClient<MockTransport> {
    client(transport).with_retry(inwx_client::RetryPolicy::new(1))
}
