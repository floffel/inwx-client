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

use inwx_client::transport::{ChunkSource, Request, Response, Transport};
use inwx_client::{read_capped_body, Error, InwxClient, Result};
use serde_json::{json, Value};

/// Size of the pieces a scripted body is delivered in, so a capped mock crosses
/// a cap the way a socket does: mid-stream, chunk by chunk. Public because a
/// test that asserts how far a capped read got needs the piece size.
pub const CHUNK_LEN: usize = 48;

/// An in-memory [`ChunkSource`] over a scripted body.
pub struct BufferChunks {
    bytes: Vec<u8>,
    position: usize,
}

impl BufferChunks {
    /// Wraps `bytes`.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, position: 0 }
    }
}

impl ChunkSource for BufferChunks {
    type Chunk = Vec<u8>;

    fn next_chunk(&mut self) -> impl std::future::Future<Output = Result<Option<Vec<u8>>>> {
        let end = (self.position + CHUNK_LEN).min(self.bytes.len());
        let chunk = if self.position < self.bytes.len() {
            Some(self.bytes[self.position..end].to_vec())
        } else {
            None
        };
        self.position = end;
        std::future::ready(Ok(chunk))
    }
}

/// Runs a scripted body through the crate's own cap check, so a mock configured
/// with [`MockTransport::with_max_response_bytes`] answers the way a capped
/// transport does: an over-cap body is an error, and none of it is returned.
async fn enforce_cap(response: &Response, limit: Option<u64>) -> Result<()> {
    let Some(limit) = limit else {
        return Ok(());
    };
    let declared = response
        .header("content-length")
        .and_then(|value| value.trim().parse::<u64>().ok());
    let mut source = BufferChunks::new(response.body().to_vec());
    read_capped_body(&mut source, declared, limit)
        .await
        .map(drop)
}

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
    max_response_bytes: Option<u64>,
}

impl MockTransport {
    /// An empty transport.
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers as a transport with a response cap does: a scripted body larger
    /// than `max_response_bytes` comes back as [`Error::ResponseTooLarge`]
    /// instead of as a response.
    #[must_use]
    pub fn with_max_response_bytes(self, max_response_bytes: u64) -> Self {
        self.state.lock().unwrap().max_response_bytes = Some(max_response_bytes);
        self
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

        let response = match reply {
            Some(Reply::Body(body)) => json_response(&body),
            Some(Reply::Login { cookie }) => Response::new(
                200,
                [(
                    "Set-Cookie".to_owned(),
                    format!("{cookie}; Path=/; HttpOnly; Secure"),
                )],
                br#"{"code":1000,"msg":"Login successful","resData":{"accountId":61140}}"#.to_vec(),
            ),
            Some(Reply::Response(response)) => response,
            Some(Reply::Failure { message, retryable }) => {
                return Err(if retryable {
                    Error::transport(message)
                } else {
                    Error::Transport {
                        message,
                        retryable: false,
                    }
                })
            }
            None => json_response(r#"{"code":1000,"msg":"ok"}"#),
        };

        // Copy the limit out first: no lock is held across the await.
        let limit = self.state.lock().unwrap().max_response_bytes;
        enforce_cap(&response, limit).await?;
        Ok(response)
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
