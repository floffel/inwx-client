//! 32 tasks on one client: the session cookie must be shared, every call must
//! reach the transport exactly once, and nothing may deadlock.
//!
//! The session is one state machine (see `src/session.rs`): one `account.login`
//! is on the wire at a time and the callers that lose the race reuse its cookie,
//! so a session that dies under thirty-two tasks costs one login — not
//! thirty-two credential POSTs that invalidate each other.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{anonymous_client, client, MockTransport};
use inwx_client::transport::{Request, Response, Transport};
use inwx_client::{DomainListQuery, DomainName, InwxClient, RecordSpec, RecordType, Result};
use serde_json::{json, Value};

const TASKS: usize = 32;

/// A server that keeps exactly one session, the way INWX does: a login replaces
/// the cookie and invalidates the previous one, a dead cookie is answered with
/// `401`, and every login is a credential POST.
#[derive(Clone)]
struct OneSessionServer {
    state: Arc<Mutex<ServerState>>,
}

#[derive(Default)]
struct ServerState {
    /// The only cookie the server accepts; a login replaces it and kills the
    /// one before, exactly like the API.
    live: Option<String>,
    logins: usize,
}

impl OneSessionServer {
    /// A server whose only valid session is `live`.
    fn new(live: Option<&str>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ServerState {
                live: live.map(str::to_owned),
                logins: 0,
            })),
        }
    }

    fn logins(&self) -> usize {
        self.state.lock().unwrap().logins
    }

    fn live(&self) -> Option<String> {
        self.state.lock().unwrap().live.clone()
    }
}

impl Transport for OneSessionServer {
    async fn execute(&self, request: Request<'_>) -> Result<Response> {
        let body: Value = serde_json::from_slice(request.body).unwrap_or(Value::Null);
        let method = body
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let cookie = request.header("cookie").map(str::to_owned);

        if method == "account.login" {
            // A login is a round trip, not an instant: without the pause the
            // callers would not overlap and the test would pass unchanged.
            tokio::time::sleep(Duration::from_millis(20)).await;
            let mut state = self.state.lock().unwrap();
            state.logins += 1;
            let cookie = format!("domrobot=session-{}", state.logins);
            state.live = Some(cookie.clone());
            return Ok(Response::new(
                200,
                [(
                    "Set-Cookie".to_owned(),
                    format!("{cookie}; Path=/; HttpOnly"),
                )],
                br#"{"code":1000,"msg":"Login successful","resData":{}}"#.to_vec(),
            ));
        }

        let live = self.live();
        if cookie.is_some() && cookie == live {
            Ok(Response::new(
                200,
                [("content-type".to_owned(), "application/json".to_owned())],
                br#"{"code":1000,"msg":"ok","resData":{"domain":[]}}"#.to_vec(),
            ))
        } else {
            // A session the server dropped: the answer that makes callers
            // relogin.
            Ok(Response::new(401, std::iter::empty(), Vec::new()))
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn thirty_two_tasks_share_one_client_with_an_existing_session() {
    let transport = MockTransport::new();
    for index in 0..TASKS {
        transport.ok(json!({
            "record": [
                {"id": index.to_string(), "name": "www", "type": "A", "content": "203.0.113.7"}
            ]
        }));
    }

    let client = Arc::new(client(transport.clone()));
    let domain = Arc::new(DomainName::parse("example.com").unwrap());

    let mut handles = Vec::with_capacity(TASKS);
    for _ in 0..TASKS {
        let client = Arc::clone(&client);
        let domain = Arc::clone(&domain);
        handles.push(tokio::spawn(
            async move { client.list_records(&domain).await },
        ));
    }

    for handle in handles {
        let records = handle.await.unwrap().unwrap();
        assert_eq!(records.len(), 1);
    }

    let calls = transport.calls();
    assert_eq!(calls.len(), TASKS);
    for call in &calls {
        assert_eq!(call.method, "nameserver.info");
        assert_eq!(call.header("cookie"), Some("domrobot=test-session"));
    }
    assert!(client.is_authenticated());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_first_calls_do_not_deadlock_while_logging_in() {
    // One login for all of them: the first caller claims the transition, the
    // rest wait for its cookie. Each extra login would invalidate the cookie
    // the others are about to replay.
    let transport = MockTransport::new();
    // Every reply is a success envelope that also sets a cookie, so any
    // interleaving of login and command replies is valid.
    for _ in 0..(TASKS * 3) {
        transport.login("domrobot=shared");
    }

    let client = Arc::new(anonymous_client(transport.clone()));

    let mut handles = Vec::with_capacity(TASKS);
    for _ in 0..TASKS {
        let client = Arc::clone(&client);
        handles.push(tokio::spawn(async move {
            client.list_domains(&DomainListQuery::default()).await
        }));
    }

    for handle in handles {
        handle.await.unwrap().unwrap();
    }

    assert!(client.is_authenticated());
    let logins = transport
        .calls()
        .iter()
        .filter(|call| call.method == "account.login")
        .count();
    let listings = transport
        .calls()
        .iter()
        .filter(|call| call.method == "domain.list")
        .count();
    assert_eq!(listings, TASKS);
    assert_eq!(logins, 1, "thirty-two tasks must cost one login");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_first_calls_post_credentials_once() {
    // The mock above answers every request with a fresh cookie, so it cannot
    // tell a shared session from thirty-two. This server keeps one: it accepts
    // only the cookie of the newest login.
    let server = OneSessionServer::new(None);
    let client = Arc::new(
        InwxClient::new(server.clone())
            .with_credentials("test-user", "test-pass")
            .unwrap()
            .with_retry(common::no_wait()),
    );

    let mut handles = Vec::with_capacity(TASKS);
    for _ in 0..TASKS {
        let client = Arc::clone(&client);
        handles.push(tokio::spawn(async move {
            client.list_domains(&DomainListQuery::default()).await
        }));
    }

    for handle in handles {
        handle.await.unwrap().unwrap();
    }

    assert_eq!(server.logins(), 1, "thirty-two tasks must cost one login");
    // What is stored has to be what the server accepts: a login that stored the
    // loser's cookie would 401 here and log in a second time.
    client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap();
    assert_eq!(server.logins(), 1);
    assert_eq!(
        server.live(),
        Some("domrobot=session-1".to_owned()),
        "the server must still accept one session"
    );
}

/// An expired session under load: every task sees `401`, and the client must
/// renew it once — not thirty-two times.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn thirty_two_expired_sessions_cost_one_relogin() {
    let server = OneSessionServer::new(Some("domrobot=expired"));
    let client = Arc::new(
        InwxClient::new(server.clone())
            .with_credentials("test-user", "test-pass")
            .unwrap()
            .with_session("domrobot=stale")
            .unwrap()
            .with_retry(common::no_wait()),
    );

    let mut handles = Vec::with_capacity(TASKS);
    for _ in 0..TASKS {
        let client = Arc::clone(&client);
        handles.push(tokio::spawn(async move {
            client.list_domains(&DomainListQuery::default()).await
        }));
    }

    for handle in handles {
        handle.await.unwrap().unwrap();
    }

    assert_eq!(server.logins(), 1, "one login renews the session for all");
    assert!(client.is_authenticated());
    // The renewed cookie is the live one: a second login here would mean the
    // client kept a session the server had already dropped.
    client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap();
    assert_eq!(server.logins(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_writes_keep_their_own_payloads() {
    let transport = MockTransport::new();
    for index in 0..TASKS {
        transport.ok(json!({ "id": index.to_string() }));
    }

    let client = Arc::new(client(transport.clone()));
    let domain = Arc::new(DomainName::parse("example.com").unwrap());

    let mut handles = Vec::with_capacity(TASKS);
    for index in 0..TASKS {
        let client = Arc::clone(&client);
        let domain = Arc::clone(&domain);
        handles.push(tokio::spawn(async move {
            let spec = RecordSpec::new(RecordType::Txt, "@", format!("value-{index}")).unwrap();
            client.create_record(&domain, &spec).await
        }));
    }

    let mut ids = Vec::with_capacity(TASKS);
    for handle in handles {
        ids.push(handle.await.unwrap().unwrap());
    }

    let mut rendered = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
    rendered.sort();
    assert_eq!(rendered.len(), TASKS);

    // Every payload reached the transport exactly once, intact.
    let mut contents = transport
        .calls()
        .iter()
        .map(|call| call.params["content"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    contents.sort();
    let mut expected = (0..TASKS)
        .map(|index| format!("value-{index}"))
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(contents, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clearing_the_session_while_calls_run_does_not_panic() {
    let transport = MockTransport::new();
    for _ in 0..64 {
        transport.ok_empty();
    }

    let client = Arc::new(
        InwxClient::new(transport.clone())
            .with_session("s=1")
            .unwrap(),
    );
    let domain = Arc::new(DomainName::parse("a.de").unwrap());

    let mut handles = Vec::new();
    for _ in 0..TASKS {
        let client = Arc::clone(&client);
        let domain = Arc::clone(&domain);
        handles.push(tokio::spawn(
            async move { client.delete_domain(&domain).await },
        ));
    }
    client.clear_session();

    for handle in handles {
        // Either the call went through with the cookie it read, or it failed
        // because the session was gone — never a panic.
        let _ = handle.await.unwrap();
    }

    // A call that read the cookie before it was cleared went out; one that did
    // not failed locally. Either way no task panicked, and no call is duplicated.
    assert!(transport.call_count() <= TASKS);
}

/// The 0.2.0 surface under the same load: zone writes, ownership commands and
/// service reads from 32 tasks on one client. Every task must see the shared
/// cookie, and the transport must see exactly one call per task.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn thirty_two_tasks_share_one_client_across_the_new_surface() {
    use inwx_client::{
        ActionKind, AuthCode, Handle, Irreversible, Timestamp, TransferRequest, ZoneCreate,
        ZoneUpdate,
    };

    let transport = MockTransport::new();
    for _ in 0..TASKS {
        transport.ok(json!({ "roId": 42, "available": 190.5, "id": "1" }));
    }

    let client = Arc::new(client(transport.clone()));
    let domain = Arc::new(DomainName::parse("example.com").unwrap());

    let mut handles = Vec::with_capacity(TASKS);
    for index in 0..TASKS {
        let client = Arc::clone(&client);
        let domain = Arc::clone(&domain);
        handles.push(tokio::spawn(async move {
            match index % 4 {
                0 => {
                    let zone = ZoneCreate::master((*domain).clone())
                        .unwrap()
                        .with_nameservers(&[
                            inwx_client::Hostname::parse("ns1.example.net").unwrap()
                        ])
                        .unwrap();
                    client.create_zone(&zone).await.map(|_| ())
                }
                1 => {
                    let update = ZoneUpdate::new((*domain).clone())
                        .with_nameservers(&[
                            inwx_client::Hostname::parse("ns2.example.net").unwrap()
                        ])
                        .unwrap();
                    client.update_zone(&update).await
                }
                2 => {
                    let request = TransferRequest::new(Irreversible::acknowledge(
                        ActionKind::Transfer,
                        &domain,
                    ))
                    .unwrap()
                    .auth_code(AuthCode::new("aB3-xY9_42").unwrap())
                    .unwrap()
                    .with_registrant(Handle::new(991).unwrap())
                    .scheduled_at(Timestamp::parse("2026-11-01T03:00:00").unwrap());
                    client.transfer_domain(&request).await.map(|_| ())
                }
                _ => client.account_balance().await.map(|_| ()),
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap().unwrap();
    }

    let calls = transport.calls();
    assert_eq!(calls.len(), TASKS);
    let mut methods: Vec<&str> = calls.iter().map(|call| call.method.as_str()).collect();
    methods.sort_unstable();
    methods.dedup();
    assert_eq!(
        methods,
        [
            "accounting.accountBalance",
            "domain.transfer",
            "nameserver.create",
            "nameserver.update"
        ]
    );
    for call in &calls {
        assert_eq!(call.header("cookie"), Some("domrobot=test-session"));
    }
}
