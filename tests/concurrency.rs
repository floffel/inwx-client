//! 32 tasks on one client: the session cookie must be shared, every call must
//! reach the transport exactly once, and nothing may deadlock.

mod common;

use std::sync::Arc;

use common::{anonymous_client, client, MockTransport};
use inwx_client::{DomainListQuery, DomainName, InwxClient, RecordSpec, RecordType};
use serde_json::json;

const TASKS: usize = 32;

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
    // One login per concurrent caller is possible and harmless: each stores a
    // valid session. What must not happen is a deadlock or a lost call.
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
    assert!(logins >= 1, "at least one login is required");
    assert!(logins <= TASKS, "no caller may log in more than once");
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
