//! The `request.*` surface on the wire: list, info, accept, deny, cancel.
//!
//! Each test asserts the method name and the exact parameters that went out, and
//! the certainty rules that make the three mutations safe: they are never
//! replayed after a transient failure, and a success that names no readable
//! request is `Error::Ambiguous`.

mod common;

use common::{client, client_without_retries, MockTransport};
use inwx_client::{Error, RequestEntry, RequestListPage, RequestListing, RequestState};
use serde_json::json;

#[tokio::test]
async fn every_request_method_sends_its_method_and_id() {
    let transport = MockTransport::new();
    transport.ok(json!({ "count": 1, "requests": [{ "id": 7, "state": "PENDING" }] }));
    transport.ok(json!({ "id": 7, "domain": "example.com", "state": "PENDING" }));
    transport.ok(json!({ "id": 7, "domain": "example.com", "state": "ACCEPTED" }));
    transport.ok(json!({ "id": 7, "domain": "example.com", "state": "DENIED" }));
    transport.ok(json!({ "id": 7, "domain": "example.com", "state": "CANCELED" }));

    let client = client(transport.clone());

    let page = client.list_requests_page(2, 25).await.unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page.requests[0].state, Some(RequestState::Pending));

    let info = client.request_info(7).await.unwrap();
    assert_eq!(info.domain.as_deref(), Some("example.com"));

    assert_eq!(
        client.accept_request(7).await.unwrap().state,
        Some(RequestState::Accepted)
    );
    assert_eq!(
        client.deny_request(7).await.unwrap().state,
        Some(RequestState::Denied)
    );
    assert_eq!(
        client.cancel_request(7).await.unwrap().state,
        Some(RequestState::Canceled)
    );

    let calls = transport.calls();
    assert_eq!(calls[0].method, "request.list");
    assert_eq!(calls[0].params["page"], 2);
    assert_eq!(calls[0].params["pagelimit"], 25);
    for (index, method) in [
        "request.info",
        "request.accept",
        "request.deny",
        "request.cancel",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(calls[index + 1].method, method);
        assert_eq!(calls[index + 1].params["id"], 7);
    }
}

#[tokio::test]
async fn list_requests_defaults_to_one_page() {
    let transport = MockTransport::new();
    transport.ok(json!({ "requests": [] }));

    let listing = client(transport.clone()).list_requests().await.unwrap();
    assert!(listing.is_empty());

    let call = transport.only_call();
    assert_eq!(call.method, "request.list");
    assert_eq!(call.params["page"], 1);
    assert_eq!(call.params["pagelimit"], 100);
}

#[tokio::test]
async fn request_answers_are_read_permissively() {
    let transport = MockTransport::new();
    // A single object where the array belongs is a page of one; a row that does
    // not fit costs the row, not the page; an unknown state is carried.
    transport.ok(json!({ "count": 2, "requests": [
        { "id": 7, "domainName": "example.com", "status": "SOMETHING", "requestType": "PUSH" },
        null
    ] }));
    transport.ok(json!({ "request": { "id": "8", "domain": "example.net" } }));

    let client = client(transport.clone());
    let page = client.list_requests().await.unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page.count, Some(2));
    assert_eq!(page.requests[0].request_type.as_deref(), Some("PUSH"));
    assert_eq!(
        page.requests[0].state,
        Some(RequestState::Other("SOMETHING".into()))
    );
    assert!(page.has_more());

    // The request object is read from the `request` wrapper, with a numeric
    // string id accepted like everywhere else.
    let info = client.request_info(8).await.unwrap();
    assert_eq!(info.id, Some(8));
    assert_eq!(info.domain.as_deref(), Some("example.net"));
}

#[tokio::test]
async fn list_all_requests_walks_every_page() {
    let transport = MockTransport::new();
    transport.ok(json!({ "count": 3, "requests": [{ "id": 1 }, { "id": 2 }] }));
    transport.ok(json!({ "requests": [{ "id": 3 }] }));

    let ids: Vec<i64> = client(transport.clone())
        .list_all_requests(
            &RequestListing::new(),
            &inwx_client::Pagination::new().with_page_size(2).unwrap(),
        )
        .collect_all()
        .await
        .unwrap()
        .iter()
        .filter_map(|request| request.id)
        .collect();
    assert_eq!(ids, [1, 2, 3]);
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn read_methods_are_replayed_but_mutations_are_not() {
    // A transient 5xx on the read is retried like any read.
    let transport = MockTransport::new();
    transport.status(500, "");
    transport.ok(json!({ "requests": [] }));
    let page = client(transport.clone()).list_requests().await.unwrap();
    assert!(page.is_empty());
    assert_eq!(transport.call_count(), 2);

    // A 5xx on a mutation says nothing about whether it ran: one attempt,
    // then `Uncertain`.
    let transport = MockTransport::new();
    transport.status(500, "");
    let error = client(transport.clone())
        .accept_request(7)
        .await
        .unwrap_err();
    assert!(error.is_uncertain(), "{error:?}");
    assert_eq!(transport.call_count(), 1);

    // A transport failure after the request was written is the same verdict.
    let transport = MockTransport::new();
    transport.uncertain_failure("connection reset after the body was written");
    let error = client(transport.clone()).deny_request(7).await.unwrap_err();
    assert!(error.is_uncertain(), "{error:?}");
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn a_mutation_answered_without_data_names_the_id_it_acted_on() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let entry = client(transport.clone()).cancel_request(7).await.unwrap();
    assert_eq!(
        entry,
        RequestEntry {
            id: Some(7),
            ..RequestEntry::default()
        }
    );
    assert_eq!(transport.only_call().method, "request.cancel");
}

#[tokio::test]
async fn a_mutation_answered_unreadably_is_ambiguous() {
    let transport = MockTransport::new();
    transport.ok(json!("not a request object"));

    let error = client(transport.clone())
        .accept_request(7)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Ambiguous { .. }), "{error:?}");
    assert!(error.is_uncertain());
    assert!(!error.is_retryable());
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn info_without_a_named_request_is_a_missing_field() {
    let transport = MockTransport::new();
    transport.ok(json!({ "unrelated": true }));

    let error = client(transport.clone()).request_info(7).await.unwrap_err();
    assert!(
        matches!(
            error,
            Error::MissingField {
                field: "resData.id",
                ..
            }
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn request_validation_short_circuits() {
    let transport = MockTransport::new();
    let client = client_without_retries(transport.clone());

    assert!(client.request_info(0).await.is_err());
    assert!(client.accept_request(-1).await.is_err());
    assert!(client.deny_request(0).await.is_err());
    assert!(client.cancel_request(-1).await.is_err());
    assert!(client.list_requests_page(1, 0).await.is_err());
    assert_eq!(transport.call_count(), 0);
}

#[test]
fn request_states_carry_unknown_values() {
    assert_eq!(
        RequestState::parse("pending").unwrap(),
        RequestState::Pending
    );
    assert_eq!(
        RequestState::parse("future-thing").unwrap(),
        RequestState::Other("FUTURE-THING".into())
    );
    assert!(RequestState::parse("").is_err());

    let page: RequestListPage =
        serde_json::from_str(r#"{"requests":{"id":7,"state":"ACCEPTED"}}"#).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page.requests[0].id, Some(7));
}
