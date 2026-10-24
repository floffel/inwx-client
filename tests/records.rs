//! Record CRUD: what goes on the wire, and how answers are parsed back.

mod common;

use common::{client, client_without_retries, MockTransport};
use inwx_client::{DomainName, Error, Hostname, RecordId, RecordSpec, RecordType, RecordUpdate};
use serde_json::json;

fn domain() -> DomainName {
    DomainName::parse("example.com").unwrap()
}

#[tokio::test]
async fn create_sends_every_documented_field() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": "4711" }));

    let client = client(transport.clone());
    let spec = RecordSpec::mx("@", 10, &Hostname::parse("mail.example.com").unwrap())
        .unwrap()
        .with_ttl(600)
        .unwrap();
    let id = client.create_record(&domain(), &spec).await.unwrap();

    assert_eq!(id, RecordId::from("4711"));
    let call = transport.only_call();
    assert_eq!(call.method, "nameserver.createRecord");
    assert_eq!(call.params["domain"], "example.com");
    assert_eq!(call.params["type"], "MX");
    assert_eq!(call.params["name"], "@");
    assert_eq!(call.params["content"], "mail.example.com");
    assert_eq!(call.params["ttl"], 600);
    assert_eq!(call.params["prio"], 10);
}

#[tokio::test]
async fn create_accepts_a_numeric_id_answer() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 4711 }));

    let client = client(transport);
    let id = client
        .create_record(&domain(), &RecordSpec::txt("@", "v=spf1 -all").unwrap())
        .await
        .unwrap();

    assert_eq!(id.as_str(), "4711");
}

#[tokio::test]
async fn create_without_an_id_is_a_missing_field_error() {
    let transport = MockTransport::new();
    transport.ok(json!({}));

    let client = client(transport);
    let error = client
        .create_record(&domain(), &RecordSpec::txt("@", "x").unwrap())
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        Error::MissingField {
            field: "resData.id",
            ..
        }
    ));
}

#[tokio::test]
async fn create_with_a_non_scalar_id_is_a_missing_field_error() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": { "unexpected": true } }));

    let client = client(transport);
    let error = client
        .create_record(&domain(), &RecordSpec::txt("@", "x").unwrap())
        .await
        .unwrap_err();

    assert!(matches!(error, Error::MissingField { .. }));
}

#[tokio::test]
async fn batch_create_is_sequential_and_returns_ids_in_order() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": "1" }));
    transport.ok(json!({ "id": "2" }));

    let client = client(transport.clone());
    let specs = [
        RecordSpec::a("www", "203.0.113.7").unwrap(),
        RecordSpec::aaaa("www", "2001:db8::1").unwrap(),
    ];
    let ids = client.create_records(&domain(), &specs).await.unwrap();

    assert_eq!(ids, [RecordId::from("1"), RecordId::from("2")]);
    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].params["type"], "A");
    assert_eq!(calls[1].params["type"], "AAAA");
}

#[tokio::test]
async fn batch_create_stops_at_the_first_failure() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": "1" }));
    transport.api_error(2302, "Object exists");

    let client = client(transport.clone());
    let specs = [
        RecordSpec::txt("@", "one").unwrap(),
        RecordSpec::txt("@", "two").unwrap(),
        RecordSpec::txt("@", "three").unwrap(),
    ];
    let error = client.create_records(&domain(), &specs).await.unwrap_err();

    assert_eq!(error.code(), Some(2302));
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn update_sends_an_id_array_and_only_the_changed_fields() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let client = client(transport.clone());
    let update = RecordUpdate::new([RecordId::from(88), RecordId::from(89)])
        .content("203.0.113.9")
        .with_ttl(300)
        .unwrap();
    client.update_record(&update).await.unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "nameserver.updateRecord");
    assert_eq!(call.params["id"], json!(["88", "89"]));
    assert_eq!(call.params["content"], "203.0.113.9");
    assert_eq!(call.params["ttl"], 300);
    assert!(call.params.get("name").is_none());
    assert!(call.params.get("type").is_none());
}

#[tokio::test]
async fn an_invalid_update_never_reaches_the_transport() {
    let transport = MockTransport::new();
    let client = client(transport.clone());
    let update = RecordUpdate::new([RecordId::from(1)]);

    let error = client.update_record(&update).await.unwrap_err();

    assert!(error.is_validation());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn delete_sends_the_id_as_a_string() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let client = client(transport.clone());
    client.delete_record(&RecordId::from(4711)).await.unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "nameserver.deleteRecord");
    assert_eq!(call.params["id"], "4711");
}

#[tokio::test]
async fn list_records_reads_nameserver_info_and_parses_records() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "domain": "example.com",
        "count": 3,
        "record": [
            {"id": "1", "name": "@", "type": "A", "content": "203.0.113.7", "ttl": "3600", "prio": 0},
            {"id": "2", "name": "mail", "type": "MX", "content": "mx.example.net", "ttl": 600, "prio": "10"},
            {"id": 3, "type": "brandnew", "content": "x", "unknownField": [1, 2]}
        ]
    }));

    let client = client(transport.clone());
    let records = client.list_records(&domain()).await.unwrap();

    assert_eq!(transport.only_call().method, "nameserver.info");
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].id, RecordId::from("1"));
    assert_eq!(records[0].ip().unwrap().to_string(), "203.0.113.7");
    assert_eq!(records[1].priority(), 10);
    assert_eq!(records[1].ttl_seconds(), 600);
    assert_eq!(records[2].record_type, RecordType::Other("BRANDNEW".into()));
    assert_eq!(records[2].ttl_seconds(), 3600); // API default when absent
    assert_eq!(records[2].name_or_apex(), "@");
}

#[tokio::test]
async fn list_records_tolerates_a_missing_or_malformed_record_list() {
    let transport = MockTransport::new();
    transport.ok(json!({ "domain": "example.com" }));
    let client = client(transport.clone());
    assert!(client.list_records(&domain()).await.unwrap().is_empty());

    let transport = MockTransport::new();
    transport.ok(json!({ "record": { "not": "an array" } }));
    let client = common::client(transport);
    assert!(client.list_records(&domain()).await.unwrap().is_empty());
}

#[tokio::test]
async fn replace_record_deletes_matching_name_and_type_then_creates() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "record": [
            {"id": "1", "name": "www", "type": "A", "content": "203.0.113.7"},
            {"id": "2", "name": "www", "type": "AAAA", "content": "2001:db8::1"},
            {"id": "3", "name": "mail", "type": "A", "content": "203.0.113.8"}
        ]
    }));
    transport.ok_empty(); // delete
    transport.ok(json!({ "id": "4" })); // create

    let client = client(transport.clone());
    let spec = RecordSpec::a("www", "203.0.113.99").unwrap();
    let id = client.replace_record(&domain(), &spec).await.unwrap();

    assert_eq!(id, RecordId::from("4"));
    let calls = transport.calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[1].method, "nameserver.deleteRecord");
    assert_eq!(calls[1].params["id"], "1"); // only the matching A record
    assert_eq!(calls[2].method, "nameserver.createRecord");
    assert_eq!(calls[2].params["content"], "203.0.113.99");
}

#[tokio::test]
async fn an_api_error_from_the_transport_is_not_retried() {
    let transport = MockTransport::new();
    transport.api_error(2004, "Parameter value range error");

    let client = client_without_retries(transport.clone());
    let error = client
        .create_record(&domain(), &RecordSpec::txt("@", "x").unwrap())
        .await
        .unwrap_err();

    assert_eq!(error.code(), Some(2004));
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn the_record_payload_carries_the_defaults_the_api_documents() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": "1" }));

    let client = client(transport.clone());
    client
        .create_record(&domain(), &RecordSpec::txt("@", "x").unwrap())
        .await
        .unwrap();

    let params = transport.only_call().params;
    assert_eq!(params["ttl"], 3600);
    assert_eq!(params["prio"], 0);
}

#[tokio::test]
async fn a_record_that_the_api_rejects_keeps_its_code_and_reason() {
    let transport = MockTransport::new();
    transport.push(common::Reply::Body(
        json!({
            "code": 2005,
            "msg": "Parameter value syntax error",
            "reasonCode": "INVALID_CONTENT",
            "reason": "content is not an IPv4 address",
            "details": [{"code":"PARAM_INVALID","msg":"content"}]
        })
        .to_string(),
    ));

    let client = client(transport);
    let error = client
        .create_record(&domain(), &RecordSpec::a("www", "203.0.113.7").unwrap())
        .await
        .unwrap_err();

    match error {
        Error::Api {
            code,
            reason_code,
            details,
            ..
        } => {
            assert_eq!(code, 2005);
            assert_eq!(reason_code.as_deref(), Some("INVALID_CONTENT"));
            assert_eq!(details[0].code, "PARAM_INVALID");
        }
        other => panic!("unexpected: {other}"),
    }
}
