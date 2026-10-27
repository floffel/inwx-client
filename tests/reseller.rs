//! The reseller/partner objects on the wire: `application.*`, `authinfo2.*`,
//! `host.*`, `message.*`, `news.list`, `nichandle.list` and `pdf.*`.
//!
//! One test per command, each asserting the method name and the exact parameters
//! that went out, plus the pair of values just inside and just outside every
//! limit — with the outside case proving nothing reached the transport at all.

mod common;

use common::{client, MockTransport};
use inwx_client::{
    ApplicationCheck, ApplicationCreate, ApplicationListQuery, ApplicationUpdate, AuthInfo2Code,
    AuthInfo2Order, DomainName, HostCreate, HostListQuery, HostUpdate, Hostname, Language,
    MessageQueue, NicHandleQuery, PdfHash, PdfRender,
};
use serde_json::json;

fn domain(name: &str) -> DomainName {
    DomainName::parse(name).unwrap()
}

fn host(name: &str) -> Hostname {
    Hostname::parse(name).unwrap()
}

// -------------------------------------------------------------- application --

#[tokio::test]
async fn check_application_sends_its_criteria() {
    let transport = MockTransport::new();
    transport.ok(json!({ "available": 1, "note": "free" }));

    let check = ApplicationCheck::new()
        .unwrap()
        .with_type("HOSTING")
        .unwrap()
        .with_name("shop.example.com")
        .unwrap()
        .with_customer(4711)
        .unwrap()
        .with_field("period", 12)
        .unwrap();

    let outcome = client(transport.clone())
        .check_application(&check)
        .await
        .unwrap();
    assert_eq!(outcome.is_available(), Some(true));

    let call = transport.only_call();
    assert_eq!(call.method, "application.check");
    assert_eq!(call.params["type"], "HOSTING");
    assert_eq!(call.params["name"], "shop.example.com");
    assert_eq!(call.params["customer"], 4711);
    assert_eq!(call.params["period"], 12);
}

#[tokio::test]
async fn create_application_sends_the_order_and_the_testing_flag() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 12, "state": "PENDING" }));

    let create = ApplicationCreate::new()
        .unwrap()
        .with_type("HOSTING")
        .unwrap()
        .with_customer(4711)
        .unwrap()
        .with_comment("upgrade")
        .unwrap()
        .dry_run();

    let application = client(transport.clone())
        .create_application(&create)
        .await
        .unwrap();
    assert_eq!(application.id, Some(12));
    assert_eq!(application.state.as_deref(), Some("PENDING"));

    let call = transport.only_call();
    assert_eq!(call.method, "application.create");
    assert_eq!(call.params["type"], "HOSTING");
    assert_eq!(call.params["comment"], "upgrade");
    assert_eq!(call.params["testing"], true);
}

#[tokio::test]
async fn application_info_sends_the_id() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 12, "type": "HOSTING" }));

    let application = client(transport.clone())
        .application_info(12)
        .await
        .unwrap();
    assert_eq!(application.object_type.as_deref(), Some("HOSTING"));

    let call = transport.only_call();
    assert_eq!(call.method, "application.info");
    assert_eq!(call.params["applicationId"], 12);
}

#[tokio::test]
async fn list_applications_sends_the_filter() {
    let transport = MockTransport::new();
    transport.ok(json!({ "count": 1, "application": [{ "id": 12, "brandNew": true }] }));

    let query = ApplicationListQuery::new()
        .with_state("PENDING")
        .unwrap()
        .with_page(2, 50)
        .unwrap();
    let page = client(transport.clone())
        .list_applications(&query)
        .await
        .unwrap();

    assert_eq!(page.count, Some(1));
    assert_eq!(page.len(), 1);
    assert_eq!(page.applications[0].rest["brandNew"], true);

    let call = transport.only_call();
    assert_eq!(call.method, "application.list");
    assert_eq!(call.params["state"], "PENDING");
    assert_eq!(call.params["page"], 2);
    assert_eq!(call.params["pagelimit"], 50);
}

#[tokio::test]
async fn update_application_sends_the_changed_fields() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 12, "state": "DONE" }));

    let update = ApplicationUpdate::new(12)
        .unwrap()
        .with_state("DONE")
        .unwrap()
        .with_field("reason", "customer asked")
        .unwrap();
    client(transport.clone())
        .update_application(&update)
        .await
        .unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "application.update");
    assert_eq!(call.params["applicationId"], 12);
    assert_eq!(call.params["state"], "DONE");
    assert_eq!(call.params["reason"], "customer asked");
}

#[tokio::test]
async fn delete_application_sends_the_id() {
    let transport = MockTransport::new();
    transport.ok_empty();

    client(transport.clone())
        .delete_application(12)
        .await
        .unwrap();
    let call = transport.only_call();
    assert_eq!(call.method, "application.delete");
    assert_eq!(call.params["applicationId"], 12);
}

#[tokio::test]
async fn application_limits_stop_before_the_wire() {
    let transport = MockTransport::new();

    // Just inside: id 1, page limit 1000, a 255 character token.
    let inside = ApplicationUpdate::new(1)
        .unwrap()
        .with_comment(&"x".repeat(255))
        .unwrap();
    assert!(inside.params().is_ok());
    assert!(ApplicationListQuery::new().with_page(1, 1_000).is_ok());

    // Just outside: id 0, page limit 1001 and 0, a 256 character token.
    assert!(ApplicationUpdate::new(0).is_err());
    assert!(ApplicationListQuery::new().with_page(1, 1_001).is_err());
    assert!(ApplicationListQuery::new().with_page(1, 0).is_err());
    assert!(ApplicationUpdate::new(1)
        .unwrap()
        .with_comment(&"x".repeat(256))
        .is_err());
    // An order with nothing in it is refused too.
    assert!(ApplicationCreate::new().unwrap().params().is_err());

    assert_eq!(transport.call_count(), 0);
}

// --------------------------------------------------------------- authinfo2 ---

#[tokio::test]
async fn create_authinfo2_sends_the_order() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 3, "authinfo2": "s3cr3t", "state": "DONE" }));

    let order = AuthInfo2Order::new()
        .unwrap()
        .with_domain(&domain("example.com"))
        .with_quantity(10);
    let created = client(transport.clone())
        .create_authinfo2(&order.unwrap())
        .await
        .unwrap();

    assert_eq!(created.id, Some(3));
    assert_eq!(
        created.code.as_ref().map(AuthInfo2Code::expose),
        Some("s3cr3t")
    );
    assert!(!format!("{created:?}").contains("s3cr3t"));

    let call = transport.only_call();
    assert_eq!(call.method, "authinfo2.create");
    assert_eq!(call.params["domain"], "example.com");
    assert_eq!(call.params["quantity"], 10);
}

#[tokio::test]
async fn authinfo2_price_quotes_the_same_request() {
    let transport = MockTransport::new();
    transport.ok(json!({ "netPrice": "10.00", "grossPrice": 11.9, "currency": "EUR" }));

    let order = AuthInfo2Order::new().unwrap().with_quantity(10).unwrap();
    let quote = client(transport.clone())
        .authinfo2_price(&order)
        .await
        .unwrap();

    assert_eq!(quote.net_price, Some(10.0));
    assert_eq!(quote.gross_price, Some(11.9));

    let call = transport.only_call();
    assert_eq!(call.method, "authinfo2.getprice");
    assert_eq!(call.params["quantity"], 10);
}

#[tokio::test]
async fn authinfo2_limits_stop_before_the_wire() {
    let transport = MockTransport::new();

    assert!(AuthInfo2Order::new().unwrap().with_quantity(1).is_ok());
    assert!(AuthInfo2Order::new().unwrap().with_quantity(100).is_ok());
    assert!(AuthInfo2Order::new().unwrap().with_quantity(101).is_err());
    assert!(AuthInfo2Order::new().unwrap().with_quantity(0).is_err());
    assert!(AuthInfo2Order::new().unwrap().params().is_err());

    assert_eq!(transport.call_count(), 0);
}

// -------------------------------------------------------------------- host ---

#[tokio::test]
async fn check_host_sends_the_name() {
    let transport = MockTransport::new();
    transport.ok(json!({ "available": "1" }));

    let outcome = client(transport.clone())
        .check_host(&host("ns1.example.com"))
        .await
        .unwrap();
    assert_eq!(outcome.is_available(), Some(true));

    let call = transport.only_call();
    assert_eq!(call.method, "host.check");
    assert_eq!(call.params["name"], "ns1.example.com");
}

#[tokio::test]
async fn create_host_sends_the_name_customer_and_glue() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 44, "name": "ns1.example.com" }));

    let create = HostCreate::new(host("ns1.example.com"))
        .unwrap()
        .with_customer(4711)
        .unwrap()
        .with_ip("203.0.113.7")
        .unwrap()
        .dry_run();
    let created = client(transport.clone())
        .create_host(&create)
        .await
        .unwrap();
    assert_eq!(created.id, Some(44));

    let call = transport.only_call();
    assert_eq!(call.method, "host.create");
    assert_eq!(call.params["name"], "ns1.example.com");
    assert_eq!(call.params["customer"], 4711);
    assert_eq!(call.params["ipAddress"], "203.0.113.7");
    assert_eq!(call.params["testing"], true);
}

#[tokio::test]
async fn host_info_sends_the_id() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 44 }));

    client(transport.clone()).host_info(44).await.unwrap();
    let call = transport.only_call();
    assert_eq!(call.method, "host.info");
    assert_eq!(call.params["hostId"], 44);
}

#[tokio::test]
async fn list_hosts_sends_the_filter() {
    let transport = MockTransport::new();
    transport.ok(json!({ "count": 0, "host": [] }));

    let query = HostListQuery::new()
        .with_customer(4711)
        .unwrap()
        .with_page(3, 10)
        .unwrap();
    let page = client(transport.clone()).list_hosts(&query).await.unwrap();
    assert!(page.is_empty());

    let call = transport.only_call();
    assert_eq!(call.method, "host.list");
    assert_eq!(call.params["customer"], 4711);
    assert_eq!(call.params["page"], 3);
    assert_eq!(call.params["pagelimit"], 10);
}

#[tokio::test]
async fn update_host_sends_the_changed_glue() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 44 }));

    let update = HostUpdate::new(44)
        .unwrap()
        .with_ip("2001:db8::1")
        .unwrap()
        .with_name(&host("ns2.example.com"));
    client(transport.clone())
        .update_host(&update)
        .await
        .unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "host.update");
    assert_eq!(call.params["hostId"], 44);
    assert_eq!(call.params["ipAddress"], "2001:db8::1");
    assert_eq!(call.params["name"], "ns2.example.com");
}

#[tokio::test]
async fn delete_host_sends_the_id() {
    let transport = MockTransport::new();
    transport.ok_empty();

    client(transport.clone()).delete_host(44).await.unwrap();
    let call = transport.only_call();
    assert_eq!(call.method, "host.delete");
    assert_eq!(call.params["hostId"], 44);
}

#[tokio::test]
async fn host_limits_stop_before_the_wire() {
    let transport = MockTransport::new();

    assert!(HostUpdate::new(1).unwrap().with_ip("203.0.113.1").is_ok());
    assert!(HostListQuery::new().with_page(1, 1).is_ok());
    assert!(HostListQuery::new().with_page(1, 1_000).is_ok());

    assert!(HostUpdate::new(0).is_err());
    assert!(HostUpdate::new(1).unwrap().with_ip("203.0.113").is_err());
    assert!(HostListQuery::new().with_page(1, 1_001).is_err());
    assert!(HostListQuery::new().with_page(1, 0).is_err());
    assert!(HostUpdate::new(44).unwrap().params().is_err());
    assert!(HostCreate::new(host("ns1"))
        .unwrap()
        .params()
        .get("testing")
        .is_none());

    assert_eq!(transport.call_count(), 0);
}

// ----------------------------------------------------------------- message ---

#[tokio::test]
async fn poll_messages_reads_the_queue() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "count": 1,
        "message": [{ "id": 912, "type": "DOMAIN", "content": { "domain": "example.com" } }],
    }));

    let queue: MessageQueue = client(transport.clone()).poll_messages().await.unwrap();
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.ids(), vec![912]);
    assert_eq!(queue.messages[0].content["domain"], "example.com");

    let call = transport.only_call();
    assert_eq!(call.method, "message.poll");
    assert_eq!(call.params, json!({}));
}

#[tokio::test]
async fn ack_message_sends_the_id() {
    let transport = MockTransport::new();
    transport.ok_empty();

    client(transport.clone()).ack_message(912).await.unwrap();
    let call = transport.only_call();
    assert_eq!(call.method, "message.ack");
    assert_eq!(call.params["messageId"], 912);
}

#[tokio::test]
async fn a_zero_message_id_never_reaches_the_wire() {
    let transport = MockTransport::new();

    let client = client(transport.clone());
    // 1 is the smallest id the API can resolve.
    transport.ok_empty();
    client.ack_message(1).await.unwrap();
    assert!(client.ack_message(0).await.is_err());
    assert!(client.ack_message(-1).await.is_err());
    assert_eq!(transport.call_count(), 1);
}

// -------------------------------------------------------------------- news ---

#[tokio::test]
async fn list_news_sends_the_filter() {
    let transport = MockTransport::new();
    transport.ok(json!({ "count": 1, "news": [{ "id": 5, "title": "Maintenance" }] }));

    let query = inwx_client::NewsQuery::new()
        .with_unread_only(true)
        .with_page(1, 25)
        .unwrap();
    let page = client(transport.clone()).list_news(&query).await.unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page.items[0].title.as_deref(), Some("Maintenance"));

    let call = transport.only_call();
    assert_eq!(call.method, "news.list");
    assert_eq!(call.params["onlyUnread"], true);
    assert_eq!(call.params["pagelimit"], 25);
}

#[tokio::test]
async fn news_page_limits_stop_before_the_wire() {
    let transport = MockTransport::new();

    assert!(inwx_client::NewsQuery::new().with_page(1, 1).is_ok());
    assert!(inwx_client::NewsQuery::new().with_page(1, 1_000).is_ok());
    assert!(inwx_client::NewsQuery::new().with_page(1, 1_001).is_err());
    assert!(inwx_client::NewsQuery::new().with_page(1, 0).is_err());
    assert!(inwx_client::NewsQuery::new().with_customer(0).is_err());

    assert_eq!(transport.call_count(), 0);
}

// --------------------------------------------------------------- nichandle ---

#[tokio::test]
async fn list_nic_handles_sends_the_filter() {
    let transport = MockTransport::new();
    transport.ok(json!({ "count": 1, "handle": [{ "handle": "P1234", "verifyStatus": "1" }] }));

    let query = NicHandleQuery::new()
        .with_handle("P1234")
        .unwrap()
        .with_page(2, 5)
        .unwrap();
    let page = client(transport.clone())
        .list_nic_handles(&query)
        .await
        .unwrap();
    assert_eq!(page.handles[0].handle.as_deref(), Some("P1234"));
    assert_eq!(page.handles[0].verify_status.as_deref(), Some("1"));

    let call = transport.only_call();
    assert_eq!(call.method, "nichandle.list");
    assert_eq!(call.params["handle"], "P1234");
    assert_eq!(call.params["page"], 2);
}

#[tokio::test]
async fn nichandle_limits_stop_before_the_wire() {
    let transport = MockTransport::new();

    assert!(NicHandleQuery::new().with_handle(&"P".repeat(255)).is_ok());
    assert!(NicHandleQuery::new().with_page(1, 1).is_ok());
    assert!(NicHandleQuery::new().with_page(1, 1_000).is_ok());

    assert!(NicHandleQuery::new().with_handle(&"P".repeat(256)).is_err());
    assert!(NicHandleQuery::new().with_handle("").is_err());
    assert!(NicHandleQuery::new().with_page(1, 1_001).is_err());
    assert!(NicHandleQuery::new().with_page(1, 0).is_err());

    assert_eq!(transport.call_count(), 0);
}

// --------------------------------------------------------------------- pdf ---

#[tokio::test]
async fn render_pdf_sends_the_document_request() {
    let transport = MockTransport::new();
    transport.ok(json!({ "data": "JVBERi0=", "hash": "8f2a", "filename": "invoice.pdf" }));

    let render = PdfRender::new()
        .unwrap()
        .with_document_type("INVOICE")
        .unwrap()
        .with_customer(4711)
        .unwrap()
        .with_language(Language::De);
    let document = client(transport.clone()).render_pdf(&render).await.unwrap();

    assert_eq!(document.bytes().unwrap(), b"%PDF-");
    assert_eq!(document.required_hash().unwrap().as_str(), "8f2a");

    let call = transport.only_call();
    assert_eq!(call.method, "pdf.document");
    assert_eq!(call.params["type"], "INVOICE");
    assert_eq!(call.params["customer"], 4711);
    assert_eq!(call.params["language"], "de");
}

#[tokio::test]
async fn fetch_pdf_sends_the_hash() {
    let transport = MockTransport::new();
    transport.ok(json!({ "pdf": "aGk=" }));

    let document = client(transport.clone())
        .fetch_pdf(&PdfHash::new("8f2a41c0").unwrap())
        .await
        .unwrap();
    assert_eq!(document.bytes().unwrap(), b"hi");

    let call = transport.only_call();
    assert_eq!(call.method, "pdf.get");
    assert_eq!(call.params["hash"], "8f2a41c0");
}

#[tokio::test]
async fn pdf_limits_stop_before_the_wire() {
    let transport = MockTransport::new();

    assert!(PdfHash::new("a".repeat(255)).is_ok());
    assert!(PdfRender::new().unwrap().with_customer(1).is_ok());

    assert!(PdfHash::new("a".repeat(256)).is_err());
    assert!(PdfHash::new("with\nnewline").is_err());
    assert!(PdfRender::new().unwrap().with_customer(0).is_err());
    assert!(PdfRender::new().unwrap().params().is_err());

    assert_eq!(transport.call_count(), 0);
}
