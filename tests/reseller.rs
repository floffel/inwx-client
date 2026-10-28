//! The reseller/partner surfaces on the wire: `application.*`, `authinfo2.*`,
//! `customer.*`, `document.*`, `host.*`, `message.*`, `news.list`,
//! `nichandle.list` and `pdf.*`.
//!
//! One test per method, each asserting the method name and the exact parameters
//! that went out, and reading back a scripted answer. Nothing here opens a
//! socket: the mock transport replays fixtures.

mod common;

use common::{client, MockTransport};
use inwx_client::{
    ApplicationCheck, ApplicationCreate, ApplicationQuery, ApplicationType, ApplicationUpdate,
    ContactVerificationSettingsUpdate, CustomerDownloadQuery, CustomerUpdate, DocumentQuery,
    DocumentUpload, DomainName, HostCheck, HostCreate, HostQuery, HostUpdate, Hostname, MessageAck,
    NicHandleQuery, PdfRender,
};
use serde_json::json;

fn domain(name: &str) -> DomainName {
    DomainName::parse(name).unwrap()
}

fn host(name: &str) -> Hostname {
    Hostname::parse(name).unwrap()
}

fn address(text: &str) -> std::net::IpAddr {
    text.parse().unwrap()
}

// ------------------------------------------------------------- application --

#[tokio::test]
async fn check_application_sends_the_selectors() {
    let transport = MockTransport::new();
    transport.ok(json!({ "available": 1, "reason": "free" }));

    let check = ApplicationCheck::new()
        .with_type(ApplicationType::parse("transfer").unwrap())
        .with_name("example.com")
        .unwrap()
        .with_domain(domain("example.com"));

    let result = client(transport.clone())
        .check_application(&check)
        .await
        .unwrap();

    assert!(result.is_available());
    assert_eq!(result.reason.as_deref(), Some("free"));

    let call = transport.only_call();
    assert_eq!(call.method, "application.check");
    assert_eq!(call.params["type"], "TRANSFER");
    assert_eq!(call.params["name"], "example.com");
    assert_eq!(call.params["domainName"], "example.com");
}

#[tokio::test]
async fn a_check_without_a_selector_never_reaches_the_transport() {
    let transport = MockTransport::new();
    let error = client(transport.clone())
        .check_application(&ApplicationCheck::new())
        .await
        .unwrap_err();

    assert!(error.is_validation());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn create_application_sends_the_typed_request() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": "4711", "status": "PENDING" }));

    let request = ApplicationCreate::new(ApplicationType::parse("renew").unwrap(), "example.com")
        .unwrap()
        .with_customer_number(123_456)
        .unwrap()
        .with_comment("asap")
        .unwrap();

    let application = client(transport.clone())
        .create_application(&request)
        .await
        .unwrap();

    assert_eq!(application.id, Some(4711));
    assert_eq!(application.status.as_deref(), Some("PENDING"));

    let call = transport.only_call();
    assert_eq!(call.method, "application.create");
    assert_eq!(call.params["type"], "RENEW");
    assert_eq!(call.params["name"], "example.com");
    assert_eq!(call.params["customerNumber"], 123_456);
    assert_eq!(call.params["comment"], "asap");
    assert!(call.params.get("testing").is_none());
}

#[tokio::test]
async fn application_id_calls_carry_applicationid() {
    let transport = MockTransport::new();
    transport.ok_empty();
    transport.ok(json!({ "id": 4711 }));

    client(transport.clone())
        .delete_application(4711)
        .await
        .unwrap();
    let application = client(transport.clone())
        .application_info(4711)
        .await
        .unwrap();
    assert_eq!(application.id, Some(4711));

    let calls = transport.calls();
    assert_eq!(calls[0].method, "application.delete");
    assert_eq!(calls[0].params["applicationId"], 4711);
    assert_eq!(calls[1].method, "application.info");
    assert_eq!(calls[1].params["applicationId"], 4711);
}

#[tokio::test]
async fn a_non_positive_application_id_is_refused_before_the_wire() {
    let transport = MockTransport::new();
    let client = client(transport.clone());

    assert!(client.delete_application(1).await.is_ok());
    assert!(client.delete_application(0).await.is_err());
    assert!(client.application_info(-3).await.is_err());
    // Only the one valid call went out.
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn list_applications_pages_and_reads_rows() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "count": 2,
        "application": [
            {"id": 1, "type": "RENEW", "status": "DONE"},
            {"id": 2, "type": "BRAND_NEW", "status": "PENDING"},
        ],
    }));

    let query = ApplicationQuery::new()
        .with_customer_number(123_456)
        .unwrap()
        .with_page(2, 5)
        .unwrap();

    let applications = client(transport.clone())
        .list_applications(&query)
        .await
        .unwrap();

    assert_eq!(applications.len(), 2);
    assert_eq!(
        applications[1]
            .application_type
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("BRAND_NEW")
    );

    let call = transport.only_call();
    assert_eq!(call.method, "application.list");
    assert_eq!(call.params["customerNumber"], 123_456);
    assert_eq!(call.params["page"], 2);
    assert_eq!(call.params["pagelimit"], 5);
}

#[tokio::test]
async fn an_empty_application_list_is_a_single_row() {
    let transport = MockTransport::new();
    transport.ok(json!({ "application": { "id": 9 } }));

    let applications = client(transport.clone())
        .list_applications(&ApplicationQuery::new())
        .await
        .unwrap();
    assert_eq!(applications.len(), 1);
}

#[tokio::test]
async fn update_application_needs_a_change() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let client = client(transport.clone());
    assert!(client
        .update_application(&ApplicationUpdate::new(4711).unwrap())
        .await
        .is_err());
    assert_eq!(transport.call_count(), 0);

    let update = ApplicationUpdate::new(4711)
        .unwrap()
        .with_comment("pinged")
        .unwrap();
    client.update_application(&update).await.unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "application.update");
    assert_eq!(call.params["applicationId"], 4711);
    assert_eq!(call.params["comment"], "pinged");
}

// ---------------------------------------------------------------- authinfo2 --

#[tokio::test]
async fn create_auth_info2_keeps_the_secret_out_of_debug() {
    let transport = MockTransport::new();
    transport.ok(json!({ "domainName": "example.com", "authInfo2": "aB3-xY9_42" }));

    let record = client(transport.clone())
        .create_auth_info2(&domain("example.com"))
        .await
        .unwrap();

    assert_eq!(
        record
            .auth_info2
            .as_ref()
            .map(inwx_client::AuthInfo2::as_str),
        Some("aB3-xY9_42")
    );
    let printed = format!("{record:?}");
    assert!(!printed.contains("aB3-xY9_42"), "{printed}");

    let call = transport.only_call();
    assert_eq!(call.method, "authinfo2.create");
    assert_eq!(call.params["domainName"], "example.com");
}

#[tokio::test]
async fn auth_info2_price_reads_the_quote() {
    let transport = MockTransport::new();
    transport.ok(json!({ "netPrice": "1.20", "currency": "EUR" }));

    let quote = client(transport.clone())
        .auth_info2_price(&domain("example.com"))
        .await
        .unwrap();

    assert_eq!(quote.net_price, Some(1.2));
    assert_eq!(quote.currency.as_deref(), Some("EUR"));

    let call = transport.only_call();
    assert_eq!(call.method, "authinfo2.getprice");
    assert_eq!(call.params["domainName"], "example.com");
}

// ----------------------------------------------------------------- customer --

#[tokio::test]
async fn customer_info_sends_the_customer_number() {
    let transport = MockTransport::new();
    transport.ok(json!({ "customerNumber": "123456", "type": "DIRECT", "restricted": 0 }));

    let customer = client(transport.clone())
        .customer_info(123_456)
        .await
        .unwrap();

    assert_eq!(customer.customer_number, Some(123_456));
    assert_eq!(customer.restricted, Some(false));

    let call = transport.only_call();
    assert_eq!(call.method, "customer.info");
    assert_eq!(call.params["customerNumber"], 123_456);
}

#[tokio::test]
async fn update_customer_sends_only_the_changed_fields() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let update = CustomerUpdate::new(123_456)
        .unwrap()
        .with_city("Leipzig")
        .unwrap()
        .with_zip("04109")
        .unwrap()
        .with_country_code("de")
        .unwrap();

    client(transport.clone())
        .update_customer(&update)
        .await
        .unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "customer.update");
    assert_eq!(call.params["customerNumber"], 123_456);
    assert_eq!(call.params["city"], "Leipzig");
    assert_eq!(call.params["zip"], "04109");
    assert_eq!(call.params["cc"], "DE");
    assert!(call.params.get("name").is_none());
}

#[tokio::test]
async fn delete_customer_needs_a_positive_number() {
    let transport = MockTransport::new();
    transport.ok_empty();
    let client = client(transport.clone());

    assert!(client.delete_customer(123_456).await.is_ok());
    assert!(client.delete_customer(0).await.is_err());

    let call = transport.only_call();
    assert_eq!(call.method, "customer.delete");
    assert_eq!(call.params["customerNumber"], 123_456);
}

#[tokio::test]
async fn contact_verification_settings_round_trip() {
    let transport = MockTransport::new();
    transport.ok(json!({ "customerNumber": 123_456, "type": "EMAIL", "verified": 0 }));
    transport.ok_empty();

    let settings = client(transport.clone())
        .contact_verification_settings(123_456)
        .await
        .unwrap();
    assert_eq!(settings.verification_type.as_deref(), Some("EMAIL"));
    assert_eq!(settings.is_verified(), Some(false));

    let update = ContactVerificationSettingsUpdate::new(123_456)
        .unwrap()
        .with_verified(true);
    client(transport.clone())
        .update_contact_verification_settings(&update)
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls[0].method, "customer.contactverificationsettingsinfo");
    assert_eq!(calls[0].params["customerNumber"], 123_456);
    assert_eq!(
        calls[1].method,
        "customer.contactverificationsettingsupdate"
    );
    assert_eq!(calls[1].params["verified"], true);
}

#[tokio::test]
async fn verification_settings_without_a_change_are_refused() {
    let transport = MockTransport::new();
    let client = client(transport.clone());
    let update = ContactVerificationSettingsUpdate::new(1).unwrap();

    assert!(client
        .update_contact_verification_settings(&update)
        .await
        .is_err());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn list_customer_downloads_pages_per_customer() {
    let transport = MockTransport::new();
    transport.ok(json!({ "download": [{ "id": 44, "status": "READY" }] }));

    let query = CustomerDownloadQuery::new(123_456)
        .unwrap()
        .with_page(1, 10)
        .unwrap();
    let downloads = client(transport.clone())
        .list_customer_downloads(&query)
        .await
        .unwrap();

    assert_eq!(downloads.len(), 1);
    assert_eq!(downloads[0].id, Some(44));

    let call = transport.only_call();
    assert_eq!(call.method, "customer.listdownloads");
    assert_eq!(call.params["customerNumber"], 123_456);
    assert_eq!(call.params["pagelimit"], 10);
}

#[tokio::test]
async fn request_data_export_reports_the_export() {
    let transport = MockTransport::new();
    transport.ok(json!({ "downloadId": 44, "status": "PENDING" }));

    let export = client(transport.clone())
        .request_customer_data_export(123_456)
        .await
        .unwrap();

    assert_eq!(export.id, Some(44));
    assert!(export.is_pending());

    let call = transport.only_call();
    assert_eq!(call.method, "customer.requestdataexport");
    assert_eq!(call.params["customerNumber"], 123_456);
}

// ----------------------------------------------------------------- document --

#[tokio::test]
async fn upload_document_base64_encodes_the_body() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 81, "filename": "mandate.pdf" }));

    let upload = DocumentUpload::new("mandate.pdf", b"%PDF-1.7")
        .unwrap()
        .with_document_type("mandate")
        .unwrap()
        .with_customer_number(123_456)
        .unwrap();

    let stored = client(transport.clone())
        .upload_document(&upload)
        .await
        .unwrap();

    assert_eq!(stored.id, Some(81));

    let call = transport.only_call();
    assert_eq!(call.method, "document.upload");
    assert_eq!(call.params["filename"], "mandate.pdf");
    assert_eq!(call.params["type"], "MANDATE");
    assert_eq!(call.params["content"], "JVBERi0xLjc=");
}

#[tokio::test]
async fn a_path_never_becomes_a_file_name() {
    let transport = MockTransport::new();

    let upload = DocumentUpload::new("../secret.pdf", b"x").unwrap_err();
    assert!(upload.is_validation());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn list_documents_filters_and_reads_rows() {
    let transport = MockTransport::new();
    transport.ok(json!({ "document": [{ "id": 1 }, { "id": 2 }] }));

    let query = DocumentQuery::new()
        .with_document_type("mandate")
        .unwrap()
        .with_page(1, 5)
        .unwrap();
    let documents = client(transport.clone())
        .list_documents(&query)
        .await
        .unwrap();
    assert_eq!(documents.len(), 2);

    let call = transport.only_call();
    assert_eq!(call.method, "document.list");
    assert_eq!(call.params["type"], "MANDATE");
    assert_eq!(call.params["pagelimit"], 5);
}

#[tokio::test]
async fn download_document_decodes_the_body() {
    let transport = MockTransport::new();
    transport.ok(json!({ "filename": "a.txt", "content": "aGk=" }));

    let document = client(transport.clone())
        .download_document(81)
        .await
        .unwrap();

    assert_eq!(document.bytes().unwrap(), b"hi");

    let call = transport.only_call();
    assert_eq!(call.method, "document.download");
    assert_eq!(call.params["documentId"], 81);
}

#[tokio::test]
async fn document_ids_are_validated_before_the_wire() {
    let transport = MockTransport::new();
    transport.ok_empty();
    let client = client(transport.clone());

    assert!(client.delete_document(81).await.is_ok());
    assert!(client.delete_document(0).await.is_err());
    assert!(client.download_document(-1).await.is_err());

    let call = transport.only_call();
    assert_eq!(call.method, "document.delete");
    assert_eq!(call.params["documentId"], 81);
}

// --------------------------------------------------------------------- host --

#[tokio::test]
async fn check_host_sends_domain_and_name() {
    let transport = MockTransport::new();
    transport.ok(json!({ "available": 0, "reason": "taken" }));

    let check = HostCheck::new(domain("example.com"), host("ns1.example.com")).unwrap();
    let result = client(transport.clone()).check_host(&check).await.unwrap();

    assert!(!result.is_available());
    assert_eq!(result.reason.as_deref(), Some("taken"));

    let call = transport.only_call();
    assert_eq!(call.method, "host.check");
    assert_eq!(call.params["domainName"], "example.com");
    assert_eq!(call.params["name"], "ns1.example.com");
}

#[tokio::test]
async fn a_host_outside_its_domain_is_refused_locally() {
    let transport = MockTransport::new();
    let check = HostCheck::new(domain("example.com"), host("ns1.example.org"));
    assert!(check.is_err());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn create_host_sends_the_address_list() {
    let transport = MockTransport::new();
    transport.ok(json!({ "hostId": 3001, "name": "ns1.example.com" }));

    let create = HostCreate::new(
        domain("example.com"),
        host("ns1"),
        &[address("198.51.100.1"), address("2001:db8::1")],
    )
    .unwrap();

    let record = client(transport.clone())
        .create_host(&create)
        .await
        .unwrap();
    assert_eq!(record.id, Some(3001));

    let call = transport.only_call();
    assert_eq!(call.method, "host.create");
    assert_eq!(call.params["name"], "ns1");
    assert_eq!(call.params["ip"][0], "198.51.100.1");
    assert_eq!(call.params["ip"][1], "2001:db8::1");
}

#[tokio::test]
async fn fourteen_addresses_never_reach_the_registry() {
    let transport = MockTransport::new();
    let addresses: Vec<std::net::IpAddr> = (1..=14)
        .map(|index| address(&format!("198.51.100.{index}")))
        .collect();

    let create = HostCreate::new(domain("example.com"), host("ns1"), &addresses);
    assert!(create.is_err());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn host_id_calls_carry_hostid() {
    let transport = MockTransport::new();
    transport.ok_empty();
    transport.ok(json!({ "hostId": 3001, "ip": ["198.51.100.1"] }));

    let client = client(transport.clone());
    client.delete_host(3001).await.unwrap();
    let record = client.host_info(3001).await.unwrap();
    assert_eq!(record.addresses, ["198.51.100.1"]);

    let calls = transport.calls();
    assert_eq!(calls[0].method, "host.delete");
    assert_eq!(calls[0].params["hostId"], 3001);
    assert_eq!(calls[1].method, "host.info");
    assert_eq!(calls[1].params["hostId"], 3001);

    assert!(client.delete_host(0).await.is_err());
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn list_hosts_filters_by_domain() {
    let transport = MockTransport::new();
    transport.ok(json!({ "host": [{ "id": 1 }, { "id": 2 }] }));

    let query = HostQuery::new()
        .with_domain(domain("example.com"))
        .with_name("ns1")
        .unwrap()
        .with_page(1, 20)
        .unwrap();

    let hosts = client(transport.clone()).list_hosts(&query).await.unwrap();
    assert_eq!(hosts.len(), 2);

    let call = transport.only_call();
    assert_eq!(call.method, "host.list");
    assert_eq!(call.params["domainName"], "example.com");
    assert_eq!(call.params["name"], "ns1");
    assert_eq!(call.params["pagelimit"], 20);
}

#[tokio::test]
async fn update_host_replaces_the_addresses() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let client = client(transport.clone());
    assert!(client
        .update_host(&HostUpdate::new(3001).unwrap())
        .await
        .is_err());
    assert_eq!(transport.call_count(), 0);

    let update = HostUpdate::new(3001)
        .unwrap()
        .with_addresses(&[address("198.51.100.9")])
        .unwrap();
    client.update_host(&update).await.unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "host.update");
    assert_eq!(call.params["hostId"], 3001);
    assert_eq!(call.params["ip"][0], "198.51.100.9");
}

// ------------------------------------------------------------------ message --

#[tokio::test]
async fn poll_message_reads_both_shapes() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 12, "type": "DOMAIN", "title": "Ready" }));
    transport.ok(json!({ "count": 1, "message": { "id": 13 } }));
    transport.ok(json!({}));

    let client = client(transport.clone());
    let flat = client.poll_message().await.unwrap();
    assert_eq!(flat.message_id().unwrap(), 12);

    let nested = client.poll_message().await.unwrap();
    assert_eq!(nested.count, Some(1));
    assert_eq!(nested.message_id().unwrap(), 13);

    let empty = client.poll_message().await.unwrap();
    assert!(empty.message.is_none());
    assert!(empty.message_id().is_err());

    let calls = transport.calls();
    assert_eq!(calls.len(), 3);
    assert!(calls.iter().all(|call| call.method == "message.poll"));
}

#[tokio::test]
async fn ack_message_sends_the_message_id() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let ack = MessageAck::new(12)
        .unwrap()
        .with_state("processed")
        .unwrap();
    client(transport.clone()).ack_message(&ack).await.unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "message.ack");
    assert_eq!(call.params["messageId"], 12);
    assert_eq!(call.params["state"], "PROCESSED");
}

#[tokio::test]
async fn a_non_positive_message_id_is_refused() {
    let transport = MockTransport::new();
    let ack = MessageAck::new(0).unwrap_err();
    assert!(ack.is_validation());
    assert_eq!(transport.call_count(), 0);
}

// --------------------------------------------------------------- news / nic --

#[tokio::test]
async fn list_news_pages() {
    let transport = MockTransport::new();
    transport.ok(json!({ "news": [{ "id": 1, "title": "Maintenance" }] }));

    let items = client(transport.clone()).list_news(1, 20).await.unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].title.as_deref(), Some("Maintenance"));

    let call = transport.only_call();
    assert_eq!(call.method, "news.list");
    assert_eq!(call.params["page"], 1);
    assert_eq!(call.params["pagelimit"], 20);
}

#[tokio::test]
async fn a_zero_page_limit_for_news_never_reaches_the_wire() {
    let transport = MockTransport::new();
    assert!(client(transport.clone()).list_news(1, 0).await.is_err());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn list_nichandles_filters_the_handle_tree() {
    let transport = MockTransport::new();
    transport.ok(json!({ "nichandle": [{ "nicId": 1, "handle": "ACME-1" }] }));

    let query = NicHandleQuery::new()
        .with_handle("ACME-1")
        .unwrap()
        .with_type("person")
        .unwrap()
        .with_page(1, 5)
        .unwrap();

    let handles = client(transport.clone())
        .list_nichandles(&query)
        .await
        .unwrap();
    assert_eq!(handles[0].handle.as_deref(), Some("ACME-1"));

    let call = transport.only_call();
    assert_eq!(call.method, "nichandle.list");
    assert_eq!(call.params["handle"], "ACME-1");
    assert_eq!(call.params["type"], "PERSON");
    assert_eq!(call.params["pagelimit"], 5);
}

// ---------------------------------------------------------------------- pdf --

#[tokio::test]
async fn render_pdf_sends_the_document_request() {
    let transport = MockTransport::new();
    transport.ok(json!({ "pdfId": "99", "filename": "invoice-4711.pdf" }));

    let handle = client(transport.clone())
        .render_pdf(&PdfRender::new("invoice", 4711).unwrap())
        .await
        .unwrap();

    assert_eq!(handle.id, Some(99));

    let call = transport.only_call();
    assert_eq!(call.method, "pdf.document");
    assert_eq!(call.params["type"], "INVOICE");
    assert_eq!(call.params["id"], 4711);
}

#[tokio::test]
async fn fetch_pdf_decodes_the_body() {
    let transport = MockTransport::new();
    transport.ok(json!({ "filename": "invoice.pdf", "content": "JVBERi0xLjc=" }));

    let file = client(transport.clone()).fetch_pdf(99).await.unwrap();

    assert_eq!(&file.bytes().unwrap()[..5], b"%PDF-");

    let call = transport.only_call();
    assert_eq!(call.method, "pdf.get");
    assert_eq!(call.params["pdfId"], 99);
}

#[tokio::test]
async fn a_bad_pdf_request_is_refused_before_the_wire() {
    let transport = MockTransport::new();
    let client = client(transport.clone());

    assert!(client.fetch_pdf(0).await.is_err());
    let render = PdfRender::new("invoice", 1)
        .unwrap()
        .with_customer_number(0)
        .unwrap_err();
    assert!(render.is_validation());
    assert_eq!(transport.call_count(), 0);
}

// ---------------------------------------------------------------- transport --

#[tokio::test]
async fn an_api_error_on_a_reseller_method_is_terminal() {
    let transport = MockTransport::new();
    transport.api_error(2303, "Object does not exist");

    let error = client(transport.clone())
        .customer_info(123_456)
        .await
        .unwrap_err();

    assert!(matches!(error, inwx_client::Error::Api { code: 2303, .. }));
    assert!(!error.is_retryable());
    assert_eq!(transport.call_count(), 1);
}
