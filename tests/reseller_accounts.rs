//! The account-shaped reseller objects on the wire: `customer.*` and
//! `document.*`.
//!
//! One test per command, asserting the method name and the exact parameters,
//! plus the boundary pair for every limit — the outside value must fail without
//! a single request leaving the client.

mod common;

use common::{client, MockTransport};
use inwx_client::{
    ContactVerificationSettingsUpdate, CustomerDownloadQuery, CustomerUpdate, DataExportRequest,
    DocumentQuery, DocumentUpload, Email,
};
use serde_json::json;

// ---------------------------------------------------------------- customer ---

#[tokio::test]
async fn customer_info_sends_the_id() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 4711, "customerNo": "110069", "city": "Kolbermoor" }));

    let customer = client(transport.clone()).customer_info(4711).await.unwrap();
    assert_eq!(customer.customer_no.as_deref(), Some("110069"));

    let call = transport.only_call();
    assert_eq!(call.method, "customer.info");
    assert_eq!(call.params["customerId"], 4711);
}

#[tokio::test]
async fn update_customer_sends_only_the_changed_fields() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 4711, "city": "Kolbermoor" }));

    let update = CustomerUpdate::new(4711)
        .unwrap()
        .with_city("Kolbermoor")
        .unwrap()
        .with_country("de")
        .unwrap()
        .with_email(Email::parse("it@example.com").unwrap())
        .with_field("company", "Acme GmbH")
        .unwrap();
    client(transport.clone())
        .update_customer(&update)
        .await
        .unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "customer.update");
    assert_eq!(call.params["customerId"], 4711);
    assert_eq!(call.params["city"], "Kolbermoor");
    assert_eq!(call.params["country"], "DE");
    assert_eq!(call.params["email"], "it@example.com");
    assert_eq!(call.params["company"], "Acme GmbH");
    // Fields nobody touched are not sent.
    assert!(call.params.get("street").is_none());
}

#[tokio::test]
async fn delete_customer_sends_the_id() {
    let transport = MockTransport::new();
    transport.ok_empty();

    client(transport.clone())
        .delete_customer(4711)
        .await
        .unwrap();
    let call = transport.only_call();
    assert_eq!(call.method, "customer.delete");
    assert_eq!(call.params["customerId"], 4711);
}

#[tokio::test]
async fn list_customer_downloads_sends_the_paging() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "count": 1,
        "downloads": [{ "hash": "8f2a", "filename": "export.zip", "size": 2048 }],
    }));

    let query = CustomerDownloadQuery::new()
        .with_customer(4711)
        .unwrap()
        .with_page(1, 25)
        .unwrap();
    let page = client(transport.clone())
        .list_customer_downloads(&query)
        .await
        .unwrap();

    assert_eq!(page.len(), 1);
    assert_eq!(page.downloads[0].hash.as_deref(), Some("8f2a"));
    assert_eq!(page.downloads[0].size, Some(2048));

    let call = transport.only_call();
    assert_eq!(call.method, "customer.listdownloads");
    assert_eq!(call.params["customer"], 4711);
    assert_eq!(call.params["pagelimit"], 25);
}

#[tokio::test]
async fn request_customer_data_export_may_send_an_empty_request() {
    let transport = MockTransport::new();
    transport.ok(json!({ "hash": "8f2a", "status": "PENDING" }));

    let export = client(transport.clone())
        .request_customer_data_export(&DataExportRequest::new())
        .await
        .unwrap();
    assert_eq!(export.status.as_deref(), Some("PENDING"));

    let call = transport.only_call();
    assert_eq!(call.method, "customer.requestdataexport");
    assert_eq!(call.params, json!({}));
}

#[tokio::test]
async fn contact_verification_settings_are_read_by_name() {
    let transport = MockTransport::new();
    transport.ok(json!({ "verifyEmail": 1, "interval": "90" }));
    transport.ok(json!({ "verifyEmail": 0 }));

    let client = client(transport.clone());
    let account = client.contact_verification_settings(None).await.unwrap();
    assert_eq!(account.bool_value("verifyEmail"), Some(true));
    assert_eq!(account.string_value("interval").as_deref(), Some("90"));

    let update = ContactVerificationSettingsUpdate::new()
        .unwrap()
        .with_customer(4711)
        .unwrap()
        .with_field("verifyEmail", false)
        .unwrap();
    let one = client
        .update_contact_verification_settings(&update)
        .await
        .unwrap();
    assert_eq!(one.bool_value("verifyEmail"), Some(false));

    let calls = transport.calls();
    assert_eq!(calls[0].method, "customer.contactverificationsettingsinfo");
    assert!(calls[0].params.get("customerId").is_none());
    assert_eq!(
        calls[1].method,
        "customer.contactverificationsettingsupdate"
    );
    assert_eq!(calls[1].params["customerId"], 4711);
    assert_eq!(calls[1].params["verifyEmail"], false);
}

#[tokio::test]
async fn contact_verification_settings_can_target_one_customer() {
    let transport = MockTransport::new();
    transport.ok(json!({}));

    client(transport.clone())
        .contact_verification_settings(Some(4711))
        .await
        .unwrap();
    let call = transport.only_call();
    assert_eq!(call.params["customerId"], 4711);
}

#[tokio::test]
async fn customer_limits_stop_before_the_wire() {
    let transport = MockTransport::new();

    // Just inside.
    assert!(CustomerUpdate::new(1).is_ok());
    assert!(CustomerUpdate::new(1)
        .unwrap()
        .with_street(&"x".repeat(255))
        .is_ok());
    assert!(CustomerUpdate::new(1).unwrap().with_country("de").is_ok());
    assert!(CustomerDownloadQuery::new().with_page(1, 1).is_ok());
    assert!(CustomerDownloadQuery::new().with_page(1, 1_000).is_ok());

    // Just outside.
    assert!(CustomerUpdate::new(0).is_err());
    assert!(CustomerUpdate::new(1)
        .unwrap()
        .with_street(&"x".repeat(256))
        .is_err());
    assert!(CustomerUpdate::new(1).unwrap().with_country("deu").is_err());
    assert!(CustomerDownloadQuery::new().with_page(1, 1_001).is_err());
    assert!(CustomerDownloadQuery::new().with_page(1, 0).is_err());
    assert!(CustomerUpdate::new(1).unwrap().params().is_err());

    assert_eq!(transport.call_count(), 0);
}

// --------------------------------------------------------------- document ---

#[tokio::test]
async fn list_documents_sends_the_filter() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "count": 1,
        "document": [{ "id": 88, "name": "contract.pdf", "mimeType": "application/pdf" }],
    }));

    let query = DocumentQuery::new()
        .with_type("CONTRACT")
        .unwrap()
        .with_page(1, 20)
        .unwrap();
    let page = client(transport.clone())
        .list_documents(&query)
        .await
        .unwrap();

    assert_eq!(
        page.documents[0].mime_type.as_deref(),
        Some("application/pdf")
    );

    let call = transport.only_call();
    assert_eq!(call.method, "document.list");
    assert_eq!(call.params["type"], "CONTRACT");
    assert_eq!(call.params["pagelimit"], 20);
}

#[tokio::test]
async fn upload_document_sends_the_base64_payload() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 88, "name": "contract.pdf" }));

    let upload = DocumentUpload::new("contract.pdf", b"%PDF-1.4 signed")
        .unwrap()
        .with_mime_type("application/pdf")
        .unwrap()
        .with_customer(4711)
        .unwrap();
    let stored = client(transport.clone())
        .upload_document(&upload)
        .await
        .unwrap();
    assert_eq!(stored.id, Some(88));

    let call = transport.only_call();
    assert_eq!(call.method, "document.upload");
    assert_eq!(call.params["name"], "contract.pdf");
    assert_eq!(call.params["type"], "application/pdf");
    assert_eq!(call.params["customer"], 4711);
    assert_eq!(
        call.params["data"], "JVBERi0xLjQgc2lnbmVk",
        "the payload must go out base64-encoded"
    );
}

#[tokio::test]
async fn download_document_decodes_the_payload() {
    let transport = MockTransport::new();
    transport.ok(json!({ "name": "contract.pdf", "data": "JVBERi0=" }));

    let download = client(transport.clone())
        .download_document(88)
        .await
        .unwrap();
    assert_eq!(download.name.as_deref(), Some("contract.pdf"));
    assert_eq!(download.bytes().unwrap(), b"%PDF-");

    let call = transport.only_call();
    assert_eq!(call.method, "document.download");
    assert_eq!(call.params["documentId"], 88);
}

#[tokio::test]
async fn delete_document_sends_the_id() {
    let transport = MockTransport::new();
    transport.ok_empty();

    client(transport.clone()).delete_document(88).await.unwrap();
    let call = transport.only_call();
    assert_eq!(call.method, "document.delete");
    assert_eq!(call.params["documentId"], 88);
}

#[tokio::test]
async fn document_limits_stop_before_the_wire() {
    let transport = MockTransport::new();

    // Just inside: an 8 MiB payload and a 255 character name.
    assert!(DocumentUpload::new("a.bin", &vec![b'x'; 8 * 1024 * 1024]).is_ok());
    assert!(DocumentUpload::new(&"a".repeat(255), b"x").is_ok());
    assert!(DocumentQuery::new().with_page(1, 1).is_ok());
    assert!(DocumentQuery::new().with_page(1, 1_000).is_ok());

    // Just outside: one byte over, one character over, no payload at all.
    assert!(DocumentUpload::new("a.bin", &vec![b'x'; 8 * 1024 * 1024 + 1]).is_err());
    assert!(DocumentUpload::new(&"a".repeat(256), b"x").is_err());
    assert!(DocumentUpload::new("a.bin", b"").is_err());
    assert!(DocumentQuery::new().with_page(1, 1_001).is_err());
    assert!(DocumentQuery::new().with_page(1, 0).is_err());
    assert!(DocumentQuery::new().with_customer(0).is_err());

    assert_eq!(transport.call_count(), 0);
}
