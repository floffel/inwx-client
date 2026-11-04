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
    ApplicationCheck, ApplicationCreate, ApplicationListPage, ApplicationQuery, ApplicationType,
    ApplicationUpdate, AuthInfo2Order, ContactVerificationSettingsUpdate, CustomerDownloadQuery,
    CustomerUpdate, DocumentFormat, DocumentKind, DocumentQuery, DocumentUpload,
    DocumentUploadOutcome, DomainName, Error, HostCheck, HostCreate, HostQuery, HostUpdate,
    Hostname, MessageAck, NicHandleQuery, Pagination, PdfRender,
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

    let page = client(transport.clone())
        .list_applications(&query)
        .await
        .unwrap();
    let applications = page.applications;

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

    let page = client(transport.clone())
        .list_applications(&ApplicationQuery::new())
        .await
        .unwrap();
    assert_eq!(page.applications.len(), 1);
}

#[tokio::test]
async fn list_applications_reports_truncation_with_count() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "count": 51,
        "application": [
            {"id": 1, "status": "PENDING"},
            {"id": 2, "status": "PENDING"},
        ],
    }));

    let page = client(transport.clone())
        .list_applications(&ApplicationQuery::new().with_page(1, 2).unwrap())
        .await
        .unwrap();

    assert_eq!(page.count, Some(51));
    assert_eq!(page.len(), 2);
    assert!(page.has_more());
    assert_eq!(page.applications[0].id, Some(1));
}

#[tokio::test]
async fn an_application_page_without_count_is_not_more_by_itself() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "application": [
            {"id": 1, "status": "PENDING"},
            {"id": 2, "status": "PENDING"},
        ],
    }));

    let page: ApplicationListPage = client(transport.clone())
        .list_applications(&ApplicationQuery::new())
        .await
        .unwrap();

    assert_eq!(page.count, None);
    assert_eq!(page.len(), 2);
    assert!(!page.has_more());
}

#[tokio::test]
async fn list_all_applications_fetches_until_the_reported_total() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "count": 3,
        "application": [
            {"id": 1, "status": "DONE"},
            {"id": 2, "status": "PENDING"},
        ],
    }));
    transport.ok(json!({
        "count": 3,
        "application": [
            {"id": 3, "status": "PENDING"},
        ],
    }));
    transport.ok(json!({
        "count": 3,
        "application": [
            {"id": 99, "status": "NEVER-REQUESTED"},
        ],
    }));

    let pagination = Pagination::new().with_page_size(2).unwrap();
    let applications = client(transport.clone())
        .list_all_applications(
            &ApplicationQuery::new()
                .with_customer_number(123_456)
                .unwrap(),
            &pagination,
        )
        .collect_all()
        .await
        .unwrap();

    assert_eq!(
        applications
            .iter()
            .filter_map(|application| application.id)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].params["customerNumber"], 123_456);
    assert_eq!(calls[0].params["page"], 1);
    assert_eq!(calls[1].params["page"], 2);
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
async fn create_auth_info2_sends_the_domain_and_only_a_set_testing_flag() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "product": "DE-AuthInfo2", "net_price": "1.20", "price": 1.43,
        "currency": "EUR", "message": "order placed", "vat": 19.0
    }));

    let result = client(transport.clone())
        .create_auth_info2(&AuthInfo2Order::new(domain("example.de"), false))
        .await
        .unwrap();

    assert_eq!(result.product.as_deref(), Some("DE-AuthInfo2"));
    assert_eq!(result.net_price, Some(1.2));
    assert_eq!(result.price, Some(1.43));
    assert_eq!(result.currency.as_deref(), Some("EUR"));
    assert_eq!(result.message.as_deref(), Some("order placed"));

    let call = transport.only_call();
    assert_eq!(call.method, "authinfo2.create");
    assert_eq!(call.params["domain"], "example.de");
    // The upstream default is false, so a real order says nothing about it.
    assert!(call.params.get("testing").is_none(), "{}", call.params);
}

#[tokio::test]
async fn a_testing_order_sends_the_flag_and_a_real_one_does_not() {
    let transport = MockTransport::new();
    transport.ok(json!({ "product": "DE-AuthInfo2" }));
    client(transport.clone())
        .create_auth_info2(&AuthInfo2Order::new(domain("example.de"), true))
        .await
        .unwrap();

    let call = transport.only_call();
    assert_eq!(call.params["testing"], json!(true));
    assert_eq!(call.params["domain"], "example.de");
}

#[tokio::test]
async fn auth_info2_price_sends_no_parameters() {
    let transport = MockTransport::new();
    transport.ok(json!({ "netPrice": "1.20", "currency": "EUR" }));

    let quote = client(transport.clone()).auth_info2_price().await.unwrap();

    assert_eq!(quote.net_price, Some(1.2));
    assert_eq!(quote.currency.as_deref(), Some("EUR"));

    let call = transport.only_call();
    assert_eq!(call.method, "authinfo2.getprice");
    assert_eq!(call.params, json!({}), "{}", call.params);
}

#[tokio::test]
async fn an_order_is_never_replayed_after_a_transient_status() {
    // A 5xx says nothing about whether the billable order went through, so the
    // outcome is reported as uncertain after exactly one attempt.
    let transport = MockTransport::new();
    transport.status(500, "");

    let error = client(transport.clone())
        .create_auth_info2(&AuthInfo2Order::new(domain("example.de"), false))
        .await
        .unwrap_err();

    assert!(error.is_uncertain(), "{error:?}");
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn an_order_is_never_replayed_after_a_timeout_either() {
    let transport = MockTransport::new();
    transport.uncertain_failure("connection reset after the body was written");

    let error = client(transport.clone())
        .create_auth_info2(&AuthInfo2Order::new(domain("example.de"), false))
        .await
        .unwrap_err();

    assert!(error.is_uncertain(), "{error:?}");
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn a_transient_status_on_an_order_with_a_verdict_stays_an_api_error() {
    // The API did answer with a rejection: that is a verdict, not an
    // uncertainty, and a rejected command is never repeated.
    let transport = MockTransport::new();
    transport.status(500, r#"{"code":2303,"msg":"domain not found"}"#);
    transport.ok(json!({ "product": "DE-AuthInfo2" }));

    let error = client(transport.clone())
        .create_auth_info2(&AuthInfo2Order::new(domain("example.de"), false))
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Api { code: 2303, .. }), "{error:?}");
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn a_success_envelope_behind_a_transient_status_is_still_uncertain_for_an_order() {
    // HTTP says the transport failed, the body says it worked. For a billable
    // order that contradiction is not an answer: report it and stop.
    let transport = MockTransport::new();
    transport.status(
        502,
        r#"{"code":1000,"msg":"Command completed successfully","resData":{"price":1.43}}"#,
    );

    let error = client(transport.clone())
        .create_auth_info2(&AuthInfo2Order::new(domain("example.de"), false))
        .await
        .unwrap_err();

    assert!(error.is_uncertain(), "{error:?}");
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn the_price_query_is_replayed_like_any_read() {
    let transport = MockTransport::new();
    transport.status(500, "");
    transport.ok(json!({ "price": 1.43, "currency": "EUR" }));

    let quote = client(transport.clone()).auth_info2_price().await.unwrap();

    assert_eq!(quote.price, Some(1.43));
    assert_eq!(transport.call_count(), 2);
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

    assert_eq!(stored.id(), Some(81));
    assert!(stored.is_stored());
    assert_eq!(
        stored.entry().and_then(|entry| entry.filename.as_deref()),
        Some("mandate.pdf")
    );

    let call = transport.only_call();
    assert_eq!(call.method, "document.upload");
    assert_eq!(call.params["filename"], "mandate.pdf");
    assert_eq!(call.params["type"], "MANDATE");
    assert_eq!(call.params["content"], "JVBERi0xLjc=");
}

#[tokio::test]
async fn a_dry_run_upload_reports_that_nothing_was_stored() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let upload = DocumentUpload::new("mandate.pdf", b"%PDF-1.7")
        .unwrap()
        .with_testing(true);

    let outcome = client(transport.clone())
        .upload_document(&upload)
        .await
        .expect("a dry run is a certain outcome, not an error");

    assert_eq!(outcome, DocumentUploadOutcome::dry_run());
    assert!(outcome.is_dry_run());
    assert!(!outcome.is_stored());
    assert_eq!(outcome.id(), None);

    let call = transport.only_call();
    assert_eq!(call.params["testing"], true);
}

#[tokio::test]
async fn an_upload_without_an_id_is_ambiguous_not_a_success() {
    let transport = MockTransport::new();
    // Stored by the service, but the answer names nothing: a caller that took
    // this as `Ok` would own a document it can never download or delete.
    transport.ok(json!({ "filename": "mandate.pdf" }));

    let upload = DocumentUpload::new("mandate.pdf", b"%PDF-1.7").unwrap();
    let error = client(transport.clone())
        .upload_document(&upload)
        .await
        .expect_err("an upload without an id is not a success");

    assert!(matches!(
        error,
        Error::Ambiguous {
            method: "document.upload",
            ..
        }
    ));
    assert!(error.is_uncertain());
    assert!(!error.is_retryable());
    assert!(
        error.to_string().contains("before"),
        "the error says what to do instead: {error}"
    );
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn the_last_usable_id_is_one_and_zero_is_not_usable() {
    // Just inside: the smallest id `download_document` accepts.
    let stored_transport = MockTransport::new();
    stored_transport.ok(json!({ "id": 1 }));
    let upload = DocumentUpload::new("a.pdf", b"x").unwrap();
    let outcome = client(stored_transport.clone())
        .upload_document(&upload)
        .await
        .unwrap();
    assert_eq!(outcome.id(), Some(1));

    // Just outside: `0` is not a handle, so it may not be handed out as one.
    let zero_transport = MockTransport::new();
    zero_transport.ok(json!({ "id": 0 }));
    let error = client(zero_transport.clone())
        .upload_document(&upload)
        .await
        .expect_err("an id of zero is not a usable handle");
    assert!(error.is_uncertain());

    // And a negative id is the same shape of nonsense.
    let negative_transport = MockTransport::new();
    negative_transport.ok(json!({ "documentId": -7 }));
    assert!(client(negative_transport.clone())
        .upload_document(&upload)
        .await
        .is_err());
}

#[tokio::test]
async fn an_unreadable_upload_answer_stays_uncertain_with_its_cause() {
    let transport = MockTransport::new();
    transport.ok(json!("stored"));

    let upload = DocumentUpload::new("a.pdf", b"x").unwrap();
    let error = client(transport.clone())
        .upload_document(&upload)
        .await
        .expect_err("a scalar is not a document row");

    assert!(error.is_uncertain());
    assert!(!error.is_retryable());
    assert!(
        std::error::Error::source(&error).is_some(),
        "the parse failure stays walkable: {error}"
    );
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
async fn list_documents_defaults_to_the_first_page_of_fifty() {
    let transport = MockTransport::new();
    transport.ok(json!({ "document": [] }));

    let documents = client(transport.clone())
        .list_documents(&DocumentQuery::new())
        .await
        .unwrap();
    assert_eq!(
        documents.len(),
        0,
        "an empty array is an answer, not an error"
    );

    let call = transport.only_call();
    assert_eq!(call.method, "document.list");
    assert_eq!(call.params["page"], 1);
    assert_eq!(call.params["pagelimit"], 50);
    assert!(call.params.get("type").is_none());
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
async fn a_download_carrying_both_field_spellings_is_merged() {
    let transport = MockTransport::new();
    // A rename in flight: the answer carries the new key and the old one. This
    // used to fail as `Error::Json`, losing a document the API did send.
    transport.ok(json!({
        "documentId": 81,
        "id": 81,
        "filename": "a.txt",
        "content": "aGk=",
        "data": "aGk=",
        "mimeType": "text/plain",
        "mime_type": "text/plain"
    }));

    let document = client(transport.clone())
        .download_document(81)
        .await
        .unwrap();

    assert_eq!(document.id, Some(81));
    assert_eq!(document.mime_type.as_deref(), Some("text/plain"));
    assert_eq!(document.bytes().unwrap(), b"hi");
}

#[tokio::test]
async fn a_downloaded_file_is_classified_by_its_bytes_not_by_its_name() {
    // Issue #123: `scan.pdf` holding a JPEG was reported as a PDF, because the
    // name was checked before the body.
    let transport = MockTransport::new();
    transport.ok(json!({
        "documentId": 81,
        "filename": "scan.pdf",
        "content": "/9j/4AAQSkZJRg==",
        "mimeType": "image/jpeg",
        "size": 10
    }));
    let jpeg = client(transport).download_document(81).await.unwrap();
    assert_eq!(jpeg.kind().unwrap(), DocumentKind::Other);
    assert_eq!(jpeg.bytes().unwrap().len(), 10);

    // The header alone decides for a renamed PDF, whatever the MIME type says.
    let transport = MockTransport::new();
    transport.ok(json!({
        "filename": "scan.bin",
        "content": "JVBERi0xLjc=",
        "mimeType": "application/octet-stream"
    }));
    let pdf = client(transport).download_document(81).await.unwrap();
    assert_eq!(pdf.kind().unwrap(), DocumentKind::Pdf);

    // A body shorter than the header is unidentified rather than "not a PDF".
    let transport = MockTransport::new();
    transport.ok(json!({ "filename": "a.pdf", "content": "aGk=" }));
    let tiny = client(transport).download_document(81).await.unwrap();
    assert_eq!(tiny.kind().unwrap(), DocumentKind::Unknown);
}

#[tokio::test]
async fn a_download_whose_body_is_not_base64_fails_the_classification() {
    // Before the fix the decode error was folded into `false`/`true`; now it is
    // the error it is.
    let transport = MockTransport::new();
    transport.ok(json!({ "filename": "x.pdf", "content": "!!!not base64!!!" }));
    let document = client(transport).download_document(81).await.unwrap();
    let error = document.kind().unwrap_err();
    assert!(error.is_validation());
    assert!(document.bytes().is_err());
}

#[tokio::test]
async fn a_listed_row_carrying_both_field_spellings_keeps_its_place() {
    let transport = MockTransport::new();
    // Both rows are inside the page; the first carries every key twice.
    transport.ok(json!({
        "document": [
            { "documentId": 1, "id": 1, "filename": "a.pdf", "size": 10, "read": 0 },
            { "id": 2, "filename": "b.pdf", "size": 20, "read": 1 }
        ]
    }));

    let documents = client(transport.clone())
        .list_documents(&DocumentQuery::new())
        .await
        .unwrap();

    assert_eq!(documents.len(), 2);
    assert_eq!(documents[0].id, Some(1));
    assert_eq!(documents[0].read, Some(false));
    assert_eq!(documents[1].id, Some(2));
    assert_eq!(documents[1].read, Some(true));
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
async fn a_flat_poll_answer_spelled_message_id_reaches_the_caller() {
    let transport = MockTransport::new();
    transport.ok(json!({ "messageId": 12, "title": "Ready" }));

    let client = client(transport.clone());
    let polled = client.poll_message().await.unwrap();
    assert_eq!(polled.message_id().unwrap(), 12);
    assert_eq!(
        polled.message.as_ref().and_then(|m| m.title.as_deref()),
        Some("Ready")
    );
    assert_eq!(transport.only_call().method, "message.poll");
}

#[tokio::test]
async fn a_counted_poll_answer_without_a_message_is_an_error() {
    let transport = MockTransport::new();
    transport.ok(json!({ "count": 3 }));

    let err = client(transport.clone()).poll_message().await.unwrap_err();
    assert!(
        matches!(
            err,
            Error::UnexpectedAnswer {
                field: "message",
                ..
            }
        ),
        "{err}"
    );
    assert!(!err.is_retryable());
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

    let page = client(transport.clone()).list_news(1, 20).await.unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page.items[0].title.as_deref(), Some("Maintenance"));
    assert!(!page.has_more());

    let call = transport.only_call();
    assert_eq!(call.method, "news.list");
    assert_eq!(call.params["page"], 1);
    assert_eq!(call.params["pagelimit"], 20);
}

#[tokio::test]
async fn an_unparseable_news_row_fails_the_page_instead_of_vanishing() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "news": [
            { "id": 1, "title": "Maintenance" },
            { "id": 2, "message": "short", "text": "long" }
        ]
    }));

    let error = client(transport)
        .list_news(2, 20)
        .await
        .expect_err("a duplicated alias must not be dropped");

    assert!(matches!(
        error,
        Error::UnexpectedAnswer {
            method: "news.list",
            field: "news",
            ..
        }
    ));
    let message = error.to_string();
    assert!(message.contains("page 2"), "{message}");
    assert!(message.contains("entry 1"), "{message}");
}

#[tokio::test]
async fn a_zero_page_limit_for_news_never_reaches_the_wire() {
    let transport = MockTransport::new();
    assert!(client(transport.clone()).list_news(1, 0).await.is_err());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn news_page_limit_stays_inside_the_crate_ceiling() {
    let transport = MockTransport::new();
    transport.ok(json!({ "news": [] }));

    let page = client(transport.clone())
        .list_news(1, inwx_client::MAX_PAGE_SIZE)
        .await
        .unwrap();
    assert_eq!(page.limit, inwx_client::MAX_PAGE_SIZE);
    assert_eq!(transport.only_call().params["pagelimit"], 1000);

    let transport = MockTransport::new();
    let error = client(transport.clone())
        .list_news(1, inwx_client::MAX_PAGE_SIZE + 1)
        .await
        .unwrap_err();
    assert!(error.is_validation());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn a_full_news_page_says_that_more_may_follow() {
    let transport = MockTransport::new();
    transport.ok(json!({ "news": [{ "id": 1 }, { "id": 2 }] }));

    let page = client(transport).list_news(1, 2).await.unwrap();
    assert_eq!(page.len(), 2);
    assert!(page.has_more());
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

    let page = client(transport.clone())
        .list_nichandles(&query)
        .await
        .unwrap();
    assert_eq!(page.handles[0].handle.as_deref(), Some("ACME-1"));
    assert!(page.count.is_none());

    let call = transport.only_call();
    assert_eq!(call.method, "nichandle.list");
    assert_eq!(call.params["handle"], "ACME-1");
    assert_eq!(call.params["type"], "PERSON");
    assert_eq!(call.params["pagelimit"], 5);
}

#[tokio::test]
async fn list_nichandles_reports_truncation_with_count() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "count": 51,
        "nichandle": [
            { "nicId": 1, "handle": "ACME-1" },
            { "nicId": 2, "handle": "ACME-2" },
        ],
    }));

    let page = client(transport.clone())
        .list_nichandles(&NicHandleQuery::new().with_page(1, 2).unwrap())
        .await
        .unwrap();

    assert_eq!(page.count, Some(51));
    assert_eq!(page.len(), 2);
    assert!(page.has_more());
}

#[tokio::test]
async fn list_all_nichandles_reads_a_single_short_page() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "count": 2,
        "nichandle": [
            { "nicId": 1, "handle": "ACME-1" },
            { "nicId": 2, "handle": "ACME-2" },
        ],
    }));

    let pagination = Pagination::new().with_page_size(50).unwrap();
    let handles = client(transport.clone())
        .list_all_nichandles(&NicHandleQuery::new(), &pagination)
        .collect_all()
        .await
        .unwrap();

    assert_eq!(
        handles.iter().map(|handle| handle.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn list_all_nichandles_fetches_until_the_reported_total() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "count": 3,
        "nichandle": [
            { "nicId": 1, "handle": "ACME-1" },
            { "nicId": 2, "handle": "ACME-2" },
        ],
    }));
    transport.ok(json!({
        "count": 3,
        "nichandle": [
            { "nicId": 3, "handle": "ACME-3" },
        ],
    }));
    transport.ok(json!({
        "count": 3,
        "nichandle": [
            { "nicId": 99, "handle": "NEVER-REQUESTED" },
        ],
    }));

    let pagination = Pagination::new().with_page_size(2).unwrap();
    let handles = client(transport.clone())
        .list_all_nichandles(
            &NicHandleQuery::new().with_customer_number(123_456).unwrap(),
            &pagination,
        )
        .collect_all()
        .await
        .unwrap();

    assert_eq!(
        handles.iter().map(|handle| handle.id).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].params["customerNumber"], 123_456);
    assert_eq!(calls[0].params["page"], 1);
    assert_eq!(calls[1].params["page"], 2);
}

#[tokio::test]
async fn list_all_nichandles_stops_on_an_exactly_complete_page() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "count": 2,
        "nichandle": [
            { "nicId": 1, "handle": "ACME-1" },
            { "nicId": 2, "handle": "ACME-2" },
        ],
    }));
    transport.ok(json!({
        "count": 2,
        "nichandle": [
            { "nicId": 99, "handle": "NEVER-REQUESTED" },
        ],
    }));

    let pagination = Pagination::new().with_page_size(2).unwrap();
    let handles = client(transport.clone())
        .list_all_nichandles(&NicHandleQuery::new(), &pagination)
        .collect_all()
        .await
        .unwrap();

    assert_eq!(
        handles.iter().map(|handle| handle.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn list_all_nichandles_does_not_treat_a_full_page_without_count_as_complete() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "nichandle": [
            { "nicId": 1, "handle": "ACME-1" },
            { "nicId": 2, "handle": "ACME-2" },
        ],
    }));
    transport.ok(json!({
        "nichandle": [],
    }));

    let pagination = Pagination::new().with_page_size(2).unwrap();
    let handles = client(transport.clone())
        .list_all_nichandles(&NicHandleQuery::new(), &pagination)
        .collect_all()
        .await
        .unwrap();

    assert_eq!(
        handles.iter().map(|handle| handle.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn list_all_nichandles_counts_skipped_rows_as_part_of_the_page() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "count": 3,
        "nichandle": [
            { "nicId": 1, "handle": "ACME-1" },
            { "nicId": "not-a-number", "handle": "BROKEN" },
        ],
    }));
    transport.ok(json!({
        "count": 3,
        "nichandle": [
            { "nicId": 2, "handle": "ACME-2" },
        ],
    }));

    let pagination = Pagination::new().with_page_size(2).unwrap();
    let handles = client(transport.clone())
        .list_all_nichandles(&NicHandleQuery::new(), &pagination)
        .collect_all()
        .await
        .unwrap();

    assert_eq!(
        handles.iter().map(|handle| handle.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(transport.call_count(), 2);
    assert_eq!(transport.calls()[1].params["page"], 2);
}

// ---------------------------------------------------------------------- pdf --

#[tokio::test]
async fn render_pdf_sends_the_document_request() {
    let transport = MockTransport::new();
    transport.ok(json!({ "pdfId": "99", "filename": "invoice-4711.pdf" }));

    let handle = client(transport.clone())
        .render_pdf(
            &PdfRender::new("invoice", 4711)
                .unwrap()
                .with_format(DocumentFormat::Pdf)
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(handle.id, Some(99));

    let call = transport.only_call();
    assert_eq!(call.method, "pdf.document");
    assert_eq!(call.params["type"], "INVOICE");
    assert_eq!(call.params["id"], 4711);
    assert_eq!(call.params["format"], "PDF");
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
    let raw = PdfRender::new("invoice", 1)
        .unwrap()
        .with_format(DocumentFormat::Raw)
        .unwrap_err();
    assert!(raw.is_validation());
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
