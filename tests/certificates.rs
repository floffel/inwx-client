//! Certificates and accounting on the wire, including the money guard.

mod common;

use common::{client, client_without_retries, MockTransport};
use inwx_client::{
    ActionKind, CertificateId, CertificateOrder, CertificateProductQuery, CertificateQuery,
    CertificateTerm, CertificateUpdate, CertificateValidationMethod, Document, DocumentFormat,
    DomainName, Email, Handle, Irreversible, PostalDelivery, RefundRequest, StatementQuery,
    Timestamp, TransactionLogQuery,
};
use serde_json::json;

fn domain(name: &str) -> DomainName {
    DomainName::parse(name).unwrap()
}

fn certificate_id() -> CertificateId {
    CertificateId::new(9).unwrap()
}

fn order() -> CertificateOrder {
    CertificateOrder::new(17)
        .unwrap()
        .with_common_name(domain("example.com"))
        .with_term(CertificateTerm::TwoYears)
        .with_sans(&[domain("www.example.com")])
        .unwrap()
        .with_wildcard_san("*.example.com")
        .unwrap()
        .with_validation(CertificateValidationMethod::Dns, None)
        .unwrap()
        .with_owner(Handle::new(991).unwrap())
        .with_admin(Handle::new(992).unwrap())
        .with_tech(Handle::new(993).unwrap())
        .with_san_count(5, 1)
        .with_hosting(false)
        .with_autorenew(true)
}

#[tokio::test]
async fn order_certificate_sends_every_documented_field() {
    let transport = MockTransport::new();
    transport
        .ok(json!({ "certificateId": 9, "status": "PENDING", "price": 39.9, "missing": ["csr"] }));

    let result = client(transport.clone())
        .order_certificate(&order())
        .await
        .unwrap();
    assert_eq!(result.certificate_id, Some(9));
    assert_eq!(result.missing, ["csr"]);
    assert!(!result.is_complete());

    let call = transport.only_call();
    assert_eq!(call.method, "certificate.create");
    assert_eq!(call.params["productId"], 17);
    assert_eq!(call.params["commonName"], "example.com");
    assert_eq!(call.params["period"], 2);
    assert_eq!(call.params["san"], "www.example.com,*.example.com");
    assert_eq!(call.params["validationMethod"], "DNS");
    assert_eq!(call.params["ownerc"], 991);
    assert_eq!(call.params["adminc"], 992);
    assert_eq!(call.params["techc"], 993);
    assert_eq!(call.params["numberOfSan"], 5);
    assert_eq!(call.params["numberOfWildcardSan"], 1);
    assert_eq!(call.params["hosting"], false);
    assert_eq!(call.params["autorenew"], true);
    assert_eq!(call.params["testing"], false);
}

#[tokio::test]
async fn order_with_a_csr_and_email_validation() {
    let transport = MockTransport::new();
    transport.ok(json!({ "certificateId": 9 }));

    let request = CertificateOrder::new(17)
        .unwrap()
        .with_csr("-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----")
        .unwrap()
        .with_validation(
            CertificateValidationMethod::Email,
            Some(Email::parse("admin@example.com").unwrap()),
        )
        .unwrap()
        .dry_run();

    client(transport.clone())
        .order_certificate(&request)
        .await
        .unwrap();
    let call = transport.only_call();
    assert!(call.params["csr"]
        .as_str()
        .unwrap()
        .starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
    assert_eq!(call.params["validationMethod"], "EMAIL");
    assert_eq!(call.params["validationEmail"], "admin@example.com");
    assert_eq!(call.params["testing"], true);
}

#[tokio::test]
async fn order_without_csr_or_common_name_never_reaches_the_wire() {
    let transport = MockTransport::new();
    let error = client_without_retries(transport.clone())
        .order_certificate(&CertificateOrder::new(17).unwrap())
        .await
        .unwrap_err();
    assert!(error.is_validation());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn certificate_commands_send_their_ids() {
    let transport = MockTransport::new();
    transport.ok_empty();
    transport.ok(json!({ "id": 17, "name": "DomainValidation", "type": "DV", "wildcard": 0, "price1year": 39.9 }));
    transport.ok(json!({ "id": 9, "status": "ACTIVE", "active": 1, "san": "www.example.com,shop.example.com" }));
    transport.ok(json!([{ "id": 9, "status": "ACTIVE" }, { "id": 10, "status": "EXPIRED" }]));
    transport.ok(json!([{ "id": 17, "name": "DV" }]));
    transport.ok(json!({ "certificateId": "9", "missing": ["csr"] }));
    transport.ok(json!([]));
    transport.ok(json!({ "certificateId": 9, "status": "PENDING", "missing": [] }));

    let client = client(transport.clone());
    client.cancel_certificate(certificate_id()).await.unwrap();
    let product = client.certificate_product(17).await.unwrap();
    assert_eq!(product.name.as_deref(), Some("DomainValidation"));
    assert!(!product.is_wildcard());

    let info = client.certificate_info(certificate_id()).await.unwrap();
    assert!(info.is_active());
    assert_eq!(info.san_list(), ["www.example.com", "shop.example.com"]);

    let listed = client
        .list_certificates(
            &CertificateQuery::new()
                .with_inactive()
                .with_limit(50)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.len(), 2);

    let products = client
        .list_certificate_products(&CertificateProductQuery::new())
        .await
        .unwrap();
    assert_eq!(products.len(), 1);

    let missing = client
        .certificate_missing_data(certificate_id())
        .await
        .unwrap();
    assert_eq!(missing.certificate_id.as_deref(), Some("9"));

    let log = client.certificate_log(None).await.unwrap();
    assert_eq!(log.len(), 0);

    let updated = client
        .update_certificate_order(
            &CertificateUpdate::new(certificate_id())
                .unwrap()
                .with_csr("-----BEGIN CERTIFICATE REQUEST-----\nMIIB")
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(updated.status.as_deref(), Some("PENDING"));

    let calls = transport.calls();
    assert_eq!(calls[0].method, "certificate.cancel");
    assert_eq!(calls[0].params["certificateId"], 9);
    assert_eq!(calls[1].method, "certificate.getProduct");
    assert_eq!(calls[1].params["productId"], 17);
    assert_eq!(calls[2].method, "certificate.info");
    assert_eq!(calls[3].method, "certificate.list");
    assert_eq!(calls[3].params["showInactive"], true);
    assert_eq!(calls[3].params["limit"], 50);
    assert_eq!(calls[4].method, "certificate.listProducts");
    assert_eq!(calls[5].method, "certificate.listRemainingNeededData");
    assert_eq!(calls[6].method, "certificate.log");
    assert_eq!(calls[6].params, json!({}));
    assert_eq!(calls[7].method, "certificate.updateOrder");
    assert_eq!(calls[7].params["certificateId"], 9);
}

#[tokio::test]
async fn reissue_renew_and_settings_commands() {
    let transport = MockTransport::new();
    transport.ok(json!({ "certificateId": 10, "status": "PENDING" }));
    transport.ok(json!({ "certificateId": 11, "status": "PENDING", "price": 39.9 }));
    transport.ok_empty();
    transport.ok_empty();
    transport.ok(json!([{ "certificateId": 9, "status": "ISSUED", "netto": 33.53 }]));

    let client = client(transport.clone());
    let reissued = client
        .reissue_certificate(
            certificate_id(),
            "-----BEGIN CERTIFICATE REQUEST-----\nMIIB",
        )
        .await
        .unwrap();
    assert_eq!(reissued.certificate_id, Some(10));

    let renew = CertificateUpdate::new(certificate_id())
        .unwrap()
        .with_common_name(domain("example.com"))
        .with_sans(&[domain("www.example.com")])
        .unwrap()
        .with_validation(
            CertificateValidationMethod::Email,
            Some(Email::parse("admin@example.com").unwrap()),
        )
        .unwrap()
        .with_owner(Handle::new(991).unwrap())
        .with_admin(Handle::new(992).unwrap())
        .with_tech(Handle::new(993).unwrap())
        .with_hosting(false)
        .with_autorenew(true)
        .dry_run();
    let renewed = client.renew_certificate(&renew).await.unwrap();
    assert_eq!(renewed.price, Some(39.9));

    client
        .set_certificate_autorenew(certificate_id(), true)
        .await
        .unwrap();
    client
        .resend_certificate_approval(certificate_id(), true)
        .await
        .unwrap();
    let log = client
        .certificate_log(Some(certificate_id()))
        .await
        .unwrap();
    assert!((log[0].net_price() - 33.53).abs() < 1e-9);

    let calls = transport.calls();
    assert_eq!(calls[0].method, "certificate.reissue");
    assert_eq!(calls[0].params["certificateId"], 9);
    assert_eq!(calls[1].method, "certificate.renew");
    assert_eq!(calls[1].params["testing"], true);
    assert_eq!(calls[1].params["autorenew"], true);
    assert_eq!(calls[2].method, "certificate.setAutorenew");
    assert_eq!(calls[2].params["autorenew"], true);
    assert_eq!(calls[3].method, "certificate.setresendapproval");
    assert_eq!(calls[3].params["resend_approval"], true);
    assert_eq!(calls[4].params["certificateId"], 9);
}

#[tokio::test]
async fn certificate_validation_short_circuits() {
    let transport = MockTransport::new();
    let client = client_without_retries(transport.clone());

    assert!(client.certificate_product(0).await.is_err());
    assert!(client
        .reissue_certificate(certificate_id(), "not a csr")
        .await
        .is_err());
    assert!(client
        .reissue_certificate(certificate_id(), "-----BEGIN PRIVATE KEY-----\nMIIB")
        .await
        .is_err());
    assert!(client
        .update_certificate_order(&CertificateUpdate::new(certificate_id()).unwrap())
        .await
        .is_err());
    assert!(CertificateQuery::new().with_status("  ").is_err());
    assert!(CertificateQuery::new().with_common_name(" ").is_err());
    assert!(CertificateProductQuery::new().with_kind("XX").is_err());
    assert!(CertificateProductQuery::new().with_brand("").is_err());
    assert_eq!(transport.call_count(), 0);
}

#[test]
fn certificate_order_builders_validate_before_the_wire() {
    let base = || {
        CertificateOrder::new(17)
            .unwrap()
            .with_common_name(domain("example.com"))
    };

    // An email method needs an address; a non-email method must not carry one.
    assert!(base()
        .with_validation(CertificateValidationMethod::Email, None)
        .is_err());
    assert!(base()
        .with_validation(
            CertificateValidationMethod::Dns,
            Some(Email::parse("admin@example.com").unwrap())
        )
        .is_err());

    // Wildcard SANs: exactly one leftmost label.
    assert!(base().with_wildcard_san("*.*.example.com").is_err());
    assert!(base().with_wildcard_san("www.example.com").is_err());

    // Duplicates are refused.
    let www = domain("www.example.com");
    assert!(base().with_sans(&[www.clone(), www]).is_err());

    // A private key is never a CSR; a CSR is never empty or huge.
    assert!(base().with_csr("").is_err());
    assert!(base()
        .with_csr("-----BEGIN PRIVATE KEY-----\nMIIB")
        .is_err());
    assert!(base().with_csr("x".repeat(10_001)).is_err());
    assert!(base()
        .with_csr("-----BEGIN CERTIFICATE REQUEST-----\nMIIB")
        .is_ok());

    // A product id must be positive.
    assert!(CertificateOrder::new(0).is_err());
    assert!(CertificateOrder::new(-1).is_err());
}

// ------------------------------------------------------------- ACCOUNTING ----

#[tokio::test]
async fn accounting_reads_send_their_parameters() {
    let transport = MockTransport::new();
    transport.ok(json!({ "total": 250.0, "available": 190.5, "locked": 59.5, "creditLimit": 0 }));
    transport.ok(
        json!({ "log": { "id": 7, "amount": 100.0, "creditType": "PAYPAL", "last4": "4242" } }),
    );
    transport.ok(json!({ "invoice": [{ "invoiceId": "2026-0042", "date": "2026-10-01", "afterTax": 119.0 }] }));
    transport.ok(json!({ "funds": [{ "domain": "example.com", "amount": 12.5 }], "sslFunds": [{ "certificateId": 9, "netto": 10.0, "vat": 1.9 }] }));
    transport.ok(json!({ "count": 1, "sum": -8.9, "log": [{ "amount": -8.9, "type": "RENEW", "refundable": true }] }));
    transport.ok(json!({ "pdf": "JVBERi0xLjQK" }));
    transport.ok(json!({ "raw": "statement" }));

    let client = client(transport.clone());
    let balance = client.account_balance().await.unwrap();
    assert_eq!(balance.available, Some(190.5));

    let log = client.credit_log(7).await.unwrap();
    assert_eq!(log.last4.as_deref(), Some("4242"));

    let invoices = client.list_invoices().await.unwrap();
    assert_eq!(invoices[0].invoice_id.as_deref(), Some("2026-0042"));

    let funds = client.locked_funds(None, None, 1, 20).await.unwrap();
    assert_eq!(funds.funds.len(), 1);
    assert_eq!(funds.ssl_funds.len(), 1);

    let transactions = client
        .account_log(&TransactionLogQuery::new())
        .await
        .unwrap();
    assert!(transactions.entries[0].is_refundable());

    let pdf = client.invoice_document("2026-0042").await.unwrap();
    assert!(pdf.pdf_bytes().unwrap().starts_with(b"%PDF-"));

    let statement = client
        .statement(
            &StatementQuery::new(
                Timestamp::parse("2026-01-01T00:00:00").unwrap(),
                Timestamp::parse("2026-12-31T23:59:59").unwrap(),
            )
            .unwrap()
            .with_format(DocumentFormat::Raw)
            .with_page(2, 10),
        )
        .await
        .unwrap();
    assert!(!statement.is_pdf());

    let calls = transport.calls();
    assert_eq!(calls[0].method, "accounting.accountBalance");
    assert_eq!(calls[1].method, "accounting.creditLogById");
    assert_eq!(calls[1].params["creditLogId"], 7);
    assert_eq!(calls[2].method, "accounting.listInvoices");
    assert_eq!(calls[3].method, "accounting.lockedFunds");
    assert_eq!(calls[3].params["pagelimit"], 20);
    assert_eq!(calls[4].method, "accounting.log");
    assert_eq!(calls[5].method, "accounting.getInvoice");
    assert_eq!(calls[5].params["invoiceId"], "2026-0042");
    assert_eq!(calls[6].method, "accounting.getstatement");
    assert_eq!(calls[6].params["format"], "RAW");
    assert_eq!(calls[6].params["page"], 2);
}

#[tokio::test]
async fn preview_receipt_and_postal_commands() {
    let transport = MockTransport::new();
    transport.ok(json!({ "pdf": "JVBERi0xLjQK" }));
    transport.ok(json!({ "pdf": "JVBERi0xLjQK" }));
    transport.ok_empty();

    let client = client(transport.clone());
    let preview = client.preview_invoice(2026, 10).await.unwrap();
    assert!(preview.is_pdf());
    let receipt = client
        .receipt(7, "100.00", "Deposit", "2026-10-01")
        .await
        .unwrap();
    assert!(receipt.is_pdf());
    client
        .send_invoice_by_post(
            &PostalDelivery::new("2026-0042", true)
                .unwrap()
                .allowing_duplicates()
                .dry_run(),
        )
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls[0].method, "accounting.getPreviewInvoice");
    assert_eq!(calls[0].params["year"], 2026);
    assert_eq!(calls[0].params["month"], 10);
    assert_eq!(calls[1].method, "accounting.getReceipt");
    assert_eq!(calls[1].params["amount"], "100.00");
    assert_eq!(calls[2].method, "accounting.sendbypost");
    assert_eq!(calls[2].params["acceptCosts"], true);
    assert_eq!(calls[2].params["sendTwice"], true);
    assert_eq!(calls[2].params["testing"], true);
}

#[tokio::test]
async fn refund_requires_the_refund_acknowledgement() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let domain = domain("example.com");
    let refund = RefundRequest::new(
        Irreversible::acknowledge(ActionKind::Refund, &domain),
        7,
        25.0,
    )
    .unwrap();
    assert_eq!(refund.intent().action(), ActionKind::Refund);
    client(transport.clone()).refund(&refund).await.unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "accounting.refund");
    assert_eq!(call.params["creditlogid"], 7);
    assert_eq!(call.params["amount"], 25.0);
}

#[tokio::test]
async fn accounting_validation_short_circuits() {
    let transport = MockTransport::new();
    let client = client_without_retries(transport.clone());
    let domain = domain("example.com");

    // Wrong intent, non-positive id, non-positive amount.
    let wrong = Irreversible::acknowledge(ActionKind::Transfer, &domain);
    assert!(RefundRequest::new(wrong, 7, 10.0).is_err());
    let right = Irreversible::acknowledge(ActionKind::Refund, &domain);
    assert!(RefundRequest::new(right.clone(), 0, 10.0).is_err());
    assert!(RefundRequest::new(right, 7, 0.0).is_err());

    assert!(client.credit_log(0).await.is_err());
    assert!(client.invoice_document(" ").await.is_err());
    assert!(client.preview_invoice(2026, 13).await.is_err());
    assert!(client.preview_invoice(1999, 1).await.is_err());
    assert!(client.receipt(0, "1.00", "x", "2026-01-01").await.is_err());
    assert!(client.receipt(7, "", "x", "2026-01-01").await.is_err());
    assert!(client.locked_funds(None, None, 1, 0).await.is_err());
    assert!(PostalDelivery::new("", true).is_err());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn reversed_ranges_are_refused_locally() {
    let transport = MockTransport::new();
    let client = client_without_retries(transport.clone());
    let later = Timestamp::parse("2026-12-31T00:00:00").unwrap();
    let earlier = Timestamp::parse("2026-01-01T00:00:00").unwrap();

    assert!(client
        .locked_funds(Some(later.clone()), Some(earlier.clone()), 1, 20)
        .await
        .is_err());
    assert!(StatementQuery::new(later.clone(), earlier.clone()).is_err());
    assert!(TransactionLogQuery::new()
        .with_range(later, earlier)
        .is_err());
    assert_eq!(transport.call_count(), 0);
}

#[test]
fn documents_and_sums_behave() {
    let document = Document::parse(r#"{"pdf":"JVBERi0xLjQK"}"#).unwrap();
    assert_eq!(document.pdf_bytes().unwrap().len(), 9);
    assert!(Document::parse("[]").is_err());
    assert!(Document::parse("not json").is_err());

    let broken = Document::parse(r#"{"pdf":"!!!"}"#).unwrap();
    assert!(broken.pdf_bytes().is_err());

    let fund: inwx_client::SslFund = serde_json::from_str(r#"{"netto":10.0,"vat":1.9}"#).unwrap();
    assert!((fund.gross() - 11.9).abs() < 1e-9);
    let unknown: inwx_client::SslFund = serde_json::from_str(r#"{"netto":10.0}"#).unwrap();
    assert!(unknown.gross() < f64::EPSILON);

    let entry: inwx_client::Transaction = serde_json::from_str(r"{}").unwrap();
    assert!(!entry.is_refundable());
}

#[test]
fn certificate_term_and_validation_methods_round_trip() {
    assert_eq!(CertificateTerm::OneYear.years(), 1);
    assert_eq!(CertificateTerm::default(), CertificateTerm::OneYear);
    assert!(CertificateTerm::try_from(3u8).is_err());
    assert_eq!(
        "file"
            .parse::<CertificateValidationMethod>()
            .unwrap()
            .as_str(),
        "FILE"
    );
    assert!("phone".parse::<CertificateValidationMethod>().is_err());
    assert_eq!(CertificateId::new(9).unwrap().to_string(), "9");
    assert!(CertificateId::new(0).is_err());
}
