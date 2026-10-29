//! Completeness sweep for the 0.2.0 surface.
//!
//! `cargo llvm-cov` counts test binaries, never doctests, so the `Display`,
//! `FromStr`, `Serialize` and `Deserialize` impls and the error branches that
//! the doctests already exercise have to be called again from here — otherwise
//! the coverage gate reports a crate that is documented but untested.

mod common;

use common::{client, MockTransport};
use inwx_client::{
    parse_ip, AccountBalance, AccountRole, AccountRoleEntry, AddDnsKeyRequest, ApplicationCheck,
    ApplicationCreate, ApplicationQuery, ApplicationType, ApplicationUpdate, AuthCode, AuthInfo2,
    Certificate, CertificateLogEntry, CertificateOrder, CertificateProduct,
    CertificateProductQuery, CertificateQuery, CertificateUpdate, CertificateValidationMethod,
    ContactVerificationSettings, ContactVerificationSettingsUpdate, CustomerUpdate, DataExport,
    DnsKey, DnssecAlgorithm, DnssecDigestType, DnssecDomainStatus, DnssecFlag, DnssecKeyQuery,
    DnssecKeyStatus, Document, DocumentFormat, DocumentQuery, DocumentUpload, DomainName,
    DownloadedDocument, DsRecord, DynDnsAccount, DynDnsAccountRef, DynDnsRecord, Email, Handle,
    HostCheck, HostCreate, HostUpdate, HostingOrder, HostingPeriod, Hostname, Irreversible,
    NameserverSet, NameserverSetType, NameserverSetUpdate, NewsItem, NicHandle, NicHandleQuery,
    PdfFile, PdfRender, PostalDelivery, RecordSet, RecordSpec, RefundRequest, StatementQuery,
    TagUpdate, Timestamp, TransferAnswer, UrlRedirectType, ZoneCreate, ZoneType, ZoneUpdate,
};
use serde_json::json;

fn domain(name: &str) -> DomainName {
    DomainName::parse(name).unwrap()
}

fn host(name: &str) -> Hostname {
    Hostname::parse(name).unwrap()
}

#[test]
fn enum_display_and_from_str_round_trip() {
    assert_eq!(ZoneType::Master.to_string(), "MASTER");
    assert_eq!(ZoneType::Slave.to_string(), "SLAVE");
    assert_eq!(ZoneType::Other("PRIMARY".into()).to_string(), "PRIMARY");
    assert_eq!(" master ".parse::<ZoneType>().unwrap(), ZoneType::Master);

    assert_eq!(UrlRedirectType::Frame.to_string(), "FRAME");
    assert_eq!(
        "header301".parse::<UrlRedirectType>().unwrap(),
        UrlRedirectType::Header301
    );

    assert_eq!(TransferAnswer::Ack.to_string(), "ACK");
    assert_eq!(
        "ack".parse::<TransferAnswer>().unwrap(),
        TransferAnswer::Ack
    );

    assert_eq!(DocumentFormat::Pdf.to_string(), "PDF");
    assert_eq!(DocumentFormat::Pdf.as_str(), "PDF");
    assert_eq!(DocumentFormat::Csv.to_string(), "CSV");

    assert_eq!(DnssecDomainStatus::DeleteAll.to_string(), "DELETE_ALL");
    assert_eq!(DnssecDomainStatus::Update.to_string(), "UPDATE");
    assert_eq!(
        "delete_all".parse::<DnssecDomainStatus>().unwrap(),
        DnssecDomainStatus::DeleteAll
    );

    assert_eq!(DnssecKeyStatus::Create.to_string(), "CREATE");
    assert_eq!(DnssecKeyStatus::Deleted.to_string(), "DELETED");
    assert_eq!(DnssecKeyStatus::Ignore.to_string(), "IGNORE");
    assert_eq!(
        "create".parse::<DnssecKeyStatus>().unwrap(),
        DnssecKeyStatus::Create
    );

    assert_eq!(NameserverSetType::External.to_string(), "EXTERNAL");
    assert_eq!(
        "external".parse::<NameserverSetType>().unwrap(),
        NameserverSetType::External
    );

    assert_eq!(HostingPeriod::Months1.to_string(), "1");
    assert_eq!(HostingPeriod::Months3.to_string(), "3");
    assert_eq!(HostingPeriod::Months6.to_string(), "6");
    assert_eq!(HostingPeriod::Months12.to_string(), "12");
    assert_eq!(HostingPeriod::Months18.to_string(), "18");
    assert_eq!(HostingPeriod::Months24.to_string(), "24");

    assert_eq!(CertificateValidationMethod::Email.to_string(), "EMAIL");

    assert_eq!(format!("{}", DnssecAlgorithm::RsaSha1), "5");
    assert_eq!(format!("{}", DnssecDigestType::Sha384), "4");
    assert_eq!(format!("{}", DnssecFlag::Zone), "256");
}

#[test]
fn enums_serialize_and_deserialize_through_serde() {
    // Every enum that appears inside a request or a response.
    assert_eq!(
        serde_json::to_string(&ZoneType::Slave).unwrap(),
        "\"SLAVE\""
    );
    let zone_type: ZoneType = serde_json::from_str("\"slave\"").unwrap();
    assert_eq!(zone_type, ZoneType::Slave);
    assert!(serde_json::from_str::<ZoneType>("\"\"").is_err());

    assert_eq!(
        serde_json::to_string(&UrlRedirectType::Header302).unwrap(),
        "\"HEADER302\""
    );
    let redirect: UrlRedirectType = serde_json::from_str("\"frame\"").unwrap();
    assert_eq!(redirect, UrlRedirectType::Frame);
    assert!(serde_json::from_str::<UrlRedirectType>("\"HEADER200\"").is_err());

    let status: DnssecDomainStatus = serde_json::from_str("\"manual\"").unwrap();
    assert_eq!(status, DnssecDomainStatus::Manual);
    assert_eq!(
        serde_json::to_string(&DnssecDomainStatus::Other("NEW".into())).unwrap(),
        "\"NEW\""
    );

    let key_status: DnssecKeyStatus = serde_json::from_str("\"ok\"").unwrap();
    assert_eq!(key_status, DnssecKeyStatus::Ok);
    assert!(serde_json::from_str::<DnssecKeyStatus>("null").is_err());

    let set_type: NameserverSetType = serde_json::from_str("\"primary\"").unwrap();
    assert_eq!(set_type, NameserverSetType::Primary);
    assert!(serde_json::from_str::<NameserverSetType>("\"\"").is_err());

    assert_eq!(
        serde_json::to_string(&TransferAnswer::Nack).unwrap(),
        "\"NACK\""
    );

    let format: DocumentFormat = serde_json::from_str("\"pdf\"").unwrap();
    assert_eq!(format, DocumentFormat::Pdf);
    assert!(serde_json::from_str::<DocumentFormat>("\"docx\"").is_err());

    // The numeric DNSSEC types.
    assert_eq!(
        serde_json::to_string(&DnssecAlgorithm::Ed25519).unwrap(),
        "15"
    );
    let algorithm: DnssecAlgorithm = serde_json::from_str("15").unwrap();
    assert_eq!(algorithm, DnssecAlgorithm::Ed25519);
    assert!(serde_json::from_str::<DnssecAlgorithm>("99").is_err());
    assert!(serde_json::from_str::<DnssecAlgorithm>("999").is_err());

    assert_eq!(
        serde_json::to_string(&DnssecDigestType::Sha384).unwrap(),
        "4"
    );
    let digest: DnssecDigestType = serde_json::from_str("\"2\"").unwrap();
    assert_eq!(digest, DnssecDigestType::Sha256);
    assert!(serde_json::from_str::<DnssecDigestType>("999").is_err());

    assert_eq!(serde_json::to_string(&DnssecFlag::Zone).unwrap(), "256");
    let flag: DnssecFlag = serde_json::from_str("257").unwrap();
    assert_eq!(flag, DnssecFlag::ZoneSep);
    assert!(serde_json::from_str::<DnssecFlag>("999").is_err());

    // HostingPeriod is only ever sent, never parsed back by the API.
    assert_eq!(
        serde_json::to_string(&HostingPeriod::Months6).unwrap(),
        "\"6\""
    );
}

/// A struct that deserialises the value types, to exercise their `Deserialize`.
#[derive(serde::Deserialize)]
struct Holder {
    email: Email,
    at: Timestamp,
}

#[test]
fn small_value_types_round_trip() {
    assert_eq!(Handle::new(7).unwrap().get(), 7);
    assert_eq!(
        Email::parse("a@example.com").unwrap().to_string(),
        "a@example.com"
    );
    assert_eq!(
        "a@example.com".parse::<Email>().unwrap().as_str(),
        "a@example.com"
    );
    assert!(Email::parse(&format!("{}@example.com", "a".repeat(250))).is_err());

    let code = AuthCode::new("code-1").unwrap();
    assert_eq!("code-1".parse::<AuthCode>().unwrap(), code);

    let at = Timestamp::parse("2026-01-01T00:00:00").unwrap();
    assert_eq!(at.to_string(), "2026-01-01T00:00:00");
    assert_eq!("2026-01-01T00:00:00".parse::<Timestamp>().unwrap(), at);
    assert!(Timestamp::parse("").is_err());

    let holder: Holder =
        serde_json::from_str(r#"{"email":"a@example.com","at":"2026-01-01T00:00:00"}"#).unwrap();
    assert_eq!(holder.email.as_str(), "a@example.com");
    assert_eq!(holder.at, at);
    assert!(serde_json::from_str::<Holder>(r#"{"email":"nope","at":"x"}"#).is_err());

    assert!(parse_ip("not an ip").is_err());
}

#[test]
fn permissive_scalars_cover_their_fallbacks() {
    // A number where a number is expected, an object where nothing fits.
    let page: inwx_client::ZoneListPage = serde_json::from_str(r#"{"count":{}}"#).unwrap();
    assert!(page.count.is_none());

    let balance: AccountBalance =
        serde_json::from_str(r#"{"total":{},"available":"190.5"}"#).unwrap();
    assert!(balance.total.is_none());
    assert_eq!(balance.available, Some(190.5));

    let zone: inwx_client::ZoneSummary =
        serde_json::from_str(r#"{"domain":"a.de","web":true,"mail":{"nested":1},"url":null}"#)
            .unwrap();
    assert_eq!(zone.web.as_deref(), Some("true"));
    assert!(zone.mail.is_some());
    assert!(zone.url.is_none());

    // Record ids and types inside the DynDNS record list, numeric and missing.
    let account: inwx_client::DynDnsAccountInfo =
        serde_json::from_str(r#"{"records":[{"id":88,"type":"A"},{"id":null,"type":""}]}"#)
            .unwrap();
    assert_eq!(account.records[0].id.as_ref().unwrap().as_str(), "88");
    assert!(account.records[1].id.is_none());
    assert!(account.records[1].record_type.is_none());

    // `vec_string` given an array of objects drops the odd entries.
    let certificate: Certificate =
        serde_json::from_str(r#"{"commonName":["a.com",{}],"san":null}"#).unwrap();
    assert_eq!(certificate.common_name, ["a.com"]);
    assert_eq!(certificate.san_list().len(), 0);
}

#[test]
fn zone_error_branches() {
    // A redirect type without a web target.
    assert!(ZoneCreate::master(domain("a.de"))
        .unwrap()
        .with_redirect_type(UrlRedirectType::Header301)
        .is_err());
    assert!(ZoneUpdate::new(domain("a.de"))
        .with_redirect_type(UrlRedirectType::Header301)
        .is_err());

    // Frame metadata set first, then the type changed away from FRAME.
    let create = ZoneCreate::master(domain("a.de"))
        .unwrap()
        .with_web("https://example.net")
        .unwrap()
        .with_redirect_type(UrlRedirectType::Frame)
        .unwrap()
        .with_frame_title("x")
        .unwrap()
        .with_redirect_type(UrlRedirectType::Header301)
        .unwrap();
    assert!(create.params().is_err());

    let update = ZoneUpdate::new(domain("a.de"))
        .with_web("https://example.net")
        .unwrap()
        .with_redirect_type(UrlRedirectType::Frame)
        .unwrap()
        .with_frame_title("x")
        .unwrap()
        .with_redirect_type(UrlRedirectType::Header301)
        .unwrap();
    assert!(update.params().is_err());

    // Frame metadata with no type at all.
    assert!(ZoneUpdate::new(domain("a.de"))
        .with_frame_title("x")
        .is_err());

    // The remaining token setters, on the update builder.
    let update = ZoneUpdate::new(domain("a.de"))
        .with_web("https://example.net")
        .unwrap()
        .with_redirect_type(UrlRedirectType::Frame)
        .unwrap()
        .with_frame_description("d")
        .unwrap()
        .with_frame_favicon("https://example.net/f.ico")
        .unwrap()
        .with_frame_keywords("k")
        .unwrap();
    let params = update.params().unwrap();
    assert_eq!(params["urlRedirectDescription"], "d");
    assert_eq!(params["urlRedirectFavIcon"], "https://example.net/f.ico");
    assert_eq!(params["urlRedirectKeywords"], "k");
    assert_eq!(update.domain().as_str(), "a.de");

    // Accessors nobody needs but everybody can call.
    let create = ZoneCreate::master(domain("a.de")).unwrap();
    assert_eq!(create.domain().as_str(), "a.de");
    assert_eq!(create.zone_type(), ZoneType::Master);
}

#[test]
fn token_and_text_validators_cover_their_limits() {
    // `validate_token` rejects newlines; `validate_text` rejects control
    // characters and over-long values.
    assert!(ZoneCreate::master(domain("a.de"))
        .unwrap()
        .with_web("line\nbreak")
        .is_err());
    assert!(ZoneCreate::master(domain("a.de"))
        .unwrap()
        .with_mail("x".repeat(256))
        .is_err());
    assert!(ZoneCreate::master(domain("a.de"))
        .unwrap()
        .with_mail("nul\u{0}byte")
        .is_err());
    assert!(ZoneCreate::master(domain("a.de"))
        .unwrap()
        .with_mail("")
        .is_err());

    // Usernames: the character set is checked after the length.
    assert!(DynDnsAccountRef::by_username("with space").is_err());
    assert!(DynDnsAccountRef::by_id(0).is_err());

    // A DynDNS password with a control character.
    assert!(DynDnsAccount::create("tenant-42", "pa\u{0}ss", &[host("a.example.net")]).is_err());
    assert_eq!(
        DynDnsAccount::create("tenant-42", "pass", &[host("a.example.net")])
            .unwrap()
            .dry_run()
            .params()["testing"],
        true
    );
}

#[test]
fn dnssec_error_branches() {
    // Non-numeric flag and algorithm in a DNSKEY.
    assert!(DnsKey::parse("example.com. IN DNSKEY flag 3 13 ac12").is_err());
    assert!(DnsKey::parse("example.com. IN DNSKEY 257 3 alg ac12").is_err());

    // DS: wrong class, non-numeric algorithm, non-numeric digest type.
    assert!(DsRecord::parse("example.com. IN A 1234 13 2 AA").is_err());
    assert!(DsRecord::parse("example.com. IN DS 1234 alg 2 AA").is_err());
    assert!(DsRecord::parse("example.com. IN DS 1234 13 dt AA").is_err());

    // Accessors and formatting.
    let ds = DsRecord::parse("example.com. IN DS 1234 13 2 AA").unwrap();
    assert_eq!(ds.as_str(), "example.com. IN DS 1234 13 2 AA");
    assert_eq!(ds.key_tag(), 1234);
    assert_eq!(ds.algorithm(), DnssecAlgorithm::EcdsaP256);
    assert_eq!(ds.digest_type(), DnssecDigestType::Sha256);
    assert_eq!(ds.to_string(), ds.as_str());
    assert_eq!(
        "example.com. IN DS 1234 13 2 AA"
            .parse::<DsRecord>()
            .unwrap(),
        ds
    );

    let key = DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12").unwrap();
    assert_eq!(key.flag(), DnssecFlag::ZoneSep);
    assert_eq!(key.algorithm(), DnssecAlgorithm::EcdsaP256);
    assert_eq!(key.to_string(), key.as_str());
    assert_eq!(
        "example.com. IN DNSKEY 257 3 13 ac12"
            .parse::<DnsKey>()
            .unwrap(),
        key
    );

    // Both a DS and a calculated digest.
    let request = AddDnsKeyRequest::new(domain("example.com"), key.clone())
        .unwrap()
        .calculating_digest(DnssecDigestType::Sha256)
        .unwrap();
    assert!(request.clone().with_ds(ds.clone()).is_err());
    assert_eq!(request.domain().as_str(), "example.com");
    assert!(AddDnsKeyRequest::new(domain("example.com"), key)
        .unwrap()
        .with_ds(ds)
        .is_ok());

    // Empty domain filter.
    let transport = MockTransport::new();
    let client = client(transport.clone());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    assert!(runtime.block_on(client.dnssec_info(Some(&[]))).is_err());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn dnssec_answers_without_arrays_are_tolerated() {
    let transport = MockTransport::new();
    transport.ok(json!({}));
    transport.ok(json!({}));
    transport.ok(json!({ "data": "not an array" }));
    transport.ok(json!({ "dnskey": {} }));

    let client = client(transport);
    assert_eq!(client.dnssec_info(None).await.unwrap().len(), 0);
    assert_eq!(
        client
            .list_dns_keys(&DnssecKeyQuery::new())
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(client.dnssec_info(None).await.unwrap().len(), 0);
    assert_eq!(
        client
            .list_dns_keys(&DnssecKeyQuery::new())
            .await
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn certificate_query_and_update_branches() {
    assert_eq!(CertificateValidationMethod::Email.as_str(), "EMAIL");

    let order = CertificateOrder::new(17)
        .unwrap()
        .with_common_name(domain("example.com"));
    assert!(order.clone().with_sans(&[]).is_err());
    let www = domain("www.example.com");
    assert!(order.with_sans(&[www.clone(), www]).is_err());

    let update = CertificateUpdate::new(inwx_client::CertificateId::new(1).unwrap()).unwrap();
    assert!(update.clone().with_sans(&[]).is_err());
    let www = domain("www.example.com");
    assert!(update.clone().with_sans(&[www.clone(), www]).is_err());
    assert!(update
        .clone()
        .with_validation(CertificateValidationMethod::Email, None)
        .is_err());
    assert!(update
        .clone()
        .with_validation(
            CertificateValidationMethod::Dns,
            Some(Email::parse("a@example.com").unwrap())
        )
        .is_err());
    // A CSR with a raw NUL byte.
    assert!(update
        .with_csr("-----BEGIN CERTIFICATE REQUEST-----\u{0}")
        .is_err());

    // Query setters and their limits.
    let query = CertificateQuery::new()
        .with_owner(991)
        .with_status("ACTIVE")
        .unwrap()
        .with_common_name("example.com")
        .unwrap()
        .with_limit(10)
        .unwrap();
    let params = query.params();
    assert_eq!(params["ownerc"], "991");
    assert_eq!(params["status"], "ACTIVE");
    assert_eq!(params["commonName"], "example.com");
    assert_eq!(params["limit"], 10);
    assert!(CertificateQuery::new().with_limit(0).is_err());

    let products = CertificateProductQuery::new()
        .with_kind("OV")
        .unwrap()
        .with_brand("ExampleCA")
        .unwrap()
        .with_wildcard(false)
        .unwrap();
    let params = products.params();
    assert_eq!(params["type"], "OV");
    assert_eq!(params["brand"], "ExampleCA");
    assert_eq!(params["wildcard"], false);
}

#[tokio::test]
async fn certificate_answers_without_arrays_are_tolerated() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 9 }));
    transport.ok(json!({ "id": 17 }));
    transport.ok(json!({ "certificateId": 9 }));
    transport.ok(json!([]));

    let client = client(transport);
    assert_eq!(
        client
            .list_certificates(&CertificateQuery::new())
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        client
            .list_certificate_products(&CertificateProductQuery::new())
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(client.certificate_log(None).await.unwrap().len(), 1);
    assert_eq!(
        client
            .list_certificates(&CertificateQuery::new())
            .await
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn transfer_branches() {
    // An acknowledged action renders and parses.
    assert_eq!(TransferAnswer::Ack.as_str(), "ACK");
    assert_eq!(TransferAnswer::Ack.to_string(), "ACK");

    let ack = Irreversible::acknowledge(inwx_client::ActionKind::Transfer, &domain("a.de"));
    assert_eq!(ack.domain().as_str(), "a.de");

    let transfer = inwx_client::TransferRequest::new(ack.clone()).unwrap();
    assert_eq!(transfer.domain().as_str(), "a.de");

    let trade = inwx_client::TradeRequest::new(Irreversible::acknowledge(
        inwx_client::ActionKind::Trade,
        &domain("a.de"),
    ))
    .unwrap();
    assert_eq!(trade.domain().as_str(), "a.de");

    let push = inwx_client::PushRequest::new(Irreversible::acknowledge(
        inwx_client::ActionKind::Push,
        &domain("a.de"),
    ))
    .unwrap();
    assert_eq!(push.domain().as_str(), "a.de");
    assert!(push.clone().with_target("").is_err());
    assert!(push.with_target("x".repeat(65)).is_err());

    let restore = inwx_client::RestoreRequest::new(Irreversible::acknowledge(
        inwx_client::ActionKind::Restore,
        &domain("a.de"),
    ))
    .unwrap();
    assert_eq!(restore.domain().as_str(), "a.de");
    assert_eq!(restore.dry_run().params()["testing"], true);

    // Nameserver validation inside the ownership builders.
    assert!(transfer.clone().with_nameservers(&[]).is_err());
    let ns = host("ns1.example.net");
    assert!(transfer.with_nameservers(&[ns.clone(), ns]).is_err());
    assert!(trade.with_nameservers(&[]).is_err());

    // Extra data keys: too long, and a documented value.
    let mut extra = inwx_client::ExtData::new();
    assert!(extra.set(&"K".repeat(65), "x").is_err());
    assert!(extra.no_domain_check(false).is_ok());
    assert!(extra.birth_date("2026-02-28").is_ok());
}

#[test]
fn accounting_query_branches() {
    let from = Timestamp::parse("2026-01-01T00:00:00").unwrap();
    let to = Timestamp::parse("2026-02-01T00:00:00").unwrap();

    let statement = StatementQuery::new(from.clone(), to.clone())
        .unwrap()
        .with_page(0, 5);
    assert_eq!(statement.params()["page"], 1);

    let log = inwx_client::TransactionLogQuery::new()
        .with_range(from, to)
        .unwrap()
        .with_prices(0.0, 99.9)
        .unwrap()
        .with_page(0, 10);
    let params = log.params();
    assert_eq!(params["dateFrom"], "2026-01-01T00:00:00");
    assert_eq!(params["dateTo"], "2026-02-01T00:00:00");
    assert_eq!(params["priceMin"], 0.0);
    assert_eq!(params["priceMax"], 99.9);
    assert_eq!(params["page"], 1);
    assert_eq!(params["pagelimit"], 10);
}

#[tokio::test]
async fn accounting_answers_without_arrays_are_tolerated() {
    let transport = MockTransport::new();
    transport.ok(json!({}));

    let invoices = client(transport).list_invoices().await.unwrap();
    assert_eq!(invoices.len(), 0);
}

#[tokio::test]
async fn hosting_answers_without_arrays_are_tolerated() {
    let transport = MockTransport::new();
    transport.ok(json!({ "hosting": null }));
    transport.ok(json!({}));

    let client = client(transport);
    assert_eq!(client.list_hosting().await.unwrap().len(), 0);
    assert_eq!(client.hosting_prices().await.unwrap().len(), 0);
    assert_eq!(
        HostingOrder::existing(5).unwrap().dry_run().params()["testing"],
        true
    );
}

#[tokio::test]
async fn nameserver_set_answers_without_arrays_are_tolerated() {
    let transport = MockTransport::new();
    transport.ok(json!({ "nsset": null }));
    transport.ok(json!({ "id": 9, "ns": [] }));

    let client = client(transport);
    assert_eq!(
        client
            .list_nameserver_sets(true, 1, 10)
            .await
            .unwrap()
            .len(),
        0
    );
    // A set without `type` defaults to PRIMARY.
    let set: NameserverSet = client.nameserver_set_info(9).await.unwrap();
    assert_eq!(set.set_type, NameserverSetType::Primary);

    // Duplicate nameservers in an update.
    let ns = host("ns1.example.net");
    assert!(NameserverSetUpdate::new(9)
        .unwrap()
        .with_nameservers(&[ns.clone(), ns])
        .is_err());
}

#[tokio::test]
async fn dyndns_answers_without_arrays_are_tolerated() {
    let transport = MockTransport::new();
    transport.ok(json!([{ "accountId": 71 }]));
    transport.ok(json!({ "accountId": 71 }));
    transport.ok(json!(null));

    let client = client(transport);
    assert_eq!(client.list_dyndns(None).await.unwrap().len(), 1);
    assert_eq!(
        client
            .list_dyndns(Some(&DynDnsAccountRef::by_id(71).unwrap()))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(client.list_dyndns(None).await.unwrap().len(), 0);
}

#[tokio::test]
async fn tag_answers_without_arrays_are_tolerated() {
    let transport = MockTransport::new();
    transport.ok(json!({}));

    assert!(client(transport)
        .list_tags(None, None)
        .await
        .unwrap()
        .is_empty());
    // An empty add/rem list is refused.
    assert!(TagUpdate::new(3).unwrap().tagging(&[]).is_err());
    assert!(TagUpdate::new(3).unwrap().untagging(&[]).is_err());
}

#[tokio::test]
async fn dyndns_subscription_answers_are_tolerated() {
    let transport = MockTransport::new();
    transport.ok(json!({ "subscription": { "id": 7 } }));
    transport.ok(json!({ "subscription": [] }));

    let client = client(transport);
    assert_eq!(
        client.list_dyndns_subscriptions(1, 5).await.unwrap().len(),
        1
    );
    assert_eq!(
        client
            .list_dyndns_subscription_products(1, 5)
            .await
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn record_set_and_document_helpers() {
    // The apex spelling used by `apex_normalised` for an empty name.
    let mut set = RecordSet::new().unwrap();
    assert!(set.push(RecordSpec::txt("@", "x").unwrap()).is_ok());
    assert_eq!(set.records().len(), 1);

    let document = Document::parse(r#"{"pdf":"JVBERi0="}"#).unwrap();
    assert!(document.is_pdf());
    assert!(!Document::parse(r#"{"raw":"x"}"#).unwrap().is_pdf());

    // Two records of the same type at the same name but different content are
    // both allowed (round-robin A records).
    let mut set = RecordSet::new().unwrap();
    set.push(RecordSpec::a("www", "203.0.113.7").unwrap())
        .unwrap();
    set.push(RecordSpec::a("www", "203.0.113.8").unwrap())
        .unwrap();
    assert_eq!(set.len(), 2);
}

#[test]
fn remaining_public_accessors_and_parsers() {
    // `DynDnsRecord` accessors and `CertificateLogEntry::net_price`.
    let record: DynDnsRecord = serde_json::from_str(
        r#"{"id":"1","name":"home","type":"AAAA","content":"2001:db8::1","ttl":60}"#,
    )
    .unwrap();
    assert_eq!(record.name.as_deref(), Some("home"));
    assert_eq!(record.ttl, Some(60));

    let entry: CertificateLogEntry = serde_json::from_str(r#"{"netto":1.5}"#).unwrap();
    assert!((entry.net_price() - 1.5).abs() < 1e-9);

    let product: CertificateProduct = serde_json::from_str(r#"{"wildcard":false}"#).unwrap();
    assert!(!product.is_wildcard());

    // `RefundRequest::intent` and `PostalDelivery` accessors.
    let intent = Irreversible::acknowledge(inwx_client::ActionKind::Refund, &domain("a.de"));
    let refund = RefundRequest::new(intent, 3, 1.0).unwrap();
    assert_eq!(refund.intent().domain().as_str(), "a.de");
    let delivery = PostalDelivery::new("2026-0042", false).unwrap();
    assert_eq!(delivery.params()["acceptCosts"], false);

    // `HostingPeriod` parsing from a string, including a non-numeric one.
    assert!("abc".parse::<HostingPeriod>().is_err());
    assert_eq!("18".parse::<HostingPeriod>().unwrap().months(), 18);
}

#[test]
fn listing_helpers_report_empty_and_full_pages() {
    let page: inwx_client::DomainListPage =
        serde_json::from_str(r#"{"count":0,"domain":[]}"#).unwrap();
    assert_eq!(page.len(), 0);
    assert_eq!(page.len(), 0);
    assert!(!page.has_more());

    let full: inwx_client::DomainListPage =
        serde_json::from_str(r#"{"count":40,"domain":[{"domain":"a.de"},{"domain":"b.de"}]}"#)
            .unwrap();
    assert_eq!(full.len(), 2);
    assert!(full.has_more());
}

// ------------------------------------------------------------ reseller #22 --

#[test]
fn reseller_value_types_run_their_trait_impls() {
    // `ApplicationType`: `Display`, `Debug`, `FromStr`, `Serialize`, `Deserialize`.
    let application_type: ApplicationType = "domain-transfer".parse().unwrap();
    assert_eq!(application_type.to_string(), "DOMAIN-TRANSFER");
    assert_eq!(
        format!("{application_type:?}"),
        "ApplicationType(\"DOMAIN-TRANSFER\")"
    );
    assert_eq!(
        serde_json::to_string(&application_type).unwrap(),
        "\"DOMAIN-TRANSFER\""
    );
    let carried: ApplicationType = serde_json::from_str("\"whatever else\"").unwrap();
    assert_eq!(carried.as_str(), "WHATEVER ELSE");

    // `AuthInfo2`: parsing, serde, and the non-ASCII branch.
    let secret: AuthInfo2 = "aB3-xY9".parse().unwrap();
    assert_eq!(serde_json::to_string(&secret).unwrap(), "\"aB3-xY9\"");
    let round: AuthInfo2 = serde_json::from_str("\"aB3-xY9\"").unwrap();
    assert_eq!(round, secret);
    assert!(serde_json::from_str::<AuthInfo2>("\"\"").is_err());
    let err = AuthInfo2::new("geheim\u{e4}").unwrap_err();
    assert!(err.is_validation());

    // The read helpers of the small answer types.
    let news: NewsItem = serde_json::from_str(r#"{"id":1,"read":1}"#).unwrap();
    assert_eq!(news.is_read(), Some(true));
    let handle: NicHandle = serde_json::from_str(r#"{"nicId":1,"deleted":0}"#).unwrap();
    assert_eq!(handle.is_deleted(), Some(false));
    let settings: ContactVerificationSettings =
        serde_json::from_str(r#"{"verified":"1"}"#).unwrap();
    assert_eq!(settings.is_verified(), Some(true));
    let export: DataExport = serde_json::from_str(r#"{"status":"PENDING"}"#).unwrap();
    assert!(export.is_pending());

    // A downloaded document is a PDF by name, by magic bytes, or not at all.
    let by_name: DownloadedDocument =
        serde_json::from_str(r#"{"filename":"X.PDF","content":"aGk="}"#).unwrap();
    assert!(by_name.is_pdf());
    let by_magic: DownloadedDocument =
        serde_json::from_str(r#"{"filename":"x.bin","content":"JVBERi0xLjc="}"#).unwrap();
    assert!(by_magic.is_pdf());
    let text: DownloadedDocument =
        serde_json::from_str(r#"{"filename":"x.txt","content":"aGk="}"#).unwrap();
    assert!(!text.is_pdf());
    assert!(DownloadedDocument::default().bytes().is_err());
    assert!(PdfFile::default().bytes().is_err());
}

#[test]
fn reseller_builders_send_every_field_they_carry() {
    let domain = DomainName::parse("example.com").unwrap();
    let renew = ApplicationType::parse("renew").unwrap();

    // `application.check`: every selector at once.
    let check = ApplicationCheck::new()
        .with_id(7)
        .unwrap()
        .with_type(renew.clone())
        .with_name("example.com")
        .unwrap()
        .with_domain(domain.clone())
        .with_country_code("de")
        .unwrap();
    let params = check.params().unwrap();
    assert_eq!(params["applicationId"], 7);
    assert_eq!(params["type"], "RENEW");
    assert_eq!(params["cc"], "DE");

    // `application.create`: domain, comment and dry run.
    let create = ApplicationCreate::new(renew.clone(), "example.com")
        .unwrap()
        .with_domain(domain.clone())
        .with_customer_number(123_456)
        .unwrap()
        .with_comment("urgent")
        .unwrap()
        .with_testing(true);
    let params = create.params();
    assert_eq!(params["domainName"], "example.com");
    assert_eq!(params["comment"], "urgent");
    assert_eq!(params["testing"], true);

    // `application.list`: every filter.
    let query = ApplicationQuery::new()
        .with_id(3)
        .unwrap()
        .with_type(renew.clone())
        .with_customer_number(9)
        .unwrap()
        .with_status("pending")
        .unwrap()
        .with_page(2, 10)
        .unwrap();
    let params = query.params().unwrap();
    assert_eq!(params["applicationId"], 3);
    assert_eq!(params["type"], "RENEW");
    assert_eq!(params["status"], "PENDING");
    assert_eq!(params["page"], 2);

    // `application.update`: every changed field.
    let update = ApplicationUpdate::new(11)
        .unwrap()
        .with_name("example.net")
        .unwrap()
        .with_domain(domain.clone())
        .with_customer_number(123_456)
        .unwrap()
        .with_comment("note")
        .unwrap()
        .with_testing(true);
    let params = update.params().unwrap();
    assert_eq!(params["name"], "example.net");
    assert_eq!(params["domainName"], "example.com");
    assert_eq!(params["customerNumber"], 123_456);
    assert_eq!(params["testing"], true);

    // `customer.update`: the address fields no other test touched.
    let customer = CustomerUpdate::new(123_456)
        .unwrap()
        .with_company("ACME GmbH")
        .unwrap()
        .with_street("Hauptstr. 1")
        .unwrap()
        .with_city("Leipzig")
        .unwrap()
        .with_zip("04109")
        .unwrap()
        .with_country_code("de")
        .unwrap()
        .with_phone("+49341000000")
        .unwrap()
        .with_fax("+49341000001")
        .unwrap()
        .with_vat("DE1234567890")
        .unwrap()
        .with_comment("moved")
        .unwrap()
        .with_testing(true);
    let params = customer.params().unwrap();
    assert_eq!(params["company"], "ACME GmbH");
    assert_eq!(params["street"], "Hauptstr. 1");
    assert_eq!(params["phone"], "+49341000000");
    assert_eq!(params["fax"], "+49341000001");
    assert_eq!(params["vat"], "DE1234567890");
    assert_eq!(params["testing"], true);

    // `customer.contactverificationsettingsupdate`.
    let settings = ContactVerificationSettingsUpdate::new(123_456)
        .unwrap()
        .with_verification_type("email")
        .unwrap()
        .with_verified(true)
        .with_testing(true);
    let params = settings.params().unwrap();
    assert_eq!(params["type"], "EMAIL");
    assert_eq!(params["verified"], true);
    assert_eq!(params["testing"], true);
}

#[test]
fn reseller_documents_and_pdfs_fill_their_parameters() {
    let domain = DomainName::parse("example.com").unwrap();

    let upload = DocumentUpload::new("mandate.pdf", b"%PDF-1.7")
        .unwrap()
        .with_document_type("mandate")
        .unwrap()
        .with_customer_number(123_456)
        .unwrap()
        .with_domain(domain.clone())
        .with_comment("signed")
        .unwrap()
        .with_testing(true);
    let params = upload.params();
    assert_eq!(params["domainName"], "example.com");
    assert_eq!(params["comment"], "signed");
    assert_eq!(params["testing"], true);

    let query = DocumentQuery::new()
        .with_document_type("mandate")
        .unwrap()
        .with_customer_number(123_456)
        .unwrap()
        .with_domain(domain.clone())
        .with_filename("mandate.pdf")
        .unwrap()
        .with_page(1, 5)
        .unwrap();
    let params = query.params().unwrap();
    assert_eq!(params["type"], "MANDATE");
    assert_eq!(params["customerNumber"], 123_456);
    assert_eq!(params["domainName"], "example.com");
    assert_eq!(params["filename"], "mandate.pdf");
    assert_eq!(params["pagelimit"], 5);

    let render = PdfRender::new("invoice", 4711)
        .unwrap()
        .with_customer_number(123_456)
        .unwrap()
        .with_format(DocumentFormat::Raw)
        .unwrap()
        .with_from(Timestamp::parse("2026-01-01T00:00:00").unwrap())
        .with_to(Timestamp::parse("2026-02-01T00:00:00").unwrap())
        .with_testing(true);
    let params = render.params().unwrap();
    assert_eq!(params["customerNumber"], 123_456);
    assert_eq!(params["format"], "RAW");
    assert_eq!(params["testing"], true);

    let handles = NicHandleQuery::new()
        .with_handle("H-1")
        .unwrap()
        .with_name("Max Mustermann")
        .unwrap()
        .with_email("max@example.com")
        .unwrap()
        .with_customer_number(123_456)
        .unwrap()
        .with_type("person")
        .unwrap()
        .with_page(1, 3)
        .unwrap();
    let params = handles.params().unwrap();
    assert_eq!(params["name"], "Max Mustermann");
    assert_eq!(params["email"], "max@example.com");
    assert_eq!(params["customerNumber"], 123_456);
    assert_eq!(params["type"], "PERSON");
}

#[test]
fn reseller_hosts_cover_the_testing_and_rename_fields() {
    let domain = DomainName::parse("example.com").unwrap();
    let address = parse_ip("198.51.100.1").unwrap();

    let create = HostCreate::new(domain.clone(), Hostname::parse("ns1").unwrap(), &[address])
        .unwrap()
        .with_testing(true);
    assert_eq!(create.params().unwrap()["testing"], true);

    let update = HostUpdate::new(3001)
        .unwrap()
        .with_name(Hostname::parse("ns2").unwrap())
        .unwrap()
        .with_addresses(&[address])
        .unwrap()
        .with_testing(true);
    let params = update.params().unwrap();
    assert_eq!(params["name"], "ns2");
    assert_eq!(params["testing"], true);

    // A single label below a long domain must still fit in 253 characters:
    // 57 + 1 + 195 is the last name that does.
    let long_domain = format!(
        "{}.{}.{}.com",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63)
    );
    let long_domain = DomainName::parse(&long_domain).unwrap();
    assert_eq!(long_domain.as_str().len(), 195);
    assert!(HostCheck::new(
        long_domain.clone(),
        Hostname::parse(&"n".repeat(57)).unwrap()
    )
    .is_ok());
    assert!(HostCheck::new(long_domain, Hostname::parse(&"n".repeat(58)).unwrap()).is_err());
}

// --------------------------------------------------------- account roles (#74)

#[tokio::test]
async fn account_roles_reads_both_spellings_of_the_answer_list() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "roles": [
            {"handle": "4711", "role": "TECH", "customer": "example"},
            {"handle": 4712, "role": "TRUSTEE", "username": "other", "extra": true}
        ]
    }));
    let client = client(transport.clone());
    let rows = client.account_roles().await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].handle, Some(4711));
    assert_eq!(rows[0].role, Some(AccountRole::Tech));
    assert_eq!(rows[0].customer.as_deref(), Some("example"));
    assert_eq!(rows[1].role, Some(AccountRole::Other("TRUSTEE".into())));
    assert_eq!(rows[1].customer.as_deref(), Some("other"));

    // A single object arrives as one row ...
    transport.ok(json!({ "role": { "handle": 1, "role": "OWNER" } }));
    let rows = client.account_roles().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].role, Some(AccountRole::Owner));

    // ... and an answer without either key is simply empty.
    transport.ok(json!({}));
    let rows = client.account_roles().await.unwrap();
    assert_eq!(rows, Vec::new());
}

#[tokio::test]
async fn add_role_and_remove_role_send_the_expected_command() {
    let transport = MockTransport::new();
    transport.ok_empty();
    let client = client(transport.clone());
    client.add_role(4711, &AccountRole::Tech).await.unwrap();
    let call = transport.only_call();
    assert_eq!(call.method, "account.addrole");
    assert_eq!(call.params, json!({"handle": 4711, "role": "TECH"}));

    transport.ok_empty();
    client.remove_role(4711, &AccountRole::None).await.unwrap();
    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].method, "account.removerole");
    assert_eq!(calls[1].params, json!({"handle": 4711, "role": "NONE"}));
}

#[tokio::test]
async fn an_account_role_command_stops_at_the_handle_and_role_limits() {
    let transport = MockTransport::new();
    let client = client(transport.clone());

    // Just inside the 255-character role limit: the request goes out.
    transport.ok_empty();
    client
        .add_role(1, &AccountRole::Other("x".repeat(255)))
        .await
        .unwrap();
    assert_eq!(transport.call_count(), 1);

    // Just outside it, and a handle that is not positive: refused before the
    // socket is touched.
    assert!(client
        .add_role(1, &AccountRole::Other("x".repeat(256)))
        .await
        .is_err());
    assert!(client.add_role(0, &AccountRole::Tech).await.is_err());
    assert!(client.remove_role(-1, &AccountRole::Tech).await.is_err());
    assert!(client
        .remove_role(1, &AccountRole::Other(" ".into()))
        .await
        .is_err());
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn an_uncertain_failure_replays_getroles_but_not_removerole() {
    let transport = MockTransport::new();
    transport.uncertain_failure("timeout waiting for response");
    transport.ok(json!({ "roles": [] }));

    let client = client(transport.clone());
    let rows = client.account_roles().await.unwrap();
    assert_eq!(rows, Vec::new());
    assert_eq!(transport.call_count(), 2);

    transport.uncertain_failure("timeout waiting for response");
    transport.ok_empty();
    let error = client
        .remove_role(4711, &AccountRole::Tech)
        .await
        .unwrap_err();
    assert!(error.is_uncertain());
    assert_eq!(transport.call_count(), 3);
}

#[test]
fn account_role_display_and_serde_cover_the_error_branches() {
    assert_eq!(
        " admin ".parse::<AccountRole>().unwrap(),
        AccountRole::Admin
    );
    assert!("".parse::<AccountRole>().is_err());
    assert_eq!(
        serde_json::to_string(&AccountRole::Tech).unwrap(),
        "\"TECH\""
    );
    assert_eq!(
        serde_json::to_string(&AccountRole::Other("TRUSTEE".into())).unwrap(),
        "\"TRUSTEE\""
    );
    assert_eq!(
        serde_json::from_str::<AccountRole>("\"trustee\"").unwrap(),
        AccountRole::Other("TRUSTEE".into())
    );
    // Empty and non-string inputs fail instead of silently becoming a role.
    assert!(serde_json::from_str::<AccountRole>("\"\"").is_err());
    assert!(serde_json::from_str::<AccountRole>("null").is_err());
    assert!(serde_json::from_str::<AccountRole>("7").is_err());

    // The row model accepts nulls and ignores unknown fields.
    let row: AccountRoleEntry =
        serde_json::from_str(r#"{"handle":null,"role":null,"customer":null,"extra":1}"#).unwrap();
    assert_eq!(row, AccountRoleEntry::default());
}
