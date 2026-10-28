//! Completeness sweep for the 0.2.0 surface.
//!
//! `cargo llvm-cov` counts test binaries, never doctests, so the `Display`,
//! `FromStr`, `Serialize` and `Deserialize` impls and the error branches that
//! the doctests already exercise have to be called again from here — otherwise
//! the coverage gate reports a crate that is documented but untested.

mod common;

use common::{client, MockTransport};
use inwx_client::{
    parse_ip, AccountBalance, AddDnsKeyRequest, AuthCode, Certificate, CertificateLogEntry,
    CertificateOrder, CertificateProduct, CertificateProductQuery, CertificateQuery,
    CertificateUpdate, CertificateValidationMethod, DnsKey, DnssecAlgorithm, DnssecDigestType,
    DnssecDomainStatus, DnssecFlag, DnssecKeyQuery, DnssecKeyStatus, Document, DocumentFormat,
    DomainName, DsRecord, DynDnsAccount, DynDnsAccountRef, DynDnsRecord, Email, Handle,
    HostingOrder, HostingPeriod, Hostname, Irreversible, NameserverSet, NameserverSetType,
    NameserverSetUpdate, PostalDelivery, RecordSet, RecordSpec, RefundRequest, StatementQuery,
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

#[tokio::test]
async fn domain_read_answers_without_arrays_are_tolerated() {
    // Every shape INWX uses for a result set has to decode into the same list,
    // and a payload that is none of them has to decode into an empty one.
    // (payload, entries it must yield). The zero rows are the payloads that are
    // not a result set at all: they must decode empty instead of failing.
    for (payload, expected) in [
        (json!(null), 0),
        (json!([]), 0),
        (json!({}), 0),
        (json!("text"), 0),
        (json!(42), 0),
        (json!({"logs": "not a list"}), 0),
        (json!({"0": {"action": "create"}}), 1),
        (json!({"logs": [{"action": "create"}]}), 1),
        (json!([{"action": "create"}]), 1),
    ] {
        let transport = MockTransport::new();
        transport.ok(payload.clone());
        let log = client(transport)
            .domain_log(&inwx_client::DomainLogQuery::new(domain("example.com")))
            .await
            .unwrap();
        assert_eq!(log.len(), expected, "payload {payload}");
    }

    // The same sweep for the other three reads.
    for payload in [
        json!(null),
        json!([]),
        json!({}),
        json!("text"),
        json!(true),
    ] {
        let transport = MockTransport::new();
        for _ in 0..3 {
            transport.ok(payload.clone());
        }
        let client = client(transport);
        let stats = client.domain_stats(None).await.unwrap();
        let rules = client.tld_rules("de").await.unwrap();
        let groups = client.tld_groups().await.unwrap();
        assert_eq!((stats.len(), rules.len(), groups.len()), (0, 0, 0));
        assert!(!stats.has_more() && !rules.has_more() && !groups.has_more());
        assert!(stats.find("de").is_none());
        assert!(rules.find("MIN-PERIOD").is_none());
        assert!(groups.find("cctlds").is_none());
        assert!(stats.counter("nope").is_none());
        assert!(stats.amount_for("nope").is_none());
        assert!(stats.text_for("nope").is_none());
        assert!(rules.value_for("nope").is_none());
        assert!(rules.integer_for("nope").is_none());
    }
}

#[test]
fn domain_read_helpers_read_every_scalar_shape() {
    // Numbers, numeric strings, non-numeric strings and non-scalars all reach
    // a defined answer from the flat `domain.stats` shape.
    let stats: inwx_client::DomainStats = serde_json::from_str(
        r#"{"totalDomains":"12","totalAmount":"108.50","state":"active",
            "plain":7,"flagged":true,"nested":{"a":1},"badCount":"many"}"#,
    )
    .unwrap();
    assert_eq!(stats.counter("totalDomains"), Some(12));
    assert_eq!(stats.counter("plain"), Some(7));
    assert_eq!(stats.counter("badCount"), None);
    assert_eq!(stats.counter("flagged"), None);
    assert_eq!(stats.counter("nested"), None);
    assert_eq!(stats.amount_for("totalAmount"), Some(108.5));
    assert_eq!(stats.amount_for("nested"), None);
    assert_eq!(stats.text_for("state"), Some("active"));
    assert_eq!(stats.text_for("plain"), None);
    // Lookup ignores case, surrounding whitespace and a leading dot.
    assert_eq!(stats.counter(" TotalDomains "), Some(12));
    assert_eq!(stats.counter(".totaldomains"), Some(12));

    // A flag value in any of the four spellings, and one that is not a flag.
    for (raw, expected) in [
        ("1", Some(true)),
        ("TRUE", Some(true)),
        (" yes ", Some(true)),
        ("on", Some(true)),
        ("0", Some(false)),
        ("no", Some(false)),
        ("OFF", Some(false)),
        ("01", None),
    ] {
        let rule: inwx_client::DomainRule =
            serde_json::from_str(&format!(r#"{{"value":"{raw}"}}"#)).unwrap();
        assert_eq!(rule.flag(), expected, "{raw:?}");
    }

    // Timestamps that are not timestamps, and the absent case.
    let blank: inwx_client::DomainLogEntry = serde_json::from_str("{}").unwrap();
    assert!(blank.occurred_at().is_none());
    let odd: inwx_client::DomainLogEntry = serde_json::from_str(r#"{"date":1700000000}"#).unwrap();
    assert_eq!(odd.date.as_deref(), Some("1700000000"));
    assert!(odd.occurred_at().is_none());

    // A group with a single `TLD` string is still a one-element list.
    let group: inwx_client::TldGroup = serde_json::from_str(r#"{"tld":"de"}"#).unwrap();
    assert!(group.contains("de"));
    assert!(!group.contains("at"));
}
