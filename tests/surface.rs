//! Every public builder, accessor and trait impl gets exercised here.
//!
//! The other test files prove behaviour; this one is the completeness sweep that
//! keeps line coverage honest — a setter nobody calls is a setter nobody has
//! tested.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::str::FromStr;

use inwx_client::{
    rpc::{self, Detail, RpcRequest, RpcResponse},
    transport::{Request, Response},
    AccountInfo, Contact, ContactQuery, ContactRequest, ContactType, ContactUpdate, Credentials,
    DnsRecord, DomainCheck, DomainCreate, DomainInfo, DomainListPage, DomainListQuery, DomainName,
    DomainPriceQuote, DomainRenew, DomainUpdate, Error, Hostname, InwxClient, Language,
    NameserverCheck, Period, PriceList, PriceType, RecordId, RecordSpec, RecordType, RecordUpdate,
    RenewalMode, RetryPolicy, TldPrice, ZoneInfo, ZoneListPage, ZoneSummary,
};
use serde_json::json;

fn domain(name: &str) -> DomainName {
    DomainName::parse(name).unwrap()
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Holder {
    host: Hostname,
}

#[test]
fn domain_name_traits_and_accessors() {
    let name = domain("Shop.Example.CO.UK");
    assert_eq!(name.as_str(), "shop.example.co.uk");
    assert_eq!(name.to_string(), "shop.example.co.uk");
    assert_eq!(name.tld(), "uk");
    assert_eq!(name.sld(), "co");
    assert_eq!(name.as_ref(), "shop.example.co.uk");
    assert_eq!(format!("{name:?}"), "DomainName(\"shop.example.co.uk\")");
    assert_eq!(DomainName::try_from("a.de").unwrap(), domain("a.de"));
    assert_eq!(DomainName::from_str("a.de").unwrap().as_str(), "a.de");
    assert!(!name.is_idn());

    // Ordering matters for deterministic output.
    let mut names = [domain("b.de"), domain("a.de")];
    names.sort();
    assert_eq!(names[0].as_str(), "a.de");
    let mut map = HashMap::new();
    map.insert(name.clone(), 1);
    assert_eq!(map[&domain("shop.example.co.uk")], 1);
}

#[test]
fn hostname_traits() {
    let host = Hostname::parse("NS1.Example.COM.").unwrap();
    assert_eq!(host.as_str(), "ns1.example.com");
    assert_eq!(host.to_string(), "ns1.example.com");
    assert_eq!(host.as_ref(), "ns1.example.com");
    assert_eq!(format!("{host:?}"), "Hostname(\"ns1.example.com\")");
    assert_eq!(
        "ns2.example.com".parse::<Hostname>().unwrap().as_str(),
        "ns2.example.com"
    );
    assert!(Hostname::parse("ns1..example.com").is_err());

    // Serde both ways, including a value that fails validation on the way in.
    let encoded = serde_json::to_string(&Holder { host: host.clone() }).unwrap();
    assert_eq!(encoded, r#"{"host":"ns1.example.com"}"#);
    let decoded: Holder = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.host, host);
    assert!(serde_json::from_str::<Holder>(r#"{"host":"not a host"}"#).is_err());
}

#[test]
fn period_traits() {
    assert_eq!(Period::OneMonth.to_string(), "1M");
    assert_eq!(Period::ONE_MONTH, Period::OneMonth);
    assert_eq!(Period::years(3).unwrap().to_string(), "3Y");
    assert_eq!("10Y".parse::<Period>().unwrap(), Period::Years(10));
    assert!("1m".parse::<Period>().is_ok());
    assert_eq!(
        serde_json::to_string(&Period::years(2).unwrap()).unwrap(),
        "\"2Y\""
    );
    assert!(Period::years(0).is_err());
}

#[test]
fn renewal_mode_traits() {
    for (text, expected) in [
        ("AUTORENEW", RenewalMode::AutoRenew),
        ("autodelete", RenewalMode::AutoDelete),
        ("AutoExpire", RenewalMode::AutoExpire),
    ] {
        assert_eq!(RenewalMode::from_str(text).unwrap(), expected);
        assert_eq!(expected.to_string(), expected.as_str());
    }
    let custom = RenewalMode::Other("MANUAL".into());
    assert_eq!(custom.to_string(), "MANUAL");
    assert_eq!(serde_json::to_string(&custom).unwrap(), "\"MANUAL\"");
    let parsed: RenewalMode = serde_json::from_str("\"AUTODELETE\"").unwrap();
    assert_eq!(parsed, RenewalMode::AutoDelete);
    assert!(serde_json::from_str::<RenewalMode>("\"\"").is_err());
}

#[test]
fn contact_type_traits() {
    assert_eq!(ContactType::Org.to_string(), "ORG");
    assert_eq!(ContactType::Role.to_string(), "ROLE");
    assert_eq!(ContactType::Person.to_string(), "PERSON");
    assert_eq!(ContactType::Other("TRUSTEE".into()).to_string(), "TRUSTEE");
    assert_eq!(ContactType::from_str("role").unwrap(), ContactType::Role);
    assert_eq!(serde_json::to_string(&ContactType::Org).unwrap(), "\"ORG\"");
    let parsed: ContactType = serde_json::from_str("\"trustee\"").unwrap();
    assert_eq!(parsed, ContactType::Other("TRUSTEE".into()));
    assert!(ContactType::parse("").is_err());
    assert!(serde_json::from_str::<ContactType>("\"\"").is_err());
}

#[test]
fn price_type_traits() {
    assert_eq!(PriceType::Reg.to_string(), "reg");
    assert_eq!(PriceType::Renewal.as_str(), "renewal");
    assert_eq!(PriceType::Transfer.as_str(), "transfer");
    assert_eq!(PriceType::Trade.as_str(), "trade");
    assert_eq!(PriceType::Update.as_str(), "update");
    assert_eq!(PriceType::Restore.as_str(), "restore");
    assert_eq!(PriceType::from_str("RENEWAL").unwrap(), PriceType::Renewal);
    assert_eq!(
        PriceType::from_str("transfer").unwrap(),
        PriceType::Transfer
    );
    assert!(PriceType::from_str("gift").is_err());
}

#[test]
fn record_type_traits_and_helpers() {
    assert_eq!(RecordType::Aaaa.to_string(), "AAAA");
    assert_eq!(RecordType::from_str("mx").unwrap(), RecordType::Mx);
    assert!(RecordType::A.is_address());
    assert!(RecordType::Aaaa.is_address());
    assert!(RecordType::Alias.requires_hostname());
    assert!(RecordType::Ptr.requires_hostname());
    assert!(RecordType::Srv.requires_hostname());
    assert_eq!(
        serde_json::to_string(&RecordType::Tlsa).unwrap(),
        "\"TLSA\""
    );
    let parsed: RecordType = serde_json::from_str("\"caa\"").unwrap();
    assert_eq!(parsed, RecordType::Caa);
    assert!(serde_json::from_str::<RecordType>("\"\"").is_err());
    assert_eq!(RecordType::ALL.len(), 26);
}

#[test]
fn record_id_traits() {
    assert_eq!(RecordId::from("7").to_string(), "7");
    assert_eq!(RecordId::from(String::from("8")).as_str(), "8");
    assert_eq!(format!("{:?}", RecordId::from("9")), "RecordId(\"9\")");
    assert_eq!(
        serde_json::to_string(&RecordId::from("10")).unwrap(),
        "\"10\""
    );
    let from_number: RecordId = serde_json::from_str("11").unwrap();
    assert_eq!(from_number.as_str(), "11");
    // Ordering is by the underlying string, which is fine for ids.
    assert!(RecordId::from("2") < RecordId::from("20"));
}

#[test]
fn every_record_spec_constructor_and_accessor() {
    let cname = RecordSpec::cname("shop", &Hostname::parse("stores.example.net").unwrap()).unwrap();
    assert_eq!(cname.content(), "stores.example.net");
    assert_eq!(cname.record_type(), RecordType::Cname);
    assert_eq!(cname.name(), "shop");

    let aaaa = RecordSpec::aaaa("www", "2001:db8::1").unwrap();
    assert_eq!(aaaa.content(), "2001:db8::1");

    let with_prio = RecordSpec::txt("@", "x").unwrap().with_prio(7);
    assert_eq!(with_prio.params()["prio"], 7);

    let mx = RecordSpec::mx("@", 10, &Hostname::parse("mx.example.com").unwrap()).unwrap();
    assert_eq!(mx.params()["type"], "MX");
    assert_eq!(mx.ttl(), inwx_client::DEFAULT_TTL);
}

#[test]
fn every_record_update_setter() {
    let update = RecordUpdate::new([RecordId::from(1), RecordId::from(2)])
        .name("www")
        .record_type(RecordType::Aaaa)
        .content("2001:db8::2")
        .with_ttl(120)
        .unwrap()
        .prio(3);
    let params = update.params().unwrap();
    assert_eq!(params["name"], "www");
    assert_eq!(params["type"], "AAAA");
    assert_eq!(params["content"], "2001:db8::2");
    assert_eq!(params["ttl"], 120);
    assert_eq!(params["prio"], 3);
    assert_eq!(params["id"], json!(["1", "2"]));

    // A name-only change is enough; content is not re-validated without a type.
    let rename = RecordUpdate::new([RecordId::from(1)]).name("api");
    assert!(rename.params().is_ok());

    // A name that is too long is refused.
    let long = RecordUpdate::new([RecordId::from(1)]).name("a".repeat(254));
    assert!(long.params().is_err());
}

#[test]
fn record_spec_name_length_is_bounded() {
    let long_name = "a".repeat(254);
    assert!(RecordSpec::txt(long_name, "x").is_err());
    let longest = "a".repeat(253);
    assert!(RecordSpec::txt(longest, "x").is_ok());
}

#[test]
fn every_domain_create_setter() {
    let request = DomainCreate::new(domain("example.com"), 991)
        .unwrap()
        .with_period(Period::years(2).unwrap())
        .with_admin(2)
        .with_tech(3)
        .with_billing(4)
        .with_nameservers(&[Hostname::parse("ns1.example.com").unwrap()])
        .with_transfer_lock(false)
        .with_renewal_mode(RenewalMode::AutoDelete)
        .with_agreed_price(250.5)
        .with_voucher("SUMMER");
    assert_eq!(request.domain().as_str(), "example.com");

    let params = request.params();
    assert_eq!(params["period"], "2Y");
    assert_eq!(params["admin"], 2);
    assert_eq!(params["tech"], 3);
    assert_eq!(params["billing"], 4);
    assert_eq!(params["transferLock"], false);
    assert_eq!(params["renewalMode"], "AUTODELETE");
    assert_eq!(params["agreedPrice"], 250.5);
    assert_eq!(params["voucher"], "SUMMER");
    assert_eq!(params["ns"][0], "ns1.example.com");
    assert_eq!(params["registrant"], 991);
}

#[test]
fn every_domain_update_setter() {
    let update = DomainUpdate::new(domain("example.com"))
        .with_registrant(1)
        .with_admin(2)
        .with_tech(3)
        .with_billing(4)
        .with_nameservers(&[Hostname::parse("ns1.example.net").unwrap()])
        .with_transfer_lock(true)
        .with_renewal_mode(RenewalMode::AutoRenew)
        .with_auth_code("AUTH")
        .with_period(Period::years(3).unwrap());
    let params = update.params().unwrap();

    assert_eq!(params["registrant"], 1);
    assert_eq!(params["admin"], 2);
    assert_eq!(params["tech"], 3);
    assert_eq!(params["billing"], 4);
    assert_eq!(params["ns"][0], "ns1.example.net");
    assert_eq!(params["transferLock"], true);
    assert_eq!(params["renewalMode"], "AUTORENEW");
    assert_eq!(params["authCode"], "AUTH");
    assert_eq!(params["period"], "3Y");
    assert_eq!(params["domain"], "example.com");
}

#[test]
fn domain_renew_params_and_query_paging() {
    let renew = DomainRenew::new(domain("a.de"), Period::OneMonth, "2027-01-31").unwrap();
    assert_eq!(renew.params()["period"], "1M");

    let query = DomainListQuery::new()
        .with_filter("acme")
        .with_status(["ok"])
        .with_page(2, 20);
    let params = query.params();
    assert_eq!(params["page"], 2);
    assert_eq!(params["pagelimit"], 20);
    assert_eq!(params["status"][0], "ok");
    assert_eq!(query, query.clone());

    let contact_query = ContactQuery::new().with_search("x").with_page(3, 7);
    assert_eq!(contact_query.params()["page"], 3);
    assert_eq!(ContactQuery::new().params(), json!({}));
}

#[test]
fn every_contact_request_setter() {
    let request = ContactRequest::new(ContactType::Org, "ACME GmbH", "ops@acme.test")
        .unwrap()
        .with_org("ACME GmbH")
        .with_street("Weg 2")
        .with_city("Berlin")
        .with_postcode("10115")
        .with_state("BE")
        .with_country("de")
        .with_voice("+49.891")
        .with_fax("+49.892")
        .with_remarks("Mo-Fr");
    let params = request.params();

    assert_eq!(params["sp"], "BE");
    assert_eq!(params["fax"], "+49.892");
    assert_eq!(params["remarks"], "Mo-Fr");
    assert_eq!(params["cc"], "DE");
    assert!(request.validate().is_ok());
}

#[test]
fn every_contact_update_setter() {
    let update = ContactUpdate::new(991)
        .unwrap()
        .with_name("Erika")
        .with_org("ACME")
        .with_street("Weg 2")
        .with_city("Berlin")
        .with_postcode("10115")
        .with_state("BE")
        .with_country("de")
        .with_voice("+49.891")
        .with_fax("+49.892")
        .with_email("erika@example.com")
        .with_remarks("x");
    let params = update.params().unwrap();

    assert_eq!(params["name"], "Erika");
    assert_eq!(params["org"], "ACME");
    assert_eq!(params["street"], "Weg 2");
    assert_eq!(params["city"], "Berlin");
    assert_eq!(params["pc"], "10115");
    assert_eq!(params["sp"], "BE");
    assert_eq!(params["cc"], "DE");
    assert_eq!(params["voice"], "+49.891");
    assert_eq!(params["fax"], "+49.892");
    assert_eq!(params["email"], "erika@example.com");
    assert_eq!(params["remarks"], "x");
    assert_eq!(params["id"], 991);
}

#[test]
fn contact_validation_covers_every_optional_length() {
    let base = || {
        ContactRequest::new(ContactType::Person, "Erika", "erika@example.com")
            .unwrap()
            .with_street("Weg 2")
            .with_city("Berlin")
            .with_postcode("10115")
            .with_country("DE")
            .with_voice("+49.891")
    };

    assert!(base().with_org("x".repeat(256)).validate().is_err());
    assert!(base().with_state("x".repeat(65)).validate().is_err());
    assert!(base().with_fax("x".repeat(65)).validate().is_err());
    assert!(base().with_remarks("x".repeat(256)).validate().is_err());
    assert!(base().with_city("x".repeat(65)).validate().is_err());
    assert!(base().with_voice("x".repeat(65)).validate().is_err());
    assert!(base().with_street("x".repeat(65)).validate().is_err());
}

#[test]
fn transport_request_accessors() {
    let body = b"{}";
    let request = Request::post_json("https://example.test/jsonrpc/", body)
        .with_header("Content-Type", "application/json")
        .with_header("Cookie", "a=b")
        .with_timeout(Some(std::time::Duration::from_secs(3)));
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(request.header("cookie"), Some("a=b"));
    assert_eq!(request.header("missing"), None);
    assert_eq!(request.timeout, Some(std::time::Duration::from_secs(3)));
    assert_eq!(request.url, "https://example.test/jsonrpc/");
    assert_eq!(request.body, body);

    let response = Response::new(
        200,
        [("X-Test".to_owned(), "1".to_owned())],
        br#"{"a":1}"#.to_vec(),
    );
    assert_eq!(response.status(), 200);
    assert_eq!(response.header("x-test"), Some("1"));
    assert_eq!(response.header("missing"), None);
    assert!(response.is_success());
    assert_eq!(response.json().unwrap()["a"], 1);
    assert_eq!(response.body(), br#"{"a":1}"#);
}

#[test]
fn rpc_request_and_detail_types() {
    let request = RpcRequest::new("account.check", &json!({"a": 1}));
    assert_eq!(request.method, "account.check");
    assert_eq!(request.params["a"], 1);
    assert!(String::from_utf8(request.to_bytes().unwrap())
        .unwrap()
        .contains("account.check"));

    let detail = Detail {
        code: "X".into(),
        msg: "why".into(),
    };
    let encoded = serde_json::to_string(&detail).unwrap();
    let decoded: Detail = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, detail);
    let empty: Detail = serde_json::from_str("{}").unwrap();
    assert_eq!(empty.code, "");

    assert!(rpc::is_success_code(1500));
    assert!(!rpc::is_success_code(1501));
    assert_eq!(rpc::CODE_SUCCESS, 1000);
}

#[test]
fn rpc_response_accessors() {
    let response = RpcResponse::parse(
        br#"{"code":1000,"msg":"ok","resData":{"id":1},"svTRID":"abc","runtime":0.5,"details":[]}"#,
    )
    .unwrap();
    assert_eq!(response.code, 1000);
    assert_eq!(response.msg, "ok");
    assert_eq!(response.sv_trid.as_deref(), Some("abc"));
    assert_eq!(response.runtime, Some(0.5));
    assert_eq!(response.details.len(), 0);
    assert!(response.reason_code.is_none());
    assert!(response.reason.is_none());
    assert_eq!(response.error_message(), "ok");
    assert!(response.is_success());
    assert!(!response.is_authentication());

    let cloned = response.clone();
    assert_eq!(cloned.code, 1000);
    let encoded = serde_json::to_string(&response).unwrap();
    assert!(encoded.contains("svTRID"));
}

#[test]
fn error_helpers_cover_every_branch() {
    assert_eq!(Error::validation("f", "m").code(), None);
    assert!(Error::validation("f", "m").to_string().contains('f'));

    let api = Error::Api {
        code: 2300,
        message: "pending".into(),
        reason_code: Some("PENDING".into()),
        reason: None,
        details: Vec::new(),
    };
    assert!(api.is_retryable());
    assert!(!api.is_authentication());

    let auth = Error::Authentication {
        message: "no cookie".into(),
    };
    assert!(auth.is_authentication());
    assert!(!auth.is_retryable());
    assert!(Error::NotAuthenticated.is_authentication());

    let transport = Error::Transport {
        message: "reset".into(),
        retryable: false,
    };
    assert!(!transport.is_retryable());

    let ambiguous = Error::ambiguous("timeout");
    assert!(ambiguous.is_ambiguous());
    assert!(!ambiguous.is_retryable());
    assert!(ambiguous.to_string().contains("timeout"));
    assert!(!Error::transport("refused").is_ambiguous());

    let missing = Error::MissingField {
        method: "domain.info",
        field: "resData.id",
    };
    assert!(missing.to_string().contains("domain.info"));

    let http = Error::Http {
        status: 502,
        body: "bad gateway".into(),
    };
    assert!(http.to_string().contains("502"));
}

#[test]
fn client_configuration_round_trips() {
    use inwx_client::transport::{Request as TRequest, Response as TResponse, Transport};

    struct Never;
    impl Transport for Never {
        async fn execute(&self, _request: TRequest<'_>) -> inwx_client::Result<TResponse> {
            std::future::ready(()).await;
            unreachable!("configuration only")
        }
    }

    let client = InwxClient::new(Never)
        .with_credentials("user", "pass")
        .unwrap()
        .with_session("domrobot=s")
        .unwrap()
        .with_base_url("https://inwx.test/")
        .with_timeout(None)
        .with_language(Language::En)
        .with_retry(RetryPolicy::new(2).with_base_delay(std::time::Duration::ZERO));

    assert_eq!(client.base_url(), "https://inwx.test/");
    assert_eq!(client.timeout(), None);
    assert!(client.is_authenticated());
    assert_eq!(Language::En.as_str(), "en");
    assert_eq!(Language::default(), Language::En);
    assert_eq!(Credentials::new("u", "p").unwrap().username(), "u");
    assert_eq!(RetryPolicy::new(0).attempts(), 1);
    assert_eq!(RetryPolicy::default().attempts(), 3);

    client.clear_session();
    assert!(!client.is_authenticated());
    // Debug never shows the cookie.
    client
        .with_session("domrobot=secret")
        .map(|client| assert!(!format!("{client:?}").contains("secret")))
        .unwrap();
}

#[test]
fn response_payload_types_are_constructible_and_comparable() {
    // Defaults exist so callers can build fixtures without the API.
    let check = DomainCheck {
        domain: "a.de".into(),
        avail: Some(1),
        status: Some("free".into()),
        reason: None,
        premium: None,
        price: Some(8.9),
    };
    assert!(check.is_available());
    assert_eq!(check.clone(), check);

    let page = DomainListPage::default();
    assert_eq!(page.len(), 0);
    assert_eq!(page.len(), 0);
    assert!(!page.has_more());

    let zones = ZoneListPage::default();
    assert_eq!(zones.zones.len(), 0);
    assert!(zones.count.is_none());

    let zone = ZoneInfo::default();
    assert!(!zone.is_master());

    let summary = ZoneSummary {
        ro_id: Some(1),
        domain: domain("example.com"),
        zone_type: Some("SLAVE".into()),
        master_ip: Some("203.0.113.1".into()),
        web: None,
        mail: None,
        url: None,
    };
    assert_eq!(summary.domain.as_str(), "example.com");

    let nameserver = NameserverCheck::default();
    assert!(!nameserver.is_ok());
    assert_eq!(nameserver.message.len(), 0);

    let info = DomainInfo::default();
    assert_eq!(info.domain.len(), 0);
    assert!(info.registrant_handle().is_none());

    let record = DnsRecord {
        id: RecordId::from(1),
        name: None,
        record_type: RecordType::Txt,
        content: "x".into(),
        ttl: None,
        prio: None,
    };
    assert_eq!(record.name_or_apex(), "@");
    assert!(record.ip().is_none());
    assert_eq!(record.ttl_seconds(), i64::from(inwx_client::DEFAULT_TTL));
    assert_eq!(record.priority(), 0);

    let price = TldPrice::default();
    assert_eq!(price.tld.len(), 0);
    let list = PriceList::default();
    assert_eq!(list.len(), 0);
    assert!(list.find("de").is_none());

    let quote = DomainPriceQuote::default();
    assert!(quote.price.is_none());

    let contact = Contact::default();
    assert!(contact.handle().is_none());
    assert!(AccountInfo::default().account_id.is_none());
}
