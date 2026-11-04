//! The edge-case matrix: everything the API could hand us that is not the happy
//! path, plus the inputs this crate refuses to send.

mod common;

use common::{client, MockTransport};
use inwx_client::{
    rpc::RpcResponse, Contact, ContactQuery, ContactRequest, ContactType, Credentials,
    DomainListQuery, DomainName, Error, Hostname, InwxClient, Page, Pagination, Period, RecordId,
    RecordSpec, RecordType, RecordUpdate, RpcRequest, MAX_TTL,
};
use serde_json::{json, Value};

// ---------------------------------------------------------- credentials

#[test]
fn empty_and_whitespace_credentials_are_refused() {
    assert!(Credentials::new("user", "p").is_ok());
    assert!(Credentials::new("", "pass").is_err());
    assert!(Credentials::new("user", "").is_err());
    assert!(Credentials::new("   ", "pass").is_err());
    assert!(
        Credentials::new("user", "   ").is_ok(),
        "spaces are a legal password"
    );
}

#[test]
fn credentials_compare_both_fields_without_exposing_the_password() {
    let credentials = Credentials::new("user", "pass").unwrap();
    assert_eq!(credentials, Credentials::new("user", "pass").unwrap());
    assert_ne!(credentials, Credentials::new("other", "pass").unwrap());
    assert_ne!(credentials, Credentials::new("user", "pAss").unwrap());
    assert_ne!(credentials, Credentials::new("user", "password").unwrap());
}

#[test]
fn credentials_with_control_characters_are_refused() {
    for (user, pass) in [
        ("us\ner", "pass"),
        ("user", "pa\rs"),
        ("user", "pa\u{0}ss"),
        ("us\ter", "pass"),
    ] {
        assert!(
            Credentials::new(user, pass).is_err(),
            "{user:?}/{pass:?} should be refused"
        );
    }
}

#[test]
fn the_client_refuses_empty_credentials_before_any_call() {
    let transport = MockTransport::new();
    let error = InwxClient::new(transport.clone())
        .with_credentials("", "")
        .unwrap_err();
    assert!(error.is_validation());
    assert_eq!(transport.call_count(), 0);
}

// --------------------------------------------------------------- sessions

#[test]
fn malformed_session_ids_are_refused() {
    let transport = MockTransport::new();
    for cookie in ["", "   ", "a=b\r\nX-Evil: 1", "a=b\n", "a=b\u{0}"] {
        let result = InwxClient::new(transport.clone()).with_session(cookie);
        assert!(result.is_err(), "{cookie:?} should be refused");
    }
    assert!(InwxClient::new(transport)
        .with_session("domrobot=abc; other=1")
        .is_ok());
}

// ------------------------------------------------------------ record types

#[test]
fn an_empty_record_type_is_refused_but_unknown_ones_are_kept() {
    assert!(RecordType::parse("").is_err());
    assert!(RecordType::parse("   ").is_err());

    let unknown = RecordType::parse("x-new-type").unwrap();
    assert_eq!(unknown, RecordType::Other("X-NEW-TYPE".into()));
    assert_eq!(unknown.to_string(), "X-NEW-TYPE");
    assert!(!unknown.is_address());
    assert!(!unknown.requires_hostname());
}

#[test]
fn record_types_are_case_insensitive_and_trimmed() {
    assert_eq!(RecordType::parse("  aaaa ").unwrap(), RecordType::Aaaa);
    assert_eq!(RecordType::parse("txt").unwrap(), RecordType::Txt);
}

// -------------------------------------------------------------- ip records

#[test]
fn an_a_record_refuses_ipv6_and_an_aaaa_record_refuses_ipv4() {
    let error = RecordSpec::a("www", "2001:db8::1").unwrap_err();
    assert!(matches!(
        error,
        Error::Validation {
            field: "record.content",
            ..
        }
    ));

    let error = RecordSpec::aaaa("www", "203.0.113.7").unwrap_err();
    assert!(matches!(
        error,
        Error::Validation {
            field: "record.content",
            ..
        }
    ));

    assert!(RecordSpec::a("www", "203.0.113.7").is_ok());
    assert!(RecordSpec::aaaa("www", "2001:db8::1").is_ok());
    assert!(RecordSpec::a("www", "::1").is_err());
}

#[test]
fn a_name_based_record_refuses_an_ip_literal() {
    assert!(RecordSpec::new(RecordType::Cname, "www", "203.0.113.7").is_err());
    assert!(RecordSpec::new(RecordType::Mx, "@", "203.0.113.7").is_err());
    assert!(RecordSpec::new(RecordType::Ns, "@", "ns1").is_ok());
}

// -------------------------------------------------------------------- ttl

#[test]
fn the_ttl_bounds_are_the_documented_int_range() {
    let spec = RecordSpec::txt("@", "x").unwrap();
    assert_eq!(spec.ttl(), inwx_client::DEFAULT_TTL);
    assert!(spec.clone().with_ttl(0).is_ok());
    assert!(spec.clone().with_ttl(MAX_TTL).is_ok());
    assert!(spec.clone().with_ttl(MAX_TTL + 1).is_err());
    assert!(spec.with_ttl(u32::MAX).is_err());
}

#[test]
fn a_mutation_after_construction_is_still_checked_by_validate() {
    // The builders cannot produce a bad spec, but `validate` is public so a spec
    // built by other means can be checked before it is sent.
    let mut spec = RecordSpec::txt("@", "x").unwrap();
    assert!(spec.validate().is_ok());
    spec = spec.with_ttl(60).unwrap();
    assert!(spec.validate().is_ok());
}

// -------------------------------------------------------------- unicode

#[test]
fn unicode_domains_are_converted_to_punycode() {
    let domain = DomainName::parse("Bücher.example").unwrap();
    assert_eq!(domain.as_str(), "xn--bcher-kva.example");
    assert!(domain.is_idn());

    let ascii = DomainName::parse("example.com").unwrap();
    assert!(!ascii.is_idn());
}

#[test]
fn unicode_host_names_are_converted_too() {
    let host = Hostname::parse("münchen.example").unwrap();
    assert_eq!(host.as_str(), "xn--mnchen-3ya.example");
}

#[test]
fn a_unicode_name_round_trips_through_serde() {
    let domain = DomainName::parse("bücher.de").unwrap();
    let encoded = serde_json::to_string(&domain).unwrap();
    assert_eq!(encoded, "\"xn--bcher-kva.de\"");
    let decoded: DomainName = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, domain);
}

#[test]
fn unicode_names_are_mapped_to_their_ascii_form() {
    // UTS-46 mapping, not just encoding: emoji become punycode (some TLDs sell
    // those names), and characters the mapping deletes leave no trace. This is
    // why `as_str()` — the ACE form — is what a caller should log and compare.
    assert_eq!(DomainName::parse("😀.de").unwrap().as_str(), "xn--e28h.de");
    assert_eq!(
        DomainName::parse("a\u{200b}b.de").unwrap().as_str(),
        "ab.de"
    );

    // Whitespace and an empty label are still refused.
    assert!(DomainName::parse("bü cher.de").is_err());
    assert!(DomainName::parse("a..de").is_err());
}

// ------------------------------------------------------------- name rules

#[test]
fn name_length_limits_are_enforced() {
    let label = "a".repeat(64);
    assert!(DomainName::parse(&format!("{label}.com")).is_err());

    let long_name = format!("{}.com", vec!["a".repeat(60); 5].join("."));
    assert!(DomainName::parse(&long_name).is_err());

    assert!(DomainName::parse("localhost").is_err());
    assert!(DomainName::parse("-leading.com").is_err());
    assert!(DomainName::parse("trailing-.com").is_err());
    assert!(DomainName::parse("under_score.com").is_err());
    assert!(DomainName::parse("").is_err());
    assert!(DomainName::parse(".").is_err());
}

#[test]
fn record_names_cannot_contain_whitespace_or_control_characters() {
    assert!(RecordSpec::txt("with space", "x").is_err());
    assert!(RecordSpec::txt("with\ttab", "x").is_err());
    assert!(RecordSpec::txt("with\nnewline", "x").is_err());
    assert!(RecordSpec::txt("@", "control\u{0}char").is_err());
}

#[test]
fn txt_content_is_limited_to_the_documented_length() {
    assert!(RecordSpec::txt("@", "x".repeat(1024)).is_ok());
    assert!(RecordSpec::txt("@", "x".repeat(1025)).is_err());
    assert!(RecordSpec::txt("@", "").is_err());
}

// ---------------------------------------------------------------- records

#[test]
fn record_ids_accept_strings_numbers_and_reject_nonsense() {
    assert_eq!(RecordId::from_number(1).as_str(), "1");
    assert_eq!(RecordId::parse("0011").unwrap().as_str(), "0011");
    assert_eq!(RecordId::try_from("1").unwrap().as_str(), "1");
    assert_eq!(
        RecordId::try_from(String::from("0011")).unwrap().as_str(),
        "0011"
    );
    assert!(RecordId::parse("").is_err());
    assert!(RecordId::parse("a\nb").is_err());
    assert!(RecordId::parse("x".repeat(65)).is_err());
    assert!(RecordId::parse("x".repeat(64)).is_ok());
    assert!(RecordId::try_from("").is_err());
    assert!(RecordId::try_from(String::from("a\nb")).is_err());
}

#[test]
fn a_record_update_needs_an_id_and_a_change() {
    assert!(RecordUpdate::new([]).name("x").params().is_err());
    let no_change = RecordUpdate::new([RecordId::from_number(1)]);
    assert!(no_change.params().is_err());
    let over_ttl = RecordUpdate::new([RecordId::from_number(1)]).with_ttl(MAX_TTL + 1);
    assert!(over_ttl.is_err());
    let bad_name = RecordUpdate::new([RecordId::from_number(1)]).name("bad name");
    assert!(bad_name.params().is_err());
}

#[test]
fn mx_accepts_the_full_priority_range() {
    let host = Hostname::parse("mx.example.com").unwrap();
    assert!(RecordSpec::mx("@", 0, &host).is_ok());
    assert!(RecordSpec::mx("@", u16::MAX, &host).is_ok());
}

// --------------------------------------------------------------- contacts

#[test]
fn contact_validation_covers_email_and_country() {
    let base = || {
        ContactRequest::new(ContactType::Org, "ACME", "ops@acme.test")
            .unwrap()
            .with_street("Weg 2")
            .with_city("Berlin")
            .with_postcode("10115")
            .with_country("DE")
            .with_voice("+49.891")
    };

    assert!(base().validate().is_ok());
    assert!(base().with_country("Germany").validate().is_err());
    assert!(base().with_postcode("12345678901").validate().is_err());
    assert!(base().with_remarks("x".repeat(256)).validate().is_err());
    assert!(ContactRequest::new(ContactType::Person, "", "a@b.test").is_err());
    assert!(ContactRequest::new(ContactType::Person, "A", "no-at-sign").is_err());
}

#[tokio::test]
async fn contact_list_reads_a_single_handle_and_skips_unusable_rows() {
    let transport = MockTransport::new();

    // The documented shape first: an array of handles with a numeric total.
    transport.ok(json!({"count": 2, "contact": [{"roId": 991}, {"roId": 992}]}));
    // A single object where the array belongs is a page of one.
    transport.ok(json!({"count": 1, "contact": {"roId": 991}}));
    // One row that does not fit a handle costs that row, not the page — on
    // both sides of the array.
    transport.ok(json!({"count": 3, "contact": [null, {"roId": 991}, "nope"]}));
    // Neither an array nor an object: an empty page, not a failed call, and a
    // numeric-string total still counts.
    transport.ok(json!({"count": "12", "contact": 7}));
    // A count that is an object leaves the total unset instead of failing.
    transport.ok(json!({"count": {"total": 4}, "contact": {"roId": 1}}));
    // An answer without either key is simply empty.
    transport.ok(json!({}));

    let client = client(transport.clone());
    let query = ContactQuery::new();

    let page = client.list_contacts(&query).await.unwrap();
    assert_eq!(
        page.contacts
            .iter()
            .filter_map(Contact::handle)
            .collect::<Vec<_>>(),
        [991, 992]
    );
    assert_eq!(page.count, Some(2));

    let page = client.list_contacts(&query).await.unwrap();
    assert_eq!(page.contacts.len(), 1);
    assert_eq!(page.contacts[0].handle(), Some(991));
    assert_eq!(page.count, Some(1));

    let page = client.list_contacts(&query).await.unwrap();
    assert_eq!(
        page.contacts
            .iter()
            .filter_map(Contact::handle)
            .collect::<Vec<_>>(),
        [991]
    );
    assert_eq!(
        page.count,
        Some(3),
        "the total is read independently of the rows"
    );

    let page = client.list_contacts(&query).await.unwrap();
    assert_eq!(page.contacts, Vec::<Contact>::new());
    assert_eq!(page.count, Some(12));

    let page = client.list_contacts(&query).await.unwrap();
    assert_eq!(page.contacts[0].handle(), Some(1));
    assert_eq!(page.count, None);

    let page = client.list_contacts(&query).await.unwrap();
    assert_eq!(page.total(), None);
    assert_eq!(page.into_items(), Vec::<Contact>::new());

    assert_eq!(transport.call_count(), 6);
    assert_eq!(transport.calls()[0].method, "contact.list");
}

#[tokio::test]
async fn a_contact_walk_reads_the_same_permissive_page() {
    let transport = MockTransport::new();
    // One handle as a single object: the walker decodes pages through the same
    // type, so it must not fail on the shape `list_contacts` accepts.
    transport.ok(json!({"count": 1, "contact": {"roId": 991}}));

    let client = client(transport.clone());
    let handles = client
        .list_all_contacts(&ContactQuery::new(), &Pagination::new())
        .collect_all()
        .await
        .unwrap();
    assert_eq!(
        handles
            .iter()
            .filter_map(Contact::handle)
            .collect::<Vec<_>>(),
        [991]
    );
    assert_eq!(transport.call_count(), 1);
}

// ------------------------------------------------------------ rpc framing

#[test]
fn rpc_parsing_survives_arbitrary_bodies() {
    assert!(matches!(RpcResponse::parse(b""), Err(Error::Json { .. })));
    assert!(matches!(
        RpcResponse::parse(b"not json"),
        Err(Error::Json { .. })
    ));
    assert!(matches!(
        RpcResponse::parse(b"null"),
        Err(Error::Json { .. })
    ));
    assert!(matches!(RpcResponse::parse(b"[]"), Err(Error::Json { .. })));
    assert!(matches!(
        RpcResponse::parse(&[0xff, 0xfe, 0x00]),
        Err(Error::Json { .. })
    ));

    let scalar = RpcResponse::parse(br#"{"code":"2200","msg":"nope"}"#).unwrap();
    assert_eq!(scalar.code, 2200);
    assert!(scalar.is_authentication());
}

#[test]
fn a_request_with_non_object_params_is_refused() {
    // Just inside: the documented object shape, empty or not.
    assert_eq!(
        RpcRequest::new("account.logout", &json!({}))
            .unwrap()
            .params
            .len(),
        0
    );

    // Just outside: an array is not an object, and must not be sent as one.
    let error = RpcRequest::new("account.logout", &json!([1, 2, 3])).unwrap_err();
    assert!(error.is_validation());
}

#[test]
fn periods_cover_the_documented_set() {
    assert_eq!(Period::ONE_MONTH.to_string(), "1M");
    for years in 1..=10 {
        assert_eq!(
            Period::years(years).unwrap().to_string(),
            format!("{years}Y")
        );
    }
    assert!(Period::years(11).is_err());
    assert!("12M".parse::<Period>().is_err());
    assert!("1.5Y".parse::<Period>().is_err());
}

// -------------------------------------------------------- transport errors

#[tokio::test]
async fn a_long_error_body_is_truncated_in_the_http_error() {
    let cap = inwx_client::MAX_HTTP_BODY_CHARS;

    // Exactly the cap: nothing is dropped, so no marker.
    let fitting = MockTransport::new();
    fitting.status(400, &"x".repeat(cap));
    let body = match client(fitting)
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err()
    {
        Error::Http { body, .. } => body,
        other => panic!("unexpected: {other}"),
    };
    assert_eq!(body.as_str().chars().count(), cap);
    assert!(!body.as_str().ends_with("[truncated]"));

    // One character more: cut at the cap, and the cut is visible.
    let transport = MockTransport::new();
    transport.status(400, &"x".repeat(cap + 1));
    let body = match client(transport)
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err()
    {
        Error::Http { status, body, .. } => {
            assert_eq!(status, 400);
            body
        }
        other => panic!("unexpected: {other}"),
    };
    assert_eq!(body.as_str().chars().count(), cap + " [truncated]".len());
    assert!(body.as_str().starts_with(&"x".repeat(cap)));
    assert!(body.as_str().ends_with("[truncated]"));
}

/// A `200` with nothing readable in the body is an answer that arrived without
/// an envelope: the command may have run, so it is uncertain rather than a
/// certain decode failure.
#[tokio::test]
async fn a_blank_body_on_200_is_an_uncertain_undecodable_answer() {
    let transport = MockTransport::new();
    transport.status(200, "   ");

    let client = client(transport);
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Undecodable { .. }), "{error:?}");
    assert!(error.is_uncertain(), "{error:?}");
    assert!(!error.is_retryable(), "{error:?}");
}

#[tokio::test]
async fn a_response_with_wrong_types_degrades_instead_of_failing() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "domain": [{"domain": "a.de", "avail": [], "status": 7, "price": "free"}]
    }));

    let client = client(transport);
    let checks = client
        .check_domains(&[DomainName::parse("a.de").unwrap()])
        .await
        .unwrap();

    assert_eq!(checks.len(), 1);
    assert!(!checks[0].is_available());
    assert_eq!(checks[0].status.as_deref(), Some("7"));
    assert!(checks[0].price.is_none());
}

#[tokio::test]
async fn domain_list_and_zone_list_read_a_single_row_and_skip_unusable_rows() {
    let transport = MockTransport::new();

    // The documented shape first: arrays with concrete rows.
    transport.ok(json!({"count": 2, "domain": [{"domain": "a.de"}, {"domain": "b.de"}]}));
    transport.ok(json!({"count": 2, "domains": [{"domain": "a.de"}, {"domain": "b.de"}]}));
    // A single object where the array belongs is a page of one.
    transport.ok(json!({"count": 1, "domain": {"domain": "a.de"}}));
    transport.ok(json!({"count": 1, "domains": {"domain": "a.de"}}));
    // One row that does not fit the model costs that row, not the page.
    transport.ok(json!({"count": 2, "domain": [null, {"domain": "a.de"}]}));
    transport.ok(json!({"count": 2, "domains": [null, {"domain": "a.de"}]}));
    // A syntactically invalid zone name is a row-level failure too, not a
    // page-level one; the raw row stays visible to the caller.
    transport.ok(json!({"count": 3, "domains": [
        {"domain": "good.de"},
        {"domain": "bad name"},
        {"domain": ""}
    ]}));

    let client = client(transport.clone());

    let page = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap();
    assert_eq!(page.len(), 2);
    assert_eq!(page.count, Some(2));
    let page = client.list_zones().await.unwrap();
    assert_eq!(page.len(), 2);
    assert_eq!(page.count, Some(2));

    let page = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page.domains[0].domain.as_str(), "a.de");
    let page = client.list_zones().await.unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page.zones[0].domain.as_str(), "a.de");

    let page = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page.count, Some(2));
    let page = client.list_zones().await.unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page.count, Some(2));

    assert_eq!(transport.call_count(), 6);
    let page = client.list_zones().await.unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page.zones[0].domain.as_str(), "good.de");
    assert_eq!(page.unparsed.len(), 2);
    assert_eq!(page.unparsed[0]["domain"], "bad name");
    assert_eq!(page.unparsed[1]["domain"], "");

    assert_eq!(transport.call_count(), 7);
}

#[tokio::test]
async fn a_zone_walk_advances_past_a_full_page_with_unusable_rows() {
    let transport = MockTransport::new();
    transport.ok(json!({"count": 3, "domains": [
        {"domain": "a.de"},
        {"domain": "bad name"}
    ]}));
    transport.ok(json!({"count": 3, "domains": [{"domain": "b.de"}]}));

    let client = client(transport.clone());
    let zones = client
        .list_all_zones(
            &inwx_client::ZoneListing::new(),
            &Pagination::new().with_page_size(2).unwrap(),
        )
        .collect_all()
        .await
        .unwrap();

    assert_eq!(
        zones
            .iter()
            .map(|zone| zone.domain.as_str())
            .collect::<Vec<_>>(),
        ["a.de", "b.de"]
    );
    assert_eq!(transport.call_count(), 2);
    assert_eq!(transport.calls()[1].params["page"], 2);
}

#[test]
fn value_helpers_accept_the_shapes_the_api_uses() {
    // `wide` is documented as int, `avail` as int, but both appear as bools in
    // the wild; parsing must not care.
    let record: inwx_client::DnsRecord = serde_json::from_value(json!({
        "id": 9, "type": "A", "content": "203.0.113.7", "ttl": true
    }))
    .unwrap();
    assert_eq!(record.ttl_seconds(), i64::from(inwx_client::DEFAULT_TTL));

    let value: Value = serde_json::from_str(r#"{"a":1}"#).unwrap();
    assert!(value.is_object());
}
