//! Domains, contacts, zones and prices against the scripted transport.

mod common;

use common::{client, MockTransport};
use inwx_client::{
    is_read_only_method, ClientHoldResult, ContactQuery, ContactRequest, ContactType,
    ContactUpdate, DomainCreate, DomainListQuery, DomainName, DomainRenew, DomainUpdate, Error,
    ExtraDataRule, Hostname, Period, PriceType, RemoveClientHold, RenewalMode, SetClientHold,
};
use serde_json::json;

fn domain(name: &str) -> DomainName {
    DomainName::parse(name).unwrap()
}

// ---------------------------------------------------------------- domains

#[tokio::test]
async fn checking_domains_sends_an_array_and_parses_availability() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "domain": [
            {"domain": "frei.de", "avail": 1, "status": "free", "price": 8.9},
            {"domain": "vergeben.de", "avail": 0, "status": "registered", "reason": "taken"}
        ]
    }));

    let client = client(transport.clone());
    let checks = client
        .check_domains(&[domain("frei.de"), domain("vergeben.de")])
        .await
        .unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "domain.check");
    assert_eq!(call.params["domain"], json!(["frei.de", "vergeben.de"]));
    assert_eq!(call.params["wide"], 1);

    assert_eq!(checks.len(), 2);
    assert!(checks[0].is_available());
    assert_eq!(checks[0].price, Some(8.9));
    assert!(!checks[1].is_available());
    assert_eq!(checks[1].reason.as_deref(), Some("taken"));
}

#[tokio::test]
async fn checking_one_domain_accepts_a_single_object_answer() {
    let transport = MockTransport::new();
    transport.ok(json!({"domain": {"domain": "frei.de", "status": "free"}}));

    let client = client(transport);
    assert!(client
        .check_domain(&domain("frei.de"))
        .await
        .unwrap()
        .is_available());
}

#[tokio::test]
async fn checking_one_domain_without_an_answer_is_a_missing_field() {
    let transport = MockTransport::new();
    transport.ok(json!({"domain": []}));

    let client = client(transport);
    let error = client.check_domain(&domain("frei.de")).await.unwrap_err();

    assert!(matches!(
        error,
        Error::MissingField {
            method: "domain.check",
            ..
        }
    ));
}

#[tokio::test]
async fn checking_nothing_is_rejected_locally() {
    let transport = MockTransport::new();
    let client = client(transport.clone());
    assert!(client.check_domains(&[]).await.unwrap_err().is_validation());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn registering_a_domain_sends_the_builder_payload() {
    let transport = MockTransport::new();
    transport.ok(json!({"roId": 42, "price": 8.9, "currency": "EUR"}));

    let client = client(transport.clone());
    let request = DomainCreate::new(domain("example.com"), 991)
        .unwrap()
        .with_period(Period::years(1).unwrap())
        .with_nameservers(&[Hostname::parse("ns1.example.com").unwrap()])
        .with_transfer_lock(true)
        .with_renewal_mode(RenewalMode::AutoRenew);
    let registration = client.register_domain(&request).await.unwrap();

    assert_eq!(registration.ro_id, 42);
    assert_eq!(registration.currency.as_deref(), Some("EUR"));
    let params = transport.only_call().params;
    assert_eq!(transport.only_call().method, "domain.create");
    assert_eq!(params["registrant"], 991);
    assert_eq!(params["period"], "1Y");
    assert_eq!(params["ns"][0], "ns1.example.com");
    assert_eq!(params["transferLock"], true);
    assert_eq!(params["renewalMode"], "AUTORENEW");
}

#[tokio::test]
async fn domain_info_parses_the_wide_answer() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "roId": "42",
        "domain": "example.com",
        "status": "ok",
        "crDate": "2020-01-01",
        "exDate": "2027-01-31",
        "reDate": "2026-12-01",
        "transferLock": 0,
        "renewalMode": "AUTORENEW",
        "authCode": "AUTH-1",
        "registrant": 991,
        "ns": ["ns1.example.com"],
        "verificationStatus": "verified"
    }));

    let client = client(transport.clone());
    let info = client.domain_info(&domain("example.com")).await.unwrap();

    assert_eq!(transport.only_call().params["wide"], 1);
    assert_eq!(info.ro_id, Some(42));
    assert_eq!(info.transfer_lock, Some(false));
    assert_eq!(info.renewal_mode, Some(RenewalMode::AutoRenew));
    assert_eq!(info.expires_at.as_deref(), Some("2027-01-31"));
    assert_eq!(info.registrant_handle(), Some(991));
    assert!(info.is_delegated());
    assert_eq!(info.verification_status.as_deref(), Some("verified"));
}

#[tokio::test]
async fn listing_domains_passes_the_query_through() {
    let transport = MockTransport::new();
    transport.ok(json!({"count": 1, "domain": [{"domain": "a.de", "status": "ok"}]}));

    let client = client(transport.clone());
    let query = DomainListQuery::new().with_filter("a.de").with_page(2, 10);
    let page = client.list_domains(&query).await.unwrap();

    assert_eq!(page.len(), 1);
    assert_eq!(page.count, Some(1));
    let params = transport.only_call().params;
    assert_eq!(params["page"], 2);
    assert_eq!(params["pagelimit"], 10);
    assert_eq!(params["domain"][0], "a.de");
}

#[tokio::test]
async fn updating_a_domain_requires_a_change_and_sends_it() {
    let transport = MockTransport::new();
    transport.ok_empty();
    let client = client(transport.clone());

    let empty = DomainUpdate::new(domain("example.com"));
    assert!(client
        .update_domain(&empty)
        .await
        .unwrap_err()
        .is_validation());
    assert_eq!(transport.call_count(), 0);

    let update = DomainUpdate::new(domain("example.com"))
        .with_admin(991)
        .with_nameservers(&[Hostname::parse("ns1.example.net").unwrap()]);
    client.update_domain(&update).await.unwrap();

    let params = transport.only_call().params;
    assert_eq!(params["admin"], 991);
    assert_eq!(params["ns"][0], "ns1.example.net");
    assert!(params.get("tech").is_none());
}

#[tokio::test]
async fn renewal_sends_the_current_expiry_date() {
    let transport = MockTransport::new();
    transport.ok(json!({"exDate": "2028-01-31", "reDate": "2027-01-31", "price": 8.9}));

    let client = client(transport.clone());
    let request = DomainRenew::new(
        domain("example.com"),
        Period::years(1).unwrap(),
        "2027-01-31",
    )
    .unwrap();
    let result = client.renew_domain(&request).await.unwrap();

    assert_eq!(result.expires_at.as_deref(), Some("2028-01-31"));
    let params = transport.only_call().params;
    assert_eq!(params["expiration"], "2027-01-31");
    assert_eq!(params["period"], "1Y");
}

#[tokio::test]
async fn deleting_a_domain_sends_only_the_name() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let client = client(transport.clone());
    client.delete_domain(&domain("example.com")).await.unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "domain.delete");
    assert_eq!(call.params, json!({"domain": "example.com"}));
}

#[tokio::test]
async fn convenience_setters_go_through_domain_update() {
    let transport = MockTransport::new();
    transport.ok_empty();
    transport.ok_empty();

    let client = client(transport.clone());
    client
        .set_renewal_mode(&domain("a.de"), RenewalMode::AutoExpire)
        .await
        .unwrap();
    client
        .set_transfer_lock(&domain("a.de"), false)
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls[0].method, "domain.update");
    assert_eq!(calls[0].params["renewalMode"], "AUTOEXPIRE");
    assert_eq!(calls[1].params["transferLock"], false);
}

#[tokio::test]
async fn auth_code_and_whois_report_missing_fields() {
    let transport = MockTransport::new();
    transport.ok(json!({"domain": "a.de"}));
    let client = client(transport);
    let error = client.auth_code(&domain("a.de")).await.unwrap_err();
    assert!(matches!(
        error,
        Error::MissingField {
            field: "resData.authCode",
            ..
        }
    ));

    let transport = MockTransport::new();
    transport.ok(json!({"domain": "a.de"}));
    let client = common::client(transport);
    let error = client.whois(&domain("a.de")).await.unwrap_err();
    assert!(matches!(
        error,
        Error::MissingField {
            field: "resData.whois",
            ..
        }
    ));
}

#[tokio::test]
async fn auth_code_and_whois_return_their_payloads() {
    let transport = MockTransport::new();
    transport.ok(json!({"domain": "a.de", "authCode": "XYZ"}));
    transport.ok(json!({"whois": "Domain Name: a.de"}));

    let client = client(transport.clone());
    assert_eq!(client.auth_code(&domain("a.de")).await.unwrap(), "XYZ");
    assert_eq!(
        client.whois(&domain("a.de")).await.unwrap(),
        "Domain Name: a.de"
    );
    assert_eq!(transport.calls()[1].method, "domain.whois");
}

// ---------------------------------------------------------- registry hold

#[tokio::test]
async fn setting_a_registry_hold_sends_the_domain_and_the_testing_flag() {
    let transport = MockTransport::new();
    transport.ok(json!({"roId": 42}));

    let client = client(transport.clone());
    let held = client
        .set_client_hold(&SetClientHold::new(domain("a.de")))
        .await
        .unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "domain.setClientHold");
    assert_eq!(call.params, json!({"domain": "a.de", "testing": false}));
    assert_eq!(held.ro_id, Some(42));
}

#[tokio::test]
async fn lifting_a_registry_hold_uses_its_own_method() {
    let transport = MockTransport::new();
    transport.ok(json!({"roId": 42}));

    let client = client(transport.clone());
    let released = client
        .remove_client_hold(&RemoveClientHold::new(domain("a.de")))
        .await
        .unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "domain.removeClientHold");
    assert_eq!(call.params, json!({"domain": "a.de", "testing": false}));
    assert_eq!(released.ro_id, Some(42));
}

#[tokio::test]
async fn a_registry_hold_dry_run_validates_without_changing_anything() {
    let transport = MockTransport::new();
    transport.ok_empty();
    transport.ok_empty();

    let client = client(transport.clone());
    client
        .set_client_hold(&SetClientHold::new(domain("a.de")).dry_run())
        .await
        .unwrap();
    client
        .remove_client_hold(&RemoveClientHold::new(domain("a.de")).dry_run())
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    for call in calls {
        assert_eq!(call.params["testing"], true);
        assert_eq!(call.params["domain"], "a.de");
    }
}

#[tokio::test]
async fn a_registry_hold_answer_is_decoded_permissively() {
    // The id as a string, plus a field nobody has seen before.
    let transport = MockTransport::new();
    transport.ok(json!({"roId": "42", "brandNewField": {"a": 1}}));
    // A success that reports nothing at all.
    transport.ok_empty();

    let client = client(transport.clone());
    let held = client
        .set_client_hold(&SetClientHold::new(domain("a.de")))
        .await
        .unwrap();
    let released = client
        .remove_client_hold(&RemoveClientHold::new(domain("a.de")))
        .await
        .unwrap();

    assert_eq!(held, ClientHoldResult { ro_id: Some(42) });
    assert_eq!(released.ro_id, None);
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn a_hold_for_a_domain_that_is_not_mine_reports_the_api_code() {
    let transport = MockTransport::new();
    transport.api_error(2303, "Object does not exist");

    let client = client(transport);
    let error = client
        .set_client_hold(&SetClientHold::new(domain("not-mine.de")))
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Api { code: 2303, .. }));
    assert!(!error.is_retryable());
}

/// An answer that is a bare scalar cannot be read as a `ClientHoldResult`. The
/// command already ran and the API said it succeeded, so this is a terminal
/// decode error — retryable would mean replaying a mutation because the body
/// looked unexpected. A sequence is not covered here: serde accepts it as the
/// struct's seq form, so `[{…}]` decodes into a result instead of failing.
#[tokio::test]
async fn a_registry_hold_answer_that_is_not_an_object_is_a_terminal_json_error() {
    let transport = MockTransport::new();
    transport.ok(json!("held"));
    transport.ok(json!(7));

    let client = client(transport.clone());
    let set = client
        .set_client_hold(&SetClientHold::new(domain("a.de")))
        .await
        .unwrap_err();
    let removed = client
        .remove_client_hold(&RemoveClientHold::new(domain("a.de")))
        .await
        .unwrap_err();

    for error in [set, removed] {
        assert!(matches!(error, Error::Json { .. }), "{error:?}");
        assert!(!error.is_retryable(), "{error:?}");
        assert!(!error.is_uncertain(), "{error:?}");
    }
    assert_eq!(transport.call_count(), 2);
}

/// A hold is a mutation: a timeout may already have parked the domain at the
/// registry, so the client reports the ambiguity instead of replaying it.
#[tokio::test]
async fn an_uncertain_registry_hold_is_never_replayed() {
    let transport = MockTransport::new();
    transport.uncertain_failure("timeout waiting for response");
    transport.ok(json!({"roId": 42}));
    let error = client(transport.clone())
        .set_client_hold(&SetClientHold::new(domain("a.de")))
        .await
        .unwrap_err();
    assert_uncertain_after_one_attempt("set_client_hold", &error, &transport);

    let transport = MockTransport::new();
    transport.uncertain_failure("timeout waiting for response");
    transport.ok(json!({"roId": 42}));
    let error = client(transport.clone())
        .remove_client_hold(&RemoveClientHold::new(domain("a.de")))
        .await
        .unwrap_err();
    assert_uncertain_after_one_attempt("remove_client_hold", &error, &transport);
}

/// The failure happened after the request was written, so exactly one attempt
/// may have been made — and the scripted success behind it must stay unused.
fn assert_uncertain_after_one_attempt(label: &str, error: &Error, transport: &MockTransport) {
    assert!(error.is_uncertain(), "{label}: {error:?}");
    assert!(!error.is_retryable(), "{label}: {error:?}");
    assert_eq!(transport.call_count(), 1, "{label} must not be replayed");
}

/// Both commands change registry state, so they must stay outside the read-only
/// table that authorises a replay.
#[test]
fn registry_hold_commands_are_not_read_only() {
    for method in [
        "domain.setClientHold",
        "domain.removeClientHold",
        "DOMAIN.SETCLIENTHOLD",
        " domain.removeClientHold ",
    ] {
        assert!(!is_read_only_method(method), "{method} is not read-only");
    }
}

// --------------------------------------------------------------- contacts

fn contact_request() -> ContactRequest {
    ContactRequest::new(ContactType::Person, "Erika Mustermann", "erika@example.com")
        .unwrap()
        .with_street("Musterstraße 1")
        .with_city("München")
        .with_postcode("80331")
        .with_country("DE")
        .with_voice("+49.8912345678")
}

#[tokio::test]
async fn creating_a_contact_sends_every_field() {
    let transport = MockTransport::new();
    transport.ok(json!({"id": 991}));

    let client = client(transport.clone());
    let id = client
        .create_contact(&contact_request().with_org("ACME GmbH").with_remarks("tag"))
        .await
        .unwrap();

    assert_eq!(id, 991);
    let call = transport.only_call();
    assert_eq!(call.method, "contact.create");
    assert_eq!(call.params["type"], "PERSON");
    assert_eq!(call.params["cc"], "DE");
    assert_eq!(call.params["org"], "ACME GmbH");
    assert_eq!(call.params["remarks"], "tag");
    assert_eq!(call.params["name"], "Erika Mustermann");
}

#[tokio::test]
async fn an_incomplete_contact_never_reaches_the_transport() {
    let transport = MockTransport::new();
    let client = client(transport.clone());
    let incomplete =
        ContactRequest::new(ContactType::Person, "Erika", "erika@example.com").unwrap();

    let error = client.create_contact(&incomplete).await.unwrap_err();

    assert!(matches!(
        error,
        Error::Validation {
            field: "contact.street",
            ..
        }
    ));
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn creating_a_contact_without_an_id_is_a_missing_field() {
    let transport = MockTransport::new();
    transport.ok(json!({}));

    let client = client(transport);
    let error = client.create_contact(&contact_request()).await.unwrap_err();
    assert!(matches!(
        error,
        Error::MissingField {
            method: "contact.create",
            ..
        }
    ));
}

#[tokio::test]
async fn contact_info_unwraps_the_contact_object() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "contact": {
            "roId": 991, "type": "PERSON", "name": "Erika",
            "street": "Weg 2", "city": "Berlin", "pc": "10115", "cc": "DE",
            "voice": "+49.891", "email": "erika@example.com", "usedCount": 2
        }
    }));

    let client = client(transport);
    let contact = client.contact_info(991).await.unwrap();

    assert_eq!(contact.handle(), Some(991));
    assert_eq!(contact.contact_type, Some(ContactType::Person));
    assert_eq!(contact.used_count, Some(2));
    assert_eq!(contact.city.as_deref(), Some("Berlin"));
}

#[tokio::test]
async fn contact_info_also_accepts_an_unwrapped_answer() {
    let transport = MockTransport::new();
    transport.ok(json!({"roId": 5, "name": "Solo"}));

    let client = client(transport);
    assert_eq!(client.contact_info(5).await.unwrap().handle(), Some(5));
}

#[tokio::test]
async fn listing_contacts_pages_and_searches() {
    let transport = MockTransport::new();
    transport.ok(json!({"count": 1, "contact": [{"roId": 991}]}));

    let client = client(transport.clone());
    let page = client
        .list_contacts(&ContactQuery::new().with_search("ACME").with_page(1, 5))
        .await
        .unwrap();

    assert_eq!(page.contacts.len(), 1);
    let params = transport.only_call().params;
    assert_eq!(params["search"], "ACME");
    assert_eq!(params["pagelimit"], 5);
}

#[tokio::test]
async fn updating_a_contact_requires_a_change() {
    let transport = MockTransport::new();
    transport.ok_empty();
    let client = client(transport.clone());

    assert!(client
        .update_contact(&ContactUpdate::new(991).unwrap())
        .await
        .unwrap_err()
        .is_validation());
    assert_eq!(transport.call_count(), 0);

    client
        .update_contact(
            &ContactUpdate::new(991)
                .unwrap()
                .with_email("neu@example.com"),
        )
        .await
        .unwrap();
    assert_eq!(transport.only_call().method, "contact.update");
    assert_eq!(transport.only_call().params["id"], 991);
}

#[tokio::test]
async fn deleting_a_contact_sends_the_id() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let client = client(transport.clone());
    client.delete_contact(991).await.unwrap();

    assert_eq!(transport.only_call().params, json!({"id": 991}));
}

// ------------------------------------------------------------------ zones

#[tokio::test]
async fn zone_info_parses_records_and_metadata() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "roId": 7,
        "domain": "example.com",
        "type": "MASTER",
        "SOAserial": "2026010101",
        "lastZoneCheck": "2026-01-01 00:00:00",
        "count": 1,
        "record": [{"id": "1", "name": "@", "type": "A", "content": "203.0.113.7"}]
    }));

    let client = client(transport);
    let zone = client.zone_info(&domain("example.com")).await.unwrap();

    assert!(zone.is_master());
    assert_eq!(zone.ro_id, Some(7));
    assert_eq!(zone.soa_serial.as_deref(), Some("2026010101"));
    assert_eq!(zone.records.len(), 1);
    assert_eq!(zone.count, Some(1));
}

#[tokio::test]
async fn listing_zones_uses_the_documented_default_page_size() {
    let transport = MockTransport::new();
    transport.ok(json!({"count": 1, "domains": [{"domain": "a.de", "type": "MASTER"}]}));

    let client = client(transport.clone());
    let page = client.list_zones().await.unwrap();

    assert_eq!(page.zones[0].domain.as_str(), "a.de");
    let params = transport.only_call().params;
    assert_eq!(params["page"], 1);
    assert_eq!(params["pagelimit"], 100);
}

#[tokio::test]
async fn a_zero_page_size_is_rejected_locally() {
    let transport = MockTransport::new();
    let client = client(transport.clone());
    assert!(client
        .list_zones_page(1, 0)
        .await
        .unwrap_err()
        .is_validation());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn deleting_a_zone_sends_the_domain() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let client = client(transport.clone());
    client.delete_zone(&domain("example.com")).await.unwrap();

    assert_eq!(transport.only_call().method, "nameserver.delete");
}

#[tokio::test]
async fn checking_delegation_sends_the_nameserver_list() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "details": [
            {"ns": "ns1.example.com", "status": "OK", "message": ["fine"]},
            {"ns": "ns2.example.com", "status": "ERROR", "message": "not answering"}
        ]
    }));

    let client = client(transport.clone());
    let checks = client
        .check_delegation(
            &domain("example.com"),
            &[
                Hostname::parse("ns1.example.com").unwrap(),
                Hostname::parse("ns2.example.com").unwrap(),
            ],
        )
        .await
        .unwrap();

    assert_eq!(transport.only_call().params["ns"][0], "ns1.example.com");
    assert_eq!(checks.len(), 2);
    assert!(checks[0].is_ok());
    assert!(!checks[1].is_ok());
    assert_eq!(checks[1].message, ["not answering"]);
}

#[tokio::test]
async fn checking_an_empty_nameserver_list_is_rejected_locally() {
    let transport = MockTransport::new();
    let client = client(transport.clone());
    assert!(client
        .check_delegation(&domain("a.de"), &[])
        .await
        .unwrap_err()
        .is_validation());
    assert_eq!(transport.call_count(), 0);
}

// ----------------------------------------------------------------- prices

#[tokio::test]
async fn tld_prices_normalise_the_tld_list() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "price": [
            {"tld": "de", "currency": "EUR", "createPrice": 8.9, "renewalPrice": "8.90"},
            {"tld": "com", "createPrice": 12.5}
        ]
    }));

    let client = client(transport.clone());
    let prices = client.tld_prices(&[".DE", " com "]).await.unwrap();

    assert_eq!(transport.only_call().params["tld"], json!(["de", "com"]));
    assert_eq!(prices.len(), 2);
    assert_eq!(prices.find("de").unwrap().renewal, Some(8.9));
}

#[tokio::test]
async fn an_empty_tld_list_asks_for_everything() {
    let transport = MockTransport::new();
    transport.ok(json!({"price": []}));

    let client = client(transport.clone());
    assert_eq!(client.tld_prices(&["", "."]).await.unwrap().len(), 0);
    assert_eq!(transport.only_call().params, json!({}));
}

#[tokio::test]
async fn a_domain_price_quote_is_read_from_the_first_entry() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "domain": [{
            "domain": "example.com", "type": "renewal", "period": "1Y",
            "price": 12.5, "currency": "EUR", "premium": 0, "promo": false
        }]
    }));

    let client = client(transport.clone());
    let quote = client
        .domain_price(
            &domain("example.com"),
            PriceType::Renewal,
            Some(Period::ONE_MONTH),
        )
        .await
        .unwrap();

    assert_eq!(quote.price, Some(12.5));
    assert_eq!(quote.price_type.as_deref(), Some("renewal"));
    assert_eq!(quote.premium, Some(false));
    let params = transport.only_call().params;
    assert_eq!(params["pricetype"], "renewal");
    assert_eq!(params["period"], "1M");
    assert_eq!(params["domain"][0], "example.com");
}

#[tokio::test]
async fn a_domain_price_quote_also_accepts_a_flat_answer() {
    let transport = MockTransport::new();
    transport.ok(json!({"domain": "example.com", "type": "reg", "price": 8.9}));

    let client = client(transport);
    let quote = client
        .domain_price(&domain("example.com"), PriceType::Reg, None)
        .await
        .unwrap();

    assert_eq!(quote.price, Some(8.9));
}

#[tokio::test]
async fn the_full_price_table_is_paged_and_normalises_its_tld_list() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "count": 3,
        "price": [
            {"tld": "de", "currency": "EUR", "createPrice": 8.9, "createPeriod": 1},
            {"tld": "com", "createPrice": "12.50"}
        ]
    }));

    let client = client(transport.clone());
    let prices = client
        .all_domain_prices(&[".DE", " COM"], 2, 2)
        .await
        .unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "domain.getalldomainprices");
    assert_eq!(call.params["tld"], json!(["de", "com"]));
    assert_eq!(call.params["page"], 2);
    assert_eq!(call.params["pagelimit"], 2);

    assert_eq!(prices.len(), 2);
    assert_eq!(prices.find("com").unwrap().create, Some(12.5));
    assert!(
        prices.has_more(),
        "count 3 with 2 entries means another page"
    );
}

#[tokio::test]
async fn the_full_price_table_leaves_out_an_empty_tld_list_and_pages_from_one() {
    let transport = MockTransport::new();
    transport.ok(json!({"count": 0, "price": []}));

    let client = client(transport.clone());
    let prices = client
        .all_domain_prices(&["", " . "], 0, 250)
        .await
        .unwrap();

    let call = transport.only_call();
    assert!(
        call.params.get("tld").is_none(),
        "nothing left after the blanks are dropped: {:?}",
        call.params
    );
    assert_eq!(
        call.params["page"], 1,
        "page 0 is clamped to the first page"
    );
    assert_eq!(call.params["pagelimit"], 250);
    assert!(prices.is_empty());
    assert!(!prices.has_more());
}

#[tokio::test]
async fn a_paged_price_method_refuses_a_page_size_of_zero() {
    for limit in [0, 1] {
        let transport = MockTransport::new();
        transport.ok(json!({"count": 0, "price": []}));
        let client = client(transport.clone());
        let result = client.all_domain_prices(&[], 1, limit).await;
        if limit == 0 {
            assert!(
                result.unwrap_err().is_validation(),
                "a page size of zero is refused locally"
            );
            assert_eq!(transport.call_count(), 0, "nothing may be sent");
        } else {
            assert!(result.is_ok(), "one is the smallest valid page size");
            assert_eq!(transport.call_count(), 1);
        }
    }
}

#[tokio::test]
async fn the_rows_of_the_full_price_table_are_read_under_each_documented_spelling() {
    for key in ["price", "prices", "domain"] {
        let transport = MockTransport::new();
        transport.ok(json!({key: [{"tld": "de", "renewal_price": "8.90"}]}));
        let client = client(transport);
        let prices = client.all_domain_prices(&["de"], 1, 10).await.unwrap();
        assert_eq!(prices.len(), 1, "rows under `{key}` must be found");
        assert_eq!(prices.find("de").unwrap().renewal, Some(8.9));
    }
}

#[tokio::test]
async fn extra_data_rules_send_the_tld_and_the_order_type() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "extradata": [
            {"tld": "de", "key": "X_FN_INDUSTRY", "type": "select", "required": 1,
             "orderType": "reg", "values": ["retail", "craft"]},
            {"tld": "de", "key": "X_FN_VAT", "type": "text", "required": 0,
             "pattern": "^DE[0-9]{9}$", "unknownRegistryFlag": true}
        ]
    }));

    let client = client(transport.clone());
    let rules = client
        .extra_data_rules(Some(".DE"), Some(PriceType::Reg))
        .await
        .unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "domain.getextradatarules");
    assert_eq!(call.params["tld"], "de");
    assert_eq!(call.params["pricetype"], "reg");

    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].key.as_deref(), Some("X_FN_INDUSTRY"));
    assert_eq!(rules[0].required, Some(true));
    assert_eq!(rules[0].price_type(), Some(PriceType::Reg));
    assert_eq!(rules[0].values, ["retail", "craft"]);
    assert!(rules[1].is_text(), "a `text` rule is the free-text kind");
    assert_eq!(rules[1].required, Some(false));
}

#[tokio::test]
async fn extra_data_rules_read_a_single_object_and_an_absent_answer() {
    let transport = MockTransport::new();
    transport.ok(json!({"extradataRules": {"key": "X_A", "orderType": "refund"}}));

    let rules = client(transport.clone())
        .extra_data_rules(None, None)
        .await
        .unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(
        rules[0].order_type.as_deref(),
        Some("refund"),
        "an order type this crate does not know is carried, not dropped"
    );
    assert_eq!(rules[0].price_type(), None);
    assert_eq!(transport.call_count(), 1);

    let empty = MockTransport::new();
    empty.ok_empty();
    let none = client(empty.clone())
        .extra_data_rules(None, None)
        .await
        .unwrap();
    assert_eq!(none, Vec::<ExtraDataRule>::new());
    assert_eq!(empty.call_count(), 1);
}

#[tokio::test]
async fn a_blank_tld_filter_is_refused_without_calling_the_api() {
    for blank in ["", " ", "."] {
        let transport = MockTransport::new();
        let client = client(transport.clone());
        assert!(
            client
                .extra_data_rules(Some(blank), None)
                .await
                .unwrap_err()
                .is_validation(),
            "{blank:?} names no TLD"
        );
        assert!(client
            .promo_codes(Some(blank), 1, 10)
            .await
            .unwrap_err()
            .is_validation());
        assert!(client
            .price_changes(Some(blank), 1, 10)
            .await
            .unwrap_err()
            .is_validation());
        assert_eq!(transport.call_count(), 0, "{blank:?} must not be sent");
    }
}

#[tokio::test]
async fn promo_codes_accept_amounts_as_numbers_and_as_strings() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "promo": [
            {"code": "SPRING26", "price": "1.00", "currency": "EUR", "tld": ["de"],
             "validFrom": "2026-01-01", "validUntil": "2026-03-31", "orderType": "reg"},
            {"promoCode": "SUMMER26", "price": 0, "discount": "10", "period": "2",
             "type": "nonsense", "order": "renewal"}
        ]
    }));

    let client = client(transport.clone());
    let promos = client.promo_codes(Some(".DE"), 3, 50).await.unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "domain.getpromos");
    assert_eq!(call.params["tld"], "de");
    assert_eq!(call.params["page"], 3);
    assert_eq!(call.params["pagelimit"], 50);

    assert_eq!(promos.len(), 2);
    assert_eq!(promos[0].price, Some(1.0));
    assert_eq!(promos[0].valid_until.as_deref(), Some("2026-03-31"));
    assert_eq!(promos[0].price_type(), Some(PriceType::Reg));
    assert_eq!(promos[1].code.as_deref(), Some("SUMMER26"));
    assert_eq!(promos[1].period, Some(2));
    assert_eq!(promos[1].price_type(), Some(PriceType::Renewal));
}

#[tokio::test]
async fn a_promo_answer_that_is_empty_or_unknown_is_no_promos() {
    for answer in [
        json!({"promo": []}),
        json!({"promos": []}),
        json!({"count": 0}),
        json!({}),
    ] {
        let transport = MockTransport::new();
        transport.ok(answer.clone());
        let client = client(transport);
        assert!(
            client.promo_codes(None, 1, 10).await.unwrap().is_empty(),
            "{answer} carries no promo"
        );
    }
}

#[tokio::test]
async fn a_scheduled_price_change_keeps_its_direction_and_its_unknown_vocabulary() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "pricechange": [
            {"tld": "com", "type": "renewal", "period": 1, "price": "13.90",
             "oldPrice": 12.5, "currency": "EUR", "startDate": "2026-01-01"},
            {"tld": "de", "action": "restoreFee", "price": "100.00", "old_price": "100.00"}
        ]
    }));

    let client = client(transport.clone());
    let changes = client.price_changes(Some("com"), 1, 10).await.unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "domain.pricechanges");
    assert_eq!(call.params["tld"], "com");
    assert_eq!(call.params["page"], 1);
    assert_eq!(call.params["pagelimit"], 10);

    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0].is_increase(), Some(true));
    assert_eq!(changes[0].effective.as_deref(), Some("2026-01-01"));
    assert_eq!(changes[0].price_type(), Some(PriceType::Renewal));
    assert_eq!(changes[1].price_type(), None);
    assert_eq!(changes[1].action.as_deref(), Some("restoreFee"));
    assert_eq!(
        changes[1].is_increase(),
        None,
        "the same amount under both spellings is neither"
    );
}

#[tokio::test]
async fn a_malformed_price_in_a_scheduled_change_is_none_not_an_error() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "pricechanges": [{"tld": "de", "price": "n/a", "oldPrice": {"amount": 1}}]
    }));

    let client = client(transport);
    let changes = client.price_changes(None, 1, 10).await.unwrap();

    assert_eq!(
        changes.len(),
        1,
        "the row survives an amount it cannot read"
    );
    assert_eq!(changes[0].tld.as_deref(), Some("de"));
    assert_eq!(changes[0].price, None);
    assert_eq!(changes[0].old_price, None);
    assert_eq!(changes[0].is_increase(), None);
}
