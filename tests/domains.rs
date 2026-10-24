//! Domains, contacts, zones and prices against the scripted transport.

mod common;

use common::{client, MockTransport};
use inwx_client::{
    ContactQuery, ContactRequest, ContactType, ContactUpdate, DomainCreate, DomainListQuery,
    DomainName, DomainRenew, DomainUpdate, Error, Hostname, Period, PriceType, RenewalMode,
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
    assert!(client.tld_prices(&["", "."]).await.unwrap().is_empty());
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
