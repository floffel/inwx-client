//! Ownership changes on the wire: transfer, trade, push, restore, the transfer
//! answers, and the guard that makes them impossible to trigger by accident.

mod common;

use common::{client, client_without_retries, MockTransport};
use inwx_client::{
    ActionKind, AuthCode, DomainName, ExtData, Handle, Hostname, Irreversible, PushRequest,
    RenewalMode, RestoreRequest, Timestamp, TradeRequest, TransferAnswer, TransferRequest,
};
use serde_json::json;

fn domain(name: &str) -> DomainName {
    DomainName::parse(name).unwrap()
}

fn ack(action: ActionKind) -> Irreversible {
    Irreversible::acknowledge(action, &domain("example.com"))
}

fn transfer() -> TransferRequest {
    TransferRequest::new(ack(ActionKind::Transfer))
        .unwrap_or_else(|error| panic!("{error}"))
        .auth_code(AuthCode::new("aB3-xY9_42").unwrap())
        .unwrap()
        .with_registrant(Handle::new(991).unwrap())
        .with_admin(Handle::new(992).unwrap())
        .with_tech(Handle::new(993).unwrap())
        .with_billing(Handle::new(994).unwrap())
        .with_nameservers(&[Hostname::parse("ns1.example.net").unwrap()])
        .unwrap()
        .with_transfer_lock(false)
        .with_renewal_mode(RenewalMode::AutoRenew)
        .with_period(inwx_client::Period::years(2).unwrap())
        .with_whois_provider("Example Whois")
        .unwrap()
        .with_whois_url("https://whois.example.net")
        .unwrap()
        .scheduled_at(Timestamp::parse("2026-11-01T03:00:00").unwrap())
        .with_voucher("SUMMER26")
        .unwrap()
        .with_agreed_price(250.0)
        .unwrap()
        .asynchronous()
}

#[tokio::test]
async fn transfer_sends_every_documented_field() {
    let transport = MockTransport::new();
    transport.ok(json!({ "roId": 42, "price": 12.5, "currency": "EUR" }));

    let client = client(transport.clone());
    let request = transfer();
    let outcome = client.transfer_domain(&request).await.unwrap();

    assert_eq!(outcome.ro_id, Some(42));
    assert_eq!(outcome.price, Some(12.5));
    assert_eq!(outcome.currency.as_deref(), Some("EUR"));

    let call = transport.only_call();
    assert_eq!(call.method, "domain.transfer");
    assert_eq!(call.params["domain"], "example.com");
    assert_eq!(call.params["authCode"], "aB3-xY9_42");
    assert_eq!(call.params["registrant"], 991);
    assert_eq!(call.params["admin"], 992);
    assert_eq!(call.params["tech"], 993);
    assert_eq!(call.params["billing"], 994);
    assert_eq!(call.params["ns"][0], "ns1.example.net");
    assert_eq!(call.params["transferLock"], false);
    assert_eq!(call.params["renewalMode"], "AUTORENEW");
    assert_eq!(call.params["period"], "2Y");
    assert_eq!(call.params["whoisProvider"], "Example Whois");
    assert_eq!(call.params["whoisUrl"], "https://whois.example.net");
    assert_eq!(call.params["scDate"], "2026-11-01T03:00:00");
    assert_eq!(call.params["voucher"], "SUMMER26");
    assert_eq!(call.params["agreedPrice"], 250.0);
    assert_eq!(call.params["asynchron"], true);
    assert_eq!(call.params["testing"], false);
}

#[tokio::test]
async fn transfer_with_contact_takeover_and_ext_data() {
    let transport = MockTransport::new();
    transport.ok(json!({ "roId": 1 }));

    let mut extra = ExtData::new();
    extra.no_domain_check(true).unwrap();
    extra.no_host_check(true).unwrap();
    extra.birth_date("1990-05-23").unwrap();
    extra.birth_city("Munich").unwrap();
    extra.set("TRADEMARK", "Example GmbH").unwrap();

    let request = TransferRequest::new(ack(ActionKind::Transfer))
        .unwrap()
        .keeping_nameservers()
        .with_contact_takeover(true)
        .with_ext_data(extra)
        .dry_run();

    client(transport.clone())
        .transfer_domain(&request)
        .await
        .unwrap();

    let call = transport.only_call();
    assert_eq!(call.params["nsTakeover"], true);
    assert_eq!(call.params["contactTakeover"], true);
    assert_eq!(call.params["testing"], true);
    assert_eq!(call.params["extData"]["NO-DOMAIN-CHECK"], true);
    assert_eq!(call.params["extData"]["NO-HOST-CHECK"], true);
    assert_eq!(call.params["extData"]["BIRTH-DATE"], "1990-05-23");
    assert_eq!(call.params["extData"]["BIRTH-CITY"], "Munich");
    assert_eq!(call.params["extData"]["TRADEMARK"], "Example GmbH");
}

#[tokio::test]
async fn transfer_refuses_to_mix_takeover_and_explicit_nameservers() {
    let transport = MockTransport::new();
    let request = TransferRequest::new(ack(ActionKind::Transfer))
        .unwrap()
        .keeping_nameservers()
        .with_nameservers(&[Hostname::parse("ns1.example.net").unwrap()])
        .unwrap();

    let error = client_without_retries(transport.clone())
        .transfer_domain(&request)
        .await
        .unwrap_err();
    assert!(error.is_validation());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn trade_sends_the_new_owner_and_optional_contacts() {
    let transport = MockTransport::new();
    transport.ok(json!({ "roId": 42, "notifications": ["TECH"] }));

    let mut extra = ExtData::new();
    extra.no_domain_check(false).unwrap();

    let request = TradeRequest::new(ack(ActionKind::Trade))
        .unwrap()
        .with_registrant(Handle::new(1201).unwrap())
        .with_admin(Handle::new(1202).unwrap())
        .with_tech(Handle::new(1203).unwrap())
        .with_billing(Handle::new(1204).unwrap())
        .with_nameservers(&[Hostname::parse("ns1.example.net").unwrap()])
        .unwrap()
        .auth_code(AuthCode::new("code-1").unwrap())
        .unwrap()
        .with_whois_provider("Example")
        .unwrap()
        .with_whois_url("https://whois.example.net")
        .unwrap()
        .scheduled_at(Timestamp::parse("2026-12-01T00:00:00").unwrap())
        .with_ext_data(extra)
        .asynchronous()
        .dry_run();

    let outcome = client(transport.clone())
        .trade_domain(&request)
        .await
        .unwrap();
    assert_eq!(outcome.notifications, ["TECH"]);

    let call = transport.only_call();
    assert_eq!(call.method, "domain.trade");
    assert_eq!(call.params["registrant"], 1201);
    assert_eq!(call.params["admin"], 1202);
    assert_eq!(call.params["tech"], 1203);
    assert_eq!(call.params["billing"], 1204);
    assert_eq!(call.params["authCode"], "code-1");
    assert_eq!(call.params["extData"]["NO-DOMAIN-CHECK"], false);
    assert_eq!(call.params["asynchron"], true);
    assert_eq!(call.params["testing"], true);
}

#[tokio::test]
async fn trade_without_a_registrant_never_reaches_the_wire() {
    let transport = MockTransport::new();
    let request = TradeRequest::new(ack(ActionKind::Trade)).unwrap();
    let error = client_without_retries(transport.clone())
        .trade_domain(&request)
        .await
        .unwrap_err();
    assert!(error.is_validation());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn push_sends_the_target_and_schedule() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let request = PushRequest::new(ack(ActionKind::Push))
        .unwrap()
        .with_target("other-registrar")
        .unwrap()
        .scheduled_at(Timestamp::parse("2026-12-01T00:00:00").unwrap())
        .dry_run();

    client(transport.clone())
        .push_domain(&request)
        .await
        .unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "domain.push");
    assert_eq!(call.params["domain"], "example.com");
    assert_eq!(call.params["target"], "other-registrar");
    assert_eq!(call.params["scDate"], "2026-12-01T00:00:00");
    assert_eq!(call.params["testing"], true);
}

#[tokio::test]
async fn restore_sends_the_renewal_mode() {
    let transport = MockTransport::new();
    transport.ok(json!({ "domain": "example.com", "domainAce": "example.com" }));

    let request = RestoreRequest::new(ack(ActionKind::Restore))
        .unwrap()
        .with_renewal_mode(RenewalMode::AutoRenew);
    let restored = client(transport.clone())
        .restore_domain(&request)
        .await
        .unwrap();

    assert_eq!(restored.domain_ace.as_deref(), Some("example.com"));
    let call = transport.only_call();
    assert_eq!(call.method, "domain.restore");
    assert_eq!(call.params["renewalMode"], "AUTORENEW");
}

#[tokio::test]
async fn cancel_transfer_and_transfer_out_send_only_the_domain() {
    let transport = MockTransport::new();
    transport.ok_empty();
    transport.ok_empty();

    let client = client(transport.clone());
    client
        .cancel_transfer(&Irreversible::acknowledge(
            ActionKind::TransferCancel,
            &domain("example.com"),
        ))
        .await
        .unwrap();
    client
        .answer_transfer_out(
            &Irreversible::acknowledge(ActionKind::TransferOut, &domain("example.com")),
            TransferAnswer::Nack,
        )
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls[0].method, "domain.transfercancel");
    assert_eq!(calls[0].params["domain"], "example.com");
    assert_eq!(calls[1].method, "domain.transferOut");
    assert_eq!(calls[1].params["answer"], "NACK");
}

#[tokio::test]
async fn a_mismatched_acknowledgement_never_reaches_the_wire() {
    let transport = MockTransport::new();
    let client = client_without_retries(transport.clone());

    // A trade acknowledgement cannot cancel a transfer.
    let error = client
        .cancel_transfer(&Irreversible::acknowledge(
            ActionKind::Trade,
            &domain("example.com"),
        ))
        .await
        .unwrap_err();
    assert!(error.is_validation());

    let error = client
        .answer_transfer_out(
            &Irreversible::acknowledge(ActionKind::Push, &domain("example.com")),
            TransferAnswer::Ack,
        )
        .await
        .unwrap_err();
    assert!(error.is_validation());

    assert_eq!(transport.call_count(), 0);
}

#[test]
fn a_builder_cannot_be_created_from_the_wrong_intent() {
    assert!(TransferRequest::new(ack(ActionKind::Push)).is_err());
    assert!(TradeRequest::new(ack(ActionKind::Transfer)).is_err());
    assert!(PushRequest::new(ack(ActionKind::Restore)).is_err());
    assert!(RestoreRequest::new(ack(ActionKind::Push)).is_err());
}

#[test]
fn auth_codes_never_appear_in_debug_output() {
    let code = AuthCode::new("super-secret").unwrap();
    assert_eq!(format!("{code:?}"), "AuthCode(<redacted>)");
    assert_eq!(code.to_string(), "<redacted>");
    assert_eq!(code.as_str(), "super-secret");

    for bad in ["", "  ", "with space", "tab\there", "ümlaut"] {
        assert!(AuthCode::new(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn handles_and_ext_data_are_validated() {
    assert!(Handle::new(0).is_err());
    assert!(Handle::try_from(-1i64).is_err());
    assert_eq!(i64::from(Handle::new(7).unwrap()), 7);

    let mut extra = ExtData::new();
    assert_eq!(extra, ExtData::new());
    assert!(extra.set("lower", "x").is_err());
    assert!(extra.set("WITH SPACE", "x").is_err());
    assert!(extra.set("OK", "").is_err());
    assert!(extra.birth_date("1990-02-30").is_err());
    assert!(extra.birth_city(&"x".repeat(65)).is_err());
    assert_eq!(extra.params().as_object().unwrap().len(), 0);
    assert_eq!(ExtData::new(), ExtData::default());
}
