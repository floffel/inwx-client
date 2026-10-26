//! The service surfaces on the wire: DNSSEC, nameserver sets, tags, DynDNS and
//! hosting packages. One test per command, each asserting the method name and
//! the exact parameters that went out.

mod common;

use common::{client, client_without_retries, MockTransport};
use inwx_client::{
    AddDnsKeyRequest, DnsKey, DnssecAlgorithm, DnssecDigestType, DnssecKeyQuery, DnssecKeyStatus,
    DomainName, DsRecord, DynDnsAccount, DynDnsAccountRef, Email, Handle, HostingOrder,
    HostingPeriod, Hostname, NameserverSetCreate, NameserverSetType, NameserverSetUpdate,
    TagUpdate, Timestamp,
};
use serde_json::json;

fn domain(name: &str) -> DomainName {
    DomainName::parse(name).unwrap()
}

fn host(name: &str) -> Hostname {
    Hostname::parse(name).unwrap()
}

// ---------------------------------------------------------------- DNSSEC ----

#[tokio::test]
async fn dnssec_toggles_send_the_domain() {
    let transport = MockTransport::new();
    transport.ok_empty();
    transport.ok_empty();
    transport.ok_empty();

    let client = client(transport.clone());
    client.enable_dnssec(&domain("example.com")).await.unwrap();
    client.disable_dnssec(&domain("example.com")).await.unwrap();
    client
        .delete_all_dns_keys(&domain("example.com"))
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls[0].method, "dnssec.enablednssec");
    assert_eq!(calls[0].params["domainName"], "example.com");
    assert_eq!(calls[1].method, "dnssec.disablednssec");
    assert_eq!(calls[2].method, "dnssec.deleteall");
}

#[tokio::test]
async fn add_dns_key_sends_the_presentation_and_digest_request() {
    let transport = MockTransport::new();
    transport.ok(json!({ "dnskey": "example.com. IN DNSKEY 257 3 13 ac12", "ds": "example.com. IN DS 1 13 2 AA" }));

    let request = AddDnsKeyRequest::new(
        domain("example.com"),
        DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12c2").unwrap(),
    )
    .unwrap()
    .calculating_digest(DnssecDigestType::Sha384)
    .unwrap();

    let pair = client(transport.clone())
        .add_dns_key(&request)
        .await
        .unwrap();

    assert!(pair.dnskey.starts_with("example.com."));
    assert_eq!(pair.ds.as_deref(), Some("example.com. IN DS 1 13 2 AA"));

    let call = transport.only_call();
    assert_eq!(call.method, "dnssec.adddnskey");
    assert_eq!(call.params["domainName"], "example.com");
    assert_eq!(
        call.params["dnskey"],
        "example.com. IN DNSKEY 257 3 13 ac12c2"
    );
    assert_eq!(call.params["calculateDigest"], true);
    assert_eq!(call.params["digestType"], 4);
    assert!(call.params.get("ds").is_none());
}

#[tokio::test]
async fn add_dns_key_with_a_supplied_ds_does_not_calculate() {
    let transport = MockTransport::new();
    transport.ok(json!({ "dnskey": "k" }));

    let request = AddDnsKeyRequest::new(
        domain("example.com"),
        DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12").unwrap(),
    )
    .unwrap()
    .with_ds(DsRecord::parse("example.com. IN DS 1234 13 2 AA").unwrap())
    .unwrap();

    client(transport.clone())
        .add_dns_key(&request)
        .await
        .unwrap();
    let call = transport.only_call();
    assert_eq!(call.params["ds"], "example.com. IN DS 1234 13 2 AA");
    assert!(call.params.get("calculateDigest").is_none());
}

#[tokio::test]
async fn add_dns_key_refuses_a_foreign_owner() {
    let transport = MockTransport::new();
    let key = DnsKey::parse("example.net. IN DNSKEY 257 3 13 ac12").unwrap();
    assert!(AddDnsKeyRequest::new(domain("example.com"), key).is_err());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn delete_dns_key_sends_the_key_id() {
    let transport = MockTransport::new();
    transport.ok_empty();

    client(transport.clone()).delete_dns_key(7).await.unwrap();
    let call = transport.only_call();
    assert_eq!(call.method, "dnssec.deletednskey");
    assert_eq!(call.params["key"], 7);

    let transport = MockTransport::new();
    assert!(client_without_retries(transport.clone())
        .delete_dns_key(0)
        .await
        .is_err());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn dnssec_info_sends_the_domain_filter_and_parses_the_states() {
    let transport = MockTransport::new();
    transport.ok(json!({ "data": [
        { "domain": "example.com", "keyCount": 2, "dnssecStatus": "MANUAL" },
        { "domain": "example.net" }
    ] }));
    transport.ok(json!({ "data": [] }));

    let client = client(transport.clone());
    let states = client
        .dnssec_info(Some(&[domain("example.com"), domain("example.net")]))
        .await
        .unwrap();
    assert_eq!(states.len(), 2);
    assert_eq!(states[0].key_count, Some(2));
    assert_eq!(states[0].status.as_str(), "MANUAL");

    let all = client.dnssec_info(None).await.unwrap();
    assert!(all.is_empty());

    let calls = transport.calls();
    assert_eq!(calls[0].method, "dnssec.info");
    assert_eq!(calls[0].params["domains"][0], "example.com");
    assert_eq!(calls[1].params, json!({}));
}

#[tokio::test]
async fn list_dns_keys_sends_every_filter() {
    let transport = MockTransport::new();
    transport.ok(json!({ "dnskey": [
        { "id": 7, "ownerName": "example.com.", "keyTag": 1234, "flagId": 257,
          "algorithmId": 13, "digestTypeId": 2, "digest": "AA", "status": "OK", "active": 1 }
    ] }));

    let query = DnssecKeyQuery::new()
        .with_domain("example.com")
        .unwrap()
        .with_key_tag(1234)
        .with_algorithm(DnssecAlgorithm::EcdsaP256)
        .with_status(&DnssecKeyStatus::Ok)
        .only_active(true)
        .created_after(&Timestamp::parse("2026-01-01T00:00:00").unwrap())
        .unwrap()
        .created_before(&Timestamp::parse("2026-12-31T00:00:00").unwrap())
        .unwrap()
        .with_page(1, 0);

    let keys = client(transport.clone())
        .list_dns_keys(&query)
        .await
        .unwrap();
    assert_eq!(keys.len(), 1);
    assert!(keys[0].is_active());

    let call = transport.only_call();
    assert_eq!(call.method, "dnssec.listkeys");
    assert_eq!(call.params["domainName"], "example.com");
    assert_eq!(call.params["keyTag"], 1234);
    assert_eq!(call.params["algorithmId"], 13);
    assert_eq!(call.params["status"], "OK");
    assert_eq!(call.params["active"], 1);
    assert_eq!(call.params["createdAfter"], "2026-01-01T00:00:00");
    assert_eq!(call.params["createdBefore"], "2026-12-31T00:00:00");
    assert_eq!(call.params["pagelimit"], 0);
}

// -------------------------------------------------------- NAMESERVER SET ----

fn nameserver_set() -> NameserverSetCreate {
    NameserverSetCreate::new(NameserverSetType::Primary, &[host("ns1.example.net")])
        .unwrap()
        .with_name("tenant-default")
        .unwrap()
        .with_hostmaster(Email::parse("hostmaster@example.net").unwrap())
        .unwrap()
        .with_visibility(false)
        .with_priority(5)
        .with_web("https://example.net")
        .unwrap()
        .with_mail("mx.example.net")
        .unwrap()
}

#[tokio::test]
async fn create_nameserver_set_sends_every_field() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 9 }));

    let id = client(transport.clone())
        .create_nameserver_set(&nameserver_set())
        .await
        .unwrap();
    assert_eq!(id, 9);

    let call = transport.only_call();
    assert_eq!(call.method, "nameserverset.create");
    assert_eq!(call.params["type"], "PRIMARY");
    assert_eq!(call.params["ns"][0], "ns1.example.net");
    assert_eq!(call.params["name"], "tenant-default");
    assert_eq!(call.params["hostmaster"], "hostmaster@example.net");
    assert_eq!(call.params["visible"], false);
    assert_eq!(call.params["prio"], 5);
    assert_eq!(call.params["web"], "https://example.net");
    assert_eq!(call.params["mail"], "mx.example.net");
}

#[tokio::test]
async fn a_secondary_set_can_carry_a_master() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 10 }));

    let request =
        NameserverSetCreate::new(NameserverSetType::Secondary, &[host("ns1.example.net")])
            .unwrap()
            .with_master_ip(inwx_client::parse_ip("198.51.100.7").unwrap())
            .unwrap()
            .dry_run();

    client(transport.clone())
        .create_nameserver_set(&request)
        .await
        .unwrap();
    let call = transport.only_call();
    assert_eq!(call.params["masterIp"], "198.51.100.7");
    assert_eq!(call.params["testing"], true);
}

#[tokio::test]
async fn create_nameserver_set_without_an_id_is_missing() {
    let transport = MockTransport::new();
    transport.ok(json!({}));
    assert!(client(transport)
        .create_nameserver_set(&nameserver_set())
        .await
        .is_err());
}

#[tokio::test]
async fn update_and_delete_nameserver_set() {
    let transport = MockTransport::new();
    transport.ok_empty();
    transport.ok_empty();
    transport.ok_empty();

    let client = client(transport.clone());
    client
        .update_nameserver_set(
            &NameserverSetUpdate::new(9)
                .unwrap()
                .with_set_type(NameserverSetType::External)
                .with_nameservers(&[host("ns2.example.net")])
                .unwrap()
                .with_name("renamed")
                .unwrap()
                .with_hostmaster(Email::parse("hostmaster@example.net").unwrap())
                .unwrap()
                .with_visibility(true)
                .with_priority(3)
                .with_web("https://example.net")
                .unwrap()
                .with_mail("mx.example.net")
                .unwrap()
                .with_master_ip(inwx_client::parse_ip("198.51.100.7").unwrap())
                .dry_run(),
        )
        .await
        .unwrap();
    client.delete_nameserver_set(9).await.unwrap();
    client
        .update_nameserver_set(&NameserverSetUpdate::new(9).unwrap().with_visibility(false))
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls[0].method, "nameserverset.update");
    assert_eq!(calls[0].params["id"], 9);
    assert_eq!(calls[0].params["type"], "EXTERNAL");
    assert_eq!(calls[0].params["ns"][0], "ns2.example.net");
    assert_eq!(calls[0].params["name"], "renamed");
    assert_eq!(calls[0].params["prio"], 3);
    assert_eq!(calls[0].params["testing"], true);
    assert_eq!(calls[1].method, "nameserverset.delete");
    assert_eq!(calls[1].params["id"], 9);
}

#[tokio::test]
async fn nameserver_set_info_and_list() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "id": "9", "name": "tenant-default", "ns": ["ns1.example.net"],
        "type": "PRIMARY", "hostmaster": "hostmaster@example.net", "visible": true, "readOnly": false
    }));
    transport.ok(json!({ "count": 1, "nsset": [{ "id": 9, "type": "PRIMARY", "ns": [] }] }));
    transport.ok(json!({ "count": 0, "nsset": [] }));

    let client = client(transport.clone());
    let set = client.nameserver_set_info(9).await.unwrap();
    assert_eq!(set.nameservers, ["ns1.example.net"]);
    assert_eq!(set.read_only, Some(false));

    let sets = client.list_nameserver_sets(true, 1, 20).await.unwrap();
    assert_eq!(sets.len(), 1);

    let wide = client.list_nameserver_sets(false, 2, 50).await.unwrap();
    assert!(wide.is_empty());

    let calls = transport.calls();
    assert_eq!(calls[0].method, "nameserverset.info");
    assert_eq!(calls[0].params["id"], 9);
    assert_eq!(calls[1].method, "nameserverset.list");
    assert_eq!(calls[1].params["wide"], true);
    assert_eq!(calls[2].params["page"], 2);
}

#[tokio::test]
async fn nameserver_set_validation_short_circuits() {
    let transport = MockTransport::new();
    let client = client_without_retries(transport.clone());

    assert!(client.nameserver_set_info(0).await.is_err());
    assert!(client.delete_nameserver_set(0).await.is_err());
    assert!(client.list_nameserver_sets(true, 1, 0).await.is_err());
    assert!(client
        .update_nameserver_set(&NameserverSetUpdate::new(9).unwrap())
        .await
        .is_err());
    assert_eq!(transport.call_count(), 0);
}

// ------------------------------------------------------------------ TAGS ----

#[tokio::test]
async fn tag_lifecycle_commands_send_their_ids() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 3, "name": "tenant-a" }));
    transport.ok(json!({ "id": 3, "name": "tenant-a" }));
    transport.ok(json!({ "id": 3, "name": "tenant-b" }));
    transport.ok_empty();
    transport.ok(json!({ "tag": [
        { "id": 3, "name": "tenant-a", "count": { "domain": 2 } },
        { "id": 4, "name": "tenant-b" }
    ] }));
    transport.ok(json!({ "tag": [] }));

    let client = client(transport.clone());
    let created = client.create_tag("tenant-a").await.unwrap();
    assert_eq!(created.id, Some(3));
    let info = client.tag_info(3).await.unwrap();
    assert_eq!(info.name.as_deref(), Some("tenant-a"));
    let renamed = client
        .update_tag(&TagUpdate::new(3).unwrap().renaming("tenant-b").unwrap())
        .await
        .unwrap();
    assert_eq!(renamed.name.as_deref(), Some("tenant-b"));
    client.delete_tag(3).await.unwrap();

    let tagged = client
        .list_tags(Some(&[domain("example.com")]), Some(&[3, 4]))
        .await
        .unwrap();
    assert_eq!(tagged.len(), 2);
    assert_eq!(tagged[0].count.domain, Some(2));

    let empty = client.list_tags(None, None).await.unwrap();
    assert!(empty.is_empty());

    let calls = transport.calls();
    assert_eq!(calls[0].method, "tag.create");
    assert_eq!(calls[0].params["name"], "tenant-a");
    assert_eq!(calls[1].method, "tag.info");
    assert_eq!(calls[1].params["id"], 3);
    assert_eq!(calls[2].method, "tag.update");
    assert_eq!(calls[2].params["name"], "tenant-b");
    assert_eq!(calls[3].method, "tag.delete");
    assert_eq!(calls[4].method, "tag.list");
    assert_eq!(calls[4].params["domain"][0], "example.com");
    assert_eq!(calls[4].params["id"][1], 4);
    assert_eq!(calls[5].params, json!({}));
}

#[tokio::test]
async fn tagging_and_untagging_send_domain_ids() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": 3 }));

    client(transport.clone())
        .update_tag(
            &TagUpdate::new(3)
                .unwrap()
                .tagging(&[101])
                .unwrap()
                .untagging(&[102])
                .unwrap(),
        )
        .await
        .unwrap();

    let call = transport.only_call();
    assert_eq!(call.params["add"]["domainId"][0], 101);
    assert_eq!(call.params["rem"]["domainId"][0], 102);
    assert!(call.params.get("name").is_none());
}

#[tokio::test]
async fn tag_validation_short_circuits() {
    let transport = MockTransport::new();
    let client = client_without_retries(transport.clone());

    assert!(client.create_tag("  ").await.is_err());
    assert!(client.tag_info(0).await.is_err());
    assert!(client.delete_tag(0).await.is_err());
    assert!(client.list_tags(Some(&[]), None).await.is_err());
    assert!(client.list_tags(None, Some(&[])).await.is_err());
    let rename_and_tag = TagUpdate::new(3)
        .unwrap()
        .renaming("x")
        .unwrap()
        .tagging(&[1])
        .unwrap();
    assert!(client.update_tag(&rename_and_tag).await.is_err());
    assert_eq!(transport.call_count(), 0);
}

// ---------------------------------------------------------------- DYNDNS ----

fn dyndns_account() -> DynDnsAccount {
    DynDnsAccount::create("tenant-42", "s3cret-pass", &[host("home.example.net")]).unwrap()
}

#[tokio::test]
async fn dyndns_create_and_check_send_their_fields() {
    let transport = MockTransport::new();
    transport.ok(json!({ "accountId": 71, "recordId": 88 }));
    transport.ok(json!({ "username": "tenant-42", "available": true }));
    transport.ok(json!({ "available": false }));

    let client = client(transport.clone());
    let created = client.create_dyndns(&dyndns_account()).await.unwrap();
    assert_eq!(created.account_id, Some(71));
    assert_eq!(created.record_id, Some(88));

    let check = client
        .check_dyndns(Some("tenant-42"), Some(&[host("home.example.net")]))
        .await
        .unwrap();
    assert!(check.is_available());

    let hostname_only = client
        .check_dyndns(None, Some(&[host("home.example.net")]))
        .await
        .unwrap();
    assert!(!hostname_only.is_available());

    let calls = transport.calls();
    assert_eq!(calls[0].method, "dyndns.create");
    assert_eq!(calls[0].params["username"], "tenant-42");
    assert_eq!(calls[0].params["password"], "s3cret-pass");
    assert_eq!(calls[0].params["hostname"][0], "home.example.net");
    assert_eq!(calls[1].method, "dyndns.check");
    assert_eq!(calls[1].params["username"], "tenant-42");
    assert_eq!(calls[1].params["hostname"][0], "home.example.net");
    assert_eq!(calls[2].params["hostname"][0], "home.example.net");
    assert!(calls[2].params.get("username").is_none());
}

#[tokio::test]
async fn dyndns_read_and_delete_commands() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "accountId": 71, "username": "tenant-42", "created": "2026-01-01T10:00:00",
        "records": [{ "id": "88", "name": "home", "type": "A", "content": "203.0.113.7" }]
    }));
    transport.ok(json!({ "accountId": 71, "username": "tenant-42", "records": [] }));
    transport.ok_empty();
    transport.ok(
        json!({ "count": 1, "logs": [{ "ip": "203.0.113.7", "date": "2026-10-26T08:00:00" }] }),
    );
    transport.ok_empty();

    let client = client(transport.clone());
    let account = client
        .dyndns_info(&DynDnsAccountRef::by_id(71).unwrap())
        .await
        .unwrap();
    assert_eq!(account.records[0].content.as_deref(), Some("203.0.113.7"));

    let listed = client
        .list_dyndns(Some(&DynDnsAccountRef::by_username("tenant-42").unwrap()))
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);

    client
        .delete_dyndns(&DynDnsAccountRef::by_id(71).unwrap())
        .await
        .unwrap();
    let log = client.dyndns_log(71).await.unwrap();
    assert_eq!(log.entries.len(), 1);
    assert_eq!(log.count, Some(1));

    client
        .change_dyndns_password("tenant-42", "new-pass")
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls[0].method, "dyndns.info");
    assert_eq!(calls[0].params["accountId"], 71);
    assert_eq!(calls[1].method, "dyndns.list");
    assert_eq!(calls[1].params["username"], "tenant-42");
    assert_eq!(calls[2].method, "dyndns.delete");
    assert_eq!(calls[3].method, "dyndns.log");
    assert_eq!(calls[3].params["accountId"], 71);
    assert_eq!(calls[4].method, "dyndns.changepassword");
    assert_eq!(calls[4].params["password"], "new-pass");
}

#[tokio::test]
async fn dyndns_update_record_sends_the_documented_addresses() {
    let transport = MockTransport::new();
    transport.ok(json!({ "ipv4_updated": 1, "ipv6_updated": 1 }));

    let updated = client(transport.clone())
        .dyndns_update_record(
            Some("203.0.113.7".parse().unwrap()),
            Some("2001:db8::1".parse().unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(updated.ipv4_updated, Some(1));

    let call = transport.only_call();
    assert_eq!(call.method, "dyndns.updateRecord");
    assert_eq!(call.params["ipAddress"], "203.0.113.7");
    assert_eq!(call.params["ipAddressV6"], "2001:db8::1");
    // Only the documented parameters go out — no invented account selector.
    assert_eq!(call.params.as_object().unwrap().len(), 2);
}

#[tokio::test]
async fn dyndns_validation_short_circuits() {
    let transport = MockTransport::new();
    let client = client_without_retries(transport.clone());

    assert!(client.check_dyndns(None, None).await.is_err());
    assert!(client.check_dyndns(Some("ab"), None).await.is_err());
    assert!(client.check_dyndns(None, Some(&[])).await.is_err());
    assert!(client.dyndns_log(0).await.is_err());
    assert!(client.dyndns_update_record(None, None).await.is_err());
    assert!(client
        .change_dyndns_password("tenant-42", "")
        .await
        .is_err());
    assert!(client.change_dyndns_password("ab", "pw").await.is_err());
    assert_eq!(transport.call_count(), 0);
}

// --------------------------------------------------------------- HOSTING ----

#[tokio::test]
async fn hosting_lifecycle_commands_send_their_ids() {
    let transport = MockTransport::new();
    transport.ok_empty();
    transport.ok(json!({ "hosting": [{ "id": 5, "product": "Hosting M", "suspended": 0 }] }));
    transport.ok(json!({ "hosting": [{ "id": 5, "product": "Hosting M" }] }));
    transport.ok(json!({ "isSuspended": false, "paidUntil": "2027-01-01" }));
    transport.ok(json!({ "url": "https://panel.example.net/5" }));
    transport.ok_empty();
    transport.ok_empty();
    transport.ok(json!({ "netPrice": 5.0, "grossPrice": 5.95, "currency": "EUR" }));
    transport.ok_empty();

    let client = client(transport.clone());
    client
        .create_hosting(&HostingOrder::product(17).unwrap())
        .await
        .unwrap();
    let packages = client.list_hosting().await.unwrap();
    assert_eq!(packages[0].id, Some(5));
    assert_eq!(packages[0].is_suspended(), Some(false));
    let products = client.hosting_prices().await.unwrap();
    assert_eq!(products.len(), 1);
    let state = client.hosting_suspended(5).await.unwrap();
    assert_eq!(state.suspended, Some(false));
    let url = client.hosting_control_panel(5).await.unwrap();
    assert!(url.starts_with("https://panel"));
    client.cancel_hosting(5).await.unwrap();
    client.reinstate_hosting(5).await.unwrap();
    let charged = client.unsuspend_hosting(5).await.unwrap();
    assert_eq!(charged.gross_price, Some(5.95));
    client
        .update_hosting_period(5, HostingPeriod::Months12)
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls[0].method, "hosting.create");
    assert_eq!(calls[0].params["productId"], "17");
    assert_eq!(calls[1].method, "hosting.list");
    assert_eq!(calls[2].method, "hosting.getPrices");
    assert_eq!(calls[3].method, "hosting.issuspended");
    assert_eq!(calls[3].params["hostingId"], 5);
    assert_eq!(calls[4].method, "hosting.controlPanel");
    assert_eq!(calls[4].params["id"], 5);
    assert_eq!(calls[5].method, "hosting.cancel");
    assert_eq!(calls[5].params["hostingId"], "5");
    assert_eq!(calls[6].method, "hosting.reinstate");
    assert_eq!(calls[7].method, "hosting.unsuspend");
    assert_eq!(calls[8].method, "hosting.updatePeriod");
    assert_eq!(calls[8].params["period"], 12);
}

#[tokio::test]
async fn hosting_control_panel_without_a_url_is_missing() {
    let transport = MockTransport::new();
    transport.ok(json!({}));
    assert!(client(transport).hosting_control_panel(5).await.is_err());
}

#[tokio::test]
async fn hosting_orders_and_periods_are_validated() {
    let transport = MockTransport::new();
    let client = client_without_retries(transport.clone());

    assert!(client.hosting_suspended(0).await.is_err());
    assert!(client.cancel_hosting(0).await.is_err());
    assert!(client.reinstate_hosting(0).await.is_err());
    assert!(client.unsuspend_hosting(0).await.is_err());
    assert!(client.hosting_control_panel(0).await.is_err());
    assert!(client
        .update_hosting_period(0, HostingPeriod::Months1)
        .await
        .is_err());
    assert!(HostingOrder::existing(0).is_err());
    assert!(HostingPeriod::try_from(9u32).is_err());
    assert_eq!(transport.call_count(), 0);
}

#[test]
fn every_handle_and_accessor_is_reachable() {
    // Cheap coverage of the small accessors that no command needs.
    assert_eq!(Handle::new(1).unwrap().to_string(), "1");
    assert_eq!(HostingPeriod::Months24.months(), 24);
    assert_eq!(HostingPeriod::Months24.as_str(), "24");
    assert_eq!("6".parse::<HostingPeriod>().unwrap().months(), 6);
    assert!("x".parse::<HostingPeriod>().is_err());
    assert_eq!(DnssecAlgorithm::Ed448.as_u8(), 16);
    assert!(DnssecAlgorithm::from_u8(13).is_ok());
    assert_eq!(DnssecDigestType::Sha256.as_u8(), 2);
    assert!(DnssecDigestType::from_u8(4).is_ok());
}

// --------------------------------------------------- DYNDNS SUBSCRIPTIONS ----

#[tokio::test]
async fn dyndns_subscription_commands_send_their_ids() {
    let transport = MockTransport::new();
    transport.ok_empty();
    transport.ok_empty();
    transport.ok(json!({ "subscription": [
        { "id": 7, "name": "DynDNS 5", "accountsAmount": 5, "price": 9.9, "currency": "EUR" }
    ] }));
    transport.ok(json!({ "subscription": [
        { "id": 4, "name": "DynDNS 10", "accountsAmount": 10, "price": 19.9 }
    ] }));

    let client = client(transport.clone());
    client.create_dyndns_subscription(4).await.unwrap();
    client.cancel_dyndns_subscription(7).await.unwrap();
    let subscriptions = client.list_dyndns_subscriptions(1, 20).await.unwrap();
    assert_eq!(subscriptions[0].accounts_amount, Some(5));
    let plans = client
        .list_dyndns_subscription_products(2, 10)
        .await
        .unwrap();
    assert_eq!(plans[0].price, Some(19.9));

    let calls = transport.calls();
    assert_eq!(calls[0].method, "dyndnssubscription.create");
    assert_eq!(calls[0].params["id"], 4);
    assert_eq!(calls[1].method, "dyndnssubscription.cancel");
    assert_eq!(calls[1].params["id"], 7);
    assert_eq!(calls[2].method, "dyndnssubscription.list");
    assert_eq!(calls[2].params["page"], 1);
    assert_eq!(calls[3].method, "dyndnssubscription.listProducts");
    assert_eq!(calls[3].params["pagelimit"], 10);
}

#[tokio::test]
async fn dyndns_subscription_validation_short_circuits() {
    let transport = MockTransport::new();
    let client = client_without_retries(transport.clone());
    assert!(client.create_dyndns_subscription(0).await.is_err());
    assert!(client.cancel_dyndns_subscription(0).await.is_err());
    assert!(client.list_dyndns_subscriptions(1, 0).await.is_err());
    assert!(client
        .list_dyndns_subscription_products(1, 0)
        .await
        .is_err());
    assert_eq!(transport.call_count(), 0);
}
