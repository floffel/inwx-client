//! The zone lifecycle on the wire: `nameserver.create`, `update`, `delete`,
//! `clone`, `export*`, and the record-set rules that guard a create.

mod common;

use common::{client, client_without_retries, MockTransport};
use inwx_client::{
    parse_ip, DocumentFormat, DomainName, Error, Hostname, RecordSet, RecordSpec, RecordType,
    UrlRedirectType, ZoneCreate, ZoneType, ZoneUpdate,
};
use serde_json::json;

fn domain(name: &str) -> DomainName {
    DomainName::parse(name).unwrap()
}

fn host(name: &str) -> Hostname {
    Hostname::parse(name).unwrap()
}

#[tokio::test]
async fn create_sends_every_documented_zone_field() {
    let transport = MockTransport::new();
    transport.ok(json!({ "roId": 42 }));

    let zone = ZoneCreate::master(domain("tenant.example.com"))
        .unwrap()
        .with_nameservers(&[host("ns1.example.net"), host("ns2.example.net")])
        .unwrap()
        .with_soa_email(inwx_client::Email::parse("hostmaster@example.net").unwrap())
        .unwrap()
        .with_mail("mx.example.net")
        .unwrap();

    let ro_id = client(transport.clone()).create_zone(&zone).await.unwrap();

    assert_eq!(ro_id, 42);
    let call = transport.only_call();
    assert_eq!(call.method, "nameserver.create");
    assert_eq!(call.params["domain"], "tenant.example.com");
    assert_eq!(call.params["type"], "MASTER");
    assert_eq!(call.params["ns"][0], "ns1.example.net");
    assert_eq!(call.params["soaEmail"], "hostmaster@example.net");
    assert_eq!(call.params["mail"], "mx.example.net");
    assert_eq!(call.params["testing"], false);
    assert!(call.params.get("ignoreExisting").is_none());
}

#[tokio::test]
async fn create_a_slave_zone_sends_its_master() {
    let transport = MockTransport::new();
    transport.ok(json!({ "roId": 7 }));

    let zone = ZoneCreate::slave(domain("example.com"), parse_ip("198.51.100.7").unwrap()).unwrap();
    client(transport.clone()).create_zone(&zone).await.unwrap();

    let call = transport.only_call();
    assert_eq!(call.params["type"], "SLAVE");
    assert_eq!(call.params["masterIp"], "198.51.100.7");
}

#[tokio::test]
async fn create_without_a_ro_id_is_a_missing_field_error() {
    let transport = MockTransport::new();
    transport.ok(json!({}));

    let zone = ZoneCreate::master(domain("example.com")).unwrap();
    let error = client(transport).create_zone(&zone).await.unwrap_err();

    assert!(matches!(error, Error::MissingField { field, .. } if field == "resData.roId"));
}

#[tokio::test]
async fn create_in_dry_run_mode_and_with_ignore_existing() {
    let transport = MockTransport::new();
    transport.ok(json!({ "roId": 1 }));
    transport.ok(json!({ "roId": 2 }));

    let zone = ZoneCreate::master(domain("example.com"))
        .unwrap()
        .dry_run()
        .ignore_existing();
    let client = client(transport.clone());
    client.create_zone(&zone).await.unwrap();
    client
        .create_zone(&ZoneCreate::master(domain("example.org")).unwrap())
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls[0].params["testing"], true);
    assert_eq!(calls[0].params["ignoreExisting"], true);
    assert_eq!(calls[1].params["testing"], false);
}

#[tokio::test]
async fn create_with_a_frame_redirect_sends_its_metadata() {
    let transport = MockTransport::new();
    transport.ok(json!({ "roId": 3 }));

    let zone = ZoneCreate::master(domain("shop.example.com"))
        .unwrap()
        .with_web("https://example.net")
        .unwrap()
        .with_redirect_type(UrlRedirectType::Frame)
        .unwrap()
        .with_frame_title("Tenant")
        .unwrap()
        .with_frame_description("Tenant portal")
        .unwrap()
        .with_frame_favicon("https://example.net/favicon.ico")
        .unwrap()
        .with_frame_keywords("tenant, portal")
        .unwrap();

    client(transport.clone()).create_zone(&zone).await.unwrap();
    let call = transport.only_call();
    assert_eq!(call.params["urlRedirectType"], "FRAME");
    assert_eq!(call.params["urlRedirectTitle"], "Tenant");
    assert_eq!(call.params["urlRedirectDescription"], "Tenant portal");
    assert_eq!(
        call.params["urlRedirectFavIcon"],
        "https://example.net/favicon.ico"
    );
    assert_eq!(call.params["urlRedirectKeywords"], "tenant, portal");
    assert_eq!(call.params["web"], "https://example.net");
}

#[tokio::test]
async fn create_rejects_an_inconsistent_request_before_the_wire() {
    let transport = MockTransport::new();
    let client = client_without_retries(transport.clone());

    let slave_without_master = ZoneCreate::new(domain("a.de"), ZoneType::Slave).unwrap();
    assert!(client.create_zone(&slave_without_master).await.is_err());

    let master_with_master = ZoneCreate::master(domain("a.de"))
        .unwrap()
        .with_master_ip(parse_ip("198.51.100.7").unwrap());
    assert!(client.create_zone(&master_with_master).await.is_err());

    assert_eq!(transport.call_count(), 0, "nothing may reach the wire");
}

#[tokio::test]
async fn update_sends_only_the_fields_that_were_set() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let update = ZoneUpdate::new(domain("tenant.example.com"))
        .with_nameservers(&[host("ns1.example.net")])
        .unwrap()
        .with_zone_type(ZoneType::Master)
        .dry_run();

    client(transport.clone())
        .update_zone(&update)
        .await
        .unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "nameserver.update");
    assert_eq!(call.params["domain"], "tenant.example.com");
    assert_eq!(call.params["type"], "MASTER");
    assert_eq!(call.params["ns"][0], "ns1.example.net");
    assert_eq!(call.params["testing"], true);
    assert!(call.params.get("web").is_none());
    // The update cannot carry records: `nameserver.update` has no such parameter.
    assert!(call.params.get("record").is_none());
    assert!(call.params.get("records").is_none());
}

#[tokio::test]
async fn update_can_set_web_forwarding_fields_individually() {
    let transport = MockTransport::new();
    transport.ok_empty();
    transport.ok_empty();
    transport.ok_empty();
    transport.ok_empty();

    let client = client(transport.clone());
    client
        .update_zone(
            &ZoneUpdate::new(domain("a.de"))
                .with_web("https://example.net")
                .unwrap(),
        )
        .await
        .unwrap();
    client
        .update_zone(
            &ZoneUpdate::new(domain("a.de"))
                .with_mail("mx.example.net")
                .unwrap(),
        )
        .await
        .unwrap();
    client
        .update_zone(
            &ZoneUpdate::new(domain("a.de")).with_master_ip(parse_ip("198.51.100.9").unwrap()),
        )
        .await
        .unwrap();
    client
        .update_zone(
            &ZoneUpdate::new(domain("a.de"))
                .with_web("https://example.net")
                .unwrap()
                .with_redirect_type(UrlRedirectType::Header302)
                .unwrap(),
        )
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls[0].params["web"], "https://example.net");
    assert_eq!(calls[1].params["mail"], "mx.example.net");
    assert_eq!(calls[2].params["masterIp"], "198.51.100.9");
    assert_eq!(calls[3].params["urlRedirectType"], "HEADER302");
}

#[tokio::test]
async fn an_empty_update_never_reaches_the_wire() {
    let transport = MockTransport::new();
    let error = client_without_retries(transport.clone())
        .update_zone(&ZoneUpdate::new(domain("a.de")))
        .await
        .unwrap_err();
    assert!(error.is_validation());
    assert_eq!(transport.call_count(), 0);
}

/// Issue #193: `has_changes` and `params` must agree on whether `testing`
/// (set by `dry_run`) counts as a change — and the error has to say so.
#[tokio::test]
async fn dry_run_alone_is_not_a_change() {
    // Just outside the limit: the flag alone is still an empty update, and the
    // message names the flag instead of pointing at an unrelated field.
    let dry_run_only = ZoneUpdate::new(domain("a.de")).dry_run();
    assert!(!dry_run_only.has_changes());
    let error = dry_run_only.params().unwrap_err();
    assert!(error.is_validation());
    let text = error.to_string();
    assert_eq!(
        text,
        "invalid zone.update: sets no field; add a change or skip the call \
         (`dry_run`/`testing` alone is not a change)"
    );

    let transport = MockTransport::new();
    let error = client_without_retries(transport.clone())
        .update_zone(&dry_run_only)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Validation { .. }));
    assert_eq!(transport.call_count(), 0);

    // Just inside the limit: one field plus the flag is a real update, and the
    // flag is still serialised next to the change.
    let update = ZoneUpdate::new(domain("a.de"))
        .with_zone_type(ZoneType::Master)
        .dry_run();
    assert!(update.has_changes());
    let params = update.params().unwrap();
    assert_eq!(params["type"], "MASTER");
    assert_eq!(params["testing"], true);
}

#[tokio::test]
async fn frame_fields_require_a_frame_redirect() {
    let mut update = ZoneUpdate::new(domain("a.de"))
        .with_web("https://example.net")
        .unwrap()
        .with_redirect_type(UrlRedirectType::Header301)
        .unwrap();
    assert!(update.clone().with_frame_title("x").is_err());
    assert!(update.clone().with_frame_description("x").is_err());
    assert!(update.clone().with_frame_favicon("x").is_err());
    assert!(update.clone().with_frame_keywords("x").is_err());

    update = ZoneUpdate::new(domain("a.de"))
        .with_web("https://example.net")
        .unwrap()
        .with_redirect_type(UrlRedirectType::Frame)
        .unwrap();
    assert!(update.with_frame_title("x").is_ok());
}

#[tokio::test]
async fn delete_and_its_dry_run_send_the_zone() {
    let transport = MockTransport::new();
    transport.ok_empty();
    transport.ok_empty();

    let client = client(transport.clone());
    client.delete_zone(&domain("a.de")).await.unwrap();
    client.delete_zone_dry_run(&domain("b.de")).await.unwrap();

    let calls = transport.calls();
    assert_eq!(calls[0].method, "nameserver.delete");
    assert_eq!(calls[0].params["domain"], "a.de");
    assert!(calls[0].params.get("testing").is_none());
    assert_eq!(calls[1].params["testing"], true);
}

#[tokio::test]
async fn clone_sends_both_domains_and_refuses_itself() {
    let transport = MockTransport::new();
    transport.ok(json!({ "roId": 9 }));
    let client = client(transport.clone());

    let target = client
        .clone_zone(&domain("example.com"), &domain("example.net"))
        .await
        .unwrap();
    assert_eq!(target, 9);
    let call = transport.only_call();
    assert_eq!(call.method, "nameserver.clone");
    assert_eq!(call.params["sourceDomain"], "example.com");
    assert_eq!(call.params["targetDomain"], "example.net");

    let error = client
        .clone_zone(&domain("example.com"), &domain("example.com"))
        .await
        .unwrap_err();
    assert!(error.is_validation());
}

#[tokio::test]
async fn clone_without_an_id_is_a_missing_field_error() {
    let transport = MockTransport::new();
    transport.ok(json!({}));
    let error = client(transport)
        .clone_zone(&domain("a.de"), &domain("b.de"))
        .await
        .unwrap_err();
    assert!(matches!(error, Error::MissingField { .. }));
}

#[tokio::test]
async fn export_sends_the_zonefile_flag() {
    let transport = MockTransport::new();
    transport.ok(json!({ "export": "example.com. 3600 IN A 203.0.113.7" }));

    let export = client(transport.clone())
        .export_zone(&domain("example.com"), true)
        .await
        .unwrap();

    assert!(export.text.contains("203.0.113.7"));
    let call = transport.only_call();
    assert_eq!(call.method, "nameserver.export");
    assert_eq!(call.params["zonefile"], true);
}

#[tokio::test]
async fn export_list_and_records_send_their_formats() {
    let transport = MockTransport::new();
    transport.ok(json!({ "count": 1, "domains": [{ "domain": "a.de", "type": "MASTER" }] }));
    transport.ok(json!({ "count": 1, "data": "name,type\nwww,A" }));

    let client = client(transport.clone());
    let page = client
        .export_zone_list(DocumentFormat::Csv, "tenant-*", 2, 25)
        .await
        .unwrap();
    assert_eq!(page.zones.len(), 1);

    let csv = client
        .export_records(DocumentFormat::Csv, "*.example.com", 1, 100)
        .await
        .unwrap();
    assert!(csv.data.starts_with("name,type"));
    assert_eq!(csv.count, Some(1));

    let calls = transport.calls();
    assert_eq!(calls[0].method, "nameserver.exportlist");
    assert_eq!(calls[0].params["format"], "CSV");
    assert_eq!(calls[0].params["domain"], "tenant-*");
    assert_eq!(calls[0].params["page"], 2);
    assert_eq!(calls[0].params["pagelimit"], 25);
    assert_eq!(calls[1].method, "nameserver.exportrecords");
    assert_eq!(calls[1].params["name"], "*.example.com");
    assert_eq!(calls[1].params["limit"], 100);
}

#[tokio::test]
async fn export_endpoints_validate_their_filters() {
    let transport = MockTransport::new();
    let client = client_without_retries(transport.clone());

    assert!(client
        .export_zone_list(DocumentFormat::Pdf, "*", 1, 0)
        .await
        .is_err());
    assert!(client
        .export_records(DocumentFormat::Csv, "  ", 1, 1)
        .await
        .is_err());
    assert!(client.find_zones(" ").await.is_err());
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn find_zones_sends_the_wildcard_filter() {
    let transport = MockTransport::new();
    transport.ok(json!({ "count": 0, "domains": [] }));

    let page = client(transport.clone())
        .find_zones("tenant-*")
        .await
        .unwrap();
    assert_eq!(page.zones.len(), 0);

    let call = transport.only_call();
    assert_eq!(call.method, "nameserver.list");
    assert_eq!(call.params["domain"], "tenant-*");
    assert_eq!(call.params["wide"], 1);
}

#[tokio::test]
async fn require_master_zone_accepts_a_master_and_refuses_a_slave() {
    let transport = MockTransport::new();
    transport.ok(json!({ "domain": "example.com", "type": "MASTER", "record": [] }));
    transport.ok(json!({ "domain": "example.com", "type": "SLAVE" }));

    let client = client(transport.clone());
    let zone = client
        .require_master_zone(&domain("example.com"))
        .await
        .unwrap();
    assert!(zone.is_master());

    let error = client
        .require_master_zone(&domain("example.com"))
        .await
        .unwrap_err();
    assert!(error.is_validation());
}

#[tokio::test]
async fn create_record_set_creates_every_record_in_order() {
    let transport = MockTransport::new();
    transport.ok(json!({ "id": "1" }));
    transport.ok(json!({ "id": "2" }));

    let set = RecordSet::from_records(vec![
        RecordSpec::a("@", "203.0.113.7").unwrap(),
        RecordSpec::txt("@", "v=spf1 -all").unwrap(),
    ])
    .unwrap();

    let ids = client(transport.clone())
        .create_record_set(&domain("example.com"), &set)
        .await
        .unwrap();

    assert_eq!(ids.len(), 2);
    let calls = transport.calls();
    assert_eq!(calls[0].method, "nameserver.createRecord");
    assert_eq!(calls[0].params["domain"], "example.com");
    assert_eq!(calls[0].params["type"], "A");
    assert_eq!(calls[1].params["type"], "TXT");
}

#[tokio::test]
async fn create_record_set_refuses_an_empty_set() {
    let transport = MockTransport::new();
    let error = client_without_retries(transport.clone())
        .create_record_set(&domain("example.com"), &RecordSet::new().unwrap())
        .await
        .unwrap_err();
    assert!(error.is_validation());
    assert_eq!(transport.call_count(), 0);
}

#[test]
fn record_set_rejects_the_combinations_dns_forbids() {
    // Apex CNAME, however it is spelled: refused either by the spec (empty
    // name) or by the set (apex).
    for apex in ["@", "", "  "] {
        let mut set = RecordSet::new().unwrap();
        if let Ok(cname) = RecordSpec::cname(apex, &host("edge.example.net")) {
            assert!(set.push(cname).is_err(), "{apex:?} must be refused");
        }
    }

    // ALIAS at the apex is fine and may coexist with MX/TXT.
    let mut set = RecordSet::new().unwrap();
    set.push(RecordSpec::new(RecordType::Alias, "@", "edge.example.net").unwrap())
        .unwrap();
    set.push(RecordSpec::mx("@", 10, &host("mx.example.net")).unwrap())
        .unwrap();
    set.push(RecordSpec::txt("@", "v=spf1 -all").unwrap())
        .unwrap();
    assert_eq!(set.len(), 3);

    // A CNAME with a sibling, in either order.
    let mut set = RecordSet::new().unwrap();
    set.push(RecordSpec::cname("www", &host("edge.example.net")).unwrap())
        .unwrap();
    assert!(set
        .push(RecordSpec::a("www", "203.0.113.7").unwrap())
        .is_err());

    let mut set = RecordSet::new().unwrap();
    set.push(RecordSpec::a("www", "203.0.113.7").unwrap())
        .unwrap();
    assert!(set
        .push(RecordSpec::cname("www", &host("edge.example.net")).unwrap())
        .is_err());

    // Two CNAMEs on the same name.
    let mut set = RecordSet::new().unwrap();
    set.push(RecordSpec::cname("shop", &host("a.example.net")).unwrap())
        .unwrap();
    assert!(set
        .push(RecordSpec::cname("shop", &host("b.example.net")).unwrap())
        .is_err());
}

#[test]
fn record_set_rejects_exact_duplicates_and_keeps_parameters() {
    let mut set = RecordSet::new().unwrap();
    let record = RecordSpec::a("www", "203.0.113.7").unwrap();
    set.push(record.clone()).unwrap();
    assert!(set.push(record).is_err());

    // The same address for a different name is not a duplicate.
    set.push(RecordSpec::a("www2", "203.0.113.7").unwrap())
        .unwrap();
    assert_eq!(set.len(), 2);

    let params = set.params_for(&domain("example.com"));
    assert_eq!(params.len(), 2);
    assert_eq!(params[0]["domain"], "example.com");
    assert_eq!(params[0]["name"], "www");
    assert_eq!(params[1]["name"], "www2");
}

#[test]
fn record_set_records_and_emptiness_are_observable() {
    let empty = RecordSet::new().unwrap();
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.records().len(), 0);
    assert_eq!(empty.params_for(&domain("a.de")).len(), 0);

    let one = RecordSet::from_records(vec![RecordSpec::txt("@", "x").unwrap()]).unwrap();
    assert!(!one.is_empty());
    assert_eq!(one.records()[0].record_type(), RecordType::Txt);
    assert_eq!(one, one.clone());
}

#[test]
fn txt_values_must_not_be_pre_quoted() {
    let error = RecordSpec::txt("@", "\"v=spf1 -all\"").unwrap_err();
    assert!(error.is_validation());
    // A quote inside the value is legitimate.
    assert!(RecordSpec::txt("@", "v=spf1 include:_spf.example.net -all").is_ok());
}
