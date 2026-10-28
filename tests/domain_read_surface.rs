//! The four read-only diagnostics commands on the wire: `domain.log`,
//! `domain.stats`, `domain.getRules` and `domain.getTldGroups`.
//!
//! Each test drives the scripted mock transport from `tests/common`, so no
//! socket is involved: the tests assert the method name and the exact
//! parameters that went out, and how the answer shapes come back.

mod common;

use common::{client, client_without_retries, MockTransport};
use inwx_client::{
    DomainLog, DomainLogQuery, DomainName, DomainStats, Error, TldGroupList, TldRules,
    MAX_PAGE_LIMIT,
};
use serde_json::json;

fn domain(name: &str) -> DomainName {
    DomainName::parse(name).unwrap()
}

// ------------------------------------------------------------- domain.log ----

#[tokio::test]
async fn domain_log_sends_the_query_verbatim() {
    let transport = MockTransport::new();
    transport.ok(json!({"count": 0, "logs": []}));

    let query = DomainLogQuery::new(domain("example.com"))
        .with_page(2, 25)
        .unwrap()
        .with_range(
            inwx_client::Timestamp::parse("2026-01-01T00:00:00").unwrap(),
            inwx_client::Timestamp::parse("2026-02-01T00:00:00").unwrap(),
        )
        .unwrap();

    let client = client(transport.clone());
    let log = client.domain_log(&query).await.unwrap();
    assert!(log.is_empty());

    let call = transport.only_call();
    assert_eq!(call.method, "domain.log");
    assert_eq!(
        call.params,
        json!({
            "domain": "example.com",
            "page": 2,
            "pagelimit": 25,
            "dateFrom": "2026-01-01T00:00:00",
            "dateTo": "2026-02-01T00:00:00",
        })
    );
}

#[tokio::test]
async fn a_bare_query_sends_only_the_domain() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let client = client(transport.clone());
    let log = client
        .domain_log(&DomainLogQuery::new(domain("example.com")))
        .await
        .unwrap();
    assert_eq!(log, DomainLog::default());

    let call = transport.only_call();
    assert_eq!(call.params, json!({"domain": "example.com"}));
}

#[tokio::test]
async fn pagelimit_is_validated_before_the_wire() {
    let transport = MockTransport::new();
    transport.ok(json!({"logs": [{"action": "create"}]}));

    // Just inside the bound: the request goes out with the value unchanged.
    let client = client(transport.clone());
    let query = DomainLogQuery::new(domain("example.com"))
        .with_page(1, MAX_PAGE_LIMIT)
        .unwrap();
    let log = client.domain_log(&query).await.unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(transport.only_call().params["pagelimit"], MAX_PAGE_LIMIT);

    // Just outside it: a local error, and nothing leaves the process.
    let too_many = DomainLogQuery::new(domain("example.com")).with_page(1, MAX_PAGE_LIMIT + 1);
    assert!(matches!(
        too_many,
        Err(Error::Validation { field, .. }) if field == "pagelimit"
    ));
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn domain_log_answers_arrive_as_entries() {
    // Array under the key — the normal shape.
    let transport = MockTransport::new();
    transport.ok(json!({
        "count": 2,
        "logs": [
            {"date": "2026-10-26T08:00:00", "action": "create", "text": "registered",
             "user": "example-user", "ip": "203.0.113.7"},
            {"date": "2026-10-27 09:30:00", "action": "update", "unexpected": true},
        ],
    }));
    let session = client(transport);
    let log = session
        .domain_log(&DomainLogQuery::new(domain("example.com")))
        .await
        .unwrap();
    assert_eq!(log.len(), 2);
    assert_eq!(log.entries[0].ip.as_deref(), Some("203.0.113.7"));
    assert_eq!(
        log.entries[1]
            .occurred_at()
            .map(|at| at.as_str().to_owned())
            .as_deref(),
        Some("2026-10-27T09:30:00")
    );
    assert_eq!(log.entries[1].extra["unexpected"], json!(true));

    // The whole resData is the list — INWX does this when there is one entry.
    let transport = MockTransport::new();
    transport.ok(json!([{"action": "create"}]));
    let log = client(transport)
        .domain_log(&DomainLogQuery::new(domain("example.com")))
        .await
        .unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log.entries[0].action.as_deref(), Some("create"));

    // …and numerically keyed.
    let transport = MockTransport::new();
    transport
        .ok(json!({"0": {"action": "first"}, "2": {"action": "third"}, "1": {"action": "second"}}));
    let log = client(transport)
        .domain_log(&DomainLogQuery::new(domain("example.com")))
        .await
        .unwrap();
    let actions: Vec<&str> = log
        .entries
        .iter()
        .filter_map(|entry| entry.action.as_deref())
        .collect();
    assert_eq!(actions, ["first", "second", "third"]);
}

#[tokio::test]
async fn an_unknown_domain_is_an_api_error() {
    let transport = MockTransport::new();
    transport.api_error(2303, "Object does not exist");

    // A rejected read is never repeated, so retries must not mask the code.
    let client = client_without_retries(transport.clone());
    let error = client
        .domain_log(&DomainLogQuery::new(domain("nope.tld")))
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Api { code: 2303, .. }));
    assert_eq!(transport.call_count(), 1);
}

// ----------------------------------------------------------- domain.stats ----

#[tokio::test]
async fn domain_stats_sends_the_domain_only_when_given() {
    let transport = MockTransport::new();
    transport.ok(json!({"count": 1, "stats": [{"domain": "de", "count": "12"}]}));
    transport.ok_empty();

    let client = client(transport.clone());
    let stats = client
        .domain_stats(Some(&domain("example.com")))
        .await
        .unwrap();
    assert_eq!(stats.counter("de"), Some(12));
    let account = client.domain_stats(None).await.unwrap();
    assert!(account.is_empty());

    let calls = transport.calls();
    assert_eq!(calls[0].method, "domain.stats");
    assert_eq!(calls[0].params, json!({"domain": "example.com"}));
    assert_eq!(calls[1].params, json!({}));
}

#[tokio::test]
async fn stats_decode_the_list_and_the_flat_answer() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "count": 3,
        "stats": [{"domain": "DE", "count": "12", "amount": "108.50", "description": "registered"}],
    }));
    transport.ok(json!({"totalDomains": "12", "state": "active"}));
    transport.ok(json!({"domain": {"action": "create"}}));

    let client = client(transport);
    let list = client.domain_stats(None).await.unwrap();
    assert_eq!(list.len(), 1);
    assert!(list.has_more());
    assert_eq!(list.amount_for("de"), Some(108.5));
    assert_eq!(list.text_for("de"), Some("registered"));

    let flat = client.domain_stats(None).await.unwrap();
    assert_eq!(flat.counter("totalDomains"), Some(12));
    assert_eq!(flat.text_for("state"), Some("active"));

    // A single object where the list belongs is still one entry.
    let single: DomainStats = client.domain_stats(None).await.unwrap();
    assert_eq!(single.stats.len(), 1);
}

// -------------------------------------------------------- domain.getRules ----

#[tokio::test]
async fn tld_rules_normalises_the_tld_before_sending_it() {
    let transport = MockTransport::new();
    for _ in 0..3 {
        transport.ok(json!({"tld": "de", "rules": []}));
    }

    let client = client(transport.clone());
    let inputs = [
        ("  DE  ", "de"),
        ("MUCHEN", "muchen"),
        ("münchen", "xn--mnchen-3ya"),
    ];
    for (input, expected) in inputs {
        client.tld_rules(input).await.unwrap();
        let sent = transport.calls();
        let last = sent.last().unwrap();
        assert_eq!(last.method, "domain.getRules");
        assert_eq!(last.params, json!({"tld": expected}), "{input:?}");
    }
    assert_eq!(transport.call_count(), inputs.len());
}

#[tokio::test]
async fn a_tld_is_length_checked_before_the_wire() {
    let transport = MockTransport::new();
    transport.ok(json!({"rules": [{"name": "MIN-PERIOD", "value": "1"}]}));

    // Just inside: one label of the maximum length goes out untouched.
    let longest = "a".repeat(inwx_client::MAX_LABEL_LEN);
    let client = client(transport.clone());
    let rules = client.tld_rules(&longest).await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(transport.only_call().params["tld"], longest);

    // Just outside: refused locally, no request, and a `.com`-style value is
    // refused as well.
    for bad in [&format!("{longest}a"), "", "example.com", "."] {
        assert!(
            matches!(
                client.tld_rules(bad).await,
                Err(Error::Validation { field, .. }) if field == "tld"
            ),
            "{bad:?} must be refused before the wire"
        );
    }
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn rules_carry_names_values_and_unknown_fields() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "tld": "de",
        "count": 2,
        "rules": [
            {"name": "BIRTH-ADDRESS-CITY", "value": "true", "type": "boolean",
             "description": "City of birth"},
            {"name": "MIN-PERIOD", "value": 12, "extraInfo": {"a": 1}},
        ],
    }));
    transport.ok(json!({"rule": {"name": "TRADE-HANDLE", "value": "true"}}));

    let client = client(transport);
    let rules = client.tld_rules("de").await.unwrap();
    assert_eq!(rules.tld.as_deref(), Some("de"));
    assert_eq!(rules.value_for("birth-address-city"), Some("true"));
    assert_eq!(rules.integer_for("MIN-PERIOD"), Some(12));
    assert_eq!(
        rules.find("MIN-PERIOD").unwrap().extra["extraInfo"],
        json!({"a": 1})
    );
    assert!(rules.value_for("MAX-PERIOD").is_none());

    let single = client.tld_rules("de").await.unwrap();
    assert_eq!(single.find("trade-handle").unwrap().flag(), Some(true));
}

// ---------------------------------------------------- domain.getTldGroups ----

#[tokio::test]
async fn tld_groups_sends_an_empty_object() {
    let transport = MockTransport::new();
    transport.ok(
        json!({"count": 1, "tldGroup": [{"roId": 1, "tldGroup": "ccTLDs", "tld": ["de", "at"]}]}),
    );

    let client = client(transport.clone());
    let groups = client.tld_groups().await.unwrap();
    assert_eq!(groups.len(), 1);
    assert!(groups
        .find("cctlds")
        .is_some_and(|group| group.contains("DE")));

    let call = transport.only_call();
    assert_eq!(call.method, "domain.getTldGroups");
    assert_eq!(call.params, json!({}));
}

#[tokio::test]
async fn groups_survive_the_shapes_the_api_actually_sends() {
    // (answer shape, number of groups it must yield) — the shapes INWX really
    // sends, plus the empty ones that must decode to no groups rather than
    // fail the call.
    let shapes = [
        (json!({"tldGroup": [{"tldGroup": "a", "tld": ["de"]}]}), 1),
        (
            json!({"tldGroup": {"0": {"tldGroup": "a", "tld": "de"}}}),
            1,
        ),
        (json!({"tldGroup": {"tldGroup": "a", "tld": "de"}}), 1),
        (
            json!({"tldGroups": [{"tld_group": "a", "tlds": ["de"]}]}),
            1,
        ),
        (json!({"tldGroup": []}), 0),
        (json!({"tldGroup": {}}), 0),
        (json!([]), 0),
        (json!(null), 0),
    ];
    for (shape, expected) in shapes {
        let transport = MockTransport::new();
        transport.ok(shape.clone());
        let groups: TldGroupList = client(transport).tld_groups().await.unwrap();
        assert_eq!(groups.len(), expected, "shape {shape}");
    }
}

#[tokio::test]
async fn a_group_without_tlds_stays_readable() {
    let transport = MockTransport::new();
    transport.ok(json!({"tldGroup": [{"roId": 9, "tldGroup": "empty", "tld": null}]}));

    let groups = client(transport).tld_groups().await.unwrap();
    assert_eq!(groups.len(), 1);
    let group = &groups.groups[0];
    assert!(group.is_empty());
    assert_eq!(group.tld_count(), 0);
    assert_eq!(group.id, Some(9));
    assert!(!groups.has_more());
}

#[tokio::test]
async fn every_read_stays_useful_without_a_payload() {
    let transport = MockTransport::new();
    for _ in 0..4 {
        transport.ok_empty();
    }

    let client = client(transport);
    let log = client
        .domain_log(&DomainLogQuery::new(domain("example.com")))
        .await
        .unwrap();
    let stats = client.domain_stats(None).await.unwrap();
    let rules = client.tld_rules("de").await.unwrap();
    let groups = client.tld_groups().await.unwrap();

    assert!(log.is_empty() && stats.is_empty() && rules.is_empty() && groups.is_empty());
    assert!(!log.has_more() && !stats.has_more() && !rules.has_more() && !groups.has_more());
}

#[tokio::test]
async fn a_tld_of_garbage_in_the_answer_does_not_break_the_decode() {
    let transport = MockTransport::new();
    transport.ok(json!({"tld": 12, "count": "many", "rules": "unavailable", "page": 1}));
    transport.ok(json!({"count": 1, "stats": {"0": "not-an-object", "1": {"domain": "de"}}}));

    let client = client(transport);
    let rules: TldRules = client.tld_rules("de").await.unwrap();
    assert_eq!(rules.tld.as_deref(), Some("12"));
    assert!(rules.count.is_none());
    assert!(rules.is_empty());

    let stats = client.domain_stats(None).await.unwrap();
    assert_eq!(stats.len(), 1);
    assert_eq!(stats.find("de").unwrap().name.as_deref(), Some("de"));
}
