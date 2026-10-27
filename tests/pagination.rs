//! Automatic pagination for `domain.list`, `contact.list` and `nameserver.list`.
//!
//! Everything runs against the recording mock transport, so no socket is
//! involved and every test can assert which pages were actually asked for.

mod common;

use common::{client, client_without_retries, MockTransport};
use inwx_client::{
    ContactPager, ContactQuery, DomainListQuery, DomainPager, Error, InwxClient, Pagination,
    ZonePager, MAX_PAGE_SIZE,
};
use serde_json::{json, Value};

/// A `domain.list` page: `count` domains in total, these names on this page.
fn domain_page(count: i64, names: &[String]) -> Value {
    json!({
        "count": count,
        "domain": names.iter().map(|name| json!({ "domain": name })).collect::<Vec<_>>(),
    })
}

/// A `contact.list` page.
fn contact_page(count: i64, ids: &[i64]) -> Value {
    json!({
        "count": count,
        "contact": ids.iter().map(|id| json!({ "roId": id })).collect::<Vec<_>>(),
    })
}

/// A `nameserver.list` page.
fn zone_page(count: i64, names: &[String]) -> Value {
    json!({
        "count": count,
        "domains": names.iter().map(|name| json!({ "domain": name })).collect::<Vec<_>>(),
    })
}

/// `how_many` synthetic names starting at `first`, for fat pages.
fn names(first: u32, how_many: usize) -> Vec<String> {
    (0..u32::try_from(how_many).unwrap())
        .map(|offset| format!("d{first}.de", first = first + offset))
        .collect()
}

fn assert_send_sync<T: Send + Sync>() {}

fn paging(page_size: u32) -> Pagination {
    Pagination::new().with_page_size(page_size).unwrap()
}

// ---------------------------------------------------------------- domains ---

#[tokio::test]
async fn domains_walk_every_page_and_keep_the_filter() {
    let transport = MockTransport::new();
    transport.ok(domain_page(3, &["a.de".to_owned(), "b.de".to_owned()]));
    transport.ok(domain_page(3, &["c.de".to_owned()]));

    let client = client(transport.clone());
    let mut pager = client.paginate_domains(&DomainListQuery::new().with_filter("de"), &paging(2));
    let found = pager.collect().await.unwrap();

    let names: Vec<&str> = found.iter().map(|info| info.domain.as_str()).collect();
    assert_eq!(names, ["a.de", "b.de", "c.de"]);
    assert_eq!(pager.pages_fetched(), 2);
    assert_eq!(pager.items_read(), 3);
    assert!(pager.is_finished());
    assert!(!pager.is_truncated());

    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].method, "domain.list");
    assert_eq!(calls[0].params["page"], 1);
    assert_eq!(calls[0].params["pagelimit"], 2);
    assert_eq!(calls[0].params["domain"], json!(["de"]));
    assert_eq!(calls[1].params["page"], 2);
    assert_eq!(calls[1].params["pagelimit"], 2);
}

#[tokio::test]
async fn domains_stop_at_count_without_an_extra_request() {
    let transport = MockTransport::new();
    transport.ok(domain_page(2, &["a.de".to_owned(), "b.de".to_owned()]));

    let client = client(transport.clone());
    let found = client
        .all_domains(&DomainListQuery::new(), &paging(2))
        .await
        .unwrap();

    assert_eq!(found.len(), 2);
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn domains_ask_for_the_next_page_when_count_promises_more() {
    let transport = MockTransport::new();
    transport.ok(domain_page(3, &["a.de".to_owned(), "b.de".to_owned()]));
    transport.ok(domain_page(3, &["c.de".to_owned()]));

    let client = client(transport.clone());
    client
        .all_domains(&DomainListQuery::new(), &paging(2))
        .await
        .unwrap();

    assert_eq!(transport.call_count(), 2);
    assert_eq!(transport.calls()[1].params["page"], 2);
}

#[tokio::test]
async fn domains_short_page_ends_the_walk_without_a_count() {
    let transport = MockTransport::new();
    transport.ok(json!({ "domain": [{ "domain": "a.de" }, { "domain": "b.de" }] }));
    transport.ok(json!({ "domain": [{ "domain": "c.de" }] }));

    let client = client(transport.clone());
    let found = client
        .all_domains(&DomainListQuery::new(), &paging(2))
        .await
        .unwrap();

    assert_eq!(found.len(), 3);
    // The short second page is the last one: no third request.
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn an_empty_page_ends_the_walk_even_when_count_lies() {
    let transport = MockTransport::new();
    transport.ok(domain_page(500, &[]));

    let client = client(transport.clone());
    let found = client
        .all_domains(&DomainListQuery::new(), &paging(2))
        .await
        .unwrap();

    assert_eq!(found.len(), 0);
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn an_api_error_mid_walk_propagates_and_keeps_what_was_read() {
    let transport = MockTransport::new();
    transport.ok(domain_page(10, &["a.de".to_owned(), "b.de".to_owned()]));
    transport.api_error(2191, "command rejected");

    let client = client_without_retries(transport.clone());
    let mut pager = client.paginate_domains(&DomainListQuery::new(), &paging(2));

    let first = pager.next_page().await.unwrap().unwrap();
    assert_eq!(first.len(), 2);
    let error = pager.next_page().await.unwrap_err();
    assert!(matches!(error, Error::Api { code: 2191, .. }));
    assert!(!error.is_retryable());
    // Not retried, and not swallowed: exactly one request per page.
    assert_eq!(transport.call_count(), 2);
    // The domains of the page that did arrive are still readable.
    assert_eq!(pager.items_read(), 2);
    assert_eq!(
        pager.next_item().await.unwrap().unwrap().domain,
        "a.de".to_owned()
    );
}

#[tokio::test]
async fn the_request_cap_boundary_pair_for_domains() {
    // Just inside: three pages of 100 for 300 domains, and `max_pages` is 3.
    let transport = MockTransport::new();
    {
        for page in 0..3u32 {
            let first = page * 100 + 1;
            transport.ok(domain_page(300, &names(first, 100)));
        }
        let client = client(transport.clone());
        let paging = paging(100).with_max_pages(3).unwrap();
        let found = client
            .all_domains(&DomainListQuery::new(), &paging)
            .await
            .unwrap();
        assert_eq!(found.len(), 300);
        assert_eq!(transport.call_count(), 3);
    }

    // Just outside: the same list with `max_pages` 2 is an error, not a
    // silently short answer.
    let transport = MockTransport::new();
    {
        for page in 0..2u32 {
            let first = page * 100 + 1;
            transport.ok(domain_page(300, &names(first, 100)));
        }
        let client = client(transport.clone());
        let paging = paging(100).with_max_pages(2).unwrap();
        let mut pager = client.paginate_domains(&DomainListQuery::new(), &paging);
        let error = pager.collect().await.unwrap_err();
        assert!(matches!(
            error,
            Error::Pagination {
                pages: 2,
                items: 200,
                ..
            }
        ));
        assert!(!error.is_retryable());
        assert!(pager.is_truncated());
        assert!(pager.is_finished());
        assert_eq!(transport.call_count(), 2);
        // Nothing read before the cap is lost.
        assert_eq!(pager.items_read(), 200);
    }
}

#[tokio::test]
async fn the_item_cap_boundary_pair_for_domains() {
    // Just inside: 100 items are available and 100 are allowed.
    let transport = MockTransport::new();
    {
        transport.ok(domain_page(100, &names(1, 50)));
        transport.ok(domain_page(100, &names(51, 50)));
        let client = client(transport.clone());
        let paging = paging(50).with_max_items(100).unwrap();
        let mut pager = client.paginate_domains(&DomainListQuery::new(), &paging);
        let found = pager.collect().await.unwrap();
        assert_eq!(found.len(), 100);
        assert!(!pager.is_truncated());
    }

    // Just outside: one item less is allowed, so the walk stops early and says
    // so — and never reads more than it was allowed to.
    let transport = MockTransport::new();
    {
        transport.ok(domain_page(100, &names(1, 50)));
        transport.ok(domain_page(100, &names(51, 50)));
        let client = client(transport.clone());
        let paging = paging(50).with_max_items(99).unwrap();
        let mut pager = client.paginate_domains(&DomainListQuery::new(), &paging);
        let found = pager.collect().await.unwrap();
        assert_eq!(found.len(), 99);
        assert!(pager.is_truncated());
        assert_eq!(transport.call_count(), 2);
        // The second request is trimmed to what is left of the cap.
        assert_eq!(transport.calls()[1].params["pagelimit"], 49);
    }
}

#[tokio::test]
async fn a_fat_page_cannot_push_a_walk_past_the_item_cap() {
    let transport = MockTransport::new();
    // The provider ignores `pagelimit` and sends five domains for one page.
    transport.ok(domain_page(5, &names(1, 5)));

    let client = client(transport.clone());
    let paging = paging(100).with_max_items(2).unwrap();
    let mut pager = client.paginate_domains(&DomainListQuery::new(), &paging);
    let found = pager.collect().await.unwrap();

    assert_eq!(found.len(), 2);
    assert!(pager.is_truncated());
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn mixing_pages_and_items_never_fetches_a_page_twice() {
    let transport = MockTransport::new();
    transport.ok(domain_page(4, &["a.de".to_owned(), "b.de".to_owned()]));
    transport.ok(domain_page(4, &["c.de".to_owned(), "d.de".to_owned()]));

    let client = client(transport.clone());
    let mut pager = client.paginate_domains(&DomainListQuery::new(), &paging(2));

    // Take the page wholesale, then dip into the buffer item by item.
    let page = pager.next_page().await.unwrap().unwrap();
    let fetched: Vec<String> = page
        .domains
        .iter()
        .map(|info| info.domain.clone())
        .collect();
    assert_eq!(fetched, ["a.de", "b.de"]);
    assert_eq!(
        pager.next_item().await.unwrap().unwrap().domain,
        "a.de".to_owned()
    );
    assert_eq!(
        pager.next_item().await.unwrap().unwrap().domain,
        "b.de".to_owned()
    );

    let page = pager.next_page().await.unwrap().unwrap();
    let fetched: Vec<String> = page
        .domains
        .iter()
        .map(|info| info.domain.clone())
        .collect();
    assert_eq!(fetched, ["c.de", "d.de"]);
    assert_eq!(
        pager.next_item().await.unwrap().unwrap().domain,
        "c.de".to_owned()
    );
    assert_eq!(
        pager.next_item().await.unwrap().unwrap().domain,
        "d.de".to_owned()
    );

    // Nothing left to read, and no third request either way.
    assert!(pager.next_item().await.unwrap().is_none());
    assert!(pager.next_page().await.unwrap().is_none());
    assert_eq!(pager.pages_fetched(), 2);
    assert_eq!(pager.items_read(), 4);
    assert_eq!(transport.call_count(), 2);
}

// --------------------------------------------------------------- contacts ---

#[tokio::test]
async fn contacts_walk_every_page_and_keep_the_search() {
    let transport = MockTransport::new();
    transport.ok(contact_page(3, &[1, 2]));
    transport.ok(contact_page(3, &[3]));

    let client = client(transport.clone());
    let query = ContactQuery::new().with_search("Erika");
    let found = client.all_contacts(&query, &paging(2)).await.unwrap();

    let ids: Vec<i64> = found.iter().filter_map(|handle| handle.ro_id).collect();
    assert_eq!(ids, [1, 2, 3]);

    let calls = transport.calls();
    assert_eq!(calls[0].method, "contact.list");
    assert_eq!(calls[0].params["search"], "Erika");
    assert_eq!(calls[0].params["page"], 1);
    assert_eq!(calls[0].params["pagelimit"], 2);
    assert_eq!(calls[1].params["page"], 2);
    assert_eq!(calls[1].params["pagelimit"], 2);
}

#[tokio::test]
async fn contacts_stop_at_count_without_an_extra_request() {
    let transport = MockTransport::new();
    transport.ok(contact_page(2, &[1, 2]));

    let client = client(transport.clone());
    let mut pager = client.paginate_contacts(&ContactQuery::new(), &paging(2));
    let found = pager.collect().await.unwrap();

    assert_eq!(found.len(), 2);
    assert!(pager.is_finished());
    assert!(!pager.is_truncated());
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn contacts_item_cap_reports_truncation() {
    let transport = MockTransport::new();
    transport.ok(contact_page(4, &[1, 2]));
    transport.ok(contact_page(4, &[3, 4]));

    let client = client(transport.clone());
    let paging = paging(2).with_max_items(3).unwrap();
    let mut pager = client.paginate_contacts(&ContactQuery::new(), &paging);
    let found = pager.collect().await.unwrap();

    assert_eq!(found.len(), 3);
    assert!(pager.is_truncated());
    assert_eq!(transport.calls()[1].params["pagelimit"], 1);
}

// ------------------------------------------------------------------ zones ---

#[tokio::test]
async fn zones_walk_every_page_and_own_the_paging() {
    let transport = MockTransport::new();
    transport.ok(zone_page(3, &["a.de".to_owned(), "b.de".to_owned()]));
    transport.ok(zone_page(3, &["c.de".to_owned()]));

    let client = client(transport.clone());
    let mut pager = client.paginate_zones(&paging(2));
    let found = pager.collect().await.unwrap();

    let names: Vec<String> = found.iter().map(|zone| zone.domain.to_string()).collect();
    assert_eq!(names, ["a.de", "b.de", "c.de"]);
    assert_eq!(pager.pages_fetched(), 2);

    let calls = transport.calls();
    assert_eq!(calls[0].method, "nameserver.list");
    assert_eq!(calls[0].params["page"], 1);
    assert_eq!(calls[0].params["pagelimit"], 2);
    assert_eq!(calls[1].params["page"], 2);
}

#[tokio::test]
async fn zones_stop_at_count_and_report_an_error_at_the_request_cap() {
    // Just inside: two pages for exactly two pages' worth of zones.
    let transport = MockTransport::new();
    {
        transport.ok(zone_page(4, &names(1, 2)));
        transport.ok(zone_page(4, &names(3, 2)));
        let client = client(transport.clone());
        let paging = paging(2).with_max_pages(2).unwrap();
        let found = client.all_zones(&paging).await.unwrap();
        assert_eq!(found.len(), 4);
        assert_eq!(transport.call_count(), 2);
    }

    // Just outside: the walk still has more to read after its only page.
    let transport = MockTransport::new();
    {
        transport.ok(zone_page(4, &names(1, 2)));
        let client = client(transport.clone());
        let paging = paging(2).with_max_pages(1).unwrap();
        let error = client.all_zones(&paging).await.unwrap_err();
        assert!(matches!(
            error,
            Error::Pagination {
                pages: 1,
                items: 2,
                ..
            }
        ));
        assert_eq!(transport.call_count(), 1);
    }
}

#[tokio::test]
async fn zones_read_one_by_one_across_pages() {
    let transport = MockTransport::new();
    transport.ok(zone_page(3, &["a.de".to_owned()]));
    transport.ok(zone_page(3, &["b.de".to_owned()]));
    transport.ok(zone_page(3, &["c.de".to_owned()]));

    let client = client(transport.clone());
    let mut pager = client.paginate_zones(&paging(1));
    let mut seen = Vec::new();
    while let Some(zone) = pager.next_item().await.unwrap() {
        seen.push(zone.domain.to_string());
    }

    assert_eq!(seen, ["a.de", "b.de", "c.de"]);
    assert_eq!(transport.call_count(), 3);
    assert_eq!(pager.pages_fetched(), 3);
    assert_eq!(pager.items_read(), 3);
    assert!(pager.is_finished());
    assert!(!pager.is_truncated());
}

// -------------------------------------------------- bounds, traits, debug ---

#[tokio::test]
async fn the_page_size_limit_is_checked_before_the_wire() {
    let transport = MockTransport::new();

    // Just inside: the biggest allowed page size goes out on the wire.
    {
        transport.ok(zone_page(1, &["a.de".to_owned()]));
        let client = client(transport.clone());
        let paging = Pagination::new().with_page_size(MAX_PAGE_SIZE).unwrap();
        client.all_zones(&paging).await.unwrap();
        assert_eq!(transport.call_count(), 1);
        assert_eq!(transport.only_call().params["pagelimit"], MAX_PAGE_SIZE);
    }

    // Just outside: rejected locally, so not a single request is made.
    {
        let transport = MockTransport::new();
        let client = client(transport.clone());
        let error = Pagination::new()
            .with_page_size(MAX_PAGE_SIZE + 1)
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Validation {
                field: "pagelimit",
                ..
            }
        ));
        // The client is still perfectly usable, it just never got a call.
        drop(client);
        assert_eq!(transport.call_count(), 0);
    }
}

#[test]
fn zero_bounds_are_refused() {
    for error in [
        Pagination::new().with_page_size(0),
        Pagination::new().with_max_items(0),
        Pagination::new().with_max_pages(0),
    ] {
        assert!(matches!(error.unwrap_err(), Error::Validation { .. }));
    }
}

#[test]
fn pagers_are_send_and_sync_and_redact_nothing_sensitive() {
    assert_send_sync::<DomainPager<'_, MockTransport>>();
    assert_send_sync::<ContactPager<'_, MockTransport>>();
    assert_send_sync::<ZonePager<'_, MockTransport>>();

    let transport = MockTransport::new();
    transport.ok(domain_page(2, &["a.de".to_owned(), "b.de".to_owned()]));
    let client: InwxClient<MockTransport> = client(transport);
    let pager = client.paginate_domains(
        &DomainListQuery::new().with_filter("secret.de"),
        &Pagination::new(),
    );
    let debug = format!("{pager:?}");
    assert!(debug.contains("DomainPager"));
    assert!(debug.contains("pages_fetched"));
    // The session cookie lives on the client, which the pager does not print.
    assert!(!debug.contains("test-session"));
}
