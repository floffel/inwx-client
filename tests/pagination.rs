//! Automatic pagination (issue #15) against the scripted mock transport.
//!
//! Everything here is offline: the pages come from `MockTransport`, so the walk
//! is asserted on what it sent (method, page, page size, filters) as well as on
//! what it yielded. Every limit is tested as a pair — the value just inside and
//! the value just outside.

mod common;

use inwx_client::{
    ContactListPage, ContactListing, ContactQuery, DomainListPage, DomainListQuery, DomainListing,
    DomainName, Error, InwxClient, Listing, Page, Pages, Pagination, ZoneListPage, ZoneListing,
    MAX_ITEMS, MAX_PAGES, MAX_PAGE_SIZE,
};
use serde_json::{json, Value};

use common::{client, client_without_retries, no_wait, MockTransport, Reply};

/// A `domain.list` page with an optional `count` and the given names.
fn domains_page(count: Option<i64>, names: &[&str]) -> Value {
    let mut page = json!({
        "domain": names.iter().map(|name| json!({"domain": name})).collect::<Vec<_>>(),
    });
    if let Some(count) = count {
        page.as_object_mut()
            .unwrap()
            .insert("count".to_owned(), json!(count));
    }
    page
}

/// A `nameserver.list` page with an optional `count` and the given names.
fn zones_page(count: Option<i64>, names: &[&str]) -> Value {
    let mut page = json!({
        "domains": names.iter().map(|name| json!({"domain": name})).collect::<Vec<_>>(),
    });
    if let Some(count) = count {
        page.as_object_mut()
            .unwrap()
            .insert("count".to_owned(), json!(count));
    }
    page
}

/// A `contact.list` page with an optional `count` and the given handles.
fn contacts_page(count: Option<i64>, handles: &[i64]) -> Value {
    let mut page = json!({
        "contact": handles.iter().map(|id| json!({"roId": id})).collect::<Vec<_>>(),
    });
    if let Some(count) = count {
        page.as_object_mut()
            .unwrap()
            .insert("count".to_owned(), json!(count));
    }
    page
}

fn domain(name: &str) -> DomainName {
    DomainName::parse(name).unwrap()
}

/// Four domains in two pages of two.
fn four_domains(transport: &MockTransport) {
    transport.ok(domains_page(Some(4), &["a.de", "b.de"]));
    transport.ok(domains_page(Some(4), &["c.de", "d.de"]));
    transport.ok(domains_page(Some(4), &["never.requested.de"]));
}

// ------------------------------------------------------------------ domains --

#[tokio::test]
async fn walking_domains_reads_every_page() {
    let transport = MockTransport::new();
    transport.ok(domains_page(Some(5), &["a.de", "b.de"]));
    transport.ok(domains_page(Some(5), &["c.de", "d.de"]));
    transport.ok(domains_page(Some(5), &["e.de"]));

    let client = client(transport.clone());
    let pagination = Pagination::new().with_page_size(2).unwrap();
    let names = client
        .list_all_domains(&DomainListQuery::new(), &pagination)
        .collect_all()
        .await
        .unwrap();
    let names = names
        .iter()
        .map(|info| info.domain.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, ["a.de", "b.de", "c.de", "d.de", "e.de"]);

    let calls = transport.calls();
    assert_eq!(calls.len(), 3, "one request per page, no extra round trip");
    for (index, call) in calls.iter().enumerate() {
        assert_eq!(call.method, "domain.list");
        assert_eq!(call.params["page"], index as u64 + 1);
        assert_eq!(call.params["pagelimit"], 2);
    }
}

#[tokio::test]
async fn the_query_filter_is_sent_with_every_page() {
    let transport = MockTransport::new();
    transport.ok(domains_page(Some(4), &["tenant-a.de", "tenant-b.de"]));
    transport.ok(domains_page(Some(4), &["tenant-c.de"]));

    let client = client(transport.clone());
    let query = DomainListQuery::new()
        .with_filter("tenant-")
        .with_status(["ok"]);
    let pagination = Pagination::new().with_page_size(2).unwrap();
    let names = client
        .list_all_domains(&query, &pagination)
        .collect_all()
        .await
        .unwrap();
    assert_eq!(names.len(), 3);

    for call in transport.calls() {
        assert_eq!(call.params["domain"][0], "tenant-");
        assert_eq!(call.params["status"][0], "ok");
    }
    assert_eq!(transport.calls()[1].params["page"], 2);
}

#[tokio::test]
async fn the_walk_owns_the_cursor_of_its_query() {
    let transport = MockTransport::new();
    four_domains(&transport);

    let client = client(transport.clone());
    // A query that pins page 7 / size 3 must not fight the walker.
    let query = DomainListQuery::new().with_page(7, 3);
    let pagination = Pagination::new().with_page_size(2).unwrap();
    let names = client
        .list_all_domains(&query, &pagination)
        .collect_all()
        .await
        .unwrap();
    assert_eq!(names.len(), 4);

    let calls = transport.calls();
    assert_eq!(calls[0].params["page"], 1);
    assert_eq!(calls[0].params["pagelimit"], 2);
    assert_eq!(calls[1].params["page"], 2);
    assert_eq!(calls[1].params["pagelimit"], 2);
}

#[tokio::test]
async fn an_empty_listing_needs_exactly_one_request() {
    let transport = MockTransport::new();
    transport.ok(domains_page(Some(0), &[]));

    let client = client(transport.clone());
    let mut walk = client.list_all_domains(&DomainListQuery::new(), &Pagination::new());
    let page = walk.next_page().await.unwrap();
    assert!(page.is_some_and(|page| page.is_empty()));
    assert!(walk.next_page().await.unwrap().is_none());
    assert!(walk.finished());
    assert!(!walk.bound_reached());
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn a_full_page_without_a_count_asks_once_more() {
    let transport = MockTransport::new();
    // No `count` anywhere: the only signal is a page that comes back short.
    transport.ok(domains_page(None, &["a.de", "b.de"]));
    transport.ok(domains_page(None, &[]));

    let client = client(transport.clone());
    let pagination = Pagination::new().with_page_size(2).unwrap();
    let names = client
        .list_all_domains(&DomainListQuery::new(), &pagination)
        .collect_all()
        .await
        .unwrap();
    assert_eq!(names.len(), 2);
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn a_short_page_ends_the_walk_without_an_extra_request() {
    let transport = MockTransport::new();
    transport.ok(domains_page(Some(9), &["a.de"]));

    let client = client(transport.clone());
    let pagination = Pagination::new().with_page_size(2).unwrap();
    let names = client
        .list_all_domains(&DomainListQuery::new(), &pagination)
        .collect_all()
        .await
        .unwrap();
    assert_eq!(names.len(), 1);
    assert_eq!(transport.call_count(), 1);
}

// -------------------------------------------------------------------- bound --

#[tokio::test]
async fn the_object_bound_truncates_the_last_page() {
    let transport = MockTransport::new();
    transport.ok(domains_page(Some(6), &["a.de", "b.de"]));
    transport.ok(domains_page(Some(6), &["c.de", "d.de"]));
    transport.ok(domains_page(Some(6), &["e.de", "f.de"]));

    let client = client(transport.clone());
    let pagination = Pagination::new()
        .with_page_size(2)
        .unwrap()
        .with_max_items(3)
        .unwrap();
    let mut walk = client.list_all_domains(&DomainListQuery::new(), &pagination);

    assert_eq!(walk.next_page().await.unwrap().unwrap().len(), 2);
    let last = walk.next_page().await.unwrap().unwrap();
    assert_eq!(last.len(), 1, "the page is cut at the bound");
    assert_eq!(last.domains[0].domain, "c.de");
    assert!(walk.next_page().await.unwrap().is_none());
    assert!(walk.bound_reached());
    assert_eq!(walk.yielded(), 3);
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn a_bound_of_exactly_the_listing_size_is_not_a_truncation() {
    let transport = MockTransport::new();
    four_domains(&transport);

    let client = client(transport.clone());
    // Just inside: four objects is the whole listing, so nothing is cut and the
    // walk reports a clean end.
    let pagination = Pagination::new()
        .with_page_size(2)
        .unwrap()
        .with_max_items(4)
        .unwrap();
    let mut walk = client.list_all_domains(&DomainListQuery::new(), &pagination);
    let mut pages = Vec::new();
    while let Some(page) = walk.next_page().await.unwrap() {
        pages.push(page.len());
    }
    assert_eq!(pages, [2, 2]);
    assert!(!walk.bound_reached());
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn a_bound_one_object_early_is_a_truncation() {
    let transport = MockTransport::new();
    four_domains(&transport);

    let client = client(transport.clone());
    // Just outside: one object before the end, so the second page is cut and
    // `bound_reached` says the listing was left unfinished.
    let pagination = Pagination::new()
        .with_page_size(2)
        .unwrap()
        .with_max_items(3)
        .unwrap();
    let mut walk = client.list_all_domains(&DomainListQuery::new(), &pagination);
    let mut pages = Vec::new();
    while let Some(page) = walk.next_page().await.unwrap() {
        pages.push(page.len());
    }
    assert_eq!(pages, [2, 1]);
    assert!(walk.bound_reached());
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn a_bound_on_a_page_edge_sends_no_further_request() {
    let transport = MockTransport::new();
    transport.ok(domains_page(Some(6), &["a.de", "b.de"]));
    transport.ok(domains_page(Some(6), &["c.de", "d.de"]));

    let client = client(transport.clone());
    // The bound lands exactly after the first page: nothing is truncated, and
    // the second page is never requested.
    let pagination = Pagination::new()
        .with_page_size(2)
        .unwrap()
        .with_max_items(2)
        .unwrap();
    let mut walk = client.list_all_domains(&DomainListQuery::new(), &pagination);
    assert_eq!(walk.next_page().await.unwrap().unwrap().len(), 2);
    assert!(walk.next_page().await.unwrap().is_none());
    assert!(walk.bound_reached(), "the listing had six domains");
    assert_eq!(walk.yielded(), 2);
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn a_contact_page_is_cut_at_the_bound() {
    let transport = MockTransport::new();
    transport.ok(contacts_page(Some(5), &[991, 992, 993]));

    let client = client(transport.clone());
    let pagination = Pagination::new()
        .with_page_size(3)
        .unwrap()
        .with_max_items(2)
        .unwrap();
    let handles = client
        .list_all_contacts(&ContactQuery::new(), &pagination)
        .collect_all()
        .await
        .unwrap();
    let handles = handles
        .iter()
        .filter_map(inwx_client::Contact::handle)
        .collect::<Vec<_>>();
    assert_eq!(handles, [991, 992], "the third handle is past the bound");
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn the_request_bound_stops_a_runaway_walk() {
    let transport = MockTransport::new();
    // A server that never runs out of full pages.
    for _ in 0..12 {
        transport.ok(domains_page(Some(1_000_000), &["a.de", "b.de"]));
    }

    let client = client(transport.clone());
    let pagination = Pagination::new()
        .with_page_size(2)
        .unwrap()
        .with_max_pages(3)
        .unwrap();
    let names = client
        .list_all_domains(&DomainListQuery::new(), &pagination)
        .collect_all()
        .await
        .unwrap();

    assert_eq!(names.len(), 6);
    assert_eq!(transport.call_count(), 3);
    assert_eq!(transport.calls()[2].params["page"], 3);
}

#[tokio::test]
async fn one_request_is_the_smallest_walk() {
    let transport = MockTransport::new();
    for _ in 0..4 {
        transport.ok(domains_page(Some(1_000_000), &["a.de", "b.de"]));
    }

    let client = client(transport.clone());
    let pagination = Pagination::new()
        .with_page_size(2)
        .unwrap()
        .with_max_pages(1)
        .unwrap();
    let names = client
        .list_all_domains(&DomainListQuery::new(), &pagination)
        .collect_all()
        .await
        .unwrap();
    assert_eq!(names.len(), 2);
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn a_page_size_of_1000_is_sent_and_1001_never_leaves() {
    let transport = MockTransport::new();
    transport.ok(domains_page(Some(0), &[]));
    let client = client(transport.clone());

    // Just inside the ceiling: the request goes out with that page size.
    let pagination = Pagination::new().with_page_size(MAX_PAGE_SIZE).unwrap();
    assert_eq!(pagination.page_size(), 1_000);
    client
        .list_all_domains(&DomainListQuery::new(), &pagination)
        .collect_all()
        .await
        .unwrap();
    assert_eq!(transport.only_call().params["pagelimit"], 1_000);

    // Just outside: a validation error, and no second request.
    let error = Pagination::new()
        .with_page_size(MAX_PAGE_SIZE + 1)
        .unwrap_err();
    assert!(error.is_validation());
    assert_eq!(error.code(), None);
    assert_eq!(
        transport.call_count(),
        1,
        "the refused page size was never sent"
    );

    // Zero sits outside the other end of the range.
    assert!(Pagination::new()
        .with_page_size(0)
        .unwrap_err()
        .is_validation());
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn the_object_bound_pair_is_checked_before_the_wire() {
    let transport = MockTransport::new();
    transport.ok(domains_page(Some(0), &[]));
    let client = client(transport.clone());

    // Just inside: 100_000 objects are allowed, and the walk runs.
    let pagination = Pagination::new().with_max_items(MAX_ITEMS).unwrap();
    assert_eq!(pagination.max_items(), Some(100_000));
    client
        .list_all_domains(&DomainListQuery::new(), &pagination)
        .collect_all()
        .await
        .unwrap();
    assert_eq!(transport.call_count(), 1);

    // Just outside, and zero: rejected locally.
    assert!(Pagination::new()
        .with_max_items(MAX_ITEMS + 1)
        .unwrap_err()
        .is_validation());
    assert!(Pagination::new()
        .with_max_items(0)
        .unwrap_err()
        .is_validation());
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn the_page_bound_pair_is_checked_before_the_wire() {
    let transport = MockTransport::new();
    transport.ok(domains_page(Some(0), &[]));
    let client = client(transport.clone());

    let pagination = Pagination::new().with_max_pages(MAX_PAGES).unwrap();
    assert_eq!(pagination.max_pages(), 10_000);
    client
        .list_all_domains(&DomainListQuery::new(), &pagination)
        .collect_all()
        .await
        .unwrap();
    assert_eq!(transport.call_count(), 1);

    assert!(Pagination::new()
        .with_max_pages(MAX_PAGES + 1)
        .unwrap_err()
        .is_validation());
    assert!(Pagination::new()
        .with_max_pages(0)
        .unwrap_err()
        .is_validation());
    assert_eq!(transport.call_count(), 1);
}

// ----------------------------------------------------------------- contacts --

#[tokio::test]
async fn walking_contacts_reads_every_page() {
    let transport = MockTransport::new();
    transport.ok(contacts_page(Some(3), &[991, 992]));
    transport.ok(contacts_page(Some(3), &[993]));

    let client = client(transport.clone());
    let pagination = Pagination::new().with_page_size(2).unwrap();
    let handles = client
        .list_all_contacts(&ContactQuery::new().with_search("ACME"), &pagination)
        .collect_all()
        .await
        .unwrap();
    let handles = handles
        .iter()
        .filter_map(inwx_client::Contact::handle)
        .collect::<Vec<_>>();
    assert_eq!(handles, [991, 992, 993]);

    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].method, "contact.list");
    assert_eq!(calls[0].params["search"], "ACME");
    assert_eq!(calls[1].params["page"], 2);
    assert_eq!(calls[1].params["pagelimit"], 2);
}

#[tokio::test]
async fn a_contact_walk_can_be_drained_item_by_item() {
    let transport = MockTransport::new();
    transport.ok(contacts_page(Some(3), &[991, 992]));
    transport.ok(contacts_page(Some(3), &[993]));

    let client = client(transport.clone());
    let pagination = Pagination::new().with_page_size(2).unwrap();
    let mut walk = client.list_all_contacts(&ContactQuery::new(), &pagination);

    assert_eq!(walk.next_item().await.unwrap().unwrap().handle(), Some(991));
    assert_eq!(
        transport.call_count(),
        1,
        "the rest of the page is buffered"
    );
    assert_eq!(walk.next_item().await.unwrap().unwrap().handle(), Some(992));
    assert_eq!(transport.call_count(), 1);
    assert_eq!(walk.next_item().await.unwrap().unwrap().handle(), Some(993));
    assert_eq!(transport.call_count(), 2);
    assert!(walk.next_item().await.unwrap().is_none());
    assert_eq!(walk.yielded(), 3);
    assert!(walk.finished());
}

// -------------------------------------------------------------------- zones --

#[tokio::test]
async fn walking_zones_reads_every_page() {
    let transport = MockTransport::new();
    transport.ok(zones_page(Some(3), &["a.de", "b.de"]));
    transport.ok(zones_page(Some(3), &["c.de"]));

    let client = client(transport.clone());
    let pagination = Pagination::new().with_page_size(2).unwrap();
    let zones = client
        .list_all_zones(&ZoneListing::new(), &pagination)
        .collect_all()
        .await
        .unwrap();
    let zones = zones
        .iter()
        .map(|zone| zone.domain.to_string())
        .collect::<Vec<_>>();
    assert_eq!(zones, ["a.de", "b.de", "c.de"]);

    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].method, "nameserver.list");
    // Unfiltered matches `list_zones`: paging parameters only.
    assert_eq!(calls[0].params, json!({"page": 1, "pagelimit": 2}));
}

#[tokio::test]
async fn a_filtered_zone_walk_sends_the_filter_like_find_zones() {
    let transport = MockTransport::new();
    transport.ok(zones_page(Some(1), &["tenant-a.de"]));

    let client = client(transport.clone());
    let listing = ZoneListing::with_filter("tenant-*").unwrap();
    let zones = client
        .list_all_zones(&listing, &Pagination::new())
        .collect_all()
        .await
        .unwrap();
    assert_eq!(zones.len(), 1);
    assert_eq!(
        transport.only_call().params,
        json!({"domain": "tenant-*", "wide": 1, "page": 1, "pagelimit": 100})
    );
}

#[tokio::test]
async fn an_empty_zone_filter_is_refused_before_the_wire() {
    let transport = MockTransport::new();
    let client = client(transport.clone());

    let error = ZoneListing::with_filter("   ").unwrap_err();
    assert!(error.is_validation());

    // Building a walk sends nothing.
    let listing = ZoneListing::with_filter(" * ").unwrap();
    assert_eq!(listing.filter(), Some("*"));
    let walk = client.list_all_zones(&listing, &Pagination::new());
    assert_eq!(walk.yielded(), 0);
    assert_eq!(transport.call_count(), 0);
}

// ------------------------------------------------------------------- errors --

#[tokio::test]
async fn a_rejected_page_is_terminal_and_is_not_retried() {
    let transport = MockTransport::new();
    transport.ok(domains_page(Some(9), &["a.de"]));
    transport.api_error(2303, "Object does not exist");

    let client = client(transport.clone());
    let pagination = Pagination::new().with_page_size(1).unwrap();
    let mut walk = client.list_all_domains(&DomainListQuery::new(), &pagination);

    assert_eq!(walk.next_page().await.unwrap().unwrap().len(), 1);
    let error = walk.next_page().await.unwrap_err();
    assert_eq!(error.code(), Some(2303));
    assert!(!error.is_retryable());
    assert_eq!(
        transport.call_count(),
        2,
        "a rejected page is never re-sent"
    );
}

#[tokio::test]
async fn a_failed_page_can_be_retried_by_the_caller() {
    let transport = MockTransport::new();
    transport.ok(domains_page(Some(2), &["a.de"]));
    transport.transport_failure("connection reset");
    transport.ok(domains_page(Some(2), &["b.de"]));

    let client = client_without_retries(transport.clone());
    let pagination = Pagination::new().with_page_size(1).unwrap();
    let mut walk = client.list_all_domains(&DomainListQuery::new(), &pagination);

    assert_eq!(walk.next_page().await.unwrap().unwrap().len(), 1);
    assert!(walk.next_page().await.unwrap_err().is_retryable());
    // The failed request was not counted, so the retry asks for page 2 again.
    assert_eq!(walk.next_page().await.unwrap().unwrap().len(), 1);
    assert!(walk.next_page().await.unwrap().is_none());

    let calls = transport.calls();
    assert_eq!(calls[1].params["page"], 2);
    assert_eq!(calls[2].params["page"], 2);
}

#[tokio::test]
async fn a_malformed_page_is_a_json_error_with_a_source() {
    let transport = MockTransport::new();
    transport.push(Reply::Body(
        json!({"code": 1000, "msg": "ok", "resData": {"domain": "not-a-list"}}).to_string(),
    ));

    let client = client(transport.clone());
    let error = client
        .list_all_domains(&DomainListQuery::new(), &Pagination::new())
        .collect_all()
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Json { .. }));
    assert!(std::error::Error::source(&error).is_some());
}

#[tokio::test]
async fn the_walk_needs_a_session_like_any_other_call() {
    let transport = MockTransport::new();
    let client = InwxClient::new(transport.clone())
        .with_base_url("https://inwx.test/jsonrpc/")
        .with_retry(no_wait());
    let error = client
        .list_all_domains(&DomainListQuery::new(), &Pagination::new())
        .collect_all()
        .await
        .unwrap_err();
    assert!(matches!(error, Error::NotAuthenticated));
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn debug_never_shows_the_session() {
    let transport = MockTransport::new();
    let client = client(transport);
    let walk = client.list_all_zones(&ZoneListing::new(), &Pagination::new());
    let debug = format!("{walk:?}");
    assert!(debug.contains("nameserver.list"));
    assert!(debug.contains("page_size: 100"));
    assert!(!debug.contains("test-session"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn walks_share_one_client_across_tasks() {
    // `Pages` only borrows the client, so eight tasks can each walk the same
    // account through one `Arc<InwxClient>` — and the walk's future is `Send`.
    let transport = MockTransport::new();
    for _ in 0..16 {
        transport.ok(domains_page(Some(4), &["a.de", "b.de"]));
    }

    let client = std::sync::Arc::new(client(transport.clone()));
    let tasks = (0..8)
        .map(|_| {
            let client = std::sync::Arc::clone(&client);
            tokio::spawn(async move {
                let pagination = Pagination::new().with_page_size(2).unwrap();
                client
                    .list_all_domains(&DomainListQuery::new(), &pagination)
                    .collect_all()
                    .await
                    .map(|domains| domains.len())
            })
        })
        .collect::<Vec<_>>();

    for task in tasks {
        assert_eq!(task.await.unwrap().unwrap(), 4);
    }
    assert_eq!(transport.call_count(), 16);
}

// ------------------------------------------------------------------- traits --

#[test]
fn the_page_trait_covers_the_three_listings() {
    let domains: DomainListPage =
        serde_json::from_str(domains_page(Some(2), &["a.de"]).to_string().as_str()).unwrap();
    assert_eq!(domains.total(), Some(2));
    assert_eq!(domains.len(), 1);
    assert!(!domains.is_empty());

    let mut zones: ZoneListPage =
        serde_json::from_str(zones_page(None, &["a.de", "b.de"]).to_string().as_str()).unwrap();
    assert!(zones.total().is_none());
    assert!(!zones.is_empty());
    zones.truncate_to(1);
    assert_eq!(zones.into_items().len(), 1);

    let contacts: ContactListPage =
        serde_json::from_str(contacts_page(Some(1), &[991]).to_string().as_str()).unwrap();
    assert_eq!(contacts.total(), Some(1));
    assert_eq!(contacts.into_items()[0].handle(), Some(991));
}

#[test]
fn listings_name_their_method_and_merge_their_filters() {
    assert_eq!(<DomainListing as Listing>::METHOD, "domain.list");
    assert_eq!(<ContactListing as Listing>::METHOD, "contact.list");
    assert_eq!(<ZoneListing as Listing>::METHOD, "nameserver.list");

    let listing = DomainListing::new(DomainListQuery::new().with_filter("acme"));
    assert_eq!(listing.query(), &DomainListQuery::new().with_filter("acme"));
    assert_eq!(listing.params(4, 40)["domain"][0], "acme");
    assert_eq!(listing.params(4, 40)["page"], 4);

    let listing = ContactListing::new(ContactQuery::new().with_search("acme"));
    assert_eq!(listing.query(), &ContactQuery::new().with_search("acme"));
    assert_eq!(listing.params(4, 40)["search"], "acme");

    assert_eq!(
        ZoneListing::new().params(1, 1),
        json!({"page": 1, "pagelimit": 1})
    );
}

#[tokio::test]
async fn a_custom_listing_can_be_walked_through_pages_new() {
    let transport = MockTransport::new();
    transport.ok(zones_page(Some(1), &["only.de"]));

    let client = client(transport.clone());
    let walk = Pages::new(&client, ZoneListing::new(), Pagination::new());
    assert_eq!(
        walk.collect_all().await.unwrap()[0].domain,
        domain("only.de")
    );
    assert_eq!(transport.only_call().method, "nameserver.list");
}
