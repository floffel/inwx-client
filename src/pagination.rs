//! Automatic pagination for the list commands (`domain.list`, `contact.list`,
//! `nameserver.list`).
//!
//! Every list command of the INWX API is paged: it takes `page` (1-based) and
//! `pagelimit`, and answers with the objects of that page plus — usually — a
//! `count` for the whole listing. Reading everything therefore needs a loop,
//! and a loop that is easy to get wrong: stop one page early and objects are
//! silently missing, forget the stop condition and the caller requests page
//! after page of an answer that never ends.
//!
//! [`Pages`] is that loop. It is built from a [`Listing`] (the command and its
//! filters) and a [`Pagination`] (page size plus the bound the walk may not
//! exceed), and everything is checked before a request leaves the process:
//!
//! * a page size outside `1..=MAX_PAGE_SIZE` and a bound outside
//!   `1..=MAX_ITEMS` / `1..=MAX_PAGES` are [`Error::Validation`], so a
//!   nonsensical walk never reaches the wire;
//! * the bound is always present — the defaults are
//!   [`Pagination::with_max_items`] and [`Pagination::with_max_pages`] — so a
//!   walk cannot run away with an account that has a million domains;
//! * a page shorter than requested, an empty page and the reported `count` all
//!   end the walk, so the last page is not followed by a pointless empty
//!   request.

use std::collections::VecDeque;
use std::fmt;

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;

/// Page size a walk uses when the caller does not choose one.
///
/// This is the size [`crate::InwxClient::list_zones`] already asks for, and the
/// INWX default for the list commands.
///
/// ```
/// use inwx_client::{Pagination, DEFAULT_PAGE_SIZE};
///
/// assert_eq!(DEFAULT_PAGE_SIZE, 100);
/// assert_eq!(Pagination::new().page_size(), DEFAULT_PAGE_SIZE);
/// ```
pub const DEFAULT_PAGE_SIZE: u32 = 100;

/// Largest page size [`Pagination::with_page_size`] accepts.
///
/// The API does not publish a maximum `pagelimit`; this is a crate-side ceiling
/// (see `docs/contracts.md`), chosen so that one request stays well inside the
/// body size a normal client wants to hold in memory.
///
/// ```
/// use inwx_client::MAX_PAGE_SIZE;
/// assert_eq!(MAX_PAGE_SIZE, 1_000);
/// ```
pub const MAX_PAGE_SIZE: u32 = 1_000;

/// Largest object count a single walk may yield ([`Pagination::with_max_items`]).
///
/// ```
/// use inwx_client::MAX_ITEMS;
/// assert_eq!(MAX_ITEMS, 100_000);
/// ```
pub const MAX_ITEMS: usize = 100_000;

/// Largest number of requests a single walk may make ([`Pagination::with_max_pages`]).
///
/// This is the stop condition for a server that keeps answering with a full
/// page: without it, a walk whose `count` is missing could not terminate.
///
/// ```
/// use inwx_client::MAX_PAGES;
/// assert_eq!(MAX_PAGES, 10_000);
/// ```
pub const MAX_PAGES: u32 = 10_000;

/// One page of a paged listing.
///
/// The three list commands name their array differently (`domain`, `contact`,
/// `domains`) and do not always send a total; this trait is what the walker
/// needs to drive all three.
///
/// ```
/// use inwx_client::{Page, ZoneListPage};
///
/// let page: ZoneListPage = serde_json::from_str(
///     r#"{"count":3,"domains":[{"domain":"a.de"},{"domain":"b.de"}]}"#,
/// )?;
/// assert_eq!(page.total(), Some(3));
/// assert_eq!(page.len(), 2);
/// assert!(!page.is_empty());
/// # Ok::<(), serde_json::Error>(())
/// ```
pub trait Page: DeserializeOwned + Sized {
    /// The objects the page carries.
    type Item;

    /// Total number of objects in the whole listing, when the API reports one.
    fn total(&self) -> Option<i64>;

    /// Number of objects on this page.
    fn len(&self) -> usize;

    /// Whether the page carries nothing.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drops every object after object number `len`.
    ///
    /// The walker uses this to cut the last page of a walk at its bound, so a
    /// walk never yields more objects than it promised.
    fn truncate_to(&mut self, len: usize);

    /// The page's objects, consumed.
    fn into_items(self) -> Vec<Self::Item>;
}

/// A paged list command: its method name, its filters and its page type.
///
/// Implemented by [`DomainListing`](crate::DomainListing),
/// [`ContactListing`](crate::ContactListing) and
/// [`ZoneListing`](crate::ZoneListing).
///
/// ```
/// use inwx_client::{ContactListing, ContactQuery, Listing};
///
/// let listing = ContactListing::new(ContactQuery::new().with_search("ACME"));
/// assert_eq!(<ContactListing as Listing>::METHOD, "contact.list");
/// let params = listing.params(2, 20);
/// assert_eq!(params["search"], "ACME");
/// assert_eq!(params["page"], 2);
/// assert_eq!(params["pagelimit"], 20);
/// ```
pub trait Listing: Clone {
    /// The page type this command answers with.
    type Page: Page;

    /// The JSON-RPC method that is called for every page.
    const METHOD: &'static str;

    /// Parameters for one page: the listing's own filters, with `page` and
    /// `pagelimit` set by the walker.
    fn params(&self, page: u32, page_size: u32) -> Value;
}

/// Page size and bound for a [`Pages`] walk.
///
/// Both are validated where they are set, so an out-of-range value is a local
/// error and never a request.
///
/// ```
/// use inwx_client::{Pagination, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE};
///
/// let pagination = Pagination::new().with_page_size(25)?.with_max_items(500)?;
/// assert_eq!(pagination.page_size(), 25);
/// assert_eq!(pagination.max_items(), Some(500));
/// assert_eq!(Pagination::default().page_size(), DEFAULT_PAGE_SIZE);
///
/// // Just inside and just outside the page size ceiling.
/// assert!(Pagination::new().with_page_size(MAX_PAGE_SIZE).is_ok());
/// assert!(Pagination::new().with_page_size(MAX_PAGE_SIZE + 1).is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pagination {
    page_size: u32,
    max_items: Option<usize>,
    max_pages: u32,
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            page_size: DEFAULT_PAGE_SIZE,
            max_items: None,
            max_pages: MAX_PAGES,
        }
    }
}

impl Pagination {
    /// The default walk: [`DEFAULT_PAGE_SIZE`] objects per request, stopped by
    /// the reported total or after [`MAX_PAGES`] requests.
    ///
    /// ```
    /// use inwx_client::{Pagination, MAX_PAGES};
    ///
    /// let pagination = Pagination::new();
    /// assert_eq!(pagination.max_items(), None);
    /// assert_eq!(pagination.max_pages(), MAX_PAGES);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets how many objects one request asks for: `1..=MAX_PAGE_SIZE`.
    ///
    /// ```
    /// use inwx_client::{Pagination, MAX_PAGE_SIZE};
    ///
    /// assert_eq!(Pagination::new().with_page_size(1)?.page_size(), 1);
    /// assert!(Pagination::new().with_page_size(0).is_err());
    /// assert!(Pagination::new().with_page_size(MAX_PAGE_SIZE + 1).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for `0` or anything above [`MAX_PAGE_SIZE`].
    pub fn with_page_size(mut self, page_size: u32) -> Result<Self> {
        if page_size == 0 {
            return Err(Error::validation("pagelimit", "must be at least 1"));
        }
        if page_size > MAX_PAGE_SIZE {
            return Err(Error::validation(
                "pagelimit",
                format!("must be at most {MAX_PAGE_SIZE}"),
            ));
        }
        self.page_size = page_size;
        Ok(self)
    }

    /// Stops the walk after this many objects: `1..=MAX_ITEMS`.
    ///
    /// The page that would cross the bound is truncated, so the walk yields
    /// exactly `max_items` objects and [`Pages::bound_reached`] reports that
    /// the listing was cut short.
    ///
    /// ```
    /// use inwx_client::{Pagination, MAX_ITEMS};
    ///
    /// assert_eq!(Pagination::new().with_max_items(1)?.max_items(), Some(1));
    /// assert_eq!(Pagination::new().with_max_items(MAX_ITEMS)?.max_items(), Some(MAX_ITEMS));
    /// assert!(Pagination::new().with_max_items(0).is_err());
    /// assert!(Pagination::new().with_max_items(MAX_ITEMS + 1).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for `0` or anything above [`MAX_ITEMS`].
    pub fn with_max_items(mut self, max_items: usize) -> Result<Self> {
        if max_items == 0 {
            return Err(Error::validation(
                "pagination.max_items",
                "must be at least 1",
            ));
        }
        if max_items > MAX_ITEMS {
            return Err(Error::validation(
                "pagination.max_items",
                format!("must be at most {MAX_ITEMS}"),
            ));
        }
        self.max_items = Some(max_items);
        Ok(self)
    }

    /// Stops the walk after this many requests: `1..=MAX_PAGES`.
    ///
    /// ```
    /// use inwx_client::{Pagination, MAX_PAGES};
    ///
    /// assert_eq!(Pagination::new().with_max_pages(1)?.max_pages(), 1);
    /// assert_eq!(Pagination::new().with_max_pages(MAX_PAGES)?.max_pages(), MAX_PAGES);
    /// assert!(Pagination::new().with_max_pages(0).is_err());
    /// assert!(Pagination::new().with_max_pages(MAX_PAGES + 1).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for `0` or anything above [`MAX_PAGES`].
    pub fn with_max_pages(mut self, max_pages: u32) -> Result<Self> {
        if max_pages == 0 {
            return Err(Error::validation(
                "pagination.max_pages",
                "must be at least 1",
            ));
        }
        if max_pages > MAX_PAGES {
            return Err(Error::validation(
                "pagination.max_pages",
                format!("must be at most {MAX_PAGES}"),
            ));
        }
        self.max_pages = max_pages;
        Ok(self)
    }

    /// Objects requested per request.
    ///
    /// ```
    /// use inwx_client::Pagination;
    /// assert_eq!(Pagination::new().page_size(), 100);
    /// ```
    #[must_use]
    pub fn page_size(&self) -> u32 {
        self.page_size
    }

    /// Object bound of the walk, when it has one.
    ///
    /// ```
    /// use inwx_client::Pagination;
    ///
    /// assert_eq!(Pagination::new().max_items(), None);
    /// assert_eq!(Pagination::new().with_max_items(7).unwrap().max_items(), Some(7));
    /// ```
    #[must_use]
    pub fn max_items(&self) -> Option<usize> {
        self.max_items
    }

    /// Request bound of the walk.
    ///
    /// ```
    /// use inwx_client::Pagination;
    /// assert_eq!(Pagination::new().with_max_pages(3).unwrap().max_pages(), 3);
    /// ```
    #[must_use]
    pub fn max_pages(&self) -> u32 {
        self.max_pages
    }
}

/// The walk over every page of a [`Listing`], up to the bound in its
/// [`Pagination`].
///
/// Built by [`InwxClient::list_all_domains`](crate::InwxClient::list_all_domains),
/// [`InwxClient::list_all_contacts`](crate::InwxClient::list_all_contacts),
/// [`InwxClient::list_all_zones`](crate::InwxClient::list_all_zones) or, for a
/// listing of your own, [`Pages::new`]. It borrows the client, so it inherits
/// the session, the retry policy and the `&self` thread-safety of the client;
/// nothing is held across an await except the client borrow itself.
///
/// The walk ends at the first of: a page shorter than requested, an empty page,
/// the `count` the API reports, [`Pagination::with_max_items`],
/// [`Pagination::with_max_pages`]. Only the last two set
/// [`Pages::bound_reached`](Pages::bound_reached).
///
/// ```
/// # use inwx_client::{
/// #     InwxClient, Pagination, Pages, ZoneListing, Result,
/// #     transport::{Request, Response, Transport},
/// # };
/// # use std::sync::{Arc, Mutex};
/// #[derive(Clone)]
/// struct Scripted(Arc<Mutex<Vec<&'static str>>>);
///
/// impl Transport for Scripted {
///     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
///         let body = self.0.lock().unwrap().remove(0);
///         Ok(Response::new(200, std::iter::empty(), body.as_bytes().to_vec()))
///     }
/// }
///
/// # async fn demo() -> Result<Vec<String>> {
/// let transport = Scripted(Arc::new(Mutex::new(vec![
///     r#"{"code":1000,"msg":"ok","resData":{"count":3,"domains":[{"domain":"a.de"},{"domain":"b.de"}]}}"#,
///     r#"{"code":1000,"msg":"ok","resData":{"domains":[{"domain":"c.de"}]}}"#,
/// ])));
/// let client = InwxClient::new(transport).with_session("domrobot=test")?;
/// let walk = Pages::new(&client, ZoneListing::new(), Pagination::new().with_page_size(2)?);
/// Ok(walk
///     .collect_all()
///     .await?
///     .iter()
///     .map(|zone| zone.domain.to_string())
///     .collect())
/// # }
/// # let zones = tokio::runtime::Runtime::new().unwrap().block_on(demo()).unwrap();
/// # assert_eq!(zones, ["a.de", "b.de", "c.de"]);
/// ```
pub struct Pages<'a, T, L>
where
    T: Transport,
    L: Listing,
{
    client: &'a InwxClient<T>,
    listing: L,
    pagination: Pagination,
    buffer: VecDeque<<L::Page as Page>::Item>,
    next_page_number: u32,
    requests_sent: u32,
    yielded: usize,
    pending_more: bool,
    finished: bool,
    bound_reached: bool,
}

impl<'a, T: Transport, L: Listing> Pages<'a, T, L> {
    /// Prepares the walk. Nothing is sent until the first call to
    /// [`Pages::next_page`] or [`Pages::next_item`].
    ///
    /// ```
    /// # use inwx_client::{
    /// #     InwxClient, Pagination, Pages, ZoneListing, Result,
    /// #     transport::{Request, Response, Transport},
    /// # };
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!("no call is made here")
    /// #     }
    /// # }
    /// # fn demo() -> Result<()> {
    /// let client = InwxClient::new(Never).with_session("domrobot=test")?;
    /// let walk = Pages::new(&client, ZoneListing::new(), Pagination::new());
    /// assert!(!walk.finished());
    /// assert_eq!(walk.yielded(), 0);
    /// # Ok(())
    /// # }
    /// # demo().unwrap();
    /// ```
    #[must_use]
    pub fn new(client: &'a InwxClient<T>, listing: L, pagination: Pagination) -> Self {
        Self {
            client,
            listing,
            pagination,
            buffer: VecDeque::new(),
            next_page_number: 1,
            requests_sent: 0,
            yielded: 0,
            pending_more: true,
            finished: false,
            bound_reached: false,
        }
    }

    /// Fetches the next page, or `None` when the walk is over.
    ///
    /// The last page of a walk with an object bound is truncated to that bound:
    /// asking for 5 objects with a page size of 2 over a listing of 10 yields
    /// pages of 2, 2 and 1 — never 2, 2, 2.
    ///
    /// ```
    /// # use inwx_client::{
    /// #     InwxClient, Page, Pagination, Pages, ZoneListing, Result,
    /// #     transport::{Request, Response, Transport},
    /// # };
    /// # use std::sync::{Arc, Mutex};
    /// #[derive(Clone)]
    /// struct Scripted(Arc<Mutex<Vec<&'static str>>>);
    ///
    /// impl Transport for Scripted {
    ///     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    ///         let body = self.0.lock().unwrap().remove(0);
    ///         Ok(Response::new(200, std::iter::empty(), body.as_bytes().to_vec()))
    ///     }
    /// }
    ///
    /// # async fn demo() -> Result<Vec<usize>> {
    /// let transport = Scripted(Arc::new(Mutex::new(vec![
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":4,"domains":[{"domain":"a.de"},{"domain":"b.de"}]}}"#,
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":4,"domains":[{"domain":"c.de"},{"domain":"d.de"}]}}"#,
    /// ])));
    /// let client = InwxClient::new(transport).with_session("domrobot=test")?;
    /// let mut walk = Pages::new(&client, ZoneListing::new(), Pagination::new().with_page_size(2)?);
    /// let mut sizes = Vec::new();
    /// while let Some(page) = walk.next_page().await? {
    ///     sizes.push(page.len());
    /// }
    /// assert!(!walk.bound_reached());
    /// Ok(sizes)
    /// # }
    /// # let sizes = tokio::runtime::Runtime::new().unwrap().block_on(demo()).unwrap();
    /// # assert_eq!(sizes, [2, 2]);
    /// ```
    ///
    /// # Errors
    ///
    /// The errors of [`InwxClient::call`] — [`Error::NotAuthenticated`],
    /// [`Error::Api`], [`Error::Transport`], [`Error::Json`], [`Error::Http`] —
    /// plus [`Error::Json`] when a page does not have the documented shape. A
    /// walk that returned an error may be continued: the failed request is not
    /// counted, so the next call repeats that page.
    pub async fn next_page(&mut self) -> Result<Option<L::Page>> {
        if self.finished {
            return Ok(None);
        }
        if self.at_bound() {
            self.finished = true;
            self.bound_reached = self.pending_more;
            return Ok(None);
        }

        let page_size = self.pagination.page_size;
        let mut page = self.fetch(self.next_page_number).await?;
        self.requests_sent += 1;
        self.next_page_number = self.next_page_number.saturating_add(1);

        let received = page.len();
        if let Some(max_items) = self.pagination.max_items {
            let room = max_items.saturating_sub(self.yielded);
            if received > room {
                page.truncate_to(room);
                self.yielded += room;
                self.finished = true;
                self.bound_reached = true;
                return Ok(Some(page));
            }
        }
        self.yielded += received;

        let requested = usize::try_from(page_size).unwrap_or(usize::MAX);
        let reported = page.total();
        let below_total =
            reported.is_none_or(|total| i64::try_from(self.yielded).unwrap_or(i64::MAX) < total);
        self.pending_more = received > 0 && received >= requested && below_total;

        if !self.pending_more || self.requests_sent >= self.pagination.max_pages {
            self.finished = true;
            self.bound_reached = self.pending_more;
        }
        Ok(Some(page))
    }

    /// Returns the next object, fetching pages as needed, or `None` when the
    /// walk is over.
    ///
    /// ```
    /// # use inwx_client::{
    /// #     InwxClient, Pagination, Pages, ZoneListing, Result,
    /// #     transport::{Request, Response, Transport},
    /// # };
    /// # use std::sync::{Arc, Mutex};
    /// #[derive(Clone)]
    /// struct Scripted(Arc<Mutex<Vec<&'static str>>>);
    ///
    /// impl Transport for Scripted {
    ///     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    ///         let body = self.0.lock().unwrap().remove(0);
    ///         Ok(Response::new(200, std::iter::empty(), body.as_bytes().to_vec()))
    ///     }
    /// }
    ///
    /// # async fn demo() -> Result<usize> {
    /// let transport = Scripted(Arc::new(Mutex::new(vec![
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":5,"domains":[{"domain":"a.de"},{"domain":"b.de"}]}}"#,
    ///     r#"{"code":1000,"msg":"ok","resData":{"domains":[{"domain":"c.de"},{"domain":"d.de"}]}}"#,
    ///     r#"{"code":1000,"msg":"ok","resData":{"domains":[{"domain":"e.de"}]}}"#,
    /// ])));
    /// let client = InwxClient::new(transport).with_session("domrobot=test")?;
    /// let mut walk = Pages::new(
    ///     &client,
    ///     ZoneListing::new(),
    ///     Pagination::new().with_page_size(2)?.with_max_items(3)?,
    /// );
    /// let mut names = Vec::new();
    /// while let Some(zone) = walk.next_item().await? {
    ///     names.push(zone.domain.to_string());
    /// }
    /// assert!(walk.bound_reached());
    /// Ok(names.len())
    /// # }
    /// # assert_eq!(
    /// #     tokio::runtime::Runtime::new().unwrap().block_on(demo()).unwrap(),
    /// #     3
    /// # );
    /// ```
    ///
    /// # Errors
    ///
    /// Same as [`Pages::next_page`].
    pub async fn next_item(&mut self) -> Result<Option<<L::Page as Page>::Item>> {
        while self.buffer.is_empty() {
            match self.next_page().await? {
                Some(page) => self.buffer.extend(page.into_items()),
                None => return Ok(None),
            }
        }
        Ok(self.buffer.pop_front())
    }

    /// Walks the rest of the listing and returns every object it yields.
    ///
    /// ```
    /// # use inwx_client::{
    /// #     InwxClient, Pagination, Pages, ZoneListing, Result,
    /// #     transport::{Request, Response, Transport},
    /// # };
    /// # use std::sync::{Arc, Mutex};
    /// #[derive(Clone)]
    /// struct Scripted(Arc<Mutex<Vec<&'static str>>>);
    ///
    /// impl Transport for Scripted {
    ///     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    ///         let body = self.0.lock().unwrap().remove(0);
    ///         Ok(Response::new(200, std::iter::empty(), body.as_bytes().to_vec()))
    ///     }
    /// }
    ///
    /// # async fn demo() -> Result<Vec<String>> {
    /// let transport = Scripted(Arc::new(Mutex::new(vec![
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":1,"domains":[{"domain":"only.de"}]}}"#,
    /// ])));
    /// let client = InwxClient::new(transport).with_session("domrobot=test")?;
    /// let walk = Pages::new(&client, ZoneListing::new(), Pagination::new());
    /// Ok(walk
    ///     .collect_all()
    ///     .await?
    ///     .iter()
    ///     .map(|zone| zone.domain.to_string())
    ///     .collect())
    /// # }
    /// # assert_eq!(
    /// #     tokio::runtime::Runtime::new().unwrap().block_on(demo()).unwrap(),
    /// #     ["only.de"]
    /// # );
    /// ```
    ///
    /// # Errors
    ///
    /// Same as [`Pages::next_page`]. The first error ends the walk; objects
    /// already fetched are dropped with it, because a half listing silently
    /// passed for a complete one is worse than an error.
    ///
    /// With [`Pagination::with_max_items`] the result can be shorter than the
    /// listing, and the bound is not reported here — drive the walk with
    /// [`Pages::next_page`] or [`Pages::next_item`] when the caller needs to
    /// know whether [`Pages::bound_reached`] cut it short.
    pub async fn collect_all(mut self) -> Result<Vec<<L::Page as Page>::Item>> {
        let mut items = Vec::new();
        while let Some(item) = self.next_item().await? {
            items.push(item);
        }
        Ok(items)
    }

    /// Whether the walk stopped because of its bound while the listing still
    /// looked unfinished.
    ///
    /// ```
    /// use inwx_client::Pagination;
    ///
    /// // A walk that never ran has not hit its bound.
    /// let pagination = Pagination::new().with_max_items(1).unwrap();
    /// assert_eq!(pagination.max_items(), Some(1));
    /// ```
    #[must_use]
    pub fn bound_reached(&self) -> bool {
        self.bound_reached
    }

    /// Whether the walk is over, for whichever reason.
    ///
    /// ```
    /// # use inwx_client::{InwxClient, Pagination, Pages, ZoneListing, Result,
    /// #     transport::{Request, Response, Transport}};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!("no call is made here")
    /// #     }
    /// # }
    /// # fn demo() -> Result<()> {
    /// let client = InwxClient::new(Never).with_session("domrobot=test")?;
    /// let walk = Pages::new(&client, ZoneListing::new(), Pagination::new());
    /// assert!(!walk.finished());
    /// # Ok(())
    /// # }
    /// # demo().unwrap();
    /// ```
    #[must_use]
    pub fn finished(&self) -> bool {
        self.finished
    }

    /// How many objects the walk has yielded so far.
    ///
    /// ```
    /// # use inwx_client::{InwxClient, Pagination, Pages, ZoneListing, Result,
    /// #     transport::{Request, Response, Transport}};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!("no call is made here")
    /// #     }
    /// # }
    /// # fn demo() -> Result<()> {
    /// let client = InwxClient::new(Never).with_session("domrobot=test")?;
    /// let walk = Pages::new(&client, ZoneListing::new(), Pagination::new());
    /// assert_eq!(walk.yielded(), 0);
    /// # Ok(())
    /// # }
    /// # demo().unwrap();
    /// ```
    #[must_use]
    pub fn yielded(&self) -> usize {
        self.yielded
    }

    /// Whether the bound — objects or requests — has been used up.
    fn at_bound(&self) -> bool {
        self.requests_sent >= self.pagination.max_pages
            || self
                .pagination
                .max_items
                .is_some_and(|max_items| self.yielded >= max_items)
    }

    /// One request for one page number.
    async fn fetch(&self, page: u32) -> Result<L::Page> {
        let params = self.listing.params(page, self.pagination.page_size);
        let data = self.client.call(L::METHOD, params).await?;
        serde_json::from_value(data).map_err(Error::from)
    }
}

/// `Debug` shows where the walk stands, never a credential: the client behind it
/// prints only whether a session exists.
impl<T, L> fmt::Debug for Pages<'_, T, L>
where
    T: Transport,
    L: Listing,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Pages")
            .field("method", &L::METHOD)
            .field("page_size", &self.pagination.page_size)
            .field("max_items", &self.pagination.max_items)
            .field("max_pages", &self.pagination.max_pages)
            .field("next_page_number", &self.next_page_number)
            .field("pages_fetched", &self.requests_sent)
            .field("yielded", &self.yielded)
            .field("finished", &self.finished)
            .field("bound_reached", &self.bound_reached)
            .finish_non_exhaustive()
    }
}

/// Inserts the walker's paging into a listing's parameter object.
pub(crate) fn with_paging(mut params: Value, page: u32, page_size: u32) -> Value {
    if !params.is_object() {
        params = Value::Object(Map::new());
    }
    if let Some(object) = params.as_object_mut() {
        object.insert("page".to_owned(), Value::from(u64::from(page)));
        object.insert("pagelimit".to_owned(), Value::from(u64::from(page_size)));
    }
    params
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_page_size_limit_is_a_pair() {
        assert_eq!(Pagination::new().with_page_size(1).unwrap().page_size(), 1);
        assert_eq!(
            Pagination::new()
                .with_page_size(MAX_PAGE_SIZE)
                .unwrap()
                .page_size(),
            MAX_PAGE_SIZE
        );
        assert!(Pagination::new()
            .with_page_size(0)
            .unwrap_err()
            .is_validation());
        assert!(Pagination::new()
            .with_page_size(MAX_PAGE_SIZE + 1)
            .unwrap_err()
            .is_validation());
    }

    #[test]
    fn both_bounds_are_pairs() {
        assert_eq!(
            Pagination::new().with_max_items(1).unwrap().max_items(),
            Some(1)
        );
        assert_eq!(
            Pagination::new()
                .with_max_items(MAX_ITEMS)
                .unwrap()
                .max_items(),
            Some(MAX_ITEMS)
        );
        assert!(Pagination::new()
            .with_max_items(0)
            .unwrap_err()
            .is_validation());
        assert!(Pagination::new()
            .with_max_items(MAX_ITEMS + 1)
            .unwrap_err()
            .is_validation());

        assert_eq!(Pagination::new().with_max_pages(1).unwrap().max_pages(), 1);
        assert_eq!(
            Pagination::new()
                .with_max_pages(MAX_PAGES)
                .unwrap()
                .max_pages(),
            MAX_PAGES
        );
        assert!(Pagination::new()
            .with_max_pages(0)
            .unwrap_err()
            .is_validation());
        assert!(Pagination::new()
            .with_max_pages(MAX_PAGES + 1)
            .unwrap_err()
            .is_validation());
    }

    #[test]
    fn the_default_walk_uses_the_documented_page_size() {
        let pagination = Pagination::default();
        assert_eq!(pagination, Pagination::new());
        assert_eq!(pagination.page_size(), DEFAULT_PAGE_SIZE);
        assert_eq!(pagination.max_items(), None);
        assert_eq!(pagination.max_pages(), MAX_PAGES);
    }

    #[test]
    fn paging_replaces_an_existing_cursor() {
        let params = with_paging(
            json!({"domain": ["acme"], "page": 7, "pagelimit": 3}),
            2,
            50,
        );
        assert_eq!(params["page"], 2);
        assert_eq!(params["pagelimit"], 50);
        assert_eq!(params["domain"][0], "acme");
    }

    #[test]
    fn paging_repairs_a_listing_that_has_no_parameter_object() {
        assert_eq!(
            with_paging(Value::String("nope".to_owned()), 1, 1),
            json!({"page": 1, "pagelimit": 1})
        );
        assert_eq!(
            with_paging(Value::Null, 3, 4),
            json!({"page": 3, "pagelimit": 4})
        );
    }
}
