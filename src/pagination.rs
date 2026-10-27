//! Bounded walking of the paginated list endpoints.
//!
//! INWX paginates the list methods with a `page` (1-based) and a `pagelimit`
//! parameter and answers with the items of that page plus a `count` of all
//! matching objects. A single call therefore returns one page, not the list.
//!
//! [`Pagination`] holds the bounds of a walk — page size, how many items to read
//! at most, how many requests to make at most — and is checked before anything
//! goes on the wire. The pagers built from it ([`DomainPager`](crate::DomainPager),
//! [`ContactPager`](crate::ContactPager), [`ZonePager`](crate::ZonePager)) then
//! walk every page and stop on their own when the provider says there is
//! nothing left.
//!
//! ```
//! # use std::sync::{Arc, Mutex};
//! # use inwx_client::transport::{Request, Response, Transport};
//! use inwx_client::{InwxClient, Pagination};
//! # use inwx_client::Result;
//! # #[derive(Clone)]
//! # struct Scripted(Arc<Mutex<Vec<&'static str>>>);
//! # impl Transport for Scripted {
//! #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
//! #         let body = self.0.lock().unwrap().remove(0);
//! #         Ok(Response::new(200, std::iter::empty(), body.as_bytes().to_vec()))
//! #     }
//! # }
//! # fn demo() -> Result<usize> {
//! let transport = Scripted(Arc::new(Mutex::new(vec![
//!     r#"{"code":1000,"msg":"ok","resData":{"count":3,"domains":[{"domain":"a.de"},{"domain":"b.de"}]}}"#,
//!     r#"{"code":1000,"msg":"ok","resData":{"count":3,"domains":[{"domain":"c.de"}]}}"#,
//! ])));
//! let client = InwxClient::new(transport).with_session("domrobot=test")?;
//! let paging = Pagination::new().with_page_size(2)?;
//! let mut pager = client.paginate_zones(&paging);
//! let runtime = tokio::runtime::Runtime::new().unwrap();
//! let zones = runtime.block_on(pager.collect())?;
//! assert_eq!(zones.len(), 3);
//! assert_eq!(pager.pages_fetched(), 2);
//! assert!(!pager.is_truncated());
//! # Ok(zones.len())
//! # }
//! # assert_eq!(demo().unwrap(), 3);
//! ```

use crate::error::{Error, Result};

/// Page size used when the caller does not pick one.
///
/// ```
/// use inwx_client::{Pagination, DEFAULT_PAGE_SIZE};
///
/// assert_eq!(Pagination::new().page_size(), DEFAULT_PAGE_SIZE);
/// ```
pub const DEFAULT_PAGE_SIZE: u32 = 100;

/// Largest page size this crate will ask for.
///
/// INWX types `pagelimit` as a plain `int` and publishes no maximum, so this is
/// a crate-side bound: it turns a mistyped `10_000_000` into a local
/// [`Error::Validation`] instead of a request that makes the provider build a
/// response nobody can hold in memory.
///
/// ```
/// use inwx_client::{Error, Pagination, MAX_PAGE_SIZE};
///
/// assert!(Pagination::new().with_page_size(MAX_PAGE_SIZE).is_ok());
/// let err = Pagination::new().with_page_size(MAX_PAGE_SIZE + 1).unwrap_err();
/// assert!(matches!(err, Error::Validation { field: "pagelimit", .. }));
/// ```
pub const MAX_PAGE_SIZE: u32 = 1000;

/// Item cap used when the caller does not pick one.
///
/// ```
/// use inwx_client::{Pagination, DEFAULT_MAX_ITEMS};
///
/// assert_eq!(Pagination::new().max_items(), DEFAULT_MAX_ITEMS);
/// ```
pub const DEFAULT_MAX_ITEMS: usize = 10_000;

/// Largest item cap that can be configured.
///
/// ```
/// use inwx_client::{Error, Pagination, MAX_ITEMS};
///
/// assert!(Pagination::new().with_max_items(MAX_ITEMS).is_ok());
/// assert!(Pagination::new().with_max_items(MAX_ITEMS + 1).is_err());
/// ```
pub const MAX_ITEMS: usize = 100_000;

/// Request cap used when the caller does not pick one.
///
/// The defaults are self-consistent: [`DEFAULT_MAX_PAGES`] pages of
/// [`DEFAULT_PAGE_SIZE`] items are exactly [`DEFAULT_MAX_ITEMS`] items.
///
/// ```
/// use inwx_client::{DEFAULT_MAX_PAGES, DEFAULT_PAGE_SIZE, Pagination};
///
/// assert_eq!(Pagination::new().max_pages(), DEFAULT_MAX_PAGES);
/// assert_eq!(
///     usize::try_from(DEFAULT_MAX_PAGES).unwrap() * DEFAULT_PAGE_SIZE as usize,
///     inwx_client::DEFAULT_MAX_ITEMS
/// );
/// ```
pub const DEFAULT_MAX_PAGES: u32 = 100;

/// Largest request cap that can be configured.
///
/// ```
/// use inwx_client::{Error, Pagination, MAX_PAGES};
///
/// assert!(Pagination::new().with_max_pages(MAX_PAGES).is_ok());
/// assert!(Pagination::new().with_max_pages(MAX_PAGES + 1).is_err());
/// ```
pub const MAX_PAGES: u32 = 10_000;

/// How far a paginated walk may go.
///
/// All three bounds are checked at construction, so a walk never dies half way
/// through because of a number that was wrong from the start. Zero is refused
/// everywhere: a walk that may not fetch a page, or may not read an item, is a
/// mistake rather than a wish.
///
/// ```
/// use inwx_client::{Error, Pagination};
///
/// let paging = Pagination::new().with_page_size(250)?.with_max_items(5_000)?;
/// assert_eq!(paging.page_size(), 250);
/// assert_eq!(paging.max_items(), 5_000);
///
/// let err = Pagination::new().with_page_size(0).unwrap_err();
/// assert!(matches!(err, Error::Validation { field: "pagelimit", .. }));
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pagination {
    page_size: u32,
    max_items: usize,
    max_pages: u32,
}

impl Default for Pagination {
    fn default() -> Self {
        Self::new()
    }
}

impl Pagination {
    /// The defaults: [`DEFAULT_PAGE_SIZE`], [`DEFAULT_MAX_ITEMS`],
    /// [`DEFAULT_MAX_PAGES`].
    ///
    /// ```
    /// use inwx_client::Pagination;
    ///
    /// assert_eq!(Pagination::new(), Pagination::default());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            page_size: DEFAULT_PAGE_SIZE,
            max_items: DEFAULT_MAX_ITEMS,
            max_pages: DEFAULT_MAX_PAGES,
        }
    }

    /// Asks for `page_size` items per request.
    ///
    /// ```
    /// use inwx_client::Pagination;
    ///
    /// assert_eq!(Pagination::new().with_page_size(1)?.page_size(), 1);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `page_size` is zero or above
    /// [`MAX_PAGE_SIZE`].
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

    /// Reads at most `max_items` items before the walk stops.
    ///
    /// Reaching the cap is not an error: the walk finishes and reports
    /// [`is_truncated`](crate::DomainPager::is_truncated).
    ///
    /// ```
    /// use inwx_client::Pagination;
    ///
    /// assert_eq!(Pagination::new().with_max_items(1)?.max_items(), 1);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `max_items` is zero or above [`MAX_ITEMS`].
    pub fn with_max_items(mut self, max_items: usize) -> Result<Self> {
        if max_items == 0 {
            return Err(Error::validation("max_items", "must be at least 1"));
        }
        if max_items > MAX_ITEMS {
            return Err(Error::validation(
                "max_items",
                format!("must be at most {MAX_ITEMS}"),
            ));
        }
        self.max_items = max_items;
        Ok(self)
    }

    /// Makes at most `max_pages` requests before the walk stops.
    ///
    /// Unlike the item cap this cap is an error when it is hit: a list that is
    /// silently cut short after a fixed number of requests is indistinguishable
    /// from a complete one, so the walk reports
    /// [`Error::Pagination`] instead.
    ///
    /// ```
    /// use inwx_client::Pagination;
    ///
    /// assert_eq!(Pagination::new().with_max_pages(1)?.max_pages(), 1);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `max_pages` is zero or above [`MAX_PAGES`].
    pub fn with_max_pages(mut self, max_pages: u32) -> Result<Self> {
        if max_pages == 0 {
            return Err(Error::validation("max_pages", "must be at least 1"));
        }
        if max_pages > MAX_PAGES {
            return Err(Error::validation(
                "max_pages",
                format!("must be at most {MAX_PAGES}"),
            ));
        }
        self.max_pages = max_pages;
        Ok(self)
    }

    /// Items requested per call.
    ///
    /// ```
    /// use inwx_client::{DEFAULT_PAGE_SIZE, Pagination};
    ///
    /// assert_eq!(Pagination::new().page_size(), DEFAULT_PAGE_SIZE);
    /// ```
    #[must_use]
    pub fn page_size(&self) -> u32 {
        self.page_size
    }

    /// Item cap of the walk.
    ///
    /// ```
    /// use inwx_client::Pagination;
    ///
    /// assert_eq!(Pagination::new().with_max_items(7)?.max_items(), 7);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn max_items(&self) -> usize {
        self.max_items
    }

    /// Request cap of the walk.
    ///
    /// ```
    /// use inwx_client::Pagination;
    ///
    /// assert_eq!(Pagination::new().with_max_pages(7)?.max_pages(), 7);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn max_pages(&self) -> u32 {
        self.max_pages
    }

    /// Starts a walk with these bounds.
    pub(crate) fn walk(&self) -> Walk {
        Walk {
            paging: *self,
            next_page: 1,
            pages: 0,
            items: 0,
            finished: false,
            truncated: false,
        }
    }
}

/// State of one running walk, shared by the three pagers.
///
/// The pagers ask [`Walk::request`] what to fetch, then report the answer to
/// [`Walk::absorb`]. Whether more pages exist is decided from the `count` field
/// when the API sent one and from the page length otherwise, so a provider that
/// omits `count` still terminates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Walk {
    paging: Pagination,
    next_page: u32,
    pages: u32,
    items: usize,
    finished: bool,
    truncated: bool,
}

impl Walk {
    /// The page and page size to fetch next.
    ///
    /// The limit is trimmed to what is left of the item cap, so a walk never
    /// receives more items than the caller allowed and never asks for more than
    /// it can keep.
    pub(crate) fn request(&self) -> (u32, u32) {
        let remaining = self.paging.max_items.saturating_sub(self.items);
        let remaining = u32::try_from(remaining).unwrap_or(u32::MAX);
        (self.next_page, self.paging.page_size.min(remaining))
    }

    /// How many items of the next page the walk may keep: at most `limit`, which
    /// is what it asked for, and never more than is left of the item cap.
    ///
    /// A provider that ignores `pagelimit` and sends a fatter page than asked
    /// therefore cannot push a walk past [`Pagination::max_items`].
    pub(crate) fn keep(&self, limit: u32, len: usize) -> usize {
        let asked = usize::try_from(limit).unwrap_or(usize::MAX);
        let left = self.paging.max_items.saturating_sub(self.items);
        len.min(asked).min(left)
    }

    /// Records one page: `limit` is what [`Walk::request`] asked for, `count`
    /// the API's total, `len` the number of items the caller kept — never more
    /// than [`Walk::keep`] allowed.
    ///
    /// The caller must buffer the items before calling this, so that the data of
    /// the page that hit the request cap survives the error.
    pub(crate) fn absorb(&mut self, limit: u32, count: Option<i64>, len: usize) -> Result<()> {
        self.pages += 1;
        self.items += len;
        self.next_page += 1;

        let more = if len == 0 {
            false
        } else {
            match count {
                Some(count) => i64::try_from(self.items).map_or(true, |items| items < count),
                None => len >= usize::try_from(limit).unwrap_or(usize::MAX),
            }
        };
        if !more {
            self.finished = true;
            self.truncated = false;
            return Ok(());
        }
        if self.items >= self.paging.max_items {
            self.finished = true;
            self.truncated = true;
            return Ok(());
        }
        if self.pages >= self.paging.max_pages {
            self.finished = true;
            self.truncated = true;
            let read = match count {
                Some(count) if count >= 0 => format!("{} of {count} items", self.items),
                _ => format!("{} items", self.items),
            };
            return Err(Error::Pagination {
                pages: self.pages,
                items: self.items,
                message: format!(
                    "read {read} and the list still has more: raise `max_pages` \
                     (currently {max}) or `page_size` (currently {size})",
                    max = self.paging.max_pages,
                    size = self.paging.page_size,
                ),
            });
        }
        Ok(())
    }

    /// Whether the walk is over, for any reason.
    pub(crate) fn is_finished(&self) -> bool {
        self.finished
    }

    /// Whether the walk stopped although the provider had more to give.
    pub(crate) fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Pages fetched so far.
    pub(crate) fn pages(&self) -> u32 {
        self.pages
    }

    /// Items read so far.
    pub(crate) fn items(&self) -> usize {
        self.items
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn field(err: &Error) -> &str {
        match err {
            Error::Validation { field, .. } => field,
            other => panic!("expected a validation error, got {other}"),
        }
    }

    #[test]
    fn page_size_boundary_pair() {
        assert_eq!(Pagination::new().with_page_size(1).unwrap().page_size(), 1);
        assert_eq!(
            Pagination::new()
                .with_page_size(MAX_PAGE_SIZE)
                .unwrap()
                .page_size(),
            MAX_PAGE_SIZE
        );
        let below = Pagination::new().with_page_size(0).unwrap_err();
        assert_eq!(field(&below), "pagelimit");
        let above = Pagination::new()
            .with_page_size(MAX_PAGE_SIZE + 1)
            .unwrap_err();
        assert_eq!(field(&above), "pagelimit");
    }

    #[test]
    fn max_items_boundary_pair() {
        assert_eq!(Pagination::new().with_max_items(1).unwrap().max_items(), 1);
        assert_eq!(
            Pagination::new()
                .with_max_items(MAX_ITEMS)
                .unwrap()
                .max_items(),
            MAX_ITEMS
        );
        assert_eq!(
            field(&Pagination::new().with_max_items(0).unwrap_err()),
            "max_items"
        );
        assert_eq!(
            field(&Pagination::new().with_max_items(MAX_ITEMS + 1).unwrap_err()),
            "max_items"
        );
    }

    #[test]
    fn max_pages_boundary_pair() {
        assert_eq!(Pagination::new().with_max_pages(1).unwrap().max_pages(), 1);
        assert_eq!(
            Pagination::new()
                .with_max_pages(MAX_PAGES)
                .unwrap()
                .max_pages(),
            MAX_PAGES
        );
        assert_eq!(
            field(&Pagination::new().with_max_pages(0).unwrap_err()),
            "max_pages"
        );
        assert_eq!(
            field(&Pagination::new().with_max_pages(MAX_PAGES + 1).unwrap_err()),
            "max_pages"
        );
    }

    #[test]
    fn defaults_are_self_consistent() {
        let paging = Pagination::new();
        assert_eq!(paging, Pagination::default());
        assert_eq!(paging.page_size(), DEFAULT_PAGE_SIZE);
        assert_eq!(paging.max_items(), DEFAULT_MAX_ITEMS);
        assert_eq!(paging.max_pages(), DEFAULT_MAX_PAGES);
        assert_eq!(
            usize::try_from(DEFAULT_MAX_PAGES).unwrap()
                * usize::try_from(DEFAULT_PAGE_SIZE).unwrap(),
            DEFAULT_MAX_ITEMS
        );
    }

    #[test]
    fn request_limit_is_trimmed_to_what_is_left() {
        let paging = Pagination::new().with_page_size(100).unwrap();
        let walk = paging.walk();
        assert_eq!(walk.request(), (1, 100));

        let small = Pagination::new()
            .with_page_size(100)
            .unwrap()
            .with_max_items(30)
            .unwrap();
        let mut walk = small.walk();
        assert_eq!(walk.request(), (1, 30));
        walk.absorb(30, Some(1_000), 30).unwrap();
        assert!(walk.is_finished());
        assert!(walk.is_truncated());
        assert_eq!(walk.items(), 30);
    }

    #[test]
    fn keep_never_allows_more_than_the_cap() {
        let paging = Pagination::new()
            .with_page_size(10)
            .unwrap()
            .with_max_items(10)
            .unwrap();
        let mut walk = paging.walk();
        // Just inside: a fat page is trimmed to what was asked for.
        assert_eq!(walk.keep(10, 12), 10);
        walk.absorb(10, Some(100), 10).unwrap();
        assert_eq!(walk.items(), 10);
        assert!(walk.is_truncated());

        // Two items left of the cap: even a page that ignores `pagelimit` may
        // only contribute those two.
        let tight = Pagination::new()
            .with_page_size(10)
            .unwrap()
            .with_max_items(12)
            .unwrap();
        let mut walk = tight.walk();
        walk.absorb(10, Some(100), 10).unwrap();
        let (_, limit) = walk.request();
        assert_eq!(limit, 2);
        assert_eq!(walk.keep(limit, 10), 2);
        assert_eq!(walk.keep(limit, 1), 1);
        walk.absorb(limit, Some(100), walk.keep(limit, 10)).unwrap();
        assert_eq!(walk.items(), 12);
        assert!(walk.is_truncated());
        // Just outside: nothing may be kept once the cap is full.
        assert_eq!(walk.keep(10, 10), 0);
    }

    #[test]
    fn count_decides_when_it_is_present() {
        let mut walk = Pagination::new().with_page_size(2).unwrap().walk();
        // A full page that reaches `count` is the last one: no extra request.
        walk.absorb(2, Some(2), 2).unwrap();
        assert!(walk.is_finished());
        assert!(!walk.is_truncated());
        assert_eq!(walk.pages(), 1);
    }

    #[test]
    fn short_page_ends_a_walk_without_count() {
        let mut walk = Pagination::new().with_page_size(4).unwrap().walk();
        walk.absorb(4, None, 4).unwrap();
        assert!(!walk.is_finished());
        walk.absorb(4, None, 3).unwrap();
        assert!(walk.is_finished());
        assert!(!walk.is_truncated());
        assert_eq!(walk.items(), 7);
    }

    #[test]
    fn empty_page_ends_a_walk_even_when_count_lies() {
        let mut walk = Pagination::new().with_page_size(2).unwrap().walk();
        walk.absorb(2, Some(500), 0).unwrap();
        assert!(walk.is_finished());
        assert!(!walk.is_truncated());
    }

    #[test]
    fn request_cap_is_a_terminal_error() {
        let paging = Pagination::new()
            .with_page_size(1)
            .unwrap()
            .with_max_items(100)
            .unwrap()
            .with_max_pages(2)
            .unwrap();
        let mut walk = paging.walk();
        walk.absorb(1, Some(100), 1).unwrap();
        let err = walk.absorb(1, Some(100), 1).unwrap_err();
        assert!(matches!(
            err,
            Error::Pagination {
                pages: 2,
                items: 2,
                ..
            }
        ));
        assert!(!err.is_retryable());
        assert!(walk.is_finished());
        assert!(walk.is_truncated());
        // Asking again does not restart a walk that already failed.
        assert!(walk.is_finished());
    }

    #[test]
    fn item_cap_truncates_without_an_error() {
        let paging = Pagination::new()
            .with_page_size(2)
            .unwrap()
            .with_max_items(3)
            .unwrap();
        let mut walk = paging.walk();
        walk.absorb(2, Some(10), 2).unwrap();
        assert_eq!(walk.request(), (2, 1));
        walk.absorb(1, Some(10), 1).unwrap();
        assert!(walk.is_finished());
        assert!(walk.is_truncated());
        assert_eq!(walk.items(), 3);
    }

    proptest! {
        #[test]
        fn a_walk_never_reads_more_than_the_cap(pages in 0usize..12, cap in 1usize..400) {
            // Whatever the page lengths are, the walk stops at `cap` items and
            // always terminates.
            let paging = Pagination::new()
                .with_page_size(7)
                .unwrap()
                .with_max_items(cap)
                .unwrap()
                .with_max_pages(12)
                .unwrap();
            let mut walk = paging.walk();
            let mut guard = 0u32;
            while !walk.is_finished() && guard < 50 {
                guard += 1;
                let (page, limit) = walk.request();
                prop_assert!(page <= paging.max_pages());
                prop_assert!(usize::try_from(limit).unwrap() <= cap);
                // The caller keeps what `keep` allows, even from a fat page.
                let kept = walk.keep(limit, pages % 9);
                prop_assert!(kept <= usize::try_from(limit).unwrap_or(usize::MAX));
                let _ = walk.absorb(limit, None, kept);
                prop_assert!(walk.items() <= cap);
            }
            prop_assert!(walk.is_finished());
        }
    }
}
