//! News (`news.list`): the announcements a reseller's customers are shown.
//!
//! One method, one page of items. The body of a news entry is free-form text,
//! so it stays a string; unknown fields survive in [`NewsItem::rest`].
//!
//! The object is described in the API documentation chapter 2 §2.17.
//!
//! ```
//! use inwx_client::NewsItem;
//!
//! let item: NewsItem = serde_json::from_str(
//!     r#"{"id":5,"title":"Maintenance","content":"on Sunday","read":0}"#,
//! )?;
//! assert_eq!(item.id, Some(5));
//! assert_eq!(item.is_read(), Some(false));
//! # Ok::<(), serde_json::Error>(())
//! ```

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::params::{self, ExtraFields};
use crate::transport::Transport;
use crate::types::de;

/// Keys owned by [`NewsQuery`].
const QUERY_KEYS: &[&str] = &["customer", "onlyUnread", "page", "pagelimit"];

/// One news entry.
///
/// ```
/// use inwx_client::NewsItem;
///
/// let camel: NewsItem =
///     serde_json::from_str(r#"{"id":"5","isRead":1,"createdAt":"2026-10-01"}"#)?;
/// let snake: NewsItem =
///     serde_json::from_str(r#"{"id":5,"is_read":true,"created_at":"2026-10-01"}"#)?;
/// assert_eq!(camel, snake);
/// assert_eq!(camel.is_read(), Some(true));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct NewsItem {
    /// News id.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Headline.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub title: Option<String>,
    /// Body text.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub content: Option<String>,
    /// Whether the customer has read the entry.
    #[serde(
        default,
        rename = "isRead",
        alias = "is_read",
        alias = "read",
        deserialize_with = "de::opt_bool"
    )]
    pub read: Option<bool>,
    /// Creation timestamp.
    #[serde(
        default,
        rename = "createdAt",
        alias = "created_at",
        deserialize_with = "de::opt_string"
    )]
    pub created_at: Option<String>,
    /// Fields this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

impl NewsItem {
    /// Whether the entry was read, or `None` when the API did not say.
    ///
    /// ```
    /// use inwx_client::NewsItem;
    ///
    /// assert_eq!(serde_json::from_str::<NewsItem>(r#"{"read":"1"}"#)?.is_read(), Some(true));
    /// assert_eq!(serde_json::from_str::<NewsItem>(r#"{}"#)?.is_read(), None);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_read(&self) -> Option<bool> {
        self.read
    }
}

/// One page of `news.list`.
///
/// ```
/// use inwx_client::NewsListPage;
///
/// let page: NewsListPage = serde_json::from_str(r#"{"count":1,"news":[{"id":5}]}"#)?;
/// assert_eq!(page.count, Some(1));
/// assert_eq!(page.len(), 1);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct NewsListPage {
    /// Total number of entries, not just this page.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The entries on this page.
    #[serde(default, rename = "news")]
    pub items: Vec<NewsItem>,
}

impl NewsListPage {
    /// Number of entries on this page.
    ///
    /// ```
    /// use inwx_client::NewsListPage;
    /// let page: NewsListPage = serde_json::from_str(r#"{"news":[{"id":1}]}"#)?;
    /// assert_eq!(page.len(), 1);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether this page carries no entry at all.
    ///
    /// ```
    /// use inwx_client::NewsListPage;
    /// assert!(NewsListPage::default().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// The filter behind `news.list`.
///
/// ```
/// use inwx_client::NewsQuery;
///
/// let query = NewsQuery::new().with_unread_only(true).with_page(1, 25)?;
/// let params = query.params();
/// assert_eq!(params["onlyUnread"], true);
/// assert_eq!(params["pagelimit"], 25);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NewsQuery {
    customer: Option<i64>,
    unread_only: Option<bool>,
    page: Option<u32>,
    limit: Option<u32>,
    fields: ExtraFields,
}

impl NewsQuery {
    /// All news of the reseller account.
    ///
    /// ```
    /// use inwx_client::NewsQuery;
    /// assert_eq!(NewsQuery::new().params(), serde_json::json!({}));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by customer id.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::NewsQuery;
    /// assert!(NewsQuery::new().with_customer(4711).is_ok());
    /// assert!(NewsQuery::new().with_customer(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer(mut self, customer: i64) -> Result<Self> {
        self.customer = Some(params::object_id("customerId", customer)?);
        Ok(self)
    }

    /// Restricts the answer to entries the customer has not read.
    ///
    /// ```
    /// use inwx_client::NewsQuery;
    /// assert_eq!(NewsQuery::new().with_unread_only(true).params()["onlyUnread"], true);
    /// ```
    #[must_use]
    pub fn with_unread_only(mut self, unread_only: bool) -> Self {
        self.unread_only = Some(unread_only);
        self
    }

    /// Adds a filter this crate does not model.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `key` is not a parameter name, or when a typed
    /// setter already owns it.
    ///
    /// ```
    /// use inwx_client::NewsQuery;
    /// let query = NewsQuery::new().with_field("type", "PRODUCT")?;
    /// assert_eq!(query.params()["type"], "PRODUCT");
    /// assert!(NewsQuery::new().with_field("customer", 1).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_field(mut self, key: &str, value: impl Into<Value>) -> Result<Self> {
        self.fields.set(key, value.into(), QUERY_KEYS)?;
        Ok(self)
    }

    /// Sets the page (1-based) and the page size.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the limit is `0` or above the crate's own
    /// ceiling of 1000 entries per page.
    ///
    /// ```
    /// use inwx_client::NewsQuery;
    /// assert!(NewsQuery::new().with_page(1, 1).is_ok());
    /// assert!(NewsQuery::new().with_page(1, 1_000).is_ok());
    /// assert!(NewsQuery::new().with_page(1, 1_001).is_err());
    /// assert!(NewsQuery::new().with_page(1, 0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_page(mut self, page: u32, limit: u32) -> Result<Self> {
        let (page, limit) = params::paging(page, limit)?;
        self.page = Some(page);
        self.limit = Some(limit);
        Ok(self)
    }

    /// The `news.list` parameters.
    ///
    /// ```
    /// use inwx_client::NewsQuery;
    /// let params = NewsQuery::new().with_page(2, 5).unwrap().params();
    /// assert_eq!(params["page"], 2);
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut map = Map::new();
        if let Some(customer) = self.customer {
            map.insert("customer".to_owned(), json!(customer));
        }
        if let Some(unread_only) = self.unread_only {
            map.insert("onlyUnread".to_owned(), json!(unread_only));
        }
        if let Some(page) = self.page {
            map.insert("page".to_owned(), json!(page));
        }
        if let Some(limit) = self.limit {
            map.insert("pagelimit".to_owned(), json!(limit));
        }
        self.fields.write_into(&mut map);
        Value::Object(map)
    }
}

impl<T: Transport> InwxClient<T> {
    /// Lists the news entries (`news.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, NewsQuery, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let page = client
    ///     .list_news(&NewsQuery::new().with_unread_only(true).with_page(1, 20)?)
    ///     .await?;
    /// for item in &page.items {
    ///     println!("{:?}", item.title);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors; the query itself validates its
    /// filters.
    pub async fn list_news(&self, query: &NewsQuery) -> Result<NewsListPage> {
        let data = self.call("news.list", query.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_limit_pair_is_one_and_one_thousand() {
        assert!(NewsQuery::new().with_page(1, 1).is_ok());
        assert!(NewsQuery::new().with_page(1, 1_000).is_ok());
        assert!(NewsQuery::new().with_page(1, 1_001).is_err());
        assert!(NewsQuery::new().with_page(1, 0).is_err());
    }

    #[test]
    fn ids_stop_at_zero() {
        assert!(NewsQuery::new().with_customer(1).is_ok());
        assert!(NewsQuery::new().with_customer(0).is_err());
    }

    #[test]
    fn an_unset_filter_is_not_sent() {
        assert!(NewsQuery::new().params().get("onlyUnread").is_none());
        assert_eq!(
            NewsQuery::new().with_unread_only(false).params()["onlyUnread"],
            false
        );
    }

    #[test]
    fn reserved_keys_cannot_be_overridden_by_hand() {
        assert!(NewsQuery::new().with_field("customer", 1).is_err());
        assert!(NewsQuery::new().with_field("type", "X").is_ok());
    }

    #[test]
    fn read_flags_are_read_permissively() {
        for (raw, expected) in [("1", Some(true)), ("0", Some(false)), ("true", Some(true))] {
            let item: NewsItem = serde_json::from_str(&format!(r#"{{"isRead":"{raw}"}}"#)).unwrap();
            assert_eq!(item.is_read(), expected, "{raw}");
        }
        assert_eq!(
            serde_json::from_str::<NewsItem>("{}").unwrap().is_read(),
            None
        );
    }
}
