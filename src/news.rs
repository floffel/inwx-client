//! Account news (`news.list`): the announcements INWX posts for a reseller.
//!
//! One method, one page of items at a time. The crate does not mark anything
//! read — the API reports a state, it does not change one here. Paging is set
//! with [`NewsQuery`], so the page number and page size travel as named values
//! instead of two adjacent `u32`s.
//!
//! ```
//! use inwx_client::NewsItem;
//!
//! let item: NewsItem = serde_json::from_str(
//!     r#"{"id":3,"date":"2026-03-01 09:00:00","title":"Maintenance","message":"Apr 1, 02:00 UTC"}"#,
//! )?;
//! assert_eq!(item.id, Some(3));
//! assert_eq!(item.title.as_deref(), Some("Maintenance"));
//! # Ok::<(), serde_json::Error>(())
//! ```

use serde::Deserialize;
use serde_json::{json, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, validate_page_limit};

/// One news item.
///
/// ```
/// use inwx_client::NewsItem;
///
/// let item: NewsItem = serde_json::from_str(
///     r#"{"id":"3","date":"2026-03-01","title":"Maintenance","text":"Apr 1","read":0}"#,
/// )?;
/// assert_eq!(item.id, Some(3));
/// assert_eq!(item.body.as_deref(), Some("Apr 1"));
/// assert_eq!(item.is_read(), Some(false));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct NewsItem {
    /// News id.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Date, as text.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub date: Option<String>,
    /// Subject line.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub title: Option<String>,
    /// Body text.
    #[serde(
        default,
        rename = "message",
        alias = "text",
        deserialize_with = "de::opt_string"
    )]
    pub body: Option<String>,
    /// Whether the account has read it.
    #[serde(default, rename = "read", deserialize_with = "de::opt_bool")]
    pub read: Option<bool>,
}

impl NewsItem {
    /// Whether the item is marked read; `None` when the API does not say.
    ///
    /// ```
    /// use inwx_client::NewsItem;
    ///
    /// let read: NewsItem = serde_json::from_str(r#"{"read":"1"}"#)?;
    /// assert_eq!(read.is_read(), Some(true));
    /// assert_eq!(NewsItem::default().is_read(), None);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_read(&self) -> Option<bool> {
        self.read
    }
}

/// A `news.list` query.
///
/// The page is 1-based and the page size is at least one. Both are set with
/// their own named method, so a page number and a page size cannot be swapped
/// by writing the arguments in the wrong order.
///
/// ```
/// use inwx_client::NewsQuery;
///
/// let query = NewsQuery::new().with_page(2)?.with_limit(50)?;
/// let params = query.params();
/// assert_eq!(params["page"], 2);
/// assert_eq!(params["pagelimit"], 50);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewsQuery {
    page: u32,
    limit: u32,
}

impl Default for NewsQuery {
    fn default() -> Self {
        Self { page: 1, limit: 50 }
    }
}

impl NewsQuery {
    /// A query for the first page, 50 items per request.
    ///
    /// ```
    /// use inwx_client::NewsQuery;
    ///
    /// let params = NewsQuery::new().params();
    /// assert_eq!(params["page"], 1);
    /// assert_eq!(params["pagelimit"], 50);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the 1-based page number.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when `page` is `0`; INWX pages start at
    /// `1`, so `0` is refused rather than silently rewritten.
    ///
    /// ```
    /// use inwx_client::NewsQuery;
    ///
    /// assert_eq!(NewsQuery::new().with_page(2)?.params()["page"], 2);
    /// assert!(NewsQuery::new().with_page(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_page(mut self, page: u32) -> Result<Self> {
        if page == 0 {
            return Err(Error::validation(
                "page",
                "must be at least 1 (pages start at 1)",
            ));
        }
        self.page = page;
        Ok(self)
    }

    /// Sets the page size.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when `limit` is `0`.
    ///
    /// ```
    /// use inwx_client::NewsQuery;
    ///
    /// assert_eq!(NewsQuery::new().with_limit(20)?.params()["pagelimit"], 20);
    /// assert!(NewsQuery::new().with_limit(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_limit(mut self, limit: u32) -> Result<Self> {
        self.limit = validate_page_limit(limit)?;
        Ok(self)
    }

    /// The `news.list` parameters.
    ///
    /// ```
    /// use inwx_client::NewsQuery;
    ///
    /// let params = NewsQuery::new().with_page(3)?.with_limit(10)?.params();
    /// assert_eq!(params["page"], 3);
    /// assert_eq!(params["pagelimit"], 10);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        json!({ "page": self.page, "pagelimit": self.limit })
    }
}

impl<T: Transport> InwxClient<T> {
    /// Lists news items, newest first (`news.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, NewsQuery, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let query = NewsQuery::new().with_limit(20)?;
    /// for item in client.list_news(&query).await? {
    ///     println!("{:?} {:?}", item.date, item.title);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::UnexpectedAnswer`] when the answer carries no `news` list or a
    /// row cannot be decoded, plus the usual transport and API errors.
    pub async fn list_news(&self, query: &NewsQuery) -> Result<Vec<NewsItem>> {
        let data = self.call("news.list", query.params()).await?;
        parse_news_page(&data, query.page)
    }
}

/// Decodes one `news.list` page, failing closed on anything the caller must not
/// confuse with an empty page.
fn parse_news_page(data: &Value, page: u32) -> Result<Vec<NewsItem>> {
    let Some(value) = data.get("news") else {
        return Err(Error::unexpected_answer(
            "news.list",
            "news",
            "expected an array of news items",
        ));
    };

    let rows = match value {
        Value::Array(rows) => rows.as_slice(),
        single @ Value::Object(_) => std::slice::from_ref(single),
        _ => {
            return Err(Error::unexpected_answer(
                "news.list",
                "news",
                "expected an array of news items",
            ));
        }
    };

    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            serde_json::from_value(row.clone()).map_err(|error| {
                Error::unexpected_answer(
                    "news.list",
                    "news",
                    format!("page {page}, entry {index} does not parse: {error}"),
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_news_query_accepts_the_bounds_and_refuses_just_outside() {
        // Valid, just inside and just outside both bounds.
        let query = NewsQuery::new()
            .with_page(2)
            .unwrap()
            .with_limit(1)
            .unwrap();
        assert_eq!(query.params()["page"], 2);
        assert_eq!(query.params()["pagelimit"], 1);
        assert!(NewsQuery::new().with_page(u32::MAX).is_ok());
        assert!(NewsQuery::new().with_limit(u32::MAX).is_ok());
        // Page 0 is refused, not rewritten to 1.
        assert!(NewsQuery::new().with_page(0).is_err());
        assert!(NewsQuery::new().with_limit(0).is_err());
        // The defaults are the first page and the documented page size.
        assert_eq!(NewsQuery::default().params()["page"], 1);
        assert_eq!(NewsQuery::default().params()["pagelimit"], 50);
    }

    #[test]
    fn news_fields_arrive_in_either_spelling() {
        let message: NewsItem = serde_json::from_str(r#"{"id":1,"message":"a"}"#).unwrap();
        let text: NewsItem = serde_json::from_str(r#"{"id":1,"text":"a"}"#).unwrap();
        assert_eq!(message, text);
    }

    #[test]
    fn a_news_row_that_does_not_parse_is_reported_with_page_and_index() {
        let error = parse_news_page(
            &json!({
                "news": [
                    { "id": 1, "title": "Maintenance" },
                    { "id": 2, "message": "short", "text": "long" }
                ]
            }),
            3,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            Error::UnexpectedAnswer {
                method: "news.list",
                field: "news",
                ..
            }
        ));
        let message = error.to_string();
        assert!(message.contains("page 3"), "{message}");
        assert!(message.contains("entry 1"), "{message}");
    }

    #[test]
    fn an_absent_or_non_list_news_value_is_reported_instead_of_empty() {
        for data in [json!({ "count": 0 }), json!({ "news": null })] {
            let error = parse_news_page(&data, 1).unwrap_err();
            assert!(matches!(
                error,
                Error::UnexpectedAnswer {
                    method: "news.list",
                    field: "news",
                    ..
                }
            ));
        }
    }

    #[test]
    fn an_empty_news_array_is_an_empty_page() {
        assert_eq!(
            parse_news_page(&json!({ "news": [] }), 1).unwrap(),
            Vec::<NewsItem>::new()
        );
    }
}
