//! Account news (`news.list`): the announcements INWX posts for a reseller.
//!
//! One method, one page of items at a time. The crate does not mark anything
//! read — the API reports a state, it does not change one here.
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
use serde_json::json;

use crate::client::InwxClient;
use crate::error::Result;
use crate::transport::Transport;
use crate::types::{de, parse_rows, validate_page_limit};

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

impl<T: Transport> InwxClient<T> {
    /// Lists news items, newest first (`news.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for item in client.list_news(1, 20).await? {
    ///     println!("{:?} {:?}", item.date, item.title);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when the page size is zero, plus the usual transport
    /// and API errors.
    pub async fn list_news(&self, page: u32, limit: u32) -> Result<Vec<NewsItem>> {
        let limit = validate_page_limit(limit)?;
        let data = self
            .call(
                "news.list",
                json!({ "page": page.max(1), "pagelimit": limit }),
            )
            .await?;
        Ok(parse_rows(&data, "news"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_limit_of_one_is_accepted_and_zero_is_not() {
        assert_eq!(validate_page_limit(1).unwrap(), 1);
        assert!(validate_page_limit(0).is_err());
    }

    #[test]
    fn news_fields_arrive_in_either_spelling() {
        let message: NewsItem = serde_json::from_str(r#"{"id":1,"message":"a"}"#).unwrap();
        let text: NewsItem = serde_json::from_str(r#"{"id":1,"text":"a"}"#).unwrap();
        assert_eq!(message, text);
    }
}
