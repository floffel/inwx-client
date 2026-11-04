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
//! assert_eq!(item.date_raw.as_deref(), Some("2026-03-01 09:00:00"));
//! assert_eq!(item.date.map(|date| date.has_time()), Some(true));
//! assert_eq!(item.title.as_deref(), Some("Maintenance"));
//! # Ok::<(), serde_json::Error>(())
//! ```

use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, validate_page_limit};

/// A date in the two shapes INWX uses for `news.list` entries.
///
/// The API sends either a date (`2026-03-01`) or a local date and time
/// (`2026-03-01 09:00:00`). The value is parsed with `time`, so callers can
/// compare and sort items without hand-writing a parser per spelling. A
/// date-only value is ordered at midnight; [`has_time`](Self::has_time)
/// distinguishes the original shape, and `Display`/serde preserve it.
///
/// ```
/// use inwx_client::NewsDate;
///
/// let day = NewsDate::parse("2026-03-01")?;
/// let at = NewsDate::parse("2026-03-01 09:00:00")?;
///
/// assert!(!day.has_time());
/// assert!(at.has_time());
/// assert!(day < at);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NewsDate {
    at: time::PrimitiveDateTime,
    has_time: bool,
}

impl NewsDate {
    /// Parses a `news.list` date.
    ///
    /// Surrounding whitespace is ignored. The accepted layouts are
    /// `YYYY-MM-DD` and `YYYY-MM-DD HH:MM:SS`; any other shape is rejected.
    ///
    /// ```
    /// use inwx_client::NewsDate;
    ///
    /// assert!(NewsDate::parse("2026-03-01").is_ok());
    /// assert!(NewsDate::parse("2026-03-01 09:00:00").is_ok());
    /// assert!(NewsDate::parse("2026-03-01T09:00:00").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or is neither of the two
    /// documented layouts.
    pub fn parse(input: &str) -> Result<Self> {
        let raw = input.trim();
        if raw.is_empty() {
            return Err(Error::validation("date", "must not be empty"));
        }
        let Some((at, has_time)) = parse_news_date(raw) else {
            return Err(Error::validation(
                "date",
                format!("{raw:?} is not a news date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)"),
            ));
        };
        Ok(Self { at, has_time })
    }

    /// Whether the original value carried a time component.
    ///
    /// ```
    /// use inwx_client::NewsDate;
    ///
    /// assert!(!NewsDate::parse("2026-03-01")?.has_time());
    /// assert!(NewsDate::parse("2026-03-01 09:00:00")?.has_time());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn has_time(&self) -> bool {
        self.has_time
    }
}

impl fmt::Display for NewsDate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        use time::macros::format_description;

        if self.has_time {
            let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
            self.at
                .format(&format)
                .map_err(|_| fmt::Error)
                .and_then(|text| formatter.write_str(&text))
        } else {
            let format = format_description!("[year]-[month]-[day]");
            self.at
                .date()
                .format(&format)
                .map_err(|_| fmt::Error)
                .and_then(|text| formatter.write_str(&text))
        }
    }
}

impl FromStr for NewsDate {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl Serialize for NewsDate {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for NewsDate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// Parses the two `news.list` date layouts.
fn parse_news_date(raw: &str) -> Option<(time::PrimitiveDateTime, bool)> {
    use time::macros::format_description;

    let date = format_description!("[year]-[month]-[day]");
    let date_time = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

    if let Ok(at) = time::PrimitiveDateTime::parse(raw, &date_time) {
        return Some((at, true));
    }

    let date = time::Date::parse(raw, &date).ok()?;
    Some((date.midnight(), false))
}

/// One news item.
///
/// ```
/// use inwx_client::NewsItem;
///
/// let item: NewsItem = serde_json::from_str(
///     r#"{"id":"3","date":"2026-03-01","title":"Maintenance","text":"Apr 1","read":0}"#,
/// )?;
/// assert_eq!(item.id, Some(3));
/// assert_eq!(item.date_raw.as_deref(), Some("2026-03-01"));
/// assert_eq!(item.date.map(|date| date.has_time()), Some(false));
/// assert_eq!(item.body.as_deref(), Some("Apr 1"));
/// assert_eq!(item.is_read(), Some(false));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawNewsItem")]
pub struct NewsItem {
    /// News id.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Date in the two documented `news.list` layouts.
    #[serde(skip)]
    pub date: Option<NewsDate>,
    /// Date exactly as the API sent it.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub date_raw: Option<String>,
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

#[derive(Deserialize)]
struct RawNewsItem {
    #[serde(default, deserialize_with = "de::opt_string")]
    date: Option<String>,
    #[serde(default, deserialize_with = "de::opt_i64")]
    id: Option<i64>,
    #[serde(default, deserialize_with = "de::opt_string")]
    title: Option<String>,
    #[serde(
        default,
        rename = "message",
        alias = "text",
        deserialize_with = "de::opt_string"
    )]
    body: Option<String>,
    #[serde(default, rename = "read", deserialize_with = "de::opt_bool")]
    read: Option<bool>,
}

impl TryFrom<RawNewsItem> for NewsItem {
    type Error = Error;

    fn try_from(raw: RawNewsItem) -> Result<Self> {
        let date = raw.date.as_deref().map(NewsDate::parse).transpose()?;
        Ok(Self {
            id: raw.id,
            date,
            date_raw: raw.date,
            title: raw.title,
            body: raw.body,
            read: raw.read,
        })
    }
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
    ///     println!("{:?} {:?}", item.date_raw, item.title);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when the page size is zero,
    /// [`crate::Error::UnexpectedAnswer`] when the answer carries no `news` list or a
    /// row cannot be decoded, plus the usual transport and API errors.
    pub async fn list_news(&self, page: u32, limit: u32) -> Result<Vec<NewsItem>> {
        let limit = validate_page_limit(limit)?;
        let page = page.max(1);
        let data = self
            .call("news.list", json!({ "page": page, "pagelimit": limit }))
            .await?;
        parse_news_page(&data, page)
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
    fn news_dates_accept_both_documented_layouts() {
        let day = NewsDate::parse("2026-03-01").unwrap();
        assert!(!day.has_time());

        let at = NewsDate::parse("2026-03-01 09:00:00").unwrap();
        assert!(at.has_time());
        assert!(day < at);
        assert_eq!(day.to_string(), "2026-03-01");
        assert_eq!(at.to_string(), "2026-03-01 09:00:00");
        assert_eq!("2026-03-01".parse::<NewsDate>().unwrap(), day);
        assert_eq!(
            serde_json::from_value::<NewsDate>(json!("2026-03-01 09:00:00")).unwrap(),
            at
        );
    }

    #[test]
    fn news_dates_reject_the_t_separated_shape() {
        let error = NewsDate::parse("2026-03-01T09:00:00").unwrap_err();
        assert!(error.is_validation(), "{error:?}");
    }

    #[test]
    fn news_dates_check_the_day_boundaries() {
        for ok in ["2026-01-01", "2026-12-31", "2026-02-28 23:59:59"] {
            assert!(NewsDate::parse(ok).is_ok(), "{ok}");
        }
        for bad in ["2025-02-29", "2026-04-31", "2026-01-01 24:00:00"] {
            assert!(NewsDate::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn news_item_keeps_raw_date_and_decodes_typed_date() {
        let item: NewsItem =
            serde_json::from_str(r#"{"id":3,"date":"2026-03-01 09:00:00","title":"Maintenance"}"#)
                .unwrap();
        assert_eq!(item.date_raw.as_deref(), Some("2026-03-01 09:00:00"));
        assert_eq!(item.date.map(|date| date.has_time()), Some(true));
    }

    #[test]
    fn news_item_refuses_an_unknown_date_shape() {
        let error = serde_json::from_str::<NewsItem>(r#"{"id":3,"date":"2026-03-01T09:00:00"}"#)
            .unwrap_err();
        assert!(error.to_string().contains("news date"), "{error}");
    }

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
