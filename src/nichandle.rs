//! NIC handles (`nichandle.list`): the contact handles a reseller holds for its
//! customers.
//!
//! A NIC handle is the person or organisation registered behind a domain. This
//! object is read-only here — `nichandle.list` — because handle *contents* are
//! written through the `contact.*` object, which this crate already models in
//! [`crate::contact`].
//!
//! The object is described in the API documentation chapter 2 §2.18.
//!
//! ```
//! use inwx_client::NicHandle;
//!
//! let handle: NicHandle = serde_json::from_str(
//!     r#"{"handle":"P1234","id":999,"firstname":"Flo","lastname":"Foffel","country":"de"}"#,
//! )?;
//! assert_eq!(handle.handle.as_deref(), Some("P1234"));
//! assert_eq!(handle.first_name.as_deref(), Some("Flo"));
//! # Ok::<(), serde_json::Error>(())
//! ```

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::params::{self, ExtraFields};
use crate::transport::Transport;
use crate::types::{de, validate_token};

/// Keys owned by [`NicHandleQuery`].
const QUERY_KEYS: &[&str] = &["customer", "handle", "page", "pagelimit"];

/// One NIC handle.
///
/// ```
/// use inwx_client::NicHandle;
///
/// let camel: NicHandle =
///     serde_json::from_str(r#"{"handle":"P1","organization":"Acme","verifyStatus":"1"}"#)?;
/// let snake: NicHandle =
///     serde_json::from_str(r#"{"handle":"P1","org":"Acme","verify_status":true}"#)?;
/// assert_eq!(camel.organization.as_deref(), Some("Acme"));
/// assert_eq!(snake.organization.as_deref(), Some("Acme"));
/// assert_eq!(camel.verify_status.as_deref(), Some("1"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct NicHandle {
    /// Handle id, for example `P1234`.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub handle: Option<String>,
    /// Numeric handle id.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// First name.
    #[serde(
        default,
        rename = "firstname",
        alias = "first_name",
        deserialize_with = "de::opt_string"
    )]
    pub first_name: Option<String>,
    /// Last name.
    #[serde(
        default,
        rename = "lastname",
        alias = "last_name",
        deserialize_with = "de::opt_string"
    )]
    pub last_name: Option<String>,
    /// Organisation.
    #[serde(
        default,
        rename = "organization",
        alias = "organisation",
        alias = "org",
        deserialize_with = "de::opt_string"
    )]
    pub organization: Option<String>,
    /// Street.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub street: Option<String>,
    /// Postal code.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub zip: Option<String>,
    /// City.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub city: Option<String>,
    /// Country code.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub country: Option<String>,
    /// E-mail address.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub email: Option<String>,
    /// Phone number.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub phone: Option<String>,
    /// Verification state of the handle, as text.
    #[serde(
        default,
        rename = "verifyStatus",
        alias = "verify_status",
        deserialize_with = "de::opt_string"
    )]
    pub verify_status: Option<String>,
    /// State of the handle record.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub state: Option<String>,
    /// Fields this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// One page of `nichandle.list`.
///
/// ```
/// use inwx_client::NicHandleListPage;
///
/// let page: NicHandleListPage = serde_json::from_str(r#"{"count":1,"handle":[{"id":1}]}"#)?;
/// assert_eq!(page.count, Some(1));
/// assert_eq!(page.len(), 1);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct NicHandleListPage {
    /// Total number of handles, not just this page.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The handles on this page.
    #[serde(
        default,
        rename = "nichandle",
        alias = "handle",
        alias = "handles",
        alias = "nichandles"
    )]
    pub handles: Vec<NicHandle>,
}

impl NicHandleListPage {
    /// Number of handles on this page.
    ///
    /// ```
    /// use inwx_client::NicHandleListPage;
    /// let page: NicHandleListPage = serde_json::from_str(r#"{"handle":[{"id":1}]}"#)?;
    /// assert_eq!(page.len(), 1);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Whether this page carries no handle at all.
    ///
    /// ```
    /// use inwx_client::NicHandleListPage;
    /// assert!(NicHandleListPage::default().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }
}

/// The filter behind `nichandle.list`.
///
/// ```
/// use inwx_client::NicHandleQuery;
///
/// let query = NicHandleQuery::new().with_handle("P1234")?.with_page(1, 50)?;
/// let params = query.params();
/// assert_eq!(params["handle"], "P1234");
/// assert_eq!(params["pagelimit"], 50);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NicHandleQuery {
    customer: Option<i64>,
    handle: Option<String>,
    page: Option<u32>,
    limit: Option<u32>,
    fields: ExtraFields,
}

impl NicHandleQuery {
    /// All handles of the reseller account.
    ///
    /// ```
    /// use inwx_client::NicHandleQuery;
    /// assert_eq!(NicHandleQuery::new().params(), serde_json::json!({}));
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
    /// use inwx_client::NicHandleQuery;
    /// assert!(NicHandleQuery::new().with_customer(4711).is_ok());
    /// assert!(NicHandleQuery::new().with_customer(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer(mut self, customer: i64) -> Result<Self> {
        self.customer = Some(params::object_id("customerId", customer)?);
        Ok(self)
    }

    /// Filters by handle id.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::NicHandleQuery;
    /// assert!(NicHandleQuery::new().with_handle("P1234").is_ok());
    /// assert!(NicHandleQuery::new().with_handle(" ").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_handle(mut self, handle: &str) -> Result<Self> {
        validate_token("nichandle.handle", handle)?;
        self.handle = Some(handle.trim().to_owned());
        Ok(self)
    }

    /// Adds a filter this crate does not model.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `key` is not a parameter name, or when a typed
    /// setter already owns it.
    ///
    /// ```
    /// use inwx_client::NicHandleQuery;
    /// let query = NicHandleQuery::new().with_field("state", "VERIFIED")?;
    /// assert_eq!(query.params()["state"], "VERIFIED");
    /// assert!(NicHandleQuery::new().with_field("handle", "P1").is_err());
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
    /// use inwx_client::NicHandleQuery;
    /// assert!(NicHandleQuery::new().with_page(1, 1).is_ok());
    /// assert!(NicHandleQuery::new().with_page(1, 1_000).is_ok());
    /// assert!(NicHandleQuery::new().with_page(1, 1_001).is_err());
    /// assert!(NicHandleQuery::new().with_page(1, 0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_page(mut self, page: u32, limit: u32) -> Result<Self> {
        let (page, limit) = params::paging(page, limit)?;
        self.page = Some(page);
        self.limit = Some(limit);
        Ok(self)
    }

    /// The `nichandle.list` parameters.
    ///
    /// ```
    /// use inwx_client::NicHandleQuery;
    /// let params = NicHandleQuery::new().with_page(2, 5).unwrap().params();
    /// assert_eq!(params["page"], 2);
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut map = Map::new();
        if let Some(customer) = self.customer {
            map.insert("customer".to_owned(), json!(customer));
        }
        if let Some(handle) = &self.handle {
            map.insert("handle".to_owned(), json!(handle));
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
    /// Lists NIC handles (`nichandle.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, NicHandleQuery, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let page = client
    ///     .list_nic_handles(&NicHandleQuery::new().with_page(1, 50)?)
    ///     .await?;
    /// for handle in &page.handles {
    ///         println!("{:?} {:?}", handle.handle, handle.organization);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors; the query itself validates its
    /// filters.
    pub async fn list_nic_handles(&self, query: &NicHandleQuery) -> Result<NicHandleListPage> {
        let data = self.call("nichandle.list", query.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_limit_pair_is_one_and_one_thousand() {
        assert!(NicHandleQuery::new().with_page(1, 1).is_ok());
        assert!(NicHandleQuery::new().with_page(1, 1_000).is_ok());
        assert!(NicHandleQuery::new().with_page(1, 1_001).is_err());
        assert!(NicHandleQuery::new().with_page(1, 0).is_err());
    }

    #[test]
    fn ids_stop_at_zero() {
        assert!(NicHandleQuery::new().with_customer(1).is_ok());
        assert!(NicHandleQuery::new().with_customer(0).is_err());
    }

    #[test]
    fn handles_stop_at_255_characters() {
        assert!(NicHandleQuery::new().with_handle(&"P".repeat(255)).is_ok());
        assert!(NicHandleQuery::new().with_handle(&"P".repeat(256)).is_err());
    }

    #[test]
    fn reserved_keys_cannot_be_overridden_by_hand() {
        assert!(NicHandleQuery::new().with_field("handle", "P1").is_err());
        assert!(NicHandleQuery::new().with_field("state", "X").is_ok());
    }

    #[test]
    fn names_are_read_under_every_spelling() {
        for raw in [r#"{"firstname":"Flo"}"#, r#"{"first_name":"Flo"}"#] {
            let handle: NicHandle = serde_json::from_str(raw).unwrap();
            assert_eq!(handle.first_name.as_deref(), Some("Flo"), "{raw}");
        }
        for raw in [
            r#"{"organization":"Acme"}"#,
            r#"{"org":"Acme"}"#,
            r#"{"organisation":"Acme"}"#,
        ] {
            let handle: NicHandle = serde_json::from_str(raw).unwrap();
            assert_eq!(handle.organization.as_deref(), Some("Acme"), "{raw}");
        }
    }

    #[test]
    fn verify_status_keeps_what_the_api_sent() {
        let text: NicHandle = serde_json::from_str(r#"{"verifyStatus":"VERIFIED"}"#).unwrap();
        assert_eq!(text.verify_status.as_deref(), Some("VERIFIED"));
        let number: NicHandle = serde_json::from_str(r#"{"verify_status":"1"}"#).unwrap();
        assert_eq!(number.verify_status.as_deref(), Some("1"));
        let absent = NicHandle::default();
        assert_eq!(absent.verify_status, None);
    }

    #[test]
    fn the_list_accepts_every_documented_container_key() {
        for raw in [
            r#"{"nichandle":[{"id":1}]}"#,
            r#"{"handle":[{"id":1}]}"#,
            r#"{"handles":[{"id":1}]}"#,
        ] {
            let page: NicHandleListPage = serde_json::from_str(raw).unwrap();
            assert_eq!(page.len(), 1, "{raw}");
        }
    }
}
