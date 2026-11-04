//! NIC handles (`nichandle.list`): the contact identities a reseller holds.
//!
//! A handle is the registrant, admin, tech or billing identity behind a domain.
//! The reseller object lists them across the whole customer tree, which is how
//! a reseller finds the handle id to put on a domain. `nichandle.list` is paged:
//! [`InwxClient::list_nichandles`] returns one page, and
//! [`InwxClient::list_all_nichandles`] walks every page with a bound that is
//! validated before the first request.
//!
//! ```
//! use inwx_client::NicHandle;
//!
//! let handle: NicHandle = serde_json::from_str(
//!     r#"{"id":98765,"handle":"ACME-1234","name":"Max Mustermann","email":"max@example.com"}"#,
//! )?;
//! assert_eq!(handle.id, Some(98765));
//! assert_eq!(handle.handle.as_deref(), Some("ACME-1234"));
//! # Ok::<(), serde_json::Error>(())
//! ```

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::pagination::{self, Listing, Page, Pages, Pagination};
use crate::transport::Transport;
use crate::types::{de, validate_id, validate_page_limit, validate_token, validate_upper_token};

/// Longest handle token this crate accepts.
const MAX_HANDLE_LEN: usize = 64;

/// One NIC handle.
///
/// ```
/// use inwx_client::NicHandle;
///
/// let handle: NicHandle = serde_json::from_str(
///     r#"{"id":"98765","handle":"ACME-1","type":"PERSON","cc":"DE","restricted":"0","deleted":0}"#,
/// )?;
/// assert_eq!(handle.id, Some(98765));
/// assert_eq!(handle.handle_type.as_deref(), Some("PERSON"));
/// assert_eq!(handle.is_deleted(), Some(false));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct NicHandle {
    /// Handle id, the number a domain refers to.
    #[serde(
        default,
        rename = "nicId",
        alias = "id",
        deserialize_with = "de::opt_i64"
    )]
    pub id: Option<i64>,
    /// Handle label.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub handle: Option<String>,
    /// Name of the person or organisation.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// Organisation, when the handle is one.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub company: Option<String>,
    /// Contact address.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub email: Option<String>,
    /// Street line.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub street: Option<String>,
    /// City.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub city: Option<String>,
    /// Postal code.
    #[serde(
        default,
        rename = "zip",
        alias = "postalCode",
        deserialize_with = "de::opt_string"
    )]
    pub zip: Option<String>,
    /// Country code.
    #[serde(
        default,
        rename = "cc",
        alias = "country",
        deserialize_with = "de::opt_string"
    )]
    pub country_code: Option<String>,
    /// Phone number.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub phone: Option<String>,
    /// Fax number.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub fax: Option<String>,
    /// Handle class, carried verbatim (`PERSON`, `ORGANISATION`, …).
    #[serde(default, rename = "type", deserialize_with = "de::opt_string")]
    pub handle_type: Option<String>,
    /// Customer the handle belongs to.
    #[serde(
        default,
        rename = "customerNumber",
        alias = "customer_number",
        deserialize_with = "de::opt_i64"
    )]
    pub customer_number: Option<i64>,
    /// Whether the handle is restricted by a registry.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub restricted: Option<bool>,
    /// Whether the handle is soft-deleted.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub deleted: Option<bool>,
}

impl NicHandle {
    /// Whether the handle is deleted; `None` when the API does not say.
    ///
    /// ```
    /// use inwx_client::NicHandle;
    ///
    /// let handle: NicHandle = serde_json::from_str(r#"{"deleted":"1"}"#)?;
    /// assert_eq!(handle.is_deleted(), Some(true));
    /// assert_eq!(NicHandle::default().is_deleted(), None);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_deleted(&self) -> Option<bool> {
        self.deleted
    }
}

/// One page of `nichandle.list`.
///
/// The `nichandle` rows are read the way every other list answer in this crate
/// is read: an array, or a single object where the array belongs (one handle),
/// and a row that does not fit [`NicHandle`] is skipped instead of failing the
/// page. `count` is `None` when the answer does not carry a usable total.
///
/// ```
/// use inwx_client::NicHandleListPage;
///
/// let page: NicHandleListPage = serde_json::from_str(
///     r#"{"count":3,"nichandle":[{"nicId":98765,"handle":"ACME-1234"}]}"#,
/// )?;
/// assert_eq!(page.handles.len(), 1);
/// assert_eq!(page.count, Some(3));
///
/// // A single handle where the array belongs is a page of one, and one row
/// // that does not fit the model costs that row rather than the page.
/// let single: NicHandleListPage =
///     serde_json::from_str(r#"{"count":1,"nichandle":{"nicId":98765}}"#)?;
/// assert_eq!(single.handles.len(), 1);
/// let mixed: NicHandleListPage = serde_json::from_str(
///     r#"{"count":2,"nichandle":[{"nicId":98765},null]}"#,
/// )?;
/// assert_eq!(mixed.handles.len(), 1);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct NicHandleListPage {
    /// Total number of handles matching the query, when the API reports one.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The handles on this page.
    #[serde(default, rename = "nichandle", deserialize_with = "de::rows")]
    pub handles: Vec<NicHandle>,
}

impl NicHandleListPage {
    /// Number of handles on this page.
    ///
    /// ```
    /// use inwx_client::NicHandleListPage;
    ///
    /// let page: NicHandleListPage = serde_json::from_str(r#"{"nichandle":[]}"#)?;
    /// assert_eq!(page.len(), 0);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Whether this page is empty.
    ///
    /// ```
    /// use inwx_client::NicHandleListPage;
    /// assert!(NicHandleListPage::default().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Whether more pages exist according to this answer's `count`.
    ///
    /// When the API omits `count`, this is `false`: the page itself cannot
    /// prove more rows exist. Use [`InwxClient::list_all_nichandles`] when the
    /// caller needs every row rather than one page.
    ///
    /// ```
    /// use inwx_client::NicHandleListPage;
    ///
    /// let page: NicHandleListPage = serde_json::from_str(
    ///     r#"{"count":3,"nichandle":[{"nicId":98765},{"nicId":98766}]}"#,
    /// )?;
    /// assert!(page.has_more());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.count
            .is_some_and(|count| i64::try_from(self.handles.len()).unwrap_or(i64::MAX) < count)
    }
}

/// The page rules [`Pages`] needs to walk `nichandle.list`.
///
/// ```
/// use inwx_client::{NicHandleListPage, Page};
///
/// let page: NicHandleListPage = serde_json::from_str(
///     r#"{"count":4,"nichandle":[{"nicId":98765},{"nicId":98766}]}"#,
/// )?;
/// assert_eq!(page.total(), Some(4));
/// assert_eq!(page.len(), 2);
/// # Ok::<(), serde_json::Error>(())
/// ```
impl Page for NicHandleListPage {
    type Item = NicHandle;

    fn total(&self) -> Option<i64> {
        self.count
    }

    fn len(&self) -> usize {
        self.handles.len()
    }

    fn truncate_to(&mut self, len: usize) {
        self.handles.truncate(len);
    }

    fn into_items(self) -> Vec<NicHandle> {
        self.handles
    }
}

/// A search + paging for `nichandle.list`.
///
/// ```
/// use inwx_client::NicHandleQuery;
///
/// let query = NicHandleQuery::new()
///     .with_handle("ACME-1")?
///     .with_customer_number(123456)?
///     .with_page(1, 20)?;
/// let params = query.params()?;
/// assert_eq!(params["handle"], "ACME-1");
/// assert_eq!(params["pagelimit"], 20);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NicHandleQuery {
    handle: Option<String>,
    name: Option<String>,
    email: Option<String>,
    customer_number: Option<i64>,
    handle_type: Option<String>,
    page: Option<u32>,
    limit: Option<u32>,
}

impl NicHandleQuery {
    /// An unfiltered query.
    ///
    /// ```
    /// use inwx_client::NicHandleQuery;
    /// assert!(NicHandleQuery::new().params().unwrap().is_object());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by handle label.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when the label is empty or too long.
    ///
    /// ```
    /// use inwx_client::NicHandleQuery;
    ///
    /// assert_eq!(NicHandleQuery::new().with_handle(" acme-1 ")?.params()?["handle"], "ACME-1");
    /// assert!(NicHandleQuery::new().with_handle(" ").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_handle(mut self, handle: impl Into<String>) -> Result<Self> {
        let handle = handle.into();
        self.handle = Some(validate_upper_token("nicHandle", &handle, MAX_HANDLE_LEN)?);
        Ok(self)
    }

    /// Filters by name substring.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when the term is empty or longer than 255 characters.
    ///
    /// ```
    /// use inwx_client::NicHandleQuery;
    ///
    /// assert_eq!(NicHandleQuery::new().with_name("Mustermann")?.params()?["name"], "Mustermann");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_name(mut self, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_token("nicHandle.name", &name)?;
        self.name = Some(name.trim().to_owned());
        Ok(self)
    }

    /// Filters by e-mail address.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when the address is empty or longer than 255
    /// characters.
    ///
    /// ```
    /// use inwx_client::NicHandleQuery;
    ///
    /// let query = NicHandleQuery::new().with_email("max@example.com")?;
    /// assert_eq!(query.params()?["email"], "max@example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_email(mut self, email: impl Into<String>) -> Result<Self> {
        let email = email.into();
        validate_token("nicHandle.email", &email)?;
        self.email = Some(email.trim().to_owned());
        Ok(self)
    }

    /// Filters by owning customer.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] for a non-positive customer number.
    ///
    /// ```
    /// use inwx_client::NicHandleQuery;
    ///
    /// assert!(NicHandleQuery::new().with_customer_number(1).is_ok());
    /// assert!(NicHandleQuery::new().with_customer_number(0).is_err());
    /// ```
    pub fn with_customer_number(mut self, customer_number: i64) -> Result<Self> {
        self.customer_number = Some(validate_id("customer.number", customer_number)?);
        Ok(self)
    }

    /// Filters by handle class, upper-cased.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] for an empty or oddly shaped class token.
    ///
    /// ```
    /// use inwx_client::NicHandleQuery;
    ///
    /// assert_eq!(NicHandleQuery::new().with_type("person")?.params()?["type"], "PERSON");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_type(mut self, handle_type: impl Into<String>) -> Result<Self> {
        self.handle_type = Some(validate_upper_token(
            "nicHandle.type",
            &handle_type.into(),
            MAX_HANDLE_LEN,
        )?);
        Ok(self)
    }

    /// Sets the page (1-based) and the page size.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when the page size is zero or above [`crate::MAX_PAGE_SIZE`].
    ///
    /// ```
    /// use inwx_client::NicHandleQuery;
    ///
    /// assert_eq!(NicHandleQuery::new().with_page(1, 1)?.params()?["pagelimit"], 1);
    /// assert!(NicHandleQuery::new().with_page(1, 0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_page(mut self, page: u32, limit: u32) -> Result<Self> {
        self.limit = Some(validate_page_limit(limit)?);
        self.page = Some(page.max(1));
        Ok(self)
    }

    /// The `nichandle.list` parameters.
    ///
    /// # Errors
    ///
    /// Never fails today: every value is validated when it is set, so the
    /// parameters are always sendable. The `Result` keeps the shape of the
    /// builders that can refuse a value.
    ///
    /// ```
    /// use inwx_client::NicHandleQuery;
    /// assert!(NicHandleQuery::new().params().unwrap().is_object());
    /// ```
    pub fn params(&self) -> Result<Value> {
        Ok(self.param_value())
    }

    fn param_value(&self) -> Value {
        let mut params = Map::new();
        if let Some(handle) = &self.handle {
            params.insert("handle".to_owned(), json!(handle));
        }
        if let Some(name) = &self.name {
            params.insert("name".to_owned(), json!(name));
        }
        if let Some(email) = &self.email {
            params.insert("email".to_owned(), json!(email));
        }
        if let Some(customer_number) = self.customer_number {
            params.insert("customerNumber".to_owned(), json!(customer_number));
        }
        if let Some(handle_type) = &self.handle_type {
            params.insert("type".to_owned(), json!(handle_type));
        }
        params.insert("page".to_owned(), json!(self.page.unwrap_or(1)));
        params.insert("pagelimit".to_owned(), json!(self.limit.unwrap_or(50)));
        Value::Object(params)
    }
}

/// The `nichandle.list` command, ready to be walked page by page with
/// [`Pages`].
///
/// The query's own `page`/`pagelimit` are overridden by the walker — a walk
/// owns its cursor.
///
/// ```
/// use inwx_client::{Listing, NicHandleListing, NicHandleQuery};
///
/// let listing = NicHandleListing::new(NicHandleQuery::new().with_handle("ACME-1234")?);
/// assert_eq!(<NicHandleListing as Listing>::METHOD, "nichandle.list");
/// let params = listing.params(2, 25);
/// assert_eq!(params["handle"], "ACME-1234");
/// assert_eq!(params["page"], 2);
/// assert_eq!(params["pagelimit"], 25);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NicHandleListing {
    query: NicHandleQuery,
}

impl NicHandleListing {
    /// The listing for one search.
    ///
    /// ```
    /// use inwx_client::{NicHandleListing, NicHandleQuery};
    ///
    /// let query = NicHandleQuery::new().with_name("Mustermann")?;
    /// assert_eq!(NicHandleListing::new(query.clone()).query(), &query);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn new(query: NicHandleQuery) -> Self {
        Self { query }
    }

    /// The search the walk is using.
    ///
    /// ```
    /// use inwx_client::{NicHandleListing, NicHandleQuery};
    ///
    /// assert_eq!(NicHandleListing::default().query(), &NicHandleQuery::new());
    /// ```
    #[must_use]
    pub fn query(&self) -> &NicHandleQuery {
        &self.query
    }
}

impl Listing for NicHandleListing {
    type Page = NicHandleListPage;

    const METHOD: &'static str = "nichandle.list";

    fn params(&self, page: u32, page_size: u32) -> Value {
        pagination::with_paging(self.query.param_value(), page, page_size)
    }
}

impl<T: Transport> InwxClient<T> {
    /// Lists one page of NIC handles (`nichandle.list`).
    ///
    /// The query defaults to page 1 and a 50-row page cap when it does not
    /// specify paging explicitly. The returned [`NicHandleListPage`] carries the
    /// handles on this page plus, usually, a `count` for the whole query.
    /// Compare `count` with the page length, or call
    /// [`NicHandleListPage::has_more`], to tell whether the query has more rows
    /// than this page returned. For more than one page use
    /// [`InwxClient::list_all_nichandles`], which walks every page until the
    /// reported total is read.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, NicHandleQuery, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let query = NicHandleQuery::new().with_name("Mustermann")?;
    /// for handle in client.list_nichandles(&query).await?.handles {
    ///     println!("{:?} {:?}", handle.id, handle.handle);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors. A malformed filter or page size is
    /// refused when it is set on [`NicHandleQuery`], before this method can use
    /// the query.
    pub async fn list_nichandles(&self, query: &NicHandleQuery) -> Result<NicHandleListPage> {
        let params = query.params()?;
        let data = self.call("nichandle.list", params).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Walks every page of NIC handles (`nichandle.list`).
    ///
    /// [`InwxClient::list_nichandles`] answers one page; this is the cursor for
    /// resellers with more handles than fit into one request. The bound in
    /// `pagination` decides how far the walk goes, and it is checked before the
    /// first request.
    ///
    /// ```
    /// # use inwx_client::{
    /// #     InwxClient, NicHandleQuery, Pagination, Result,
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
    /// # async fn demo() -> Result<Vec<i64>> {
    /// let transport = Scripted(Arc::new(Mutex::new(vec![
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":3,"nichandle":[{"nicId":1},{"nicId":2}]}}"#,
    ///     r#"{"code":1000,"msg":"ok","resData":{"nichandle":[{"nicId":3}]}}"#,
    /// ])));
    /// let client = InwxClient::new(transport).with_session("domrobot=test")?;
    /// let handles = client
    ///     .list_all_nichandles(
    ///         &NicHandleQuery::new().with_name("Mustermann")?,
    ///         &Pagination::new().with_page_size(2)?,
    ///     )
    ///     .collect_all()
    ///     .await?
    ///     .iter()
    ///     .filter_map(|handle| handle.id)
    ///     .collect();
    /// # Ok(handles)
    /// # }
    /// # assert_eq!(
    /// #     tokio::runtime::Runtime::new().unwrap().block_on(demo()).unwrap(),
    /// #     [1, 2, 3]
    /// # );
    /// ```
    ///
    /// # Errors
    ///
    /// The bound is validated when it is built (see
    /// [`Pagination::with_page_size`]); the walk itself reports the usual
    /// transport and API errors.
    pub fn list_all_nichandles(
        &self,
        query: &NicHandleQuery,
        pagination: &Pagination,
    ) -> Pages<'_, T, NicHandleListing> {
        Pages::new(self, NicHandleListing::new(query.clone()), *pagination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_of_64_characters_is_accepted_and_65_is_not() {
        let ok = "H".repeat(64);
        let query = NicHandleQuery::new().with_handle(&ok).unwrap();
        assert_eq!(query.params().unwrap()["handle"], ok.as_str());
        assert!(NicHandleQuery::new().with_handle(format!("{ok}H")).is_err());
    }

    #[test]
    fn a_handle_is_trimmed_and_upper_cased_before_it_is_sent() {
        let query = NicHandleQuery::new().with_handle(" acme-1 ").unwrap();
        assert_eq!(query.params().unwrap()["handle"], "ACME-1");
    }

    #[test]
    fn the_bound_is_measured_after_trimming() {
        let padded = format!("   {}   ", "h".repeat(64));
        let query = NicHandleQuery::new().with_handle(&padded).unwrap();
        assert_eq!(query.params().unwrap()["handle"], "H".repeat(64).as_str());
        assert!(NicHandleQuery::new()
            .with_handle(format!("   {}   ", "h".repeat(65)))
            .is_err());
    }

    #[test]
    fn a_page_limit_of_one_is_accepted_and_zero_is_not() {
        assert!(NicHandleQuery::new().with_page(1, 1).is_ok());
        assert!(NicHandleQuery::new().with_page(1, 0).is_err());
    }

    #[test]
    fn customer_numbers_must_be_positive() {
        assert!(NicHandleQuery::new().with_customer_number(1).is_ok());
        assert!(NicHandleQuery::new().with_customer_number(0).is_err());
    }

    #[test]
    fn handles_are_parsed_permissively() {
        let camel: NicHandle =
            serde_json::from_str(r#"{"nicId":"7","customerNumber":3,"deleted":1}"#).unwrap();
        let snake: NicHandle =
            serde_json::from_str(r#"{"id":7,"customer_number":"3","deleted":"true"}"#).unwrap();
        assert_eq!(camel, snake);
        assert_eq!(camel.is_deleted(), Some(true));
    }
}
