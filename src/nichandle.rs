//! NIC handles (`nichandle.list`): the contact identities a reseller holds.
//!
//! A handle is the registrant, admin, tech or billing identity behind a domain.
//! The reseller object lists them across the whole customer tree, which is how
//! a reseller finds the handle id to put on a domain.
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
use crate::error::Result;
use crate::transport::Transport;
use crate::types::{
    de, parse_rows, validate_id, validate_page_limit, validate_token, validate_upper_token,
};

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
    /// assert_eq!(NicHandleQuery::new().with_handle("ACME-1")?.params()?["handle"], "ACME-1");
    /// assert!(NicHandleQuery::new().with_handle(" ").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_handle(mut self, handle: impl Into<String>) -> Result<Self> {
        let handle = handle.into();
        validate_upper_token("nicHandle", &handle, MAX_HANDLE_LEN)?;
        self.handle = Some(handle);
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
    /// [`crate::Error::Validation`] when the page size is zero.
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
        Ok(Value::Object(params))
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
    /// let query = NicHandleQuery::new().with_name("Mustermann")?;
    /// for handle in client.list_nichandles(&query).await? {
    ///     println!("{:?} {:?}", handle.id, handle.handle);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when the query carries a bad filter or page size,
    /// plus the usual transport and API errors.
    pub async fn list_nichandles(&self, query: &NicHandleQuery) -> Result<Vec<NicHandle>> {
        let params = query.params()?;
        let data = self.call("nichandle.list", params).await?;
        Ok(parse_rows(&data, "nichandle"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_of_64_characters_is_accepted_and_65_is_not() {
        let ok = "H".repeat(64);
        assert!(NicHandleQuery::new().with_handle(&ok).is_ok());
        assert!(NicHandleQuery::new().with_handle(format!("{ok}H")).is_err());
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
