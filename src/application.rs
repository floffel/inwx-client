//! Applications (`application.*`): the reseller/partner object for a pending
//! product application.
//!
//! A reseller opens an application for a customer (a product order, a
//! name change, a contract change), watches its state and withdraws it while it
//! is still open. Six methods: `check`, `create`, `delete`, `info`, `list`,
//! `update`.
//!
//! The object is described in the API documentation chapter 2 §2.3. The
//! product-specific fields of an application are not enumerated here one by one:
//! [`ApplicationCreate::with_field`] and [`ApplicationUpdate::with_field`] carry
//! them, validated as parameter names, so a field this crate does not model is
//! still reachable without falling back to a hand-written payload.
//!
//! ```
//! use inwx_client::Application;
//!
//! let application: Application = serde_json::from_str(
//!     r#"{"id":12,"type":"HOSTING","customer":4711,"state":"PENDING","comment":"upgrade"}"#,
//! )?;
//! assert_eq!(application.id, Some(12));
//! assert_eq!(application.state.as_deref(), Some("PENDING"));
//! # Ok::<(), serde_json::Error>(())
//! ```

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::params::{self, ExtraFields};
use crate::transport::Transport;
use crate::types::{de, validate_token, CheckOutcome};

/// Keys the builders own; [`ApplicationCreate::with_field`] refuses them.
const CREATE_KEYS: &[&str] = &["type", "name", "customer", "comment", "testing"];
/// Keys owned by [`ApplicationCheck`].
const CHECK_KEYS: &[&str] = &["type", "name", "customer"];
/// Keys owned by [`ApplicationUpdate`].
const UPDATE_KEYS: &[&str] = &[
    "applicationId",
    "type",
    "name",
    "customer",
    "state",
    "comment",
];

/// One application, from `application.info`, `list`, `create` or `update`.
///
/// Every field is optional and unknown fields are kept in [`Application::rest`]:
/// the payload depends on the application type, and "not reported" stays
/// distinguishable from "empty".
///
/// ```
/// use inwx_client::Application;
///
/// let from_camel: Application =
///     serde_json::from_str(r#"{"id":"12","customerNo":"110069","createdAt":"2026-10-01"}"#)?;
/// assert_eq!(from_camel.id, Some(12));
/// assert_eq!(from_camel.customer_no.as_deref(), Some("110069"));
///
/// let from_snake: Application =
///     serde_json::from_str(r#"{"id":12,"customer_no":"110069","created_at":"2026-10-01"}"#)?;
/// assert_eq!(from_snake, from_camel);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Application {
    /// Application id, used by `info`, `update` and `delete`.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Application type, for example `HOSTING`.
    #[serde(default, rename = "type", deserialize_with = "de::opt_string")]
    pub object_type: Option<String>,
    /// Application class, when the product uses one.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub class: Option<String>,
    /// Customer the application belongs to.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub customer: Option<i64>,
    /// Customer number of that customer.
    #[serde(
        default,
        rename = "customerNo",
        alias = "customer_no",
        deserialize_with = "de::opt_string"
    )]
    pub customer_no: Option<String>,
    /// Object the application is about, for example a domain or host name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// State of the application (`PENDING`, `DONE`, …).
    #[serde(default, deserialize_with = "de::opt_string")]
    pub state: Option<String>,
    /// Free-text note.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub comment: Option<String>,
    /// Creation timestamp.
    #[serde(
        default,
        rename = "createdAt",
        alias = "created_at",
        deserialize_with = "de::opt_string"
    )]
    pub created_at: Option<String>,
    /// Last-change timestamp.
    #[serde(
        default,
        rename = "updatedAt",
        alias = "updated_at",
        deserialize_with = "de::opt_string"
    )]
    pub updated_at: Option<String>,
    /// Fields this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// One page of `application.list`.
///
/// ```
/// use inwx_client::ApplicationListPage;
///
/// let page: ApplicationListPage = serde_json::from_str(
///     r#"{"count":2,"application":[{"id":1},{"id":2}]}"#,
/// )?;
/// assert_eq!(page.count, Some(2));
/// assert_eq!(page.len(), 2);
/// assert!(!page.is_empty());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct ApplicationListPage {
    /// Total number of applications, not just this page.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The applications on this page.
    #[serde(default, rename = "application", alias = "applications")]
    pub applications: Vec<Application>,
}

impl ApplicationListPage {
    /// Number of applications on this page.
    ///
    /// ```
    /// use inwx_client::ApplicationListPage;
    /// let page: ApplicationListPage = serde_json::from_str(r#"{"application":[{"id":1}]}"#)?;
    /// assert_eq!(page.len(), 1);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.applications.len()
    }

    /// Whether this page carries no application at all.
    ///
    /// ```
    /// use inwx_client::ApplicationListPage;
    /// assert!(ApplicationListPage::default().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.applications.is_empty()
    }
}

/// The question behind `application.check`.
///
/// A check costs nothing and answers whether an application could be opened for
/// the given object. Nothing is required — the API decides which combination is
/// meaningful for which product — but an empty check is refused, because the
/// API would only answer `2003`.
///
/// ```
/// use inwx_client::ApplicationCheck;
///
/// let check = ApplicationCheck::new()?.with_type("HOSTING")?.with_name("shop.example.com")?;
/// assert_eq!(check.params()?["type"], "HOSTING");
/// assert!(ApplicationCheck::new().unwrap().params().is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApplicationCheck {
    object_type: Option<String>,
    name: Option<String>,
    customer: Option<i64>,
    fields: ExtraFields,
}

impl ApplicationCheck {
    /// An empty check; add at least one criterion.
    ///
    /// # Errors
    ///
    /// Never today; the signature leaves room for the checks the API enforces
    /// on an empty request.
    ///
    /// ```
    /// use inwx_client::ApplicationCheck;
    /// assert!(ApplicationCheck::new().is_ok());
    /// ```
    pub fn new() -> Result<Self> {
        Ok(Self::default())
    }

    /// Sets the application type.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::ApplicationCheck;
    /// assert_eq!(
    ///     ApplicationCheck::new()?.with_type("HOSTING")?.params()?["type"],
    ///     "HOSTING"
    /// );
    /// assert!(ApplicationCheck::new()?.with_type("  ").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_type(mut self, object_type: &str) -> Result<Self> {
        validate_token("application.type", object_type)?;
        self.object_type = Some(object_type.trim().to_owned());
        Ok(self)
    }

    /// Sets the object the application is about.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::ApplicationCheck;
    /// assert_eq!(
    ///     ApplicationCheck::new()?.with_name("shop.example.com")?.params()?["name"],
    ///     "shop.example.com"
    /// );
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_name(mut self, name: &str) -> Result<Self> {
        validate_token("application.name", name)?;
        self.name = Some(name.trim().to_owned());
        Ok(self)
    }

    /// Sets the customer the application would belong to.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::ApplicationCheck;
    /// assert!(ApplicationCheck::new()?.with_customer(4711).is_ok());
    /// assert!(ApplicationCheck::new()?.with_customer(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer(mut self, customer: i64) -> Result<Self> {
        self.customer = Some(params::object_id("customerId", customer)?);
        Ok(self)
    }

    /// Adds a criterion this crate does not model.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `key` is not a parameter name, or when a typed
    /// setter already owns it.
    ///
    /// ```
    /// use inwx_client::ApplicationCheck;
    /// let check = ApplicationCheck::new()?.with_type("HOSTING")?.with_field("period", 12)?;
    /// assert_eq!(check.params()?["period"], 12);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_field(mut self, key: &str, value: impl Into<Value>) -> Result<Self> {
        self.fields.set(key, value.into(), CHECK_KEYS)?;
        Ok(self)
    }

    /// The `application.check` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when no criterion was set.
    ///
    /// ```
    /// use inwx_client::ApplicationCheck;
    /// let params = ApplicationCheck::new()?.with_type("HOSTING")?.params()?;
    /// assert_eq!(params, serde_json::json!({"type": "HOSTING"}));
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut map = Map::new();
        if let Some(object_type) = &self.object_type {
            map.insert("type".to_owned(), json!(object_type));
        }
        if let Some(name) = &self.name {
            map.insert("name".to_owned(), json!(name));
        }
        if let Some(customer) = self.customer {
            map.insert("customer".to_owned(), json!(customer));
        }
        self.fields.write_into(&mut map);
        params::require_payload("application.check.params", map.len())?;
        Ok(Value::Object(map))
    }
}

/// The order behind `application.create`.
///
/// ```
/// use inwx_client::ApplicationCreate;
///
/// let create = ApplicationCreate::new()?
///     .with_type("HOSTING")?
///     .with_customer(4711)?
///     .dry_run();
/// let params = create.params()?;
/// assert_eq!(params["type"], "HOSTING");
/// assert_eq!(params["testing"], true);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApplicationCreate {
    object_type: Option<String>,
    name: Option<String>,
    customer: Option<i64>,
    comment: Option<String>,
    testing: bool,
    fields: ExtraFields,
}

impl ApplicationCreate {
    /// An empty application; add the type, the object or the customer.
    ///
    /// # Errors
    ///
    /// Never today; the signature leaves room for the checks the API enforces
    /// on an empty order.
    ///
    /// ```
    /// use inwx_client::ApplicationCreate;
    /// assert!(ApplicationCreate::new().is_ok());
    /// ```
    pub fn new() -> Result<Self> {
        Ok(Self::default())
    }

    /// Sets the application type.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::ApplicationCreate;
    /// assert_eq!(
    ///     ApplicationCreate::new()?.with_type("HOSTING")?.params()?["type"],
    ///     "HOSTING"
    /// );
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_type(mut self, object_type: &str) -> Result<Self> {
        validate_token("application.type", object_type)?;
        self.object_type = Some(object_type.trim().to_owned());
        Ok(self)
    }

    /// Sets the object the application is about.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::ApplicationCreate;
    /// assert!(ApplicationCreate::new()?.with_name("shop.example.com").is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_name(mut self, name: &str) -> Result<Self> {
        validate_token("application.name", name)?;
        self.name = Some(name.trim().to_owned());
        Ok(self)
    }

    /// Sets the customer the application belongs to.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::ApplicationCreate;
    /// assert!(ApplicationCreate::new()?.with_customer(-3).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer(mut self, customer: i64) -> Result<Self> {
        self.customer = Some(params::object_id("customerId", customer)?);
        Ok(self)
    }

    /// Adds a free-text note (`comment`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty note or one longer than 255
    /// characters.
    ///
    /// ```
    /// use inwx_client::ApplicationCreate;
    /// let create = ApplicationCreate::new()?.with_comment("upgrade to M")?;
    /// assert_eq!(create.params()?["comment"], "upgrade to M");
    /// assert!(ApplicationCreate::new()?.with_comment(&"x".repeat(256)).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_comment(mut self, comment: &str) -> Result<Self> {
        validate_token("application.comment", comment)?;
        self.comment = Some(comment.trim().to_owned());
        Ok(self)
    }

    /// Adds a parameter this crate does not model.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `key` is not a parameter name, or when a typed
    /// setter already owns it.
    ///
    /// ```
    /// use inwx_client::ApplicationCreate;
    ///
    /// let create = ApplicationCreate::new()?
    ///     .with_type("HOSTING")?
    ///     .with_field("period", 12)?;
    /// assert_eq!(create.params()?["period"], 12);
    /// assert!(ApplicationCreate::new()?.with_type("X")?.with_field("type", "Y").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_field(mut self, key: &str, value: impl Into<Value>) -> Result<Self> {
        self.fields.set(key, value.into(), CREATE_KEYS)?;
        Ok(self)
    }

    /// Runs the create in testing mode (`testing=true`), which does not book
    /// anything.
    ///
    /// ```
    /// use inwx_client::ApplicationCreate;
    /// let create = ApplicationCreate::new()?.with_type("HOSTING")?.dry_run();
    /// assert_eq!(create.params()?["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.testing = true;
        self
    }

    /// The `application.create` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when nothing but `testing` was set.
    ///
    /// ```
    /// use inwx_client::ApplicationCreate;
    /// assert!(ApplicationCreate::new()?.dry_run().params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut map = Map::new();
        if let Some(object_type) = &self.object_type {
            map.insert("type".to_owned(), json!(object_type));
        }
        if let Some(name) = &self.name {
            map.insert("name".to_owned(), json!(name));
        }
        if let Some(customer) = self.customer {
            map.insert("customer".to_owned(), json!(customer));
        }
        if let Some(comment) = &self.comment {
            map.insert("comment".to_owned(), json!(comment));
        }
        self.fields.write_into(&mut map);
        params::require_payload("application.create.params", map.len())?;
        if self.testing {
            map.insert("testing".to_owned(), json!(true));
        }
        Ok(Value::Object(map))
    }
}

/// A change to an open application (`application.update`).
///
/// An update with no field would be rejected by the API, so
/// [`ApplicationUpdate::params`] refuses it locally.
///
/// ```
/// use inwx_client::ApplicationUpdate;
///
/// let update = ApplicationUpdate::new(12)?.with_state("DONE")?;
/// assert_eq!(update.params()?["applicationId"], 12);
/// assert_eq!(update.params()?["state"], "DONE");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ApplicationUpdate {
    application_id: i64,
    object_type: Option<String>,
    name: Option<String>,
    customer: Option<i64>,
    state: Option<String>,
    comment: Option<String>,
    fields: ExtraFields,
}

impl ApplicationUpdate {
    /// Targets one application.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::ApplicationUpdate;
    /// assert!(ApplicationUpdate::new(12).is_ok());
    /// assert!(ApplicationUpdate::new(0).is_err());
    /// ```
    pub fn new(application_id: i64) -> Result<Self> {
        Ok(Self {
            application_id: params::object_id("applicationId", application_id)?,
            object_type: None,
            name: None,
            customer: None,
            state: None,
            comment: None,
            fields: ExtraFields::default(),
        })
    }

    /// Changes the application type.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::ApplicationUpdate;
    /// assert_eq!(
    ///     ApplicationUpdate::new(12)?.with_type("HOSTING")?.params()?["type"],
    ///     "HOSTING"
    /// );
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_type(mut self, object_type: &str) -> Result<Self> {
        validate_token("application.type", object_type)?;
        self.object_type = Some(object_type.trim().to_owned());
        Ok(self)
    }

    /// Changes the object the application is about.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::ApplicationUpdate;
    /// assert!(ApplicationUpdate::new(12)?.with_name("shop.example.com").is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_name(mut self, name: &str) -> Result<Self> {
        validate_token("application.name", name)?;
        self.name = Some(name.trim().to_owned());
        Ok(self)
    }

    /// Moves the application to another customer.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::ApplicationUpdate;
    /// assert!(ApplicationUpdate::new(12)?.with_customer(1).is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer(mut self, customer: i64) -> Result<Self> {
        self.customer = Some(params::object_id("customerId", customer)?);
        Ok(self)
    }

    /// Moves the application to another state.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::ApplicationUpdate;
    /// assert_eq!(
    ///     ApplicationUpdate::new(12)?.with_state("CANCELLED")?.params()?["state"],
    ///     "CANCELLED"
    /// );
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_state(mut self, state: &str) -> Result<Self> {
        validate_token("application.state", state)?;
        self.state = Some(state.trim().to_owned());
        Ok(self)
    }

    /// Changes the free-text note.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty note or one longer than 255
    /// characters.
    ///
    /// ```
    /// use inwx_client::ApplicationUpdate;
    /// let update = ApplicationUpdate::new(12)?.with_comment("second attempt")?;
    /// assert_eq!(update.params()?["comment"], "second attempt");
    /// assert!(ApplicationUpdate::new(12)?.with_comment(&"x".repeat(256)).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_comment(mut self, comment: &str) -> Result<Self> {
        validate_token("application.comment", comment)?;
        self.comment = Some(comment.trim().to_owned());
        Ok(self)
    }

    /// Changes a parameter this crate does not model.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `key` is not a parameter name, or when a typed
    /// setter already owns it.
    ///
    /// ```
    /// use inwx_client::ApplicationUpdate;
    /// let update = ApplicationUpdate::new(12)?.with_field("reason", "customer asked")?;
    /// assert_eq!(update.params()?["reason"], "customer asked");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_field(mut self, key: &str, value: impl Into<Value>) -> Result<Self> {
        self.fields.set(key, value.into(), UPDATE_KEYS)?;
        Ok(self)
    }

    /// The `application.update` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when no field was changed.
    ///
    /// ```
    /// use inwx_client::ApplicationUpdate;
    /// assert!(ApplicationUpdate::new(12)?.params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut map = Map::new();
        map.insert("applicationId".to_owned(), json!(self.application_id));
        if let Some(object_type) = &self.object_type {
            map.insert("type".to_owned(), json!(object_type));
        }
        if let Some(name) = &self.name {
            map.insert("name".to_owned(), json!(name));
        }
        if let Some(customer) = self.customer {
            map.insert("customer".to_owned(), json!(customer));
        }
        if let Some(state) = &self.state {
            map.insert("state".to_owned(), json!(state));
        }
        if let Some(comment) = &self.comment {
            map.insert("comment".to_owned(), json!(comment));
        }
        self.fields.write_into(&mut map);
        params::require_payload("application.update.params", map.len() - 1)?;
        Ok(Value::Object(map))
    }
}

/// The filter behind `application.list`.
///
/// ```
/// use inwx_client::ApplicationListQuery;
///
/// let query = ApplicationListQuery::new().with_page(2, 50)?;
/// assert_eq!(query.params()["page"], 2);
/// assert_eq!(query.params()["pagelimit"], 50);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplicationListQuery {
    object_type: Option<String>,
    state: Option<String>,
    customer: Option<i64>,
    page: Option<u32>,
    limit: Option<u32>,
}

impl ApplicationListQuery {
    /// An unfiltered query.
    ///
    /// ```
    /// use inwx_client::ApplicationListQuery;
    /// assert_eq!(ApplicationListQuery::new().params(), serde_json::json!({}));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by application type.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::ApplicationListQuery;
    /// assert_eq!(
    ///     ApplicationListQuery::new().with_type("HOSTING")?.params()["type"],
    ///     "HOSTING"
    /// );
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_type(mut self, object_type: &str) -> Result<Self> {
        validate_token("application.type", object_type)?;
        self.object_type = Some(object_type.trim().to_owned());
        Ok(self)
    }

    /// Filters by state.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::ApplicationListQuery;
    /// assert!(ApplicationListQuery::new().with_state("PENDING").is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_state(mut self, state: &str) -> Result<Self> {
        validate_token("application.state", state)?;
        self.state = Some(state.trim().to_owned());
        Ok(self)
    }

    /// Filters by customer id.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::ApplicationListQuery;
    /// assert!(ApplicationListQuery::new().with_customer(4711).is_ok());
    /// assert!(ApplicationListQuery::new().with_customer(-1).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer(mut self, customer: i64) -> Result<Self> {
        self.customer = Some(params::object_id("customerId", customer)?);
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
    /// use inwx_client::ApplicationListQuery;
    /// assert!(ApplicationListQuery::new().with_page(1, 1).is_ok());
    /// assert!(ApplicationListQuery::new().with_page(1, 1_000).is_ok());
    /// assert!(ApplicationListQuery::new().with_page(1, 1_001).is_err());
    /// assert!(ApplicationListQuery::new().with_page(1, 0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_page(mut self, page: u32, limit: u32) -> Result<Self> {
        let (page, limit) = params::paging(page, limit)?;
        self.page = Some(page);
        self.limit = Some(limit);
        Ok(self)
    }

    /// The `application.list` parameters.
    ///
    /// ```
    /// use inwx_client::ApplicationListQuery;
    /// let params = ApplicationListQuery::new().with_page(3, 10).unwrap().params();
    /// assert_eq!(params["page"], 3);
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut map = Map::new();
        if let Some(object_type) = &self.object_type {
            map.insert("type".to_owned(), json!(object_type));
        }
        if let Some(state) = &self.state {
            map.insert("state".to_owned(), json!(state));
        }
        if let Some(customer) = self.customer {
            map.insert("customer".to_owned(), json!(customer));
        }
        if let Some(page) = self.page {
            map.insert("page".to_owned(), json!(page));
        }
        if let Some(limit) = self.limit {
            map.insert("pagelimit".to_owned(), json!(limit));
        }
        Value::Object(map)
    }
}

impl<T: Transport> InwxClient<T> {
    /// Asks whether an application could be opened (`application.check`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{ApplicationCheck, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let check = ApplicationCheck::new()?.with_type("HOSTING")?;
    /// let outcome = client.check_application(&check).await?;
    /// println!("{:?}", outcome.is_available());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the check carries no criterion, plus the usual
    /// transport and API errors.
    pub async fn check_application(&self, check: &ApplicationCheck) -> Result<CheckOutcome> {
        let data = self.call("application.check", check.params()?).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Opens an application (`application.create`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{ApplicationCreate, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let create = ApplicationCreate::new()?.with_type("HOSTING")?.with_customer(4711)?;
    /// let application = client.create_application(&create).await?;
    /// println!("{:?}", application.id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the order carries no parameter, plus the usual
    /// transport and API errors.
    pub async fn create_application(&self, create: &ApplicationCreate) -> Result<Application> {
        let data = self.call("application.create", create.params()?).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Reads one application (`application.info`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let application = client.application_info(12).await?;
    /// println!("{:?}", application.state);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn application_info(&self, application_id: i64) -> Result<Application> {
        let id = params::object_id("applicationId", application_id)?;
        let data = self
            .call("application.info", json!({ "applicationId": id }))
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Lists applications (`application.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{ApplicationListQuery, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let page = client
    ///     .list_applications(&ApplicationListQuery::new().with_page(1, 50)?)
    ///     .await?;
    /// println!("{} of {:?}", page.len(), page.count);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors; the query itself validates its
    /// filters.
    pub async fn list_applications(
        &self,
        query: &ApplicationListQuery,
    ) -> Result<ApplicationListPage> {
        let data = self.call("application.list", query.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Changes an open application (`application.update`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{ApplicationUpdate, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let update = ApplicationUpdate::new(12)?.with_state("DONE")?;
    /// client.update_application(&update).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id or an update without a
    /// changed field, plus the usual transport and API errors.
    pub async fn update_application(&self, update: &ApplicationUpdate) -> Result<Application> {
        let data = self.call("application.update", update.params()?).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Withdraws an application (`application.delete`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.delete_application(12).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn delete_application(&self, application_id: i64) -> Result<()> {
        let id = params::object_id("applicationId", application_id)?;
        self.call("application.delete", json!({ "applicationId": id }))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_request_never_reaches_the_wire() {
        assert!(ApplicationCheck::new().unwrap().params().is_err());
        assert!(ApplicationCreate::new()
            .unwrap()
            .dry_run()
            .params()
            .is_err());
        assert!(ApplicationUpdate::new(12).unwrap().params().is_err());
    }

    #[test]
    fn ids_stop_at_zero() {
        assert!(ApplicationUpdate::new(1).is_ok());
        assert!(ApplicationUpdate::new(0).is_err());
        assert!(ApplicationListQuery::new().with_customer(1).is_ok());
        assert!(ApplicationListQuery::new().with_customer(0).is_err());
    }

    #[test]
    fn tokens_stop_at_255_characters() {
        let inside = "a".repeat(255);
        let outside = "a".repeat(256);
        assert!(ApplicationCreate::new().unwrap().with_name(&inside).is_ok());
        assert!(ApplicationCreate::new()
            .unwrap()
            .with_name(&outside)
            .is_err());
    }

    #[test]
    fn page_limit_pair_is_one_and_one_thousand() {
        assert!(ApplicationListQuery::new().with_page(1, 1).is_ok());
        assert!(ApplicationListQuery::new().with_page(0, 1_000).is_ok());
        assert!(ApplicationListQuery::new().with_page(1, 1_001).is_err());
        assert!(ApplicationListQuery::new().with_page(1, 0).is_err());
    }

    #[test]
    fn testing_is_only_added_when_asked_for() {
        let plain = ApplicationCreate::new().unwrap().with_type("X").unwrap();
        assert!(plain.params().unwrap().get("testing").is_none());
        let dry = plain.dry_run();
        assert_eq!(dry.params().unwrap()["testing"], true);
    }

    #[test]
    fn unknown_fields_survive_parsing() {
        let application: Application =
            serde_json::from_str(r#"{"id":1,"brandNew":{"a":1},"state":null}"#).unwrap();
        assert_eq!(application.state, None);
        assert_eq!(application.rest["brandNew"]["a"], 1);
    }

    #[test]
    fn list_accepts_singular_and_plural_keys() {
        let singular: ApplicationListPage =
            serde_json::from_str(r#"{"application":[{"id":1}]}"#).unwrap();
        let plural: ApplicationListPage =
            serde_json::from_str(r#"{"applications":[{"id":1}]}"#).unwrap();
        assert_eq!(singular, plural);
        assert_eq!(ApplicationListPage::default().len(), 0);
    }
}
