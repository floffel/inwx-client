//! Reseller applications (`application.*`): the typed request objects a
//! reseller files for a customer — a product order, a special registry action,
//! anything the API models as "an application with a type and a state".
//!
//! Six methods: check whether an application can be filed, file one, read one
//! back, list them, update one and withdraw one. Everything this crate can
//! reject without a round trip — a non-positive id, an empty name, an
//! update that changes nothing — is rejected here, before anything is charged.
//!
//! ```
//! use inwx_client::{ApplicationCreate, ApplicationType};
//!
//! let request = ApplicationCreate::new(
//!     ApplicationType::parse("domain-transfer")?,
//!     "example.com",
//! )?
//! .with_comment("customer asked for it")?;
//!
//! assert_eq!(request.params()["type"], "DOMAIN-TRANSFER");
//! assert_eq!(request.params()["name"], "example.com");
//! # Ok::<(), inwx_client::Error>(())
//! ```

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{
    de, parse_rows, validate_country_code, validate_id, validate_page_limit, validate_text,
    validate_token, validate_upper_token, DomainName,
};

/// Longest free-text comment this crate sends.
const MAX_COMMENT_LEN: usize = 4096;
/// Longest application type token.
const MAX_TYPE_LEN: usize = 64;

/// The type of an application.
///
/// INWX ships a per-account list of application types, so the crate does not
/// freeze a vocabulary: a type is a `[A-Z0-9_.-]` token of up to 64 characters,
/// upper-cased on the way in, and an unknown type is carried verbatim instead of
/// failing the parse.
///
/// ```
/// use inwx_client::ApplicationType;
///
/// assert_eq!(ApplicationType::parse("domain-transfer")?.as_str(), "DOMAIN-TRANSFER");
/// assert_eq!(ApplicationType::parse("SOMETHING_NEW")?.as_str(), "SOMETHING_NEW");
/// assert!(ApplicationType::parse("").is_err());
/// assert!(ApplicationType::parse("not a type").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ApplicationType(String);

impl ApplicationType {
    /// Parses an application type, trimming and upper-casing it.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the input is empty, longer than
    /// 64 characters, or contains a character outside `[A-Z0-9_.-]`.
    ///
    /// ```
    /// use inwx_client::ApplicationType;
    ///
    /// assert_eq!(ApplicationType::parse(" invoice ")?.as_str(), "INVOICE");
    /// assert!(ApplicationType::parse("has space").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn parse(input: &str) -> Result<Self> {
        validate_upper_token("application.type", input, MAX_TYPE_LEN).map(Self)
    }

    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::ApplicationType;
    /// assert_eq!(ApplicationType::parse("renew")?.as_str(), "RENEW");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ApplicationType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for ApplicationType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ApplicationType({:?})", self.0)
    }
}

impl FromStr for ApplicationType {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl Serialize for ApplicationType {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// Decoded permissively: any string is carried, upper-cased.
impl<'de> Deserialize<'de> for ApplicationType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(Self(raw.trim().to_ascii_uppercase()))
    }
}

/// One application, as returned by `application.info` and `application.list`.
///
/// ```
/// use inwx_client::Application;
///
/// let application: Application = serde_json::from_str(
///     r#"{"id":4711,"type":"DOMAIN-TRANSFER","name":"example.com","status":"PENDING",
///         "customerNumber":123456,"createdAt":"2026-03-01 10:00:00"}"#,
/// )?;
/// assert_eq!(application.id, Some(4711));
/// assert_eq!(application.status.as_deref(), Some("PENDING"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Application {
    /// Application id, used by `info`, `update` and `delete`.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Repository object id, when the API reports one.
    #[serde(
        default,
        rename = "roId",
        alias = "ro_id",
        deserialize_with = "de::opt_i64"
    )]
    pub ro_id: Option<i64>,
    /// Application type.
    #[serde(default, rename = "type")]
    pub application_type: Option<ApplicationType>,
    /// Name the application refers to.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// Domain the application refers to.
    #[serde(
        default,
        rename = "domainName",
        alias = "domain",
        deserialize_with = "de::opt_string"
    )]
    pub domain: Option<String>,
    /// Customer the application belongs to.
    #[serde(
        default,
        rename = "customerNumber",
        alias = "customer_number",
        deserialize_with = "de::opt_i64"
    )]
    pub customer_number: Option<i64>,
    /// State of the application, carried verbatim.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
    /// Free-text comment.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub comment: Option<String>,
    /// Creation date, as text.
    #[serde(
        default,
        rename = "createdAt",
        alias = "created_at",
        deserialize_with = "de::opt_string"
    )]
    pub created_at: Option<String>,
    /// Last change, as text.
    #[serde(
        default,
        rename = "updatedAt",
        alias = "updated_at",
        deserialize_with = "de::opt_string"
    )]
    pub updated_at: Option<String>,
}

/// The `application.check` request: what would be filed, without filing it.
///
/// ```
/// use inwx_client::{ApplicationCheck, ApplicationType};
///
/// let check = ApplicationCheck::new().with_type(ApplicationType::parse("renew")?)
///     .with_name("example.com")?;
/// assert_eq!(check.params()?["type"], "RENEW");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplicationCheck {
    application_id: Option<i64>,
    application_type: Option<ApplicationType>,
    name: Option<String>,
    domain: Option<DomainName>,
    country_code: Option<String>,
}

impl ApplicationCheck {
    /// An empty check; add at least one selector.
    ///
    /// ```
    /// use inwx_client::ApplicationCheck;
    /// assert!(ApplicationCheck::new().params().is_err());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks an existing application by id.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::ApplicationCheck;
    ///
    /// assert_eq!(ApplicationCheck::new().with_id(7)?.params()?["applicationId"], 7);
    /// assert!(ApplicationCheck::new().with_id(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_id(mut self, application_id: i64) -> Result<Self> {
        self.application_id = Some(validate_id("application.id", application_id)?);
        Ok(self)
    }

    /// Checks an application of this type.
    ///
    /// ```
    /// use inwx_client::{ApplicationCheck, ApplicationType};
    ///
    /// let check = ApplicationCheck::new().with_type(ApplicationType::parse("renew")?);
    /// assert_eq!(check.params()?["type"], "RENEW");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_type(mut self, application_type: ApplicationType) -> Self {
        self.application_type = Some(application_type);
        self
    }

    /// Checks the name the application would carry.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name is empty or longer than 255
    /// characters.
    ///
    /// ```
    /// use inwx_client::ApplicationCheck;
    ///
    /// assert_eq!(ApplicationCheck::new().with_name("example.com")?.params()?["name"], "example.com");
    /// assert!(ApplicationCheck::new().with_name(" ").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_name(mut self, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_token("application.name", &name)?;
        self.name = Some(name.trim().to_owned());
        Ok(self)
    }

    /// Checks the domain the application would refer to.
    ///
    /// ```
    /// use inwx_client::{ApplicationCheck, DomainName};
    ///
    /// let check = ApplicationCheck::new().with_domain(DomainName::parse("example.com")?);
    /// assert_eq!(check.params()?["domainName"], "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_domain(mut self, domain: DomainName) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Checks the country the application would apply to.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for anything that is not a two-letter country code.
    ///
    /// ```
    /// use inwx_client::ApplicationCheck;
    ///
    /// assert_eq!(ApplicationCheck::new().with_country_code("de")?.params()?["cc"], "DE");
    /// assert!(ApplicationCheck::new().with_country_code("deutschland").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_country_code(mut self, country_code: &str) -> Result<Self> {
        self.country_code = Some(validate_country_code("application.cc", country_code)?);
        Ok(self)
    }

    /// The `application.check` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when no selector was set: a check with nothing to
    /// check about is always a mistake.
    ///
    /// ```
    /// use inwx_client::ApplicationCheck;
    ///
    /// assert!(ApplicationCheck::new().params().is_err());
    /// assert!(ApplicationCheck::new().with_name("x")?.params().is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        if self.application_id.is_none()
            && self.application_type.is_none()
            && self.name.is_none()
            && self.domain.is_none()
            && self.country_code.is_none()
        {
            return Err(Error::validation(
                "application.check",
                "needs at least one of id, type, name, domain or country code",
            ));
        }
        let mut params = Map::new();
        if let Some(id) = self.application_id {
            params.insert("applicationId".to_owned(), json!(id));
        }
        if let Some(application_type) = &self.application_type {
            params.insert("type".to_owned(), json!(application_type.as_str()));
        }
        if let Some(name) = &self.name {
            params.insert("name".to_owned(), json!(name));
        }
        if let Some(domain) = &self.domain {
            params.insert("domainName".to_owned(), json!(domain.as_str()));
        }
        if let Some(country_code) = &self.country_code {
            params.insert("cc".to_owned(), json!(country_code));
        }
        Ok(Value::Object(params))
    }
}

/// Whether an application could be filed (`application.check`).
///
/// ```
/// use inwx_client::ApplicationCheckResult;
///
/// let result: ApplicationCheckResult =
///     serde_json::from_str(r#"{"available":1,"reason":"name is free"}"#)?;
/// assert!(result.is_available());
/// assert_eq!(result.reason.as_deref(), Some("name is free"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ApplicationCheckResult {
    /// Whether the application would be accepted.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub available: Option<bool>,
    /// Explanation, when the API sends one.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub reason: Option<String>,
    /// Application type the check applies to.
    #[serde(default, rename = "type")]
    pub application_type: Option<ApplicationType>,
}

impl ApplicationCheckResult {
    /// Whether the application would be accepted; unknown counts as not accepted.
    ///
    /// ```
    /// use inwx_client::ApplicationCheckResult;
    ///
    /// let yes: ApplicationCheckResult = serde_json::from_str(r#"{"available":"1"}"#)?;
    /// let silent = ApplicationCheckResult::default();
    /// assert!(yes.is_available());
    /// assert!(!silent.is_available());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.available.unwrap_or(false)
    }
}

/// The `application.create` request.
///
/// ```
/// use inwx_client::{ApplicationCreate, ApplicationType, DomainName};
///
/// let request = ApplicationCreate::new(ApplicationType::parse("transfer")?, "example.com")?
///     .with_domain(DomainName::parse("example.com")?)
///     .with_customer_number(123456)?;
/// assert_eq!(request.params()["type"], "TRANSFER");
/// assert_eq!(request.params()["customerNumber"], 123456);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationCreate {
    application_type: ApplicationType,
    name: String,
    domain: Option<DomainName>,
    customer_number: Option<i64>,
    comment: Option<String>,
    testing: bool,
}

impl ApplicationCreate {
    /// Files an application of `application_type` for `name`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name is empty or too long.
    ///
    /// ```
    /// use inwx_client::{ApplicationCreate, ApplicationType};
    ///
    /// assert!(ApplicationCreate::new(ApplicationType::parse("renew")?, "").is_err());
    /// assert!(ApplicationCreate::new(ApplicationType::parse("renew")?, "x").is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new(application_type: ApplicationType, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_token("application.name", &name)?;
        Ok(Self {
            application_type,
            name: name.trim().to_owned(),
            domain: None,
            customer_number: None,
            comment: None,
            testing: false,
        })
    }

    /// Sets the domain the application refers to.
    ///
    /// ```
    /// use inwx_client::{ApplicationCreate, ApplicationType, DomainName};
    ///
    /// let request = ApplicationCreate::new(ApplicationType::parse("renew")?, "example.com")?
    ///     .with_domain(DomainName::parse("example.com")?);
    /// assert_eq!(request.params()["domainName"], "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_domain(mut self, domain: DomainName) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Sets the customer the application belongs to.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive customer number.
    ///
    /// ```
    /// use inwx_client::{ApplicationCreate, ApplicationType};
    ///
    /// let request = ApplicationCreate::new(ApplicationType::parse("renew")?, "x")?
    ///     .with_customer_number(123456)?;
    /// assert_eq!(request.params()["customerNumber"], 123456);
    /// assert!(ApplicationCreate::new(ApplicationType::parse("renew")?, "x")?
    ///     .with_customer_number(-1).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer_number(mut self, customer_number: i64) -> Result<Self> {
        self.customer_number = Some(validate_id("customer.number", customer_number)?);
        Ok(self)
    }

    /// Sets a comment for the people processing the application.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the comment is empty or longer than
    /// `MAX_COMMENT_LEN` characters.
    ///
    /// ```
    /// use inwx_client::{ApplicationCreate, ApplicationType};
    ///
    /// let request = ApplicationCreate::new(ApplicationType::parse("renew")?, "x")?
    ///     .with_comment("urgent")?;
    /// assert_eq!(request.params()["comment"], "urgent");
    /// assert!(ApplicationCreate::new(ApplicationType::parse("renew")?, "x")?
    ///     .with_comment("   ").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_comment(mut self, comment: impl Into<String>) -> Result<Self> {
        let comment = comment.into();
        validate_text("application.comment", &comment, MAX_COMMENT_LEN)?;
        self.comment = Some(comment);
        Ok(self)
    }

    /// Marks the call as a dry run (`testing`).
    ///
    /// ```
    /// use inwx_client::{ApplicationCreate, ApplicationType};
    ///
    /// let request = ApplicationCreate::new(ApplicationType::parse("renew")?, "x")?
    ///     .with_testing(true);
    /// assert_eq!(request.params()["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_testing(mut self, testing: bool) -> Self {
        self.testing = testing;
        self
    }

    /// The `application.create` parameters.
    ///
    /// ```
    /// use inwx_client::{ApplicationCreate, ApplicationType};
    ///
    /// let params = ApplicationCreate::new(ApplicationType::parse("renew")?, "x")?.params();
    /// assert_eq!(params["name"], "x");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut params = Map::new();
        params.insert("type".to_owned(), json!(self.application_type.as_str()));
        params.insert("name".to_owned(), json!(self.name));
        if let Some(domain) = &self.domain {
            params.insert("domainName".to_owned(), json!(domain.as_str()));
        }
        if let Some(customer_number) = self.customer_number {
            params.insert("customerNumber".to_owned(), json!(customer_number));
        }
        if let Some(comment) = &self.comment {
            params.insert("comment".to_owned(), json!(comment));
        }
        if self.testing {
            params.insert("testing".to_owned(), json!(true));
        }
        Value::Object(params)
    }
}

/// A search + paging for `application.list`.
///
/// ```
/// use inwx_client::{ApplicationQuery, ApplicationType};
///
/// let query = ApplicationQuery::new()
///     .with_type(ApplicationType::parse("renew")?)
///     .with_page(2, 50)?;
/// let params = query.params()?;
/// assert_eq!(params["type"], "RENEW");
/// assert_eq!(params["pagelimit"], 50);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplicationQuery {
    application_id: Option<i64>,
    application_type: Option<ApplicationType>,
    customer_number: Option<i64>,
    status: Option<String>,
    page: Option<u32>,
    limit: Option<u32>,
}

impl ApplicationQuery {
    /// An unfiltered query.
    ///
    /// ```
    /// use inwx_client::ApplicationQuery;
    /// assert!(ApplicationQuery::new().params().unwrap().is_object());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by application id.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::ApplicationQuery;
    ///
    /// assert_eq!(ApplicationQuery::new().with_id(3)?.params()?["applicationId"], 3);
    /// assert!(ApplicationQuery::new().with_id(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_id(mut self, application_id: i64) -> Result<Self> {
        self.application_id = Some(validate_id("application.id", application_id)?);
        Ok(self)
    }

    /// Filters by type.
    ///
    /// ```
    /// use inwx_client::{ApplicationQuery, ApplicationType};
    ///
    /// let query = ApplicationQuery::new().with_type(ApplicationType::parse("renew")?);
    /// assert_eq!(query.params()?["type"], "RENEW");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_type(mut self, application_type: ApplicationType) -> Self {
        self.application_type = Some(application_type);
        self
    }

    /// Filters by customer.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive customer number.
    ///
    /// ```
    /// use inwx_client::ApplicationQuery;
    /// assert_eq!(ApplicationQuery::new().with_customer_number(9)?.params()?["customerNumber"], 9);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer_number(mut self, customer_number: i64) -> Result<Self> {
        self.customer_number = Some(validate_id("customer.number", customer_number)?);
        Ok(self)
    }

    /// Filters by state, upper-cased.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or oddly shaped state token.
    ///
    /// ```
    /// use inwx_client::ApplicationQuery;
    ///
    /// assert_eq!(ApplicationQuery::new().with_status("done")?.params()?["status"], "DONE");
    /// assert!(ApplicationQuery::new().with_status("").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_status(mut self, status: impl Into<String>) -> Result<Self> {
        self.status = Some(validate_upper_token(
            "application.status",
            &status.into(),
            MAX_TYPE_LEN,
        )?);
        Ok(self)
    }

    /// Sets the page (1-based) and the page size.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the page size is zero.
    ///
    /// ```
    /// use inwx_client::ApplicationQuery;
    ///
    /// assert_eq!(ApplicationQuery::new().with_page(1, 1)?.params()?["pagelimit"], 1);
    /// assert!(ApplicationQuery::new().with_page(1, 0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_page(mut self, page: u32, limit: u32) -> Result<Self> {
        self.limit = Some(validate_page_limit(limit)?);
        self.page = Some(page.max(1));
        Ok(self)
    }

    /// The `application.list` parameters.
    ///
    /// # Errors
    ///
    /// Never fails today: every value is validated when it is set, so the
    /// parameters are always sendable. The `Result` keeps the shape of the
    /// builders that can refuse a value.
    ///
    /// ```
    /// use inwx_client::ApplicationQuery;
    /// assert!(ApplicationQuery::new().params().unwrap().is_object());
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut params = Map::new();
        if let Some(id) = self.application_id {
            params.insert("applicationId".to_owned(), json!(id));
        }
        if let Some(application_type) = &self.application_type {
            params.insert("type".to_owned(), json!(application_type.as_str()));
        }
        if let Some(customer_number) = self.customer_number {
            params.insert("customerNumber".to_owned(), json!(customer_number));
        }
        if let Some(status) = &self.status {
            params.insert("status".to_owned(), json!(status));
        }
        params.insert("page".to_owned(), json!(self.page.unwrap_or(1)));
        params.insert("pagelimit".to_owned(), json!(self.limit.unwrap_or(50)));
        Ok(Value::Object(params))
    }
}

/// The `application.update` request: exactly the fields that should change.
///
/// ```
/// use inwx_client::ApplicationUpdate;
///
/// let update = ApplicationUpdate::new(4711)?.with_comment("still waiting")?;
/// let params = update.params()?;
/// assert_eq!(params["applicationId"], 4711);
/// assert_eq!(params["comment"], "still waiting");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationUpdate {
    application_id: i64,
    name: Option<String>,
    domain: Option<DomainName>,
    customer_number: Option<i64>,
    comment: Option<String>,
    testing: bool,
}

impl ApplicationUpdate {
    /// Updates the application with `application_id`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::ApplicationUpdate;
    /// assert!(ApplicationUpdate::new(1).is_ok());
    /// assert!(ApplicationUpdate::new(0).is_err());
    /// ```
    pub fn new(application_id: i64) -> Result<Self> {
        Ok(Self {
            application_id: validate_id("application.id", application_id)?,
            name: None,
            domain: None,
            customer_number: None,
            comment: None,
            testing: false,
        })
    }

    /// Renames the application.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name is unusable.
    ///
    /// ```
    /// use inwx_client::ApplicationUpdate;
    ///
    /// let update = ApplicationUpdate::new(1)?.with_name("renamed")?;
    /// assert_eq!(update.params()?["name"], "renamed");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_name(mut self, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_token("application.name", &name)?;
        self.name = Some(name.trim().to_owned());
        Ok(self)
    }

    /// Sets the domain.
    ///
    /// ```
    /// use inwx_client::{ApplicationUpdate, DomainName};
    ///
    /// let update = ApplicationUpdate::new(1)?.with_domain(DomainName::parse("example.com")?);
    /// assert_eq!(update.params()?["domainName"], "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_domain(mut self, domain: DomainName) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Moves the application to another customer.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive customer number.
    ///
    /// ```
    /// use inwx_client::ApplicationUpdate;
    ///
    /// let update = ApplicationUpdate::new(1)?.with_customer_number(2)?;
    /// assert_eq!(update.params()?["customerNumber"], 2);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer_number(mut self, customer_number: i64) -> Result<Self> {
        self.customer_number = Some(validate_id("customer.number", customer_number)?);
        Ok(self)
    }

    /// Sets the comment.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the comment is empty or too long.
    ///
    /// ```
    /// use inwx_client::ApplicationUpdate;
    ///
    /// let update = ApplicationUpdate::new(1)?.with_comment("note")?;
    /// assert_eq!(update.params()?["comment"], "note");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_comment(mut self, comment: impl Into<String>) -> Result<Self> {
        let comment = comment.into();
        validate_text("application.comment", &comment, MAX_COMMENT_LEN)?;
        self.comment = Some(comment);
        Ok(self)
    }

    /// Marks the call as a dry run (`testing`).
    ///
    /// ```
    /// use inwx_client::ApplicationUpdate;
    ///
    /// let update = ApplicationUpdate::new(1)?.with_comment("x").unwrap().with_testing(true);
    /// assert_eq!(update.params()?["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_testing(mut self, testing: bool) -> Self {
        self.testing = testing;
        self
    }

    /// The `application.update` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when nothing would change: an update with no field
    /// is always a bug in the caller.
    ///
    /// ```
    /// use inwx_client::ApplicationUpdate;
    ///
    /// assert!(ApplicationUpdate::new(1)?.params().is_err());
    /// assert!(ApplicationUpdate::new(1)?.with_comment("x")?.params().is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        if self.name.is_none()
            && self.domain.is_none()
            && self.customer_number.is_none()
            && self.comment.is_none()
        {
            return Err(Error::validation(
                "application.update",
                "needs at least one field to change",
            ));
        }
        let mut params = Map::new();
        params.insert("applicationId".to_owned(), json!(self.application_id));
        if let Some(name) = &self.name {
            params.insert("name".to_owned(), json!(name));
        }
        if let Some(domain) = &self.domain {
            params.insert("domainName".to_owned(), json!(domain.as_str()));
        }
        if let Some(customer_number) = self.customer_number {
            params.insert("customerNumber".to_owned(), json!(customer_number));
        }
        if let Some(comment) = &self.comment {
            params.insert("comment".to_owned(), json!(comment));
        }
        if self.testing {
            params.insert("testing".to_owned(), json!(true));
        }
        Ok(Value::Object(params))
    }
}

impl<T: Transport> InwxClient<T> {
    /// Asks whether an application could be filed (`application.check`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{ApplicationCheck, ApplicationType, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let check = ApplicationCheck::new().with_type(ApplicationType::parse("renew")?)
    ///     .with_name("example.com")?;
    /// println!("{}", client.check_application(&check).await?.is_available());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the check has no selector, plus the usual
    /// transport and API errors.
    pub async fn check_application(
        &self,
        check: &ApplicationCheck,
    ) -> Result<ApplicationCheckResult> {
        let params = check.params()?;
        let data = self.call("application.check", params).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Files an application (`application.create`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{ApplicationCreate, ApplicationType, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let request = ApplicationCreate::new(ApplicationType::parse("renew")?, "example.com")?;
    /// let application = client.create_application(&request).await?;
    /// println!("{:?}", application.id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors; `2104` on a billing failure.
    pub async fn create_application(&self, request: &ApplicationCreate) -> Result<Application> {
        let data = self.call("application.create", request.params()).await?;
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
    /// client.delete_application(4711).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn delete_application(&self, application_id: i64) -> Result<()> {
        validate_id("application.id", application_id)?;
        self.call(
            "application.delete",
            json!({ "applicationId": application_id }),
        )
        .await?;
        Ok(())
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
    /// let application = client.application_info(4711).await?;
    /// println!("{:?}", application.status);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors — `2303` when the application does not exist.
    pub async fn application_info(&self, application_id: i64) -> Result<Application> {
        validate_id("application.id", application_id)?;
        let data = self
            .call(
                "application.info",
                json!({ "applicationId": application_id }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Lists applications (`application.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{ApplicationQuery, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let query = ApplicationQuery::new().with_page(1, 50)?;
    /// for application in client.list_applications(&query).await? {
    ///     println!("{:?} {:?}", application.id, application.status);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the query carries an invalid id or page size,
    /// plus the usual transport and API errors.
    pub async fn list_applications(&self, query: &ApplicationQuery) -> Result<Vec<Application>> {
        let params = query.params()?;
        let data = self.call("application.list", params).await?;
        Ok(parse_rows(&data, "application"))
    }

    /// Changes an application (`application.update`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{ApplicationUpdate, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let update = ApplicationUpdate::new(4711)?.with_comment("pinged")?;
    /// client.update_application(&update).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id or an update with no field,
    /// plus the usual transport and API errors.
    pub async fn update_application(&self, update: &ApplicationUpdate) -> Result<()> {
        let params = update.params()?;
        self.call("application.update", params).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_type_token_of_64_characters_is_accepted_and_65_is_not() {
        let ok = "A".repeat(64);
        assert_eq!(ApplicationType::parse(&ok).unwrap().as_str(), ok.as_str());
        assert!(ApplicationType::parse(&format!("A{ok}")).is_err());
    }

    #[test]
    fn a_name_of_255_characters_is_accepted_and_256_is_not() {
        let ok = "a".repeat(255);
        let too_long = format!("{ok}b");
        assert!(ApplicationCreate::new(ApplicationType::parse("renew").unwrap(), ok).is_ok());
        assert!(
            ApplicationCreate::new(ApplicationType::parse("renew").unwrap(), too_long).is_err()
        );
    }

    #[test]
    fn a_comment_of_4096_characters_is_accepted_and_4097_is_not() {
        let ok = "x".repeat(4096);
        let too_long = format!("{ok}x");
        let base = || ApplicationCreate::new(ApplicationType::parse("renew").unwrap(), "n");
        assert!(base().unwrap().with_comment(ok).is_ok());
        assert!(base().unwrap().with_comment(too_long).is_err());
    }

    #[test]
    fn a_page_limit_of_one_is_accepted_and_zero_is_not() {
        assert!(ApplicationQuery::new().with_page(1, 1).is_ok());
        assert!(ApplicationQuery::new().with_page(1, 0).is_err());
    }

    #[test]
    fn ids_must_be_positive_everywhere() {
        assert!(ApplicationUpdate::new(1).is_ok());
        assert!(ApplicationUpdate::new(0).is_err());
        assert!(ApplicationCheck::new().with_id(-1).is_err());
        assert!(ApplicationQuery::new().with_customer_number(0).is_err());
    }

    #[test]
    fn a_check_needs_a_selector_and_an_update_needs_a_change() {
        assert!(ApplicationCheck::new().params().is_err());
        assert!(ApplicationCheck::new().with_country_code("de").is_ok());
        assert!(ApplicationUpdate::new(1).unwrap().params().is_err());
    }

    #[test]
    fn a_query_sends_paging_defaults() {
        let params = ApplicationQuery::new().params().unwrap();
        assert_eq!(params["page"], 1);
        assert_eq!(params["pagelimit"], 50);
    }

    #[test]
    fn answers_are_parsed_permissively() {
        // snake_case and camelCase both work, and a scalar arrives as a number
        // or a string.
        let camel: Application =
            serde_json::from_str(r#"{"id":"7","customerNumber":3,"createdAt":"x"}"#).unwrap();
        let snake: Application =
            serde_json::from_str(r#"{"id":7,"customer_number":"3","created_at":"x"}"#).unwrap();
        assert_eq!(camel, snake);
        assert_eq!(camel.id, Some(7));

        let unknown_type: Application = serde_json::from_str(r#"{"type":"brand_new"}"#).unwrap();
        assert_eq!(
            unknown_type
                .application_type
                .map(|application_type| application_type.to_string()),
            Some("BRAND_NEW".to_owned())
        );
    }
}
