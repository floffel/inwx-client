//! Customers (`customer.*`): the reseller's own customer records.
//!
//! A reseller holds its end customers as customer objects: read one, change its
//! address, delete it, ask for the GDPR data export and list the export files
//! that were generated, and read or change the contact-verification settings.
//!
//! The object is described in the API documentation chapter 2 §2.7. Customer
//! records carry more product-specific fields than this crate models one by
//! one; [`CustomerUpdate::with_field`] and
//! [`ContactVerificationSettingsUpdate::with_field`] carry them, and
//! [`ContactVerificationSettings::value`] reads them back by name.
//!
//! ```
//! use inwx_client::Customer;
//!
//! let customer: Customer = serde_json::from_str(
//!     r#"{"id":4711,"customerNo":"110069","city":"Kolbermoor","country":"de","email":"a@example.com"}"#,
//! )?;
//! assert_eq!(customer.id, Some(4711));
//! assert_eq!(customer.country.as_deref(), Some("de"));
//! # Ok::<(), serde_json::Error>(())
//! ```

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::params::{self, ExtraFields};
use crate::transport::Transport;
use crate::types::{de, validate_token, Email};

/// Keys owned by [`CustomerUpdate`].
const UPDATE_KEYS: &[&str] = &[
    "customerId",
    "title",
    "name",
    "street",
    "zip",
    "city",
    "country",
    "email",
    "phone",
    "fax",
    "locale",
    "vat",
];
/// Keys owned by [`ContactVerificationSettingsUpdate`].
const SETTINGS_KEYS: &[&str] = &["customerId"];

/// One customer of the reseller account.
///
/// Fields are optional and unknown ones are kept in [`Customer::rest`]; an
/// address field the API does not report stays `None` rather than becoming an
/// empty string.
///
/// ```
/// use inwx_client::Customer;
///
/// let camel: Customer =
///     serde_json::from_str(r#"{"id":"4711","customerNo":"110069","customerType":"PERSON"}"#)?;
/// let snake: Customer =
///     serde_json::from_str(r#"{"id":4711,"customer_no":"110069","customer_type":"PERSON"}"#)?;
/// assert_eq!(camel, snake);
/// assert_eq!(camel.customer_no.as_deref(), Some("110069"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Customer {
    /// Customer id, used by every other call.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Customer number as printed on invoices.
    #[serde(
        default,
        rename = "customerNo",
        alias = "customer_no",
        deserialize_with = "de::opt_string"
    )]
    pub customer_no: Option<String>,
    /// Academic title.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub title: Option<String>,
    /// Name of the person or company.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
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
    /// Fax number.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub fax: Option<String>,
    /// Language the customer is addressed in.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub locale: Option<String>,
    /// VAT identifier.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub vat: Option<String>,
    /// Customer type (`PERSON`, `ORGANIZATION`, …).
    #[serde(
        default,
        rename = "customerType",
        alias = "customer_type",
        deserialize_with = "de::opt_string"
    )]
    pub customer_type: Option<String>,
    /// State of the customer record.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub state: Option<String>,
    /// Credit limit of the customer.
    #[serde(default, rename = "creditLimit", deserialize_with = "de::opt_f64")]
    pub credit_limit: Option<f64>,
    /// Fields this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// A change to a customer record (`customer.update`).
///
/// The id alone is not a change: [`CustomerUpdate::params`] refuses a request
/// that would send nothing else, because the API answers it with
/// `2003 Required parameter missing`.
///
/// ```
/// use inwx_client::{CustomerUpdate, Email};
///
/// let update = CustomerUpdate::new(4711)?
///     .with_city("Kolbermoor")?
///     .with_email(Email::parse("it@example.com")?)
///     .with_country("de")?;
/// let params = update.params()?;
/// assert_eq!(params["customerId"], 4711);
/// assert_eq!(params["city"], "Kolbermoor");
/// assert_eq!(params["country"], "DE");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct CustomerUpdate {
    customer_id: i64,
    fields: Map<String, Value>,
    email: Option<Email>,
    owned: ExtraFields,
}

impl CustomerUpdate {
    /// Targets one customer.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    /// assert!(CustomerUpdate::new(4711).is_ok());
    /// assert!(CustomerUpdate::new(0).is_err());
    /// ```
    pub fn new(customer_id: i64) -> Result<Self> {
        Ok(Self {
            customer_id: params::object_id("customerId", customer_id)?,
            fields: Map::new(),
            email: None,
            owned: ExtraFields::default(),
        })
    }

    /// Sets one of the plain address fields.
    fn assign(mut self, key: &'static str, value: &str) -> Result<Self> {
        validate_token(key, value)?;
        self.fields.insert(key.to_owned(), json!(value.trim()));
        Ok(self)
    }

    /// Sets the academic title.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    /// assert_eq!(
    ///     CustomerUpdate::new(1)?.with_title("Dr.")?.params()?["title"],
    ///     "Dr."
    /// );
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_title(self, title: &str) -> Result<Self> {
        self.assign("title", title)
    }

    /// Sets the name.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    /// assert!(CustomerUpdate::new(1)?.with_name("Acme GmbH").is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_name(self, name: &str) -> Result<Self> {
        self.assign("name", name)
    }

    /// Sets the street.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    /// assert!(CustomerUpdate::new(1)?.with_street("Lindenstr. 1").is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_street(self, street: &str) -> Result<Self> {
        self.assign("street", street)
    }

    /// Sets the postal code.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    /// assert!(CustomerUpdate::new(1)?.with_zip("83059").is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_zip(self, zip: &str) -> Result<Self> {
        self.assign("zip", zip)
    }

    /// Sets the city.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    /// assert!(CustomerUpdate::new(1)?.with_city("Kolbermoor").is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_city(self, city: &str) -> Result<Self> {
        self.assign("city", city)
    }

    /// Sets the country, upper-casing a two-letter ISO 3166-1 code.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not two ASCII letters.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    /// assert_eq!(CustomerUpdate::new(1)?.with_country("de")?.params()?["country"], "DE");
    /// assert!(CustomerUpdate::new(1)?.with_country("germany").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_country(mut self, country: &str) -> Result<Self> {
        let code = params::country_code("country", country)?;
        self.fields.insert("country".to_owned(), json!(code));
        Ok(self)
    }

    /// Sets the e-mail address.
    ///
    /// [`Email`] has already checked the shape, so nothing is validated twice.
    ///
    /// ```
    /// use inwx_client::{CustomerUpdate, Email};
    /// let update = CustomerUpdate::new(1)?.with_email(Email::parse("it@example.com")?);
    /// assert_eq!(update.params()?["email"], "it@example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_email(mut self, email: Email) -> Self {
        self.email = Some(email);
        self
    }

    /// Sets the phone number.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    /// assert!(CustomerUpdate::new(1)?.with_phone("+49 89 1234").is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_phone(self, phone: &str) -> Result<Self> {
        self.assign("phone", phone)
    }

    /// Sets the fax number.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    /// assert!(CustomerUpdate::new(1)?.with_fax("+49 89 1235").is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_fax(self, fax: &str) -> Result<Self> {
        self.assign("fax", fax)
    }

    /// Sets the language the customer is addressed in.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    /// assert!(CustomerUpdate::new(1)?.with_locale("de").is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_locale(self, locale: &str) -> Result<Self> {
        self.assign("locale", locale)
    }

    /// Sets the VAT identifier.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    /// assert!(CustomerUpdate::new(1)?.with_vat("DE123456789").is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_vat(self, vat: &str) -> Result<Self> {
        self.assign("vat", vat)
    }

    /// Changes a parameter this crate does not model.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `key` is not a parameter name, or when a typed
    /// setter already owns it.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    /// let update = CustomerUpdate::new(1)?.with_field("company", "Acme GmbH")?;
    /// assert_eq!(update.params()?["company"], "Acme GmbH");
    /// assert!(CustomerUpdate::new(1)?.with_field("city", "x").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_field(mut self, key: &str, value: impl Into<Value>) -> Result<Self> {
        self.owned.set(key, value.into(), UPDATE_KEYS)?;
        Ok(self)
    }

    /// The `customer.update` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when no field was changed.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    /// assert!(CustomerUpdate::new(4711)?.params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut map = Map::new();
        params::require_payload(
            "customer.update.params",
            self.fields.len() + usize::from(self.email.is_some()) + self.owned.len(),
        )?;
        map.insert("customerId".to_owned(), json!(self.customer_id));
        for (key, value) in &self.fields {
            map.insert(key.clone(), value.clone());
        }
        if let Some(email) = &self.email {
            map.insert("email".to_owned(), json!(email.as_str()));
        }
        self.owned.write_into(&mut map);
        Ok(Value::Object(map))
    }
}

/// One generated data-export file (`customer.listdownloads`).
///
/// ```
/// use inwx_client::CustomerDownload;
///
/// let download: CustomerDownload = serde_json::from_str(
///     r#"{"hash":"8f2a","filename":"export-2026.zip","size":2048,"validUntil":"2026-11-01"}"#,
/// )?;
/// assert_eq!(download.hash.as_deref(), Some("8f2a"));
/// assert_eq!(download.size, Some(2048));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct CustomerDownload {
    /// Hash that identifies the file for a later fetch.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub hash: Option<String>,
    /// File name the API suggests.
    #[serde(
        default,
        rename = "filename",
        alias = "file_name",
        deserialize_with = "de::opt_string"
    )]
    pub filename: Option<String>,
    /// Size in bytes.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub size: Option<i64>,
    /// Until when the download stays available.
    #[serde(
        default,
        rename = "validUntil",
        alias = "valid_until",
        deserialize_with = "de::opt_string"
    )]
    pub valid_until: Option<String>,
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

/// One page of `customer.listdownloads`.
///
/// ```
/// use inwx_client::CustomerDownloadPage;
///
/// let page: CustomerDownloadPage = serde_json::from_str(
///     r#"{"count":1,"downloads":[{"hash":"8f2a"}]}"#,
/// )?;
/// assert_eq!(page.count, Some(1));
/// assert_eq!(page.len(), 1);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct CustomerDownloadPage {
    /// Total number of files, not just this page.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The files on this page.
    #[serde(default, rename = "download", alias = "downloads")]
    pub downloads: Vec<CustomerDownload>,
}

impl CustomerDownloadPage {
    /// Number of files on this page.
    ///
    /// ```
    /// use inwx_client::CustomerDownloadPage;
    /// let page: CustomerDownloadPage = serde_json::from_str(r#"{"downloads":[{"hash":"a"}]}"#)?;
    /// assert_eq!(page.len(), 1);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.downloads.len()
    }

    /// Whether this page carries no file at all.
    ///
    /// ```
    /// use inwx_client::CustomerDownloadPage;
    /// assert!(CustomerDownloadPage::default().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.downloads.is_empty()
    }
}

/// The filter behind `customer.listdownloads`.
///
/// ```
/// use inwx_client::CustomerDownloadQuery;
///
/// let query = CustomerDownloadQuery::new().with_page(1, 25)?;
/// assert_eq!(query.params()["pagelimit"], 25);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CustomerDownloadQuery {
    customer: Option<i64>,
    page: Option<u32>,
    limit: Option<u32>,
}

impl CustomerDownloadQuery {
    /// All downloads of the reseller account.
    ///
    /// ```
    /// use inwx_client::CustomerDownloadQuery;
    /// assert_eq!(CustomerDownloadQuery::new().params(), serde_json::json!({}));
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
    /// use inwx_client::CustomerDownloadQuery;
    /// assert!(CustomerDownloadQuery::new().with_customer(4711).is_ok());
    /// assert!(CustomerDownloadQuery::new().with_customer(0).is_err());
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
    /// use inwx_client::CustomerDownloadQuery;
    /// assert!(CustomerDownloadQuery::new().with_page(1, 1).is_ok());
    /// assert!(CustomerDownloadQuery::new().with_page(1, 1_000).is_ok());
    /// assert!(CustomerDownloadQuery::new().with_page(1, 1_001).is_err());
    /// assert!(CustomerDownloadQuery::new().with_page(1, 0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_page(mut self, page: u32, limit: u32) -> Result<Self> {
        let (page, limit) = params::paging(page, limit)?;
        self.page = Some(page);
        self.limit = Some(limit);
        Ok(self)
    }

    /// The `customer.listdownloads` parameters.
    ///
    /// ```
    /// use inwx_client::CustomerDownloadQuery;
    /// let params = CustomerDownloadQuery::new().with_page(2, 5).unwrap().params();
    /// assert_eq!(params["page"], 2);
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut map = Map::new();
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

/// The request behind `customer.requestdataexport`.
///
/// A data export of the whole reseller account takes no parameter, so an empty
/// request is legal here — unlike an update, which would be refused.
///
/// ```
/// use inwx_client::DataExportRequest;
///
/// let request = DataExportRequest::new().with_customer(4711)?;
/// assert_eq!(request.params()["customer"], 4711);
/// assert_eq!(DataExportRequest::new().params(), serde_json::json!({}));
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DataExportRequest {
    customer: Option<i64>,
    fields: ExtraFields,
}

impl DataExportRequest {
    /// The whole account.
    ///
    /// ```
    /// use inwx_client::DataExportRequest;
    /// assert!(DataExportRequest::new().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restricts the export to one customer.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::DataExportRequest;
    /// assert!(DataExportRequest::new().with_customer(1).is_ok());
    /// assert!(DataExportRequest::new().with_customer(-1).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer(mut self, customer: i64) -> Result<Self> {
        self.customer = Some(params::object_id("customerId", customer)?);
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
    /// use inwx_client::DataExportRequest;
    /// let request = DataExportRequest::new().with_field("format", "ZIP")?;
    /// assert_eq!(request.params()["format"], "ZIP");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_field(mut self, key: &str, value: impl Into<Value>) -> Result<Self> {
        self.fields.set(key, value.into(), SETTINGS_KEYS)?;
        Ok(self)
    }

    /// Whether nothing was restricted.
    ///
    /// ```
    /// use inwx_client::DataExportRequest;
    /// assert!(DataExportRequest::new().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.customer.is_none() && self.fields.is_empty()
    }

    /// The `customer.requestdataexport` parameters.
    ///
    /// ```
    /// use inwx_client::DataExportRequest;
    /// assert_eq!(DataExportRequest::new().params(), serde_json::json!({}));
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut map = Map::new();
        if let Some(customer) = self.customer {
            map.insert("customer".to_owned(), json!(customer));
        }
        self.fields.write_into(&mut map);
        Value::Object(map)
    }
}

/// The answer to `customer.requestdataexport`.
///
/// ```
/// use inwx_client::DataExport;
///
/// let export: DataExport =
///     serde_json::from_str(r#"{"hash":"8f2a","status":"PENDING","note":"by e-mail"}"#)?;
/// assert_eq!(export.hash.as_deref(), Some("8f2a"));
/// assert_eq!(export.note.as_deref(), Some("by e-mail"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct DataExport {
    /// Hash of the generated archive, when the API sent one.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub hash: Option<String>,
    /// State of the export job.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
    /// Explanation the API put in the payload.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub note: Option<String>,
    /// Fields this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// The contact-verification settings (`customer.contactverificationsettingsinfo`).
///
/// Which settings exist depends on the product and on the verification rules
/// INWX currently applies, so they are read by name instead of being frozen
/// into a struct field: [`ContactVerificationSettings::value`],
/// [`ContactVerificationSettings::bool_value`] and
/// [`ContactVerificationSettings::string_value`].
///
/// ```
/// use inwx_client::ContactVerificationSettings;
///
/// let settings: ContactVerificationSettings = serde_json::from_str(
///     r#"{"verifyEmail":1,"interval":"90","unknown":{"nested":true}}"#,
/// )?;
/// assert_eq!(settings.bool_value("verifyEmail"), Some(true));
/// assert_eq!(settings.string_value("interval").as_deref(), Some("90"));
/// assert_eq!(settings.value("unknown")["nested"], true);
/// assert_eq!(settings.value("absent"), serde_json::Value::Null);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct ContactVerificationSettings {
    /// Every setting the API reported, keyed by its own name.
    #[serde(flatten)]
    pub settings: Map<String, Value>,
}

impl ContactVerificationSettings {
    /// One setting as it arrived, or `Value::Null` when absent.
    ///
    /// ```
    /// use inwx_client::ContactVerificationSettings;
    ///
    /// let settings: ContactVerificationSettings = serde_json::from_str(r#"{"a":1}"#)?;
    /// assert_eq!(settings.value("a"), serde_json::json!(1));
    /// assert_eq!(settings.value("b"), serde_json::Value::Null);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn value(&self, key: &str) -> Value {
        self.settings.get(key).cloned().unwrap_or(Value::Null)
    }

    /// One setting read as a boolean, accepting `true`, `1` and `"1"`.
    ///
    /// ```
    /// use inwx_client::ContactVerificationSettings;
    ///
    /// let settings: ContactVerificationSettings =
    ///     serde_json::from_str(r#"{"on":"1","off":"0","other":"x"}"#)?;
    /// assert_eq!(settings.bool_value("on"), Some(true));
    /// assert_eq!(settings.bool_value("off"), Some(false));
    /// assert_eq!(settings.bool_value("other"), None);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn bool_value(&self, key: &str) -> Option<bool> {
        match self.settings.get(key) {
            Some(Value::Bool(flag)) => Some(*flag),
            Some(Value::Number(number)) => number.as_i64().map(|value| value != 0),
            Some(Value::String(text)) => match text.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" => Some(true),
                "0" | "false" | "no" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    /// One setting read as a string, accepting a string or a number.
    ///
    /// ```
    /// use inwx_client::ContactVerificationSettings;
    ///
    /// let settings: ContactVerificationSettings = serde_json::from_str(r#"{"interval":90}"#)?;
    /// assert_eq!(settings.string_value("interval").as_deref(), Some("90"));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn string_value(&self, key: &str) -> Option<String> {
        match self.settings.get(key) {
            Some(Value::String(text)) => Some(text.clone()),
            Some(Value::Number(number)) => Some(number.to_string()),
            _ => None,
        }
    }
}

/// A change to the contact-verification settings
/// (`customer.contactverificationsettingsupdate`).
///
/// ```
/// use inwx_client::ContactVerificationSettingsUpdate;
///
/// let update = ContactVerificationSettingsUpdate::new()?.with_field("verifyEmail", true)?;
/// assert_eq!(update.params()?["verifyEmail"], true);
/// assert!(ContactVerificationSettingsUpdate::new().unwrap().params().is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ContactVerificationSettingsUpdate {
    customer: Option<i64>,
    fields: ExtraFields,
}

impl ContactVerificationSettingsUpdate {
    /// Account-wide settings.
    ///
    /// # Errors
    ///
    /// Never today; the signature leaves room for the checks the API enforces on
    /// an empty update.
    ///
    /// ```
    /// use inwx_client::ContactVerificationSettingsUpdate;
    /// assert!(ContactVerificationSettingsUpdate::new().is_ok());
    /// ```
    pub fn new() -> Result<Self> {
        Ok(Self::default())
    }

    /// Targets one customer's settings.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::ContactVerificationSettingsUpdate;
    /// assert!(ContactVerificationSettingsUpdate::new()?.with_customer(1).is_ok());
    /// assert!(ContactVerificationSettingsUpdate::new()?.with_customer(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer(mut self, customer: i64) -> Result<Self> {
        self.customer = Some(params::object_id("customerId", customer)?);
        Ok(self)
    }

    /// Changes one setting.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `key` is not a parameter name, or when a typed
    /// setter already owns it.
    ///
    /// ```
    /// use inwx_client::ContactVerificationSettingsUpdate;
    /// let update = ContactVerificationSettingsUpdate::new()?
    ///     .with_customer(4711)?
    ///     .with_field("verifyEmail", false)?;
    /// let params = update.params()?;
    /// assert_eq!(params["customerId"], 4711);
    /// assert_eq!(params["verifyEmail"], false);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_field(mut self, key: &str, value: impl Into<Value>) -> Result<Self> {
        self.fields.set(key, value.into(), SETTINGS_KEYS)?;
        Ok(self)
    }

    /// The `customer.contactverificationsettingsupdate` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when nothing was set — an update that changes no
    /// setting is rejected by the API with `2003`.
    ///
    /// ```
    /// use inwx_client::ContactVerificationSettingsUpdate;
    /// assert!(ContactVerificationSettingsUpdate::new()?.params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut map = Map::new();
        if let Some(customer) = self.customer {
            map.insert("customerId".to_owned(), json!(customer));
        }
        self.fields.write_into(&mut map);
        params::require_payload(
            "customer.contactverificationsettingsupdate.params",
            map.len(),
        )?;
        Ok(Value::Object(map))
    }
}

impl<T: Transport> InwxClient<T> {
    /// Reads one customer (`customer.info`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let customer = client.customer_info(4711).await?;
    /// println!("{:?} {:?}", customer.name, customer.city);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn customer_info(&self, customer_id: i64) -> Result<Customer> {
        let id = params::object_id("customerId", customer_id)?;
        let data = self
            .call("customer.info", json!({ "customerId": id }))
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Changes a customer record (`customer.update`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{CustomerUpdate, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let update = CustomerUpdate::new(4711)?.with_city("Kolbermoor")?;
    /// let customer = client.update_customer(&update).await?;
    /// println!("{:?}", customer.city);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id or an update without a
    /// changed field, plus the usual transport and API errors.
    pub async fn update_customer(&self, update: &CustomerUpdate) -> Result<Customer> {
        let data = self.call("customer.update", update.params()?).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Deletes a customer record (`customer.delete`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.delete_customer(4711).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn delete_customer(&self, customer_id: i64) -> Result<()> {
        let id = params::object_id("customerId", customer_id)?;
        self.call("customer.delete", json!({ "customerId": id }))
            .await?;
        Ok(())
    }

    /// Lists the generated data-export files (`customer.listdownloads`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{CustomerDownloadQuery, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let page = client
    ///     .list_customer_downloads(&CustomerDownloadQuery::new().with_page(1, 20)?)
    ///     .await?;
    /// for download in &page.downloads {
    ///     println!("{:?} {:?}", download.hash, download.filename);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors; the query itself validates its
    /// paging.
    pub async fn list_customer_downloads(
        &self,
        query: &CustomerDownloadQuery,
    ) -> Result<CustomerDownloadPage> {
        let data = self.call("customer.listdownloads", query.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Asks INWX for a GDPR data export (`customer.requestdataexport`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DataExportRequest, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let export = client
    ///     .request_customer_data_export(&DataExportRequest::new())
    ///     .await?;
    /// println!("{:?}", export.status);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn request_customer_data_export(
        &self,
        request: &DataExportRequest,
    ) -> Result<DataExport> {
        let data = self
            .call("customer.requestdataexport", request.params())
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Reads the contact-verification settings
    /// (`customer.contactverificationsettingsinfo`).
    ///
    /// Pass `Some(customer)` for one customer's settings, `None` for the
    /// account-wide ones.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let settings = client.contact_verification_settings(None).await?;
    /// println!("{:?}", settings.bool_value("verifyEmail"));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive customer id, plus the usual
    /// transport and API errors.
    pub async fn contact_verification_settings(
        &self,
        customer: Option<i64>,
    ) -> Result<ContactVerificationSettings> {
        let mut params = Map::new();
        if let Some(customer) = customer {
            params.insert(
                "customerId".to_owned(),
                json!(params::object_id("customerId", customer)?),
            );
        }
        let data = self
            .call(
                "customer.contactverificationsettingsinfo",
                Value::Object(params),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Changes the contact-verification settings
    /// (`customer.contactverificationsettingsupdate`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{
    ///     ContactVerificationSettingsUpdate, InwxClient, ReqwestTransport,
    /// };
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let update = ContactVerificationSettingsUpdate::new()?.with_field("verifyEmail", true)?;
    /// let settings = client.update_contact_verification_settings(&update).await?;
    /// println!("{:?}", settings.bool_value("verifyEmail"));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the update changes no setting, plus the usual
    /// transport and API errors.
    pub async fn update_contact_verification_settings(
        &self,
        update: &ContactVerificationSettingsUpdate,
    ) -> Result<ContactVerificationSettings> {
        let data = self
            .call(
                "customer.contactverificationsettingsupdate",
                update.params()?,
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_update_without_a_change_is_refused() {
        assert!(CustomerUpdate::new(4711).unwrap().params().is_err());
        assert!(CustomerUpdate::new(4711)
            .unwrap()
            .with_city("Kolbermoor")
            .unwrap()
            .params()
            .is_ok());
    }

    #[test]
    fn ids_stop_at_zero() {
        assert!(CustomerUpdate::new(1).is_ok());
        assert!(CustomerUpdate::new(0).is_err());
        assert!(CustomerUpdate::new(-1).is_err());
        assert!(CustomerDownloadQuery::new().with_customer(1).is_ok());
        assert!(CustomerDownloadQuery::new().with_customer(0).is_err());
    }

    #[test]
    fn address_tokens_stop_at_255_characters() {
        let inside = "a".repeat(255);
        let outside = "a".repeat(256);
        assert!(CustomerUpdate::new(1).unwrap().with_street(&inside).is_ok());
        assert!(CustomerUpdate::new(1)
            .unwrap()
            .with_street(&outside)
            .is_err());
    }

    #[test]
    fn country_codes_stop_at_two_letters() {
        assert_eq!(
            CustomerUpdate::new(1)
                .unwrap()
                .with_country("de")
                .unwrap()
                .params()
                .unwrap()["country"],
            "DE"
        );
        assert!(CustomerUpdate::new(1).unwrap().with_country("d").is_err());
        assert!(CustomerUpdate::new(1).unwrap().with_country("deu").is_err());
    }

    #[test]
    fn page_limit_pair_is_one_and_one_thousand() {
        assert!(CustomerDownloadQuery::new().with_page(1, 1).is_ok());
        assert!(CustomerDownloadQuery::new().with_page(1, 1_000).is_ok());
        assert!(CustomerDownloadQuery::new().with_page(1, 1_001).is_err());
        assert!(CustomerDownloadQuery::new().with_page(1, 0).is_err());
    }

    #[test]
    fn reserved_keys_cannot_be_overridden_by_hand() {
        assert!(CustomerUpdate::new(1)
            .unwrap()
            .with_field("city", "x")
            .is_err());
        assert!(CustomerUpdate::new(1)
            .unwrap()
            .with_field("customerId", 2)
            .is_err());
        assert!(CustomerUpdate::new(1)
            .unwrap()
            .with_field("company", "x")
            .is_ok());
    }

    #[test]
    fn settings_are_read_by_name() {
        let settings: ContactVerificationSettings =
            serde_json::from_str(r#"{"verifyEmail":"1","interval":90,"note":null}"#).unwrap();
        assert_eq!(settings.bool_value("verifyEmail"), Some(true));
        assert_eq!(settings.string_value("interval").as_deref(), Some("90"));
        assert_eq!(settings.string_value("note"), None);
        assert_eq!(settings.bool_value("absent"), None);
        assert_eq!(settings.settings.len(), 3);
    }

    #[test]
    fn both_spellings_of_a_field_are_accepted() {
        let camel: Customer = serde_json::from_str(r#"{"customerNo":"1"}"#).unwrap();
        let snake: Customer = serde_json::from_str(r#"{"customer_no":"1"}"#).unwrap();
        assert_eq!(camel, snake);

        let downloads: CustomerDownloadPage =
            serde_json::from_str(r#"{"download":[{"file_name":"a"}]}"#).unwrap();
        assert_eq!(downloads.downloads[0].filename.as_deref(), Some("a"));
    }

    #[test]
    fn export_request_may_stay_empty() {
        assert_eq!(DataExportRequest::new().params(), serde_json::json!({}));
        assert!(DataExportRequest::new().is_empty());
        assert!(!DataExportRequest::new()
            .with_customer(1)
            .unwrap()
            .is_empty());
    }
}
