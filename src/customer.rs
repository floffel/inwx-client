//! Reseller customers (`customer.*`): the end customers under a reseller
//! account.
//!
//! Seven methods: read a customer, change the address, delete one, read and
//! change the contact-verification settings, list the data exports that have
//! been produced and ask for a new one.
//!
//! Deleting a customer is terminal — the API refuses to undo it — and a data
//! export copies personal data out of the account, so both take an explicit
//! customer number that cannot be guessed from a default.
//!
//! ```
//! use inwx_client::CustomerUpdate;
//!
//! let update = CustomerUpdate::new(123456)?
//!     .with_city("Leipzig")?
//!     .with_zip("04109")?;
//! let params = update.params()?;
//! assert_eq!(params["customerNumber"], 123456);
//! assert_eq!(params["city"], "Leipzig");
//! # Ok::<(), inwx_client::Error>(())
//! ```

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{
    de, parse_rows, validate_country_code, validate_id, validate_page_limit, validate_token,
    validate_upper_token, Email,
};

/// Longest free-text comment this crate sends for a customer.
const MAX_COMMENT_LEN: usize = 4096;
/// Longest verification-mode token.
const MAX_VERIFICATION_TYPE_LEN: usize = 64;

/// One customer of a reseller account.
///
/// ```
/// use inwx_client::Customer;
///
/// let customer: Customer = serde_json::from_str(
///     r#"{"customerNumber":123456,"name":"Max Mustermann","cc":"DE","type":"DIRECT",
///         "currency":"EUR","restricted":0}"#,
/// )?;
/// assert_eq!(customer.customer_number, Some(123_456));
/// assert_eq!(customer.country_code.as_deref(), Some("DE"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Customer {
    /// Customer number, the handle every other call needs.
    #[serde(
        default,
        rename = "customerNumber",
        alias = "customer_number",
        deserialize_with = "de::opt_i64"
    )]
    pub customer_number: Option<i64>,
    /// Name of the contact person.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// Organisation.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub company: Option<String>,
    /// E-mail address.
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
    /// VAT identifier.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub vat: Option<String>,
    /// Currency the customer is billed in.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// Customer class, carried verbatim (`DIRECT`, `RESELLER`, …).
    #[serde(default, rename = "type", deserialize_with = "de::opt_string")]
    pub customer_type: Option<String>,
    /// State of the customer, carried verbatim.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
    /// Reseller above this customer.
    #[serde(
        default,
        rename = "parentCustomerNumber",
        alias = "parent_customer_number",
        deserialize_with = "de::opt_i64"
    )]
    pub parent_customer_number: Option<i64>,
    /// Whether the account is restricted.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub restricted: Option<bool>,
    /// Creation date, as text.
    #[serde(
        default,
        rename = "createdAt",
        alias = "created_at",
        deserialize_with = "de::opt_string"
    )]
    pub created_at: Option<String>,
}

/// The `customer.update` request: the address fields that should change.
///
/// ```
/// use inwx_client::CustomerUpdate;
///
/// let update = CustomerUpdate::new(123456)?
///     .with_email("new@example.com")?
///     .with_country_code("de")?;
/// let params = update.params()?;
/// assert_eq!(params["email"], "new@example.com");
/// assert_eq!(params["cc"], "DE");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomerUpdate {
    customer_number: i64,
    name: Option<String>,
    company: Option<String>,
    email: Option<String>,
    street: Option<String>,
    city: Option<String>,
    zip: Option<String>,
    country_code: Option<String>,
    phone: Option<String>,
    fax: Option<String>,
    vat: Option<String>,
    comment: Option<String>,
    testing: bool,
}

impl CustomerUpdate {
    /// Updates the customer with `customer_number`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive customer number.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    /// assert!(CustomerUpdate::new(1).is_ok());
    /// assert!(CustomerUpdate::new(0).is_err());
    /// ```
    pub fn new(customer_number: i64) -> Result<Self> {
        Ok(Self {
            customer_number: validate_id("customer.number", customer_number)?,
            name: None,
            company: None,
            email: None,
            street: None,
            city: None,
            zip: None,
            country_code: None,
            phone: None,
            fax: None,
            vat: None,
            comment: None,
            testing: false,
        })
    }

    /// Sets the contact person.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name is empty or too long.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    ///
    /// let update = CustomerUpdate::new(1)?.with_name("Max Mustermann")?;
    /// assert_eq!(update.params()?["name"], "Max Mustermann");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_name(mut self, name: impl Into<String>) -> Result<Self> {
        self.name = Some(validated_field("customer.name", &name.into())?);
        Ok(self)
    }

    /// Sets the organisation.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    ///
    /// let update = CustomerUpdate::new(1)?.with_company("ACME GmbH")?;
    /// assert_eq!(update.params()?["company"], "ACME GmbH");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_company(mut self, company: impl Into<String>) -> Result<Self> {
        self.company = Some(validated_field("customer.company", &company.into())?);
        Ok(self)
    }

    /// Sets the e-mail address.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`Email::parse`].
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    ///
    /// let update = CustomerUpdate::new(1)?.with_email("max@example.com")?;
    /// assert_eq!(update.params()?["email"], "max@example.com");
    /// assert!(CustomerUpdate::new(1)?.with_email("nope").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_email(mut self, email: &str) -> Result<Self> {
        self.email = Some(Email::parse(email)?.as_str().to_owned());
        Ok(self)
    }

    /// Sets the street line.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    ///
    /// let update = CustomerUpdate::new(1)?.with_street("Musterstr. 1")?;
    /// assert_eq!(update.params()?["street"], "Musterstr. 1");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_street(mut self, street: impl Into<String>) -> Result<Self> {
        self.street = Some(validated_field("customer.street", &street.into())?);
        Ok(self)
    }

    /// Sets the city.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    ///
    /// let update = CustomerUpdate::new(1)?.with_city("Leipzig")?;
    /// assert_eq!(update.params()?["city"], "Leipzig");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_city(mut self, city: impl Into<String>) -> Result<Self> {
        self.city = Some(validated_field("customer.city", &city.into())?);
        Ok(self)
    }

    /// Sets the postal code.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    ///
    /// let update = CustomerUpdate::new(1)?.with_zip("04109")?;
    /// assert_eq!(update.params()?["zip"], "04109");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_zip(mut self, zip: impl Into<String>) -> Result<Self> {
        self.zip = Some(validated_field("customer.zip", &zip.into())?);
        Ok(self)
    }

    /// Sets the country code.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for anything that is not a two-letter code.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    ///
    /// let update = CustomerUpdate::new(1)?.with_country_code("de")?;
    /// assert_eq!(update.params()?["cc"], "DE");
    /// assert!(CustomerUpdate::new(1)?.with_country_code("ger").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_country_code(mut self, country_code: &str) -> Result<Self> {
        self.country_code = Some(validate_country_code("customer.cc", country_code)?);
        Ok(self)
    }

    /// Sets the phone number.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    ///
    /// let update = CustomerUpdate::new(1)?.with_phone("+49 341 000000")?;
    /// assert_eq!(update.params()?["phone"], "+49 341 000000");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_phone(mut self, phone: impl Into<String>) -> Result<Self> {
        self.phone = Some(validated_field("customer.phone", &phone.into())?);
        Ok(self)
    }

    /// Sets the fax number.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    ///
    /// let update = CustomerUpdate::new(1)?.with_fax("+49 341 000001")?;
    /// assert_eq!(update.params()?["fax"], "+49 341 000001");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_fax(mut self, fax: impl Into<String>) -> Result<Self> {
        self.fax = Some(validated_field("customer.fax", &fax.into())?);
        Ok(self)
    }

    /// Sets the VAT identifier.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    ///
    /// let update = CustomerUpdate::new(1)?.with_vat("DE123456789")?;
    /// assert_eq!(update.params()?["vat"], "DE123456789");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_vat(mut self, vat: impl Into<String>) -> Result<Self> {
        self.vat = Some(validated_field("customer.vat", &vat.into())?);
        Ok(self)
    }

    /// Sets an internal comment.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the comment is empty or too long.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    ///
    /// let update = CustomerUpdate::new(1)?.with_comment("moved 2026-03")?;
    /// assert_eq!(update.params()?["comment"], "moved 2026-03");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_comment(mut self, comment: impl Into<String>) -> Result<Self> {
        let comment = comment.into();
        crate::types::validate_text("customer.comment", &comment, MAX_COMMENT_LEN)?;
        self.comment = Some(comment);
        Ok(self)
    }

    /// Marks the call as a dry run (`testing`).
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    ///
    /// let update = CustomerUpdate::new(1)?.with_city("x")?.with_testing(true);
    /// assert!(update.params()?.get("testing").is_some());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_testing(mut self, testing: bool) -> Self {
        self.testing = testing;
        self
    }

    /// The `customer.update` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when nothing would change.
    ///
    /// ```
    /// use inwx_client::CustomerUpdate;
    ///
    /// assert!(CustomerUpdate::new(1)?.params().is_err());
    /// assert!(CustomerUpdate::new(1)?.with_city("Leipzig")?.params().is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        let changes = [
            self.name.as_deref(),
            self.company.as_deref(),
            self.email.as_deref(),
            self.street.as_deref(),
            self.city.as_deref(),
            self.zip.as_deref(),
            self.country_code.as_deref(),
            self.phone.as_deref(),
            self.fax.as_deref(),
            self.vat.as_deref(),
            self.comment.as_deref(),
        ];
        if changes.iter().all(Option::is_none) {
            return Err(Error::validation(
                "customer.update",
                "needs at least one field to change",
            ));
        }
        let mut params = Map::new();
        params.insert("customerNumber".to_owned(), json!(self.customer_number));
        for (key, value) in [
            ("name", &self.name),
            ("company", &self.company),
            ("email", &self.email),
            ("street", &self.street),
            ("city", &self.city),
            ("zip", &self.zip),
            ("cc", &self.country_code),
            ("phone", &self.phone),
            ("fax", &self.fax),
            ("vat", &self.vat),
            ("comment", &self.comment),
        ] {
            if let Some(value) = value {
                params.insert(key.to_owned(), json!(value));
            }
        }
        if self.testing {
            params.insert("testing".to_owned(), json!(true));
        }
        Ok(Value::Object(params))
    }
}

/// Trims a single-line address field and rejects the unusable values.
fn validated_field(field: &'static str, value: &str) -> Result<String> {
    validate_token(field, value)?;
    Ok(value.trim().to_owned())
}

/// The contact-verification settings of a customer.
///
/// ```
/// use inwx_client::ContactVerificationSettings;
///
/// let settings: ContactVerificationSettings = serde_json::from_str(
///     r#"{"customerNumber":123456,"type":"EMAIL","verified":1,"dueDate":"2026-04-01"}"#,
/// )?;
/// assert_eq!(settings.verification_type.as_deref(), Some("EMAIL"));
/// assert_eq!(settings.is_verified(), Some(true));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ContactVerificationSettings {
    /// Customer the settings belong to.
    #[serde(
        default,
        rename = "customerNumber",
        alias = "customer_number",
        deserialize_with = "de::opt_i64"
    )]
    pub customer_number: Option<i64>,
    /// How verification is done, carried verbatim.
    #[serde(
        default,
        rename = "type",
        alias = "verificationType",
        deserialize_with = "de::opt_string"
    )]
    pub verification_type: Option<String>,
    /// Whether the contact data has been verified.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub verified: Option<bool>,
    /// Date of the last verification, as text.
    #[serde(
        default,
        rename = "verifiedAt",
        alias = "verified_at",
        deserialize_with = "de::opt_string"
    )]
    pub verified_at: Option<String>,
    /// Date verification is due, as text.
    #[serde(
        default,
        rename = "dueDate",
        alias = "due_date",
        deserialize_with = "de::opt_string"
    )]
    pub due_date: Option<String>,
    /// Explanation, when the API sends one.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub message: Option<String>,
}

impl ContactVerificationSettings {
    /// Whether the contact data is verified; `None` when the API does not say.
    ///
    /// ```
    /// use inwx_client::ContactVerificationSettings;
    ///
    /// let settings: ContactVerificationSettings = serde_json::from_str(r#"{"verified":"0"}"#)?;
    /// assert_eq!(settings.is_verified(), Some(false));
    /// assert_eq!(ContactVerificationSettings::default().is_verified(), None);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_verified(&self) -> Option<bool> {
        self.verified
    }
}

/// The `customer.contactverificationsettingsupdate` request.
///
/// ```
/// use inwx_client::ContactVerificationSettingsUpdate;
///
/// let update = ContactVerificationSettingsUpdate::new(123456)?
///     .with_verification_type("email")?
///     .with_verified(true);
/// let params = update.params()?;
/// assert_eq!(params["type"], "EMAIL");
/// assert_eq!(params["verified"], true);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactVerificationSettingsUpdate {
    customer_number: i64,
    verification_type: Option<String>,
    verified: Option<bool>,
    testing: bool,
}

impl ContactVerificationSettingsUpdate {
    /// Changes the settings of the customer with `customer_number`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive customer number.
    ///
    /// ```
    /// use inwx_client::ContactVerificationSettingsUpdate;
    /// assert!(ContactVerificationSettingsUpdate::new(1).is_ok());
    /// assert!(ContactVerificationSettingsUpdate::new(0).is_err());
    /// ```
    pub fn new(customer_number: i64) -> Result<Self> {
        Ok(Self {
            customer_number: validate_id("customer.number", customer_number)?,
            verification_type: None,
            verified: None,
            testing: false,
        })
    }

    /// Sets how verification is done (`type`, upper-cased).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or oddly shaped token.
    ///
    /// ```
    /// use inwx_client::ContactVerificationSettingsUpdate;
    ///
    /// let update = ContactVerificationSettingsUpdate::new(1)?.with_verification_type("email")?;
    /// assert_eq!(update.params()?["type"], "EMAIL");
    /// assert!(ContactVerificationSettingsUpdate::new(1)?.with_verification_type("").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_verification_type(mut self, verification_type: impl Into<String>) -> Result<Self> {
        self.verification_type = Some(validate_upper_token(
            "customer.verificationType",
            &verification_type.into(),
            MAX_VERIFICATION_TYPE_LEN,
        )?);
        Ok(self)
    }

    /// Marks the contact data as verified or unverified.
    ///
    /// ```
    /// use inwx_client::ContactVerificationSettingsUpdate;
    ///
    /// let update = ContactVerificationSettingsUpdate::new(1)?.with_verified(true);
    /// assert_eq!(update.params()?["verified"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_verified(mut self, verified: bool) -> Self {
        self.verified = Some(verified);
        self
    }

    /// Marks the call as a dry run (`testing`).
    ///
    /// ```
    /// use inwx_client::ContactVerificationSettingsUpdate;
    ///
    /// let update = ContactVerificationSettingsUpdate::new(1)?
    ///     .with_verified(false)
    ///     .with_testing(true);
    /// assert!(update.params()?.get("testing").is_some());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_testing(mut self, testing: bool) -> Self {
        self.testing = testing;
        self
    }

    /// The parameters for the call.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when nothing would change.
    ///
    /// ```
    /// use inwx_client::ContactVerificationSettingsUpdate;
    ///
    /// assert!(ContactVerificationSettingsUpdate::new(1)?.params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        if self.verification_type.is_none() && self.verified.is_none() {
            return Err(Error::validation(
                "customer.contactverificationsettingsupdate",
                "needs a verification type or a verified flag",
            ));
        }
        let mut params = Map::new();
        params.insert("customerNumber".to_owned(), json!(self.customer_number));
        if let Some(verification_type) = &self.verification_type {
            params.insert("type".to_owned(), json!(verification_type));
        }
        if let Some(verified) = self.verified {
            params.insert("verified".to_owned(), json!(verified));
        }
        if self.testing {
            params.insert("testing".to_owned(), json!(true));
        }
        Ok(Value::Object(params))
    }
}

/// A produced data export (`customer.listdownloads`).
///
/// ```
/// use inwx_client::CustomerDownload;
///
/// let download: CustomerDownload = serde_json::from_str(
///     r#"{"id":44,"filename":"export-123456.zip","status":"READY","createdAt":"2026-03-01"}"#,
/// )?;
/// assert_eq!(download.id, Some(44));
/// assert_eq!(download.status.as_deref(), Some("READY"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct CustomerDownload {
    /// Download id.
    #[serde(
        default,
        rename = "downloadId",
        alias = "id",
        deserialize_with = "de::opt_i64"
    )]
    pub id: Option<i64>,
    /// File name of the export.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub filename: Option<String>,
    /// State of the export, carried verbatim.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
    /// Size in bytes, when the API reports one.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub size: Option<i64>,
    /// Creation date, as text.
    #[serde(
        default,
        rename = "createdAt",
        alias = "created_at",
        deserialize_with = "de::opt_string"
    )]
    pub created_at: Option<String>,
    /// Expiry date of the download, as text.
    #[serde(
        default,
        rename = "expiresAt",
        alias = "expires_at",
        deserialize_with = "de::opt_string"
    )]
    pub expires_at: Option<String>,
}

/// A paging request for `customer.listdownloads`.
///
/// ```
/// use inwx_client::CustomerDownloadQuery;
///
/// let params = CustomerDownloadQuery::new(123456)?.with_page(1, 10)?.params()?;
/// assert_eq!(params["customerNumber"], 123456);
/// assert_eq!(params["pagelimit"], 10);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomerDownloadQuery {
    customer_number: i64,
    page: Option<u32>,
    limit: Option<u32>,
}

impl CustomerDownloadQuery {
    /// Lists the exports of one customer.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive customer number.
    ///
    /// ```
    /// use inwx_client::CustomerDownloadQuery;
    /// assert!(CustomerDownloadQuery::new(1).is_ok());
    /// assert!(CustomerDownloadQuery::new(0).is_err());
    /// ```
    pub fn new(customer_number: i64) -> Result<Self> {
        Ok(Self {
            customer_number: validate_id("customer.number", customer_number)?,
            page: None,
            limit: None,
        })
    }

    /// Sets the page (1-based) and the page size.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the page size is zero.
    ///
    /// ```
    /// use inwx_client::CustomerDownloadQuery;
    ///
    /// assert_eq!(CustomerDownloadQuery::new(1)?.with_page(1, 1)?.params()?["page"], 1);
    /// assert!(CustomerDownloadQuery::new(1)?.with_page(1, 0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_page(mut self, page: u32, limit: u32) -> Result<Self> {
        self.limit = Some(validate_page_limit(limit)?);
        self.page = Some(page.max(1));
        Ok(self)
    }

    /// The `customer.listdownloads` parameters.
    ///
    /// # Errors
    ///
    /// Never fails today: every value is validated when it is set, so the
    /// parameters are always sendable. The `Result` keeps the shape of the
    /// builders that can refuse a value.
    ///
    /// ```
    /// use inwx_client::CustomerDownloadQuery;
    /// assert_eq!(CustomerDownloadQuery::new(7)?.params()?["customerNumber"], 7);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut params = Map::new();
        params.insert("customerNumber".to_owned(), json!(self.customer_number));
        params.insert("page".to_owned(), json!(self.page.unwrap_or(1)));
        params.insert("pagelimit".to_owned(), json!(self.limit.unwrap_or(50)));
        Ok(Value::Object(params))
    }
}

/// The answer of `customer.requestdataexport`.
///
/// ```
/// use inwx_client::DataExport;
///
/// let export: DataExport =
///     serde_json::from_str(r#"{"downloadId":44,"status":"PENDING","filename":"export.zip"}"#)?;
/// assert_eq!(export.id, Some(44));
/// assert!(export.is_pending());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DataExport {
    /// Id of the export that will appear in `listdownloads`.
    #[serde(
        default,
        rename = "downloadId",
        alias = "id",
        deserialize_with = "de::opt_i64"
    )]
    pub id: Option<i64>,
    /// State of the export, carried verbatim.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
    /// File name once it is built.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub filename: Option<String>,
    /// Explanation, when the API sends one.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub message: Option<String>,
}

impl DataExport {
    /// Whether the export still has to be built.
    ///
    /// ```
    /// use inwx_client::DataExport;
    ///
    /// let pending: DataExport = serde_json::from_str(r#"{"status":"pending"}"#)?;
    /// assert!(pending.is_pending());
    /// assert!(!DataExport::default().is_pending());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.status
            .as_deref()
            .is_some_and(|status| status.eq_ignore_ascii_case("PENDING"))
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
    /// let customer = client.customer_info(123456).await?;
    /// println!("{:?} {:?}", customer.name, customer.currency);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive customer number, plus the usual
    /// transport and API errors — `2303` when the customer does not exist.
    pub async fn customer_info(&self, customer_number: i64) -> Result<Customer> {
        validate_id("customer.number", customer_number)?;
        let data = self
            .call(
                "customer.info",
                json!({ "customerNumber": customer_number }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Changes a customer address (`customer.update`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{CustomerUpdate, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let update = CustomerUpdate::new(123456)?.with_city("Leipzig")?;
    /// client.update_customer(&update).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive number, an unusable field or an
    /// update with no change, plus the usual transport and API errors.
    pub async fn update_customer(&self, update: &CustomerUpdate) -> Result<()> {
        let params = update.params()?;
        self.call("customer.update", params).await?;
        Ok(())
    }

    /// Deletes a customer (`customer.delete`).
    ///
    /// This is terminal: the customer and the handles that belong to it are
    /// gone, and the API has no undo.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.delete_customer(123456).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive customer number, plus the usual
    /// transport and API errors — `4002` while the customer still holds objects.
    pub async fn delete_customer(&self, customer_number: i64) -> Result<()> {
        validate_id("customer.number", customer_number)?;
        self.call(
            "customer.delete",
            json!({ "customerNumber": customer_number }),
        )
        .await?;
        Ok(())
    }

    /// Reads the contact-verification settings (`customer.contactverificationsettingsinfo`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let settings = client.contact_verification_settings(123456).await?;
    /// println!("{:?} {:?}", settings.verification_type, settings.due_date);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive customer number, plus the usual
    /// transport and API errors.
    pub async fn contact_verification_settings(
        &self,
        customer_number: i64,
    ) -> Result<ContactVerificationSettings> {
        validate_id("customer.number", customer_number)?;
        let data = self
            .call(
                "customer.contactverificationsettingsinfo",
                json!({ "customerNumber": customer_number }),
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
    /// let update = ContactVerificationSettingsUpdate::new(123456)?
    ///     .with_verification_type("email")?;
    /// client.update_contact_verification_settings(&update).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive number or an update with no
    /// field, plus the usual transport and API errors.
    pub async fn update_contact_verification_settings(
        &self,
        update: &ContactVerificationSettingsUpdate,
    ) -> Result<()> {
        let params = update.params()?;
        self.call("customer.contactverificationsettingsupdate", params)
            .await?;
        Ok(())
    }

    /// Lists the produced data exports (`customer.listdownloads`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{CustomerDownloadQuery, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let query = CustomerDownloadQuery::new(123456)?;
    /// for download in client.list_customer_downloads(&query).await? {
    ///         println!("{:?} {:?}", download.filename, download.status);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive customer number or a zero page
    /// size, plus the usual transport and API errors.
    pub async fn list_customer_downloads(
        &self,
        query: &CustomerDownloadQuery,
    ) -> Result<Vec<CustomerDownload>> {
        let params = query.params()?;
        let data = self.call("customer.listdownloads", params).await?;
        Ok(parse_rows(&data, "download"))
    }

    /// Asks for a copy of the customer's data (`customer.requestdataexport`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let export = client.request_customer_data_export(123456).await?;
    /// println!("{:?} {:?}", export.id, export.status);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive customer number, plus the usual
    /// transport and API errors.
    pub async fn request_customer_data_export(&self, customer_number: i64) -> Result<DataExport> {
        validate_id("customer.number", customer_number)?;
        let data = self
            .call(
                "customer.requestdataexport",
                json!({ "customerNumber": customer_number }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn customer_numbers_must_be_positive() {
        assert!(CustomerUpdate::new(1).is_ok());
        assert!(CustomerUpdate::new(0).is_err());
        assert!(CustomerDownloadQuery::new(-2).is_err());
    }

    #[test]
    fn a_name_of_255_characters_is_accepted_and_256_is_not() {
        let ok = "n".repeat(255);
        let too_long = format!("{ok}n");
        assert!(CustomerUpdate::new(1).unwrap().with_name(ok).is_ok());
        assert!(CustomerUpdate::new(1).unwrap().with_name(too_long).is_err());
    }

    #[test]
    fn a_comment_of_4096_characters_is_accepted_and_4097_is_not() {
        let ok = "c".repeat(4096);
        let too_long = format!("{ok}c");
        assert!(CustomerUpdate::new(1).unwrap().with_comment(ok).is_ok());
        assert!(CustomerUpdate::new(1)
            .unwrap()
            .with_comment(too_long)
            .is_err());
    }

    #[test]
    fn a_country_code_is_two_letters() {
        assert_eq!(
            CustomerUpdate::new(1)
                .unwrap()
                .with_country_code("de")
                .unwrap()
                .params()
                .unwrap()["cc"],
            "DE"
        );
        for bad in ["", "D", "ger", "D3"] {
            assert!(
                CustomerUpdate::new(1)
                    .unwrap()
                    .with_country_code(bad)
                    .is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn an_email_is_parsed_before_the_wire() {
        assert!(CustomerUpdate::new(1)
            .unwrap()
            .with_email("max@example.com")
            .is_ok());
        assert!(CustomerUpdate::new(1)
            .unwrap()
            .with_email("max@example")
            .is_err());
    }

    #[test]
    fn an_update_needs_a_change() {
        assert!(CustomerUpdate::new(1).unwrap().params().is_err());
        assert!(CustomerUpdate::new(1)
            .unwrap()
            .with_city("Leipzig")
            .unwrap()
            .params()
            .is_ok());
        assert!(ContactVerificationSettingsUpdate::new(1)
            .unwrap()
            .params()
            .is_err());
    }

    #[test]
    fn a_page_limit_of_one_is_accepted_and_zero_is_not() {
        assert!(CustomerDownloadQuery::new(1)
            .unwrap()
            .with_page(1, 1)
            .is_ok());
        assert!(CustomerDownloadQuery::new(1)
            .unwrap()
            .with_page(1, 0)
            .is_err());
    }

    #[test]
    fn customers_are_parsed_permissively() {
        let camel: Customer =
            serde_json::from_str(r#"{"customerNumber":"7","cc":"de","restricted":"1"}"#).unwrap();
        let snake: Customer =
            serde_json::from_str(r#"{"customer_number":7,"country":"de","restricted":true}"#)
                .unwrap();
        assert_eq!(camel, snake);
        assert_eq!(camel.restricted, Some(true));

        let settings: ContactVerificationSettings =
            serde_json::from_str(r#"{"verificationType":"EMAIL","due_date":"2026-04-01"}"#)
                .unwrap();
        assert_eq!(settings.verification_type.as_deref(), Some("EMAIL"));
        assert_eq!(settings.due_date.as_deref(), Some("2026-04-01"));

        let downloads: Vec<CustomerDownload> =
            parse_rows(&json!({"download": {"id": 1}}), "download");
        assert_eq!(downloads.len(), 1);
    }
}
