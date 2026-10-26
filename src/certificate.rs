//! SSL certificates (`certificate.*`): products, orders, renewal and the
//! order-completion flow.
//!
//! An order is a two-step affair when data is missing: `certificate.create`
//! answers with a `missing` list, and `certificate.updateOrder` supplies the
//! rest. Both halves are modelled, and the local checks copy the documented
//! rules: a product id is required, a CSR or a common name is required, an
//! email validation needs an address, and a CSR must never contain a private
//! key.
//!
//! ```
//! use inwx_client::{CertificateOrder, CertificateTerm, DomainName};
//!
//! let order = CertificateOrder::new(17)?
//!     .with_common_name(DomainName::parse("example.com")?)
//!     .with_term(CertificateTerm::TwoYears);
//!
//! assert_eq!(order.params()?["productId"], 17);
//! assert_eq!(order.params()?["period"], 2);
//! # Ok::<(), inwx_client::Error>(())
//! ```

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, validate_token, DomainName, Email, Handle};

/// Longest CSR the API accepts (`text`, 10000 characters).
pub const MAX_CSR_LEN: usize = 10_000;

/// A certificate id.
///
/// ```
/// use inwx_client::CertificateId;
///
/// let id = CertificateId::new(4711)?;
/// assert_eq!(id.get(), 4711);
/// assert_eq!(id.to_string(), "4711");
/// assert!(CertificateId::new(0).is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CertificateId(i64);

impl CertificateId {
    /// Validates a certificate id.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the id is not positive.
    ///
    /// ```
    /// use inwx_client::CertificateId;
    /// assert!(CertificateId::new(1).is_ok());
    /// assert!(CertificateId::new(-5).is_err());
    /// ```
    pub fn new(id: i64) -> Result<Self> {
        if id <= 0 {
            return Err(Error::validation(
                "certificateId",
                format!("must be a positive certificate id, got {id}"),
            ));
        }
        Ok(Self(id))
    }

    /// The id as sent on the wire.
    ///
    /// ```
    /// use inwx_client::CertificateId;
    /// assert_eq!(CertificateId::new(9)?.get(), 9);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Display for CertificateId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// How the certificate authority verifies domain control
/// (`validationMethod`).
///
/// ```
/// use inwx_client::CertificateValidationMethod;
///
/// assert_eq!(CertificateValidationMethod::Dns.as_str(), "DNS");
/// assert_eq!("email".parse::<CertificateValidationMethod>()?, CertificateValidationMethod::Email);
/// assert!("phone".parse::<CertificateValidationMethod>().is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertificateValidationMethod {
    /// A verification email to `validationEmail`.
    Email,
    /// A `_acme-challenge`-style DNS record.
    Dns,
    /// A file served from the domain.
    File,
}

impl CertificateValidationMethod {
    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::CertificateValidationMethod;
    /// assert_eq!(CertificateValidationMethod::File.as_str(), "FILE");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "EMAIL",
            Self::Dns => "DNS",
            Self::File => "FILE",
        }
    }
}

impl fmt::Display for CertificateValidationMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CertificateValidationMethod {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        match input.trim().to_ascii_uppercase().as_str() {
            "EMAIL" => Ok(Self::Email),
            "DNS" => Ok(Self::Dns),
            "FILE" => Ok(Self::File),
            other => Err(Error::validation(
                "validationMethod",
                format!("{other:?} is not one of EMAIL, DNS, FILE"),
            )),
        }
    }
}

impl serde::Serialize for CertificateValidationMethod {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// The term of a certificate, in years (`period`, documented as 1 or 2).
///
/// ```
/// use inwx_client::CertificateTerm;
///
/// assert_eq!(CertificateTerm::OneYear.years(), 1);
/// assert_eq!(CertificateTerm::TwoYears.years(), 2);
/// assert!(CertificateTerm::try_from(3u8).is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CertificateTerm {
    /// The API default.
    #[default]
    OneYear,
    /// Two years.
    TwoYears,
}

impl CertificateTerm {
    /// The number of years.
    ///
    /// ```
    /// use inwx_client::CertificateTerm;
    /// assert_eq!(CertificateTerm::TwoYears.years(), 2);
    /// ```
    #[must_use]
    pub fn years(self) -> u8 {
        match self {
            Self::OneYear => 1,
            Self::TwoYears => 2,
        }
    }
}

impl TryFrom<u8> for CertificateTerm {
    type Error = Error;

    /// # Errors
    ///
    /// [`Error::Validation`] for anything but 1 or 2 years.
    ///
    /// ```
    /// use inwx_client::CertificateTerm;
    /// assert!(CertificateTerm::try_from(1u8).is_ok());
    /// assert!(CertificateTerm::try_from(0u8).is_err());
    /// ```
    fn try_from(years: u8) -> Result<Self> {
        match years {
            1 => Ok(Self::OneYear),
            2 => Ok(Self::TwoYears),
            other => Err(Error::validation(
                "certificate.period",
                format!("must be 1 or 2 years, got {other}"),
            )),
        }
    }
}

/// A purchased certificate, from `certificate.info` or `certificate.list`.
///
/// ```
/// use inwx_client::Certificate;
///
/// let certificate: Certificate = serde_json::from_str(
///     r#"{"id":9,"productId":17,"status":"ACTIVE","active":1,
///         "commonName":["example.com"],"san":"www.example.com,shop.example.com",
///         "validationMethod":"DNS","autorenew":true}"#,
/// )?;
/// assert_eq!(certificate.id, Some(9));
/// assert!(certificate.is_active());
/// assert_eq!(certificate.san_list(), ["www.example.com", "shop.example.com"]);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Certificate {
    /// Certificate id.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Product id.
    #[serde(default, rename = "productId", deserialize_with = "de::opt_i64")]
    pub product_id: Option<i64>,
    /// Creation date.
    #[serde(default, rename = "creationDate", deserialize_with = "de::opt_string")]
    pub creation_date: Option<String>,
    /// Expiry date.
    #[serde(
        default,
        rename = "expirationDate",
        deserialize_with = "de::opt_string"
    )]
    pub expiration_date: Option<String>,
    /// Last update.
    #[serde(default, rename = "updatedAt", deserialize_with = "de::opt_string")]
    pub updated_at: Option<String>,
    /// Term in years.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub period: Option<i64>,
    /// The CSR that was submitted.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub csr: Option<String>,
    /// SANs that came from the CSR.
    #[serde(default, rename = "sanFromCsr", deserialize_with = "de::vec_string")]
    pub san_from_csr: Vec<String>,
    /// The certificate (PEM).
    #[serde(default, deserialize_with = "de::opt_string")]
    pub certificate: Option<String>,
    /// CA chain (PEM).
    #[serde(default, rename = "caChain", deserialize_with = "de::opt_string")]
    pub ca_chain: Option<String>,
    /// Validation method.
    #[serde(
        default,
        rename = "validationMethod",
        deserialize_with = "de::opt_string"
    )]
    pub validation_method: Option<String>,
    /// Validation email.
    #[serde(
        default,
        rename = "validationEmail",
        deserialize_with = "de::opt_string"
    )]
    pub validation_email: Option<String>,
    /// Validation token for DNS/FILE.
    #[serde(
        default,
        rename = "validationToken",
        deserialize_with = "de::opt_string"
    )]
    pub validation_token: Option<String>,
    /// Owner contact handle.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub ownerc: Option<i64>,
    /// Admin contact handle.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub adminc: Option<i64>,
    /// Tech contact handle.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub techc: Option<i64>,
    /// Status string.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
    /// Common names.
    #[serde(default, rename = "commonName", deserialize_with = "de::vec_string")]
    pub common_name: Vec<String>,
    /// SANs, comma separated.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub san: Option<String>,
    /// Number of SANs the certificate may carry.
    #[serde(default, rename = "numberOfSan", deserialize_with = "de::opt_i64")]
    pub number_of_san: Option<i64>,
    /// Number of wildcard SANs the certificate may carry.
    #[serde(
        default,
        rename = "numberOfWildcardSan",
        deserialize_with = "de::opt_i64"
    )]
    pub number_of_wildcard_san: Option<i64>,
    /// Whether the certificate is usable.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub active: Option<bool>,
    /// Whether a hosting option is attached.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub hosting: Option<bool>,
    /// Whether the certificate renews itself.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub autorenew: Option<bool>,
    /// Product name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// Product brand.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub brand: Option<String>,
    /// Certificate type (`DV`, `OV`, `EV`).
    #[serde(default, rename = "type", deserialize_with = "de::opt_string")]
    pub kind: Option<String>,
    /// Whether the certificate is a wildcard product.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub wildcard: Option<bool>,
    /// Predecessor certificate id.
    #[serde(default, rename = "renewedFrom", deserialize_with = "de::opt_i64")]
    pub renewed_from: Option<i64>,
    /// Order reference.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub tracenumber: Option<String>,
}

impl Certificate {
    /// Whether the API reports the certificate as usable.
    ///
    /// ```
    /// use inwx_client::Certificate;
    ///
    /// let unknown: Certificate = serde_json::from_str(r#"{"id":1}"#)?;
    /// assert!(!unknown.is_active());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active == Some(true)
    }

    /// The SAN list, split out of the comma separated `san` field.
    ///
    /// ```
    /// use inwx_client::Certificate;
    ///
    /// let certificate: Certificate = serde_json::from_str(r#"{"san":"a.example.com, b.example.com"}"#)?;
    /// assert_eq!(certificate.san_list(), ["a.example.com", "b.example.com"]);
    ///
    /// let none: Certificate = serde_json::from_str(r#"{}"#)?;
    /// assert!(none.san_list().is_empty());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn san_list(&self) -> Vec<String> {
        self.san
            .as_deref()
            .map(|san| {
                san.split(',')
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// A certificate product, from `certificate.getProduct` and
/// `certificate.listProducts`.
///
/// ```
/// use inwx_client::CertificateProduct;
///
/// let product: CertificateProduct = serde_json::from_str(
///     r#"{"id":17,"name":"DomainValidation","brand":"ExampleCA","type":"DV",
///         "san":5,"freeSanIncluded":1,"wildcard":false,"price1year":39.9,
///         "currency":"EUR"}"#,
/// )?;
/// assert!(!product.is_wildcard());
/// assert_eq!(product.free_san_included, Some(1));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct CertificateProduct {
    /// Product id, needed to order.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Product name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// Brand.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub brand: Option<String>,
    /// Description.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub description: Option<String>,
    /// Certificate type (`DV`, `OV`, `EV`).
    #[serde(default, rename = "type", deserialize_with = "de::opt_string")]
    pub kind: Option<String>,
    /// Number of SANs that can be purchased.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub san: Option<i64>,
    /// Free SANs included.
    #[serde(default, rename = "freeSanIncluded", deserialize_with = "de::opt_i64")]
    pub free_san_included: Option<i64>,
    /// Whether this is a wildcard product.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub wildcard: Option<bool>,
    /// Issuance time.
    #[serde(default, rename = "issuanceTime", deserialize_with = "de::opt_string")]
    pub issuance_time: Option<String>,
    /// Unit of the issuance time.
    #[serde(
        default,
        rename = "issuanceTimeUnit",
        deserialize_with = "de::opt_string"
    )]
    pub issuance_time_unit: Option<String>,
    /// Warranty amount.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub warranty: Option<i64>,
    /// Warranty currency.
    #[serde(
        default,
        rename = "warrantyCurrency",
        deserialize_with = "de::opt_string"
    )]
    pub warranty_currency: Option<String>,
    /// Whether a reissue is free.
    #[serde(default, rename = "freeReissue", deserialize_with = "de::opt_bool")]
    pub free_reissue: Option<bool>,
    /// Price for one year, without VAT.
    #[serde(default, rename = "price1year", deserialize_with = "de::opt_f64")]
    pub price_1_year: Option<f64>,
    /// Currency of the prices.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// Price per additional SAN and year.
    #[serde(default, rename = "pricePerSan1Year", deserialize_with = "de::opt_f64")]
    pub price_per_san_1_year: Option<f64>,
}

impl CertificateProduct {
    /// Whether the product secures unlimited subdomains.
    ///
    /// ```
    /// use inwx_client::CertificateProduct;
    ///
    /// let wildcard: CertificateProduct = serde_json::from_str(r#"{"wildcard":1}"#)?;
    /// assert!(wildcard.is_wildcard());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.wildcard == Some(true)
    }
}

/// The answer to `certificate.create`, `certificate.renew`,
/// `certificate.reissue` and `certificate.updateOrder`.
///
/// ```
/// use inwx_client::CertificateOrderResult;
///
/// let result: CertificateOrderResult = serde_json::from_str(
///     r#"{"certificateId":9,"status":"PENDING","price":39.9,"missing":["csr"]}"#,
/// )?;
/// assert_eq!(result.certificate_id, Some(9));
/// assert_eq!(result.missing, ["csr"]);
/// assert!(!result.is_complete());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct CertificateOrderResult {
    /// The certificate id.
    #[serde(default, rename = "certificateId", deserialize_with = "de::opt_i64")]
    pub certificate_id: Option<i64>,
    /// Status string.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
    /// Total price including SAN and VAT.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub price: Option<f64>,
    /// Values still needed to complete the order (`csr`,
    /// `validationMethod`, `validationEmail`, `ownerc`, `adminc`, `techc`).
    #[serde(default, deserialize_with = "de::vec_string")]
    pub missing: Vec<String>,
}

impl CertificateOrderResult {
    /// Whether the order needs no further data.
    ///
    /// ```
    /// use inwx_client::CertificateOrderResult;
    ///
    /// let done: CertificateOrderResult = serde_json::from_str(r#"{"certificateId":9}"#)?;
    /// assert!(done.is_complete());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }
}

/// The missing values of an order (`certificate.listRemainingNeededData`).
///
/// ```
/// use inwx_client::CertificateMissingData;
///
/// let data: CertificateMissingData = serde_json::from_str(
///     r#"{"certificateId":"9","missing":["csr","validationMethod"]}"#,
/// )?;
/// assert_eq!(data.certificate_id.as_deref(), Some("9"));
/// assert_eq!(data.missing.len(), 2);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct CertificateMissingData {
    /// Certificate id, as a string — the API types this field `text`.
    #[serde(default, rename = "certificateId", deserialize_with = "de::opt_string")]
    pub certificate_id: Option<String>,
    /// The values still missing.
    #[serde(default, deserialize_with = "de::vec_string")]
    pub missing: Vec<String>,
}

/// One line of the certificate log (`certificate.log`).
///
/// ```
/// use inwx_client::CertificateLogEntry;
///
/// let entry: CertificateLogEntry = serde_json::from_str(
///     r#"{"certificateId":9,"commonName":["example.com"],"status":"ISSUED",
///         "price":39.9,"netto":33.53,"vat":19.0}"#,
/// )?;
/// assert_eq!(entry.certificate_id, Some(9));
/// assert_eq!(entry.net_price(), 33.53);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct CertificateLogEntry {
    /// Certificate id.
    #[serde(default, rename = "certificateId", deserialize_with = "de::opt_i64")]
    pub certificate_id: Option<i64>,
    /// Common names.
    #[serde(default, rename = "commonName", deserialize_with = "de::vec_string")]
    pub common_name: Vec<String>,
    /// When the log line was written.
    #[serde(default, rename = "creationDate", deserialize_with = "de::opt_string")]
    pub creation_date: Option<String>,
    /// Status.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
    /// Status details.
    #[serde(default, rename = "statusDetails", deserialize_with = "de::opt_string")]
    pub status_details: Option<String>,
    /// Gross price.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub price: Option<f64>,
    /// Net price.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub netto: Option<f64>,
    /// VAT rate.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub vat: Option<f64>,
    /// Product name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// Brand.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub brand: Option<String>,
}

impl CertificateLogEntry {
    /// The net price, or `0.0` when the API did not report one.
    ///
    /// ```
    /// use inwx_client::CertificateLogEntry;
    ///
    /// let entry: CertificateLogEntry = serde_json::from_str(r#"{}"#)?;
    /// assert!(entry.net_price() < f64::EPSILON);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn net_price(&self) -> f64 {
        self.netto.unwrap_or(0.0)
    }
}

/// A `certificate.create` order.
///
/// ```
/// use inwx_client::{CertificateOrder, CertificateTerm, DomainName};
///
/// let order = CertificateOrder::new(17)?
///     .with_csr("-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----")?
///     .with_sans(&[DomainName::parse("www.example.com")?])?
///     .with_term(CertificateTerm::OneYear);
///
/// assert_eq!(order.params()?["san"], "www.example.com");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateOrder {
    product_id: i64,
    csr: Option<String>,
    common_name: Option<DomainName>,
    sans: Vec<String>,
    term: Option<CertificateTerm>,
    validation_method: Option<CertificateValidationMethod>,
    validation_email: Option<Email>,
    owner: Option<Handle>,
    admin: Option<Handle>,
    tech: Option<Handle>,
    number_of_san: Option<u16>,
    number_of_wildcard_san: Option<u16>,
    hosting: Option<bool>,
    autorenew: Option<bool>,
    testing: bool,
}

impl CertificateOrder {
    /// An order for `product_id`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive product id.
    ///
    /// ```
    /// use inwx_client::{CertificateOrder, DomainName};
    /// assert!(CertificateOrder::new(17).is_ok());
    /// assert!(CertificateOrder::new(0).is_err());
    /// ```
    pub fn new(product_id: i64) -> Result<Self> {
        if product_id <= 0 {
            return Err(Error::validation(
                "certificate.productId",
                format!("must be a positive product id, got {product_id}"),
            ));
        }
        Ok(Self {
            product_id,
            csr: None,
            common_name: None,
            sans: Vec::new(),
            term: None,
            validation_method: None,
            validation_email: None,
            owner: None,
            admin: None,
            tech: None,
            number_of_san: None,
            number_of_wildcard_san: None,
            hosting: None,
            autorenew: None,
            testing: false,
        })
    }

    /// Sets the CSR.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the CSR is empty, longer than
    /// [`MAX_CSR_LEN`], or contains a private key — the API asks for a
    /// certificate signing request, and a key in that field would upload a
    /// secret to a third party.
    ///
    /// ```
    /// use inwx_client::{CertificateOrder, DomainName};
    ///
    /// let order = CertificateOrder::new(17)?;
    /// assert!(order.clone().with_csr("-----BEGIN PRIVATE KEY-----\nMIIB").is_err());
    /// assert!(order.with_csr("-----BEGIN CERTIFICATE REQUEST-----\nMIIB").is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_csr(mut self, csr: impl Into<String>) -> Result<Self> {
        self.csr = Some(validate_csr(&csr.into())?);
        Ok(self)
    }

    /// Sets the main domain (`commonName`), for orders without a CSR.
    ///
    /// ```
    /// use inwx_client::{CertificateOrder, DomainName};
    ///
    /// let order = CertificateOrder::new(17)?
    ///     .with_common_name(DomainName::parse("example.com")?);
    /// assert_eq!(order.params()?["commonName"], "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_common_name(mut self, domain: DomainName) -> Self {
        self.common_name = Some(domain);
        self
    }

    /// Sets the SANs (subject alternative names).
    ///
    /// A wildcard SAN (`*.example.com`) is accepted here because certificate
    /// products sell them; [`DomainName`] cannot represent a `*` label, so the
    /// wildcard is validated by its suffix.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty list, a duplicate, or a name that is
    /// neither a domain nor a single leftmost wildcard.
    ///
    /// ```
    /// use inwx_client::{CertificateOrder, DomainName};
    ///
    /// let order = CertificateOrder::new(17)?
    ///     .with_common_name(DomainName::parse("example.com")?)
    ///     .with_sans(&[DomainName::parse("www.example.com")?])?;
    /// assert_eq!(order.params()?["san"], "www.example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_sans(mut self, domains: &[DomainName]) -> Result<Self> {
        if domains.is_empty() {
            return Err(Error::validation("certificate.san", "must not be empty"));
        }
        for (index, domain) in domains.iter().enumerate() {
            if domains[..index].contains(domain) {
                return Err(Error::validation(
                    "certificate.san",
                    format!("{domain} is listed twice"),
                ));
            }
            self.sans.push(domain.as_str().to_owned());
        }
        Ok(self)
    }

    /// Adds one wildcard SAN such as `*.example.com`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not a single leftmost `*` label
    /// followed by a valid domain.
    ///
    /// ```
    /// use inwx_client::{CertificateOrder, DomainName};
    ///
    /// let order = CertificateOrder::new(17)?
    ///     .with_common_name(DomainName::parse("example.com")?)
    ///     .with_wildcard_san("*.example.com")?;
    /// assert_eq!(order.params()?["san"], "*.example.com");
    /// assert!(CertificateOrder::new(17)?.with_wildcard_san("*.*.example.com").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_wildcard_san(mut self, wildcard: &str) -> Result<Self> {
        let name = validate_wildcard(wildcard)?;
        self.sans.push(name);
        Ok(self)
    }

    /// Sets the term (`period`).
    ///
    /// ```
    /// use inwx_client::{CertificateOrder, CertificateTerm, DomainName};
    ///
    /// let order = CertificateOrder::new(17)?
    ///     .with_common_name(DomainName::parse("example.com")?)
    ///     .with_term(CertificateTerm::TwoYears);
    /// assert_eq!(order.params()?["period"], 2);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_term(mut self, term: CertificateTerm) -> Self {
        self.term = Some(term);
        self
    }

    /// Sets the validation method.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when an `EMAIL` method is requested without an
    /// email address, or a non-email method carries one.
    ///
    /// ```
    /// use inwx_client::{CertificateOrder, CertificateValidationMethod, DomainName};
    ///
    /// let order = CertificateOrder::new(17)?
    ///     .with_common_name(DomainName::parse("example.com")?)
    ///     .with_validation(CertificateValidationMethod::Dns, None)?;
    /// assert_eq!(order.params()?["validationMethod"], "DNS");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_validation(
        mut self,
        method: CertificateValidationMethod,
        email: Option<Email>,
    ) -> Result<Self> {
        match (method, &email) {
            (CertificateValidationMethod::Email, None) => {
                return Err(Error::validation(
                    "validationEmail",
                    "is required when the validation method is EMAIL",
                ));
            }
            (CertificateValidationMethod::Email, Some(_)) | (_, None) => {}
            (other, Some(_)) => {
                return Err(Error::validation(
                    "validationEmail",
                    format!("is only used by EMAIL, not {}", other.as_str()),
                ));
            }
        }
        self.validation_method = Some(method);
        self.validation_email = email;
        Ok(self)
    }

    /// Sets the owner contact handle.
    ///
    /// ```
    /// use inwx_client::{CertificateOrder, DomainName, Handle};
    ///
    /// let order = CertificateOrder::new(17)?
    ///     .with_common_name(DomainName::parse("example.com")?)
    ///     .with_owner(Handle::new(991)?);
    /// assert_eq!(order.params()?["ownerc"], 991);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_owner(mut self, handle: Handle) -> Self {
        self.owner = Some(handle);
        self
    }

    /// Sets the admin contact handle.
    ///
    /// ```
    /// use inwx_client::{CertificateOrder, DomainName, Handle};
    ///
    /// let order = CertificateOrder::new(17)?
    ///     .with_common_name(DomainName::parse("example.com")?)
    ///     .with_admin(Handle::new(992)?);
    /// assert_eq!(order.params()?["adminc"], 992);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_admin(mut self, handle: Handle) -> Self {
        self.admin = Some(handle);
        self
    }

    /// Sets the tech contact handle.
    ///
    /// ```
    /// use inwx_client::{CertificateOrder, DomainName, Handle};
    ///
    /// let order = CertificateOrder::new(17)?
    ///     .with_common_name(DomainName::parse("example.com")?)
    ///     .with_tech(Handle::new(993)?);
    /// assert_eq!(order.params()?["techc"], 993);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_tech(mut self, handle: Handle) -> Self {
        self.tech = Some(handle);
        self
    }

    /// Sets the number of paid SANs (`numberOfSan`).
    ///
    /// ```
    /// use inwx_client::{CertificateOrder, DomainName};
    ///
    /// let order = CertificateOrder::new(17)?
    ///     .with_common_name(DomainName::parse("example.com")?)
    ///     .with_san_count(5, 0);
    /// assert_eq!(order.params()?["numberOfSan"], 5);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_san_count(mut self, san: u16, wildcard_san: u16) -> Self {
        self.number_of_san = Some(san);
        self.number_of_wildcard_san = Some(wildcard_san);
        self
    }

    /// Attaches a hosting option (`hosting`).
    ///
    /// ```
    /// use inwx_client::{CertificateOrder, DomainName};
    ///
    /// let order = CertificateOrder::new(17)?
    ///     .with_common_name(DomainName::parse("example.com")?)
    ///     .with_hosting(true);
    /// assert_eq!(order.params()?["hosting"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_hosting(mut self, hosting: bool) -> Self {
        self.hosting = Some(hosting);
        self
    }

    /// Sets automatic renewal (`autorenew`).
    ///
    /// ```
    /// use inwx_client::{CertificateOrder, DomainName};
    ///
    /// let order = CertificateOrder::new(17)?
    ///     .with_common_name(DomainName::parse("example.com")?)
    ///     .with_autorenew(true);
    /// assert_eq!(order.params()?["autorenew"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_autorenew(mut self, autorenew: bool) -> Self {
        self.autorenew = Some(autorenew);
        self
    }

    /// Runs the order in testing mode (`testing=true`): nothing is charged.
    ///
    /// ```
    /// use inwx_client::{CertificateOrder, DomainName};
    ///
    /// let order = CertificateOrder::new(17)?
    ///     .with_common_name(DomainName::parse("example.com")?)
    ///     .dry_run();
    /// assert_eq!(order.params()?["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.testing = true;
        self
    }

    /// The `certificate.create` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when neither a CSR nor a common name was set — the
    /// API documents both as optional, but an order with neither cannot be
    /// issued.
    ///
    /// ```
    /// use inwx_client::{CertificateOrder, DomainName};
    ///
    /// assert!(CertificateOrder::new(17)?.params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        if self.csr.is_none() && self.common_name.is_none() {
            return Err(Error::validation(
                "certificate.order",
                "needs a CSR or a common name",
            ));
        }
        let mut params = Map::new();
        params.insert("productId".to_owned(), json!(self.product_id));
        if let Some(csr) = &self.csr {
            params.insert("csr".to_owned(), json!(csr));
        }
        if let Some(common_name) = &self.common_name {
            params.insert("commonName".to_owned(), json!(common_name));
        }
        if !self.sans.is_empty() {
            params.insert("san".to_owned(), json!(self.sans.join(",")));
        }
        if let Some(term) = self.term {
            params.insert("period".to_owned(), json!(term.years()));
        }
        if let Some(method) = self.validation_method {
            params.insert("validationMethod".to_owned(), json!(method));
        }
        if let Some(email) = &self.validation_email {
            params.insert("validationEmail".to_owned(), json!(email));
        }
        insert_handles(&mut params, [self.owner, self.admin, self.tech]);
        if let Some(san) = self.number_of_san {
            params.insert("numberOfSan".to_owned(), json!(san));
        }
        if let Some(san) = self.number_of_wildcard_san {
            params.insert("numberOfWildcardSan".to_owned(), json!(san));
        }
        if let Some(hosting) = self.hosting {
            params.insert("hosting".to_owned(), json!(hosting));
        }
        if let Some(autorenew) = self.autorenew {
            params.insert("autorenew".to_owned(), json!(autorenew));
        }
        params.insert("testing".to_owned(), json!(self.testing));
        Ok(Value::Object(params))
    }
}

/// A `certificate.updateOrder` or `certificate.renew` payload.
///
/// Every field is optional; the API takes whatever is still missing. The
/// difference between the two commands is the method that consumes it.
///
/// ```
/// use inwx_client::{CertificateUpdate, CertificateValidationMethod, CertificateId, Email};
///
/// let update = CertificateUpdate::new(CertificateId::new(9)?)?
///     .with_validation(CertificateValidationMethod::Email, Some(Email::parse("admin@example.com")?))?;
/// assert_eq!(update.params()?["validationEmail"], "admin@example.com");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateUpdate {
    certificate_id: CertificateId,
    csr: Option<String>,
    common_name: Option<DomainName>,
    sans: Vec<String>,
    validation_method: Option<CertificateValidationMethod>,
    validation_email: Option<Email>,
    owner: Option<Handle>,
    admin: Option<Handle>,
    tech: Option<Handle>,
    hosting: Option<bool>,
    autorenew: Option<bool>,
    testing: bool,
}

impl CertificateUpdate {
    /// An empty update for a certificate.
    ///
    /// # Errors
    ///
    /// Never today: the id is already validated by [`CertificateId::new`], and
    /// the signature keeps room for a field-level rule without a breaking change.
    ///
    /// ```
    /// use inwx_client::{CertificateId, CertificateUpdate};
    ///
    /// let update = CertificateUpdate::new(CertificateId::new(9)?)?;
    /// assert!(update.params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new(certificate_id: CertificateId) -> Result<Self> {
        Ok(Self {
            certificate_id,
            csr: None,
            common_name: None,
            sans: Vec::new(),
            validation_method: None,
            validation_email: None,
            owner: None,
            admin: None,
            tech: None,
            hosting: None,
            autorenew: None,
            testing: false,
        })
    }

    /// Sets the CSR.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the CSR is unusable or contains a private key.
    ///
    /// ```
    /// use inwx_client::{CertificateId, CertificateUpdate};
    ///
    /// let update = CertificateUpdate::new(CertificateId::new(9)?)?
    ///     .with_csr("-----BEGIN CERTIFICATE REQUEST-----\nMIIB")?;
    /// assert!(update.params()?.get("csr").is_some());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_csr(mut self, csr: impl Into<String>) -> Result<Self> {
        self.csr = Some(validate_csr(&csr.into())?);
        Ok(self)
    }

    /// Sets the common name.
    ///
    /// ```
    /// use inwx_client::{CertificateId, CertificateUpdate, DomainName};
    ///
    /// let update = CertificateUpdate::new(CertificateId::new(9)?)?
    ///     .with_common_name(DomainName::parse("example.com")?);
    /// assert_eq!(update.params()?["commonName"], "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_common_name(mut self, domain: DomainName) -> Self {
        self.common_name = Some(domain);
        self
    }

    /// Sets the SANs.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty list or a duplicate.
    ///
    /// ```
    /// use inwx_client::{CertificateId, CertificateUpdate, DomainName};
    ///
    /// let update = CertificateUpdate::new(CertificateId::new(9)?)?
    ///     .with_sans(&[DomainName::parse("www.example.com")?])?;
    /// assert_eq!(update.params()?["san"], "www.example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_sans(mut self, domains: &[DomainName]) -> Result<Self> {
        if domains.is_empty() {
            return Err(Error::validation("certificate.san", "must not be empty"));
        }
        for (index, domain) in domains.iter().enumerate() {
            if domains[..index].contains(domain) {
                return Err(Error::validation(
                    "certificate.san",
                    format!("{domain} is listed twice"),
                ));
            }
            self.sans.push(domain.as_str().to_owned());
        }
        Ok(self)
    }

    /// Sets the validation method and address.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `EMAIL` has no address or a non-email method
    /// carries one.
    ///
    /// ```
    /// use inwx_client::{CertificateId, CertificateUpdate, CertificateValidationMethod, Email};
    ///
    /// let update = CertificateUpdate::new(CertificateId::new(9)?)?
    ///     .with_validation(CertificateValidationMethod::Email, Some(Email::parse("admin@example.com")?))?;
    /// assert_eq!(update.params()?["validationMethod"], "EMAIL");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_validation(
        mut self,
        method: CertificateValidationMethod,
        email: Option<Email>,
    ) -> Result<Self> {
        match (method, &email) {
            (CertificateValidationMethod::Email, None) => {
                return Err(Error::validation(
                    "validationEmail",
                    "is required when the validation method is EMAIL",
                ));
            }
            (CertificateValidationMethod::Email, Some(_)) | (_, None) => {}
            (other, Some(_)) => {
                return Err(Error::validation(
                    "validationEmail",
                    format!("is only used by EMAIL, not {}", other.as_str()),
                ));
            }
        }
        self.validation_method = Some(method);
        self.validation_email = email;
        Ok(self)
    }

    /// Sets the owner contact handle.
    ///
    /// ```
    /// use inwx_client::{CertificateId, CertificateUpdate, Handle};
    ///
    /// let update = CertificateUpdate::new(CertificateId::new(9)?)?.with_owner(Handle::new(991)?);
    /// assert_eq!(update.params()?["ownerc"], 991);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_owner(mut self, handle: Handle) -> Self {
        self.owner = Some(handle);
        self
    }

    /// Sets the admin contact handle.
    ///
    /// ```
    /// use inwx_client::{CertificateId, CertificateUpdate, Handle};
    ///
    /// let update = CertificateUpdate::new(CertificateId::new(9)?)?.with_admin(Handle::new(992)?);
    /// assert_eq!(update.params()?["adminc"], 992);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_admin(mut self, handle: Handle) -> Self {
        self.admin = Some(handle);
        self
    }

    /// Sets the tech contact handle.
    ///
    /// ```
    /// use inwx_client::{CertificateId, CertificateUpdate, Handle};
    ///
    /// let update = CertificateUpdate::new(CertificateId::new(9)?)?.with_tech(Handle::new(993)?);
    /// assert_eq!(update.params()?["techc"], 993);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_tech(mut self, handle: Handle) -> Self {
        self.tech = Some(handle);
        self
    }

    /// Sets the hosting option.
    ///
    /// ```
    /// use inwx_client::{CertificateId, CertificateUpdate};
    ///
    /// let update = CertificateUpdate::new(CertificateId::new(9)?)?.with_hosting(false);
    /// assert_eq!(update.params()?["hosting"], false);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_hosting(mut self, hosting: bool) -> Self {
        self.hosting = Some(hosting);
        self
    }

    /// Sets automatic renewal.
    ///
    /// ```
    /// use inwx_client::{CertificateId, CertificateUpdate};
    ///
    /// let update = CertificateUpdate::new(CertificateId::new(9)?)?.with_autorenew(true);
    /// assert_eq!(update.params()?["autorenew"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_autorenew(mut self, autorenew: bool) -> Self {
        self.autorenew = Some(autorenew);
        self
    }

    /// Runs the command in testing mode (`testing=true`).
    ///
    /// ```
    /// use inwx_client::{CertificateId, CertificateUpdate};
    ///
    /// let update = CertificateUpdate::new(CertificateId::new(9)?)?
    ///     .with_autorenew(true)
    ///     .dry_run();
    /// assert_eq!(update.params()?["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.testing = true;
        self
    }

    /// The `certificate.updateOrder` / `certificate.renew` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when nothing was set.
    ///
    /// ```
    /// use inwx_client::{CertificateId, CertificateUpdate};
    ///
    /// let update = CertificateUpdate::new(CertificateId::new(9)?)?;
    /// assert!(update.params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut params = Map::new();
        params.insert("certificateId".to_owned(), json!(self.certificate_id.get()));
        if let Some(csr) = &self.csr {
            params.insert("csr".to_owned(), json!(csr));
        }
        if let Some(common_name) = &self.common_name {
            params.insert("commonName".to_owned(), json!(common_name));
        }
        if !self.sans.is_empty() {
            params.insert("san".to_owned(), json!(self.sans.join(",")));
        }
        if let Some(method) = self.validation_method {
            params.insert("validationMethod".to_owned(), json!(method));
        }
        if let Some(email) = &self.validation_email {
            params.insert("validationEmail".to_owned(), json!(email));
        }
        insert_handles(&mut params, [self.owner, self.admin, self.tech]);
        if let Some(hosting) = self.hosting {
            params.insert("hosting".to_owned(), json!(hosting));
        }
        if let Some(autorenew) = self.autorenew {
            params.insert("autorenew".to_owned(), json!(autorenew));
        }
        if self.testing {
            params.insert("testing".to_owned(), json!(true));
        }
        if params.len() == 1 {
            return Err(Error::validation(
                "certificate.update",
                "sets no field; add a change or skip the call",
            ));
        }
        Ok(Value::Object(params))
    }
}

/// A `certificate.list` query.
///
/// ```
/// use inwx_client::CertificateQuery;
///
/// let query = CertificateQuery::new().with_inactive().with_limit(50)?;
/// let params = query.params();
/// assert_eq!(params["showInactive"], true);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateQuery {
    params: Map<String, Value>,
}

impl CertificateQuery {
    /// An empty query.
    ///
    /// ```
    /// use inwx_client::CertificateQuery;
    /// assert!(CertificateQuery::new().params().as_object().unwrap().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Includes inactive certificates (`showInactive`).
    ///
    /// ```
    /// use inwx_client::CertificateQuery;
    /// assert_eq!(CertificateQuery::new().with_inactive().params()["showInactive"], true);
    /// ```
    #[must_use]
    pub fn with_inactive(mut self) -> Self {
        self.params.insert("showInactive".to_owned(), json!(true));
        self
    }

    /// Filters by owner handle.
    ///
    /// ```
    /// use inwx_client::CertificateQuery;
    /// assert_eq!(CertificateQuery::new().with_owner(991).params()["ownerc"], "991");
    /// ```
    #[must_use]
    pub fn with_owner(mut self, handle: i64) -> Self {
        self.params
            .insert("ownerc".to_owned(), json!(handle.to_string()));
        self
    }

    /// Filters by status.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the status is empty.
    ///
    /// ```
    /// use inwx_client::CertificateQuery;
    /// assert!(CertificateQuery::new().with_status("ACTIVE").is_ok());
    /// assert!(CertificateQuery::new().with_status("  ").is_err());
    /// ```
    pub fn with_status(mut self, status: &str) -> Result<Self> {
        validate_token("certificate.status", status)?;
        self.params
            .insert("status".to_owned(), json!(status.trim()));
        Ok(self)
    }

    /// Filters by common name.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty.
    ///
    /// ```
    /// use inwx_client::CertificateQuery;
    /// assert!(CertificateQuery::new().with_common_name("example.com").is_ok());
    /// ```
    pub fn with_common_name(mut self, common_name: &str) -> Result<Self> {
        validate_token("certificate.commonName", common_name)?;
        self.params
            .insert("commonName".to_owned(), json!(common_name.trim()));
        Ok(self)
    }

    /// Sets a page limit (`sortColumn`/`order` are left to the API default).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the limit is zero.
    ///
    /// ```
    /// use inwx_client::CertificateQuery;
    /// assert!(CertificateQuery::new().with_limit(10).is_ok());
    /// assert!(CertificateQuery::new().with_limit(0).is_err());
    /// ```
    pub fn with_limit(mut self, limit: u32) -> Result<Self> {
        if limit == 0 {
            return Err(Error::validation("limit", "must be at least 1"));
        }
        self.params.insert("limit".to_owned(), json!(limit));
        Ok(self)
    }

    /// The `certificate.list` parameters.
    ///
    /// ```
    /// use inwx_client::CertificateQuery;
    /// assert!(CertificateQuery::new().params().as_object().unwrap().is_empty());
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        Value::Object(self.params.clone())
    }
}

/// A `certificate.listProducts` query.
///
/// ```
/// use inwx_client::CertificateProductQuery;
///
/// let query = CertificateProductQuery::new()
///     .with_kind("DV")?
///     .with_wildcard(true)?;
/// assert_eq!(query.params()["type"], "DV");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateProductQuery {
    params: Map<String, Value>,
}

impl CertificateProductQuery {
    /// An empty query.
    ///
    /// ```
    /// use inwx_client::CertificateProductQuery;
    /// assert!(CertificateProductQuery::new().params().as_object().unwrap().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by certificate type (`DV`, `OV`, `EV`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the type is not one of the three documented
    /// values.
    ///
    /// ```
    /// use inwx_client::CertificateProductQuery;
    /// assert!(CertificateProductQuery::new().with_kind("OV").is_ok());
    /// assert!(CertificateProductQuery::new().with_kind("XX").is_err());
    /// ```
    pub fn with_kind(mut self, kind: &str) -> Result<Self> {
        let upper = kind.trim().to_ascii_uppercase();
        if !matches!(upper.as_str(), "DV" | "OV" | "EV") {
            return Err(Error::validation(
                "certificate.type",
                format!("{kind:?} is not one of DV, OV, EV"),
            ));
        }
        self.params.insert("type".to_owned(), json!(upper));
        Ok(self)
    }

    /// Filters by brand.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the brand is empty.
    ///
    /// ```
    /// use inwx_client::CertificateProductQuery;
    /// assert!(CertificateProductQuery::new().with_brand("ExampleCA").is_ok());
    /// ```
    pub fn with_brand(mut self, brand: &str) -> Result<Self> {
        validate_token("certificate.brand", brand)?;
        self.params.insert("brand".to_owned(), json!(brand.trim()));
        Ok(self)
    }

    /// Filters by wildcard support.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the filter carries nothing else — an
    /// accidental empty query is more likely a bug than a request for the whole
    /// catalogue. (The API accepts an empty filter; this is a caller guard.)
    ///
    /// ```
    /// use inwx_client::CertificateProductQuery;
    /// assert!(CertificateProductQuery::new().with_wildcard(true).is_ok());
    /// ```
    pub fn with_wildcard(mut self, wildcard: bool) -> Result<Self> {
        self.params.insert("wildcard".to_owned(), json!(wildcard));
        Ok(self)
    }

    /// The `certificate.listProducts` parameters.
    ///
    /// ```
    /// use inwx_client::CertificateProductQuery;
    /// assert!(CertificateProductQuery::new().params().as_object().unwrap().is_empty());
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        Value::Object(self.params.clone())
    }
}

/// Inserts the contact handles that were set.
fn insert_handles(params: &mut Map<String, Value>, handles: [Option<Handle>; 3]) {
    for (field, handle) in ["ownerc", "adminc", "techc"].into_iter().zip(handles) {
        if let Some(handle) = handle {
            params.insert(field.to_owned(), json!(handle));
        }
    }
}

/// Validates a CSR: non-empty, bounded, and never a private key.
fn validate_csr(csr: &str) -> Result<String> {
    let trimmed = csr.trim();
    if trimmed.is_empty() {
        return Err(Error::validation("certificate.csr", "must not be empty"));
    }
    if trimmed.chars().count() > MAX_CSR_LEN {
        return Err(Error::validation(
            "certificate.csr",
            format!("must be at most {MAX_CSR_LEN} characters"),
        ));
    }
    // A private key in this field would upload a secret to a third party.
    if trimmed.contains("PRIVATE KEY") {
        return Err(Error::validation(
            "certificate.csr",
            "must be a certificate signing request, not a private key",
        ));
    }
    if !trimmed.contains("CERTIFICATE REQUEST") && !trimmed.contains("BEGIN NEW CERTIFICATE") {
        return Err(Error::validation(
            "certificate.csr",
            "does not look like a PEM certificate signing request",
        ));
    }
    reject_control(trimmed)?;
    Ok(trimmed.to_owned())
}

/// Rejects the control characters a PEM body must not contain.
fn reject_control(value: &str) -> Result<()> {
    if value
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r')
    {
        return Err(Error::validation(
            "certificate.csr",
            "must not contain control characters",
        ));
    }
    Ok(())
}

/// Validates and returns a wildcard SAN such as `*.example.com`.
fn validate_wildcard(wildcard: &str) -> Result<String> {
    let trimmed = wildcard.trim();
    let Some(rest) = trimmed.strip_prefix("*.") else {
        return Err(Error::validation(
            "certificate.san",
            "a wildcard must start with `*.` and carry exactly one label",
        ));
    };
    if rest.contains('*') {
        return Err(Error::validation(
            "certificate.san",
            "only one wildcard label is allowed, at the leftmost position",
        ));
    }
    let domain = DomainName::parse(rest)?;
    Ok(format!("*.{domain}"))
}

impl<T: Transport> InwxClient<T> {
    /// Orders a certificate (`certificate.create`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{CertificateOrder, DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let order = CertificateOrder::new(17)?
    ///     .with_common_name(DomainName::parse("example.com")?);
    /// let result = client.order_certificate(&order).await?;
    /// println!("{:?} {:?}", result.certificate_id, result.missing);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`CertificateOrder::params`], plus the usual
    /// transport and API errors — `2104` on a billing failure.
    pub async fn order_certificate(
        &self,
        order: &CertificateOrder,
    ) -> Result<CertificateOrderResult> {
        let data = self.call("certificate.create", order.params()?).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Cancels a pending certificate request (`certificate.cancel`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{CertificateId, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.cancel_certificate(CertificateId::new(9)?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn cancel_certificate(&self, certificate_id: CertificateId) -> Result<()> {
        self.call(
            "certificate.cancel",
            json!({ "certificateId": certificate_id.get() }),
        )
        .await?;
        Ok(())
    }

    /// Reads one product (`certificate.getProduct`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let product = client.certificate_product(17).await?;
    /// println!("{:?}", product.name);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive product id, plus the usual
    /// transport and API errors.
    pub async fn certificate_product(&self, product_id: i64) -> Result<CertificateProduct> {
        if product_id <= 0 {
            return Err(Error::validation(
                "certificate.productId",
                format!("must be a positive product id, got {product_id}"),
            ));
        }
        let data = self
            .call("certificate.getProduct", json!({ "productId": product_id }))
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Reads one certificate (`certificate.info`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{CertificateId, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let certificate = client.certificate_info(CertificateId::new(9)?).await?;
    /// println!("{:?}", certificate.status);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors — `2303` when the certificate does not
    /// exist.
    pub async fn certificate_info(&self, certificate_id: CertificateId) -> Result<Certificate> {
        let data = self
            .call(
                "certificate.info",
                json!({ "certificateId": certificate_id.get() }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Lists the account's certificates (`certificate.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{CertificateQuery, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for certificate in client.list_certificates(&CertificateQuery::new()).await? {
    ///     println!("{:?} {:?}", certificate.id, certificate.status);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn list_certificates(&self, query: &CertificateQuery) -> Result<Vec<Certificate>> {
        let data = self.call("certificate.list", query.params()).await?;
        let entries = match data {
            Value::Array(entries) => entries,
            Value::Object(_) => vec![data],
            _ => Vec::new(),
        };
        Ok(entries
            .into_iter()
            .filter_map(|entry| serde_json::from_value(entry).ok())
            .collect())
    }

    /// Lists certificate products with prices (`certificate.listProducts`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{CertificateProductQuery, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let products = client
    ///     .list_certificate_products(&CertificateProductQuery::new())
    ///     .await?;
    /// println!("{} products", products.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn list_certificate_products(
        &self,
        query: &CertificateProductQuery,
    ) -> Result<Vec<CertificateProduct>> {
        let data = self
            .call("certificate.listProducts", query.params())
            .await?;
        let entries = match data {
            Value::Array(entries) => entries,
            Value::Object(_) => vec![data],
            _ => Vec::new(),
        };
        Ok(entries
            .into_iter()
            .filter_map(|entry| serde_json::from_value(entry).ok())
            .collect())
    }

    /// Lists the data an order still needs
    /// (`certificate.listRemainingNeededData`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{CertificateId, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let missing = client
    ///     .certificate_missing_data(CertificateId::new(9)?)
    ///     .await?;
    /// println!("{:?}", missing.missing);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn certificate_missing_data(
        &self,
        certificate_id: CertificateId,
    ) -> Result<CertificateMissingData> {
        let data = self
            .call(
                "certificate.listRemainingNeededData",
                json!({ "certificateId": certificate_id.get() }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Reads the certificate log, for one certificate or all
    /// (`certificate.log`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::InwxClient;
    /// use inwx_client::ReqwestTransport;
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for entry in client.certificate_log(None).await? {
    ///     println!("{:?} {:?}", entry.certificate_id, entry.status);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn certificate_log(
        &self,
        certificate_id: Option<CertificateId>,
    ) -> Result<Vec<CertificateLogEntry>> {
        let params =
            certificate_id.map_or_else(|| json!({}), |id| json!({ "certificateId": id.get() }));
        let data = self.call("certificate.log", params).await?;
        let entries = match data {
            Value::Array(entries) => entries,
            Value::Object(_) => vec![data],
            _ => Vec::new(),
        };
        Ok(entries
            .into_iter()
            .filter_map(|entry| serde_json::from_value(entry).ok())
            .collect())
    }

    /// Reissues a certificate with a new CSR (`certificate.reissue`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{CertificateId, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let result = client
    ///     .reissue_certificate(
    ///         CertificateId::new(9)?,
    ///         "-----BEGIN CERTIFICATE REQUEST-----\nMIIB",
    ///     )
    ///     .await?;
    /// println!("{:?}", result.status);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the CSR is unusable, plus the usual transport
    /// and API errors.
    pub async fn reissue_certificate(
        &self,
        certificate_id: CertificateId,
        csr: &str,
    ) -> Result<CertificateOrderResult> {
        let csr = validate_csr(csr)?;
        let data = self
            .call(
                "certificate.reissue",
                json!({ "certificateId": certificate_id.get(), "csr": csr }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Renews a certificate (`certificate.renew`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{CertificateId, CertificateUpdate, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let renew = CertificateUpdate::new(CertificateId::new(9)?)?
    ///     .with_autorenew(true);
    /// let result = client.renew_certificate(&renew).await?;
    /// println!("{:?}", result.certificate_id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`CertificateUpdate::params`], plus the usual
    /// transport and API errors.
    pub async fn renew_certificate(
        &self,
        renew: &CertificateUpdate,
    ) -> Result<CertificateOrderResult> {
        let data = self.call("certificate.renew", renew.params()?).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Turns automatic renewal on or off (`certificate.setAutorenew`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{CertificateId, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client
    ///     .set_certificate_autorenew(CertificateId::new(9)?, true)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn set_certificate_autorenew(
        &self,
        certificate_id: CertificateId,
        autorenew: bool,
    ) -> Result<()> {
        self.call(
            "certificate.setAutorenew",
            json!({ "certificateId": certificate_id.get(), "autorenew": autorenew }),
        )
        .await?;
        Ok(())
    }

    /// Resends the approval mail for a certificate
    /// (`certificate.setresendapproval`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{CertificateId, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client
    ///     .resend_certificate_approval(CertificateId::new(9)?, true)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn resend_certificate_approval(
        &self,
        certificate_id: CertificateId,
        resend: bool,
    ) -> Result<()> {
        self.call(
            "certificate.setresendapproval",
            json!({ "certificateId": certificate_id.get(), "resend_approval": resend }),
        )
        .await?;
        Ok(())
    }

    /// Submits the missing data of an order (`certificate.updateOrder`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{CertificateId, CertificateUpdate, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let update = CertificateUpdate::new(CertificateId::new(9)?)?
    ///     .with_csr("-----BEGIN CERTIFICATE REQUEST-----\nMIIB")?;
    /// let result = client.update_certificate_order(&update).await?;
    /// println!("{:?}", result.missing);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`CertificateUpdate::params`], plus the usual
    /// transport and API errors.
    pub async fn update_certificate_order(
        &self,
        update: &CertificateUpdate,
    ) -> Result<CertificateOrderResult> {
        let data = self
            .call("certificate.updateOrder", update.params()?)
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_csr_must_never_carry_a_private_key() {
        let err = validate_csr("-----BEGIN PRIVATE KEY-----\nMIIB").unwrap_err();
        assert!(err.is_validation());
        assert!(validate_csr("-----BEGIN CERTIFICATE REQUEST-----\nMIIB").is_ok());
    }

    #[test]
    fn a_csr_must_look_like_a_request() {
        assert!(validate_csr("MIIBbase64").is_err());
        assert!(validate_csr("").is_err());
        assert!(validate_csr(&"x".repeat(MAX_CSR_LEN + 1)).is_err());
    }

    #[test]
    fn email_validation_needs_an_address() {
        let order = CertificateOrder::new(17).unwrap();
        assert!(order
            .clone()
            .with_validation(CertificateValidationMethod::Email, None)
            .is_err());
        let email = Email::parse("admin@example.com").unwrap();
        assert!(order
            .clone()
            .with_validation(CertificateValidationMethod::Dns, Some(email.clone()))
            .is_err());
        assert!(order
            .with_validation(CertificateValidationMethod::Email, Some(email))
            .is_ok());
    }

    #[test]
    fn wildcard_sans_allow_exactly_one_leftmost_label() {
        assert!(validate_wildcard("*.example.com").is_ok());
        assert!(validate_wildcard("*.*.example.com").is_err());
        assert!(validate_wildcard("www.example.com").is_err());
        assert!(validate_wildcard("WWW.Example.COM").is_err());
    }

    #[test]
    fn an_order_needs_a_csr_or_a_common_name() {
        assert!(CertificateOrder::new(17).unwrap().params().is_err());
        assert!(CertificateOrder::new(17)
            .unwrap()
            .with_common_name(DomainName::parse("example.com").unwrap())
            .params()
            .is_ok());
    }

    #[test]
    fn san_lists_reject_duplicates() {
        let domain = DomainName::parse("www.example.com").unwrap();
        assert!(CertificateOrder::new(17)
            .unwrap()
            .with_sans(&[domain.clone(), domain])
            .is_err());
    }

    #[test]
    fn updates_need_a_change() {
        let update = CertificateUpdate::new(CertificateId::new(9).unwrap()).unwrap();
        assert!(update.params().is_err());
    }
}
