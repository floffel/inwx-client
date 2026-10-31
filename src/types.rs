//! Validated value types shared by every request and response.
//!
//! The types here exist so an invalid value never reaches the wire: a
//! [`DomainName`] is known to be a syntactically valid, punycode-encoded name,
//! a [`Period`] is one the API documents, and so on. Everything parses from
//! `&str` (or `TryFrom`) and renders back with `Display`.

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize as _;

use crate::{Error, Result};

/// Longest legal DNS name in presentation form, without the trailing root dot.
///
/// ```
/// use inwx_client::{DomainName, MAX_DOMAIN_LEN};
///
/// // 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253.
/// let at_limit = format!(
///     "{}.{}.{}.{}",
///     "a".repeat(63),
///     "b".repeat(63),
///     "c".repeat(63),
///     "d".repeat(61)
/// );
/// assert_eq!(at_limit.len(), MAX_DOMAIN_LEN);
/// assert!(DomainName::parse(&at_limit).is_ok());
///
/// let over_limit = format!("{at_limit}e");
/// assert!(DomainName::parse(&over_limit).is_err());
/// ```
pub const MAX_DOMAIN_LEN: usize = 253;

/// Longest legal single DNS label.
///
/// ```
/// use inwx_client::{DomainName, MAX_LABEL_LEN};
///
/// let at_limit = format!("{}.com", "a".repeat(MAX_LABEL_LEN));
/// assert!(DomainName::parse(&at_limit).is_ok());
///
/// let over_limit = format!("{}.com", "a".repeat(MAX_LABEL_LEN + 1));
/// assert!(DomainName::parse(&over_limit).is_err());
/// ```
pub const MAX_LABEL_LEN: usize = 63;

/// Longest password the crate accepts, in characters.
///
/// INWX types its password fields as `token255`, so a longer value cannot be
/// stored by the API and is rejected before the request is built.
///
/// ```
/// use inwx_client::{MAX_PASSWORD_LEN, Password};
///
/// assert_eq!(MAX_PASSWORD_LEN, 255);
///
/// let at_limit = Password::new("x".repeat(MAX_PASSWORD_LEN))?;
/// assert_eq!(at_limit.as_str().chars().count(), MAX_PASSWORD_LEN);
///
/// // One character longer is refused without touching the network.
/// assert!(Password::new("x".repeat(MAX_PASSWORD_LEN + 1)).is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
pub const MAX_PASSWORD_LEN: usize = 255;

/// A domain name, validated and converted to its ASCII (punycode) form.
///
/// `parse` trims surrounding whitespace and one trailing root dot, applies
/// UTS-46 (`idna`) so unicode names become `xn--…`, lower-cases the result and
/// then enforces the DNS length and label rules. The original unicode spelling
/// is not kept: INWX stores and returns the ACE form, so keeping both invites
/// mismatches.
///
/// ```
/// use inwx_client::DomainName;
///
/// let domain = DomainName::parse("Example.COM.")?;
/// assert_eq!(domain.as_str(), "example.com");
/// assert_eq!(domain.tld(), "com");
/// assert_eq!(domain.sld(), "example");
///
/// let idn = DomainName::parse("München.de")?;
/// assert_eq!(idn.as_str(), "xn--mnchen-3ya.de");
/// assert!(idn.is_idn());
/// # Ok::<(), inwx_client::Error>(())
/// ```
///
/// # Rejected input
///
/// ```
/// use inwx_client::DomainName;
///
/// for bad in ["", " ", "localhost", "exa mple.com", "-bad.com", "bad-.com", "a..b"] {
///     assert!(DomainName::parse(bad).is_err(), "{bad:?} should be rejected");
/// }
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainName(String);

impl DomainName {
    /// Parses and validates a domain name.
    ///
    /// ```
    /// use inwx_client::{DomainName, Error};
    ///
    /// let err = DomainName::parse("not a domain").unwrap_err();
    /// assert!(matches!(err, Error::Validation { field: "domain", .. }));
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name is not a syntactically valid domain.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim().trim_end_matches('.');
        let ascii = idna::domain_to_ascii(trimmed).map_err(|error| {
            Error::validation(
                "domain",
                format!("{input:?} is not a valid domain: {error}"),
            )
        })?;
        validate_dns_name("domain", &ascii, true)?;
        Ok(Self(ascii))
    }

    /// The ASCII (punycode) form, as sent to INWX.
    ///
    /// ```
    /// use inwx_client::DomainName;
    /// assert_eq!(DomainName::parse("example.com")?.as_str(), "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The top level domain, i.e. everything after the last dot.
    ///
    /// ```
    /// use inwx_client::DomainName;
    /// assert_eq!(DomainName::parse("shop.example.co.uk")?.tld(), "uk");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn tld(&self) -> &str {
        self.0.rsplit_once('.').map_or("", |(_, tld)| tld)
    }

    /// The second level domain, i.e. the label left of the TLD.
    ///
    /// ```
    /// use inwx_client::DomainName;
    /// assert_eq!(DomainName::parse("shop.example.co.uk")?.sld(), "co");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn sld(&self) -> &str {
        self.0
            .rsplit_once('.')
            .and_then(|(rest, _)| rest.rsplit('.').next())
            .unwrap_or("")
    }

    /// Whether the ASCII form is punycode, i.e. the input was unicode.
    ///
    /// ```
    /// use inwx_client::DomainName;
    /// assert!(DomainName::parse("bücher.de")?.is_idn());
    /// assert!(!DomainName::parse("example.com")?.is_idn());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn is_idn(&self) -> bool {
        self.0.split('.').any(|label| label.starts_with("xn--"))
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for DomainName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "DomainName({:?})", self.0)
    }
}

impl AsRef<str> for DomainName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for DomainName {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl FromStr for DomainName {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl Serialize for DomainName {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DomainName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// A host name: same rules as [`DomainName`] but one label is enough, for
/// nameserver and mail exchanger targets.
///
/// ```
/// use inwx_client::Hostname;
///
/// assert_eq!(Hostname::parse("ns1.example.com")?.as_str(), "ns1.example.com");
/// assert_eq!(Hostname::parse("localhost")?.as_str(), "localhost");
/// assert!(Hostname::parse("ns1..example.com").is_err());
/// assert!(Hostname::parse("under_score.example.com").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hostname(String);

impl Hostname {
    /// Parses and validates a host name.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name exceeds [`MAX_DOMAIN_LEN`], a label
    /// is empty or exceeds [`MAX_LABEL_LEN`], a label starts or ends with a
    /// hyphen, or contains a character outside `[a-z0-9-]`.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim().trim_end_matches('.');
        let ascii = idna::domain_to_ascii(trimmed).map_err(|error| {
            Error::validation(
                "hostname",
                format!("{input:?} is not a valid host name: {error}"),
            )
        })?;
        validate_dns_name("hostname", &ascii, false)?;
        Ok(Self(ascii))
    }

    /// The ASCII form.
    ///
    /// ```
    /// use inwx_client::Hostname;
    /// assert_eq!(Hostname::parse("MX.Example.COM")?.as_str(), "mx.example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for Hostname {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Hostname({:?})", self.0)
    }
}

impl AsRef<str> for Hostname {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for Hostname {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl Serialize for Hostname {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Hostname {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// Shared label validation for [`DomainName`] and [`Hostname`].
fn validate_dns_name(field: &'static str, ascii: &str, require_dot: bool) -> Result<()> {
    if ascii.is_empty() {
        return Err(Error::validation(field, "must not be empty"));
    }
    if ascii.len() > MAX_DOMAIN_LEN {
        return Err(Error::validation(
            field,
            format!(
                "must be at most {MAX_DOMAIN_LEN} characters, got {}",
                ascii.len()
            ),
        ));
    }
    let labels = ascii.split('.').collect::<Vec<_>>();
    if require_dot && labels.len() < 2 {
        return Err(Error::validation(
            field,
            "must contain at least one dot (a TLD)",
        ));
    }
    for label in labels {
        if label.is_empty() {
            return Err(Error::validation(field, "must not contain empty labels"));
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(Error::validation(
                field,
                format!("label {label:?} exceeds {MAX_LABEL_LEN} characters"),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(Error::validation(
                field,
                format!("label {label:?} must not start or end with a hyphen"),
            ));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(Error::validation(
                field,
                format!("label {label:?} contains a character outside [a-z0-9-]"),
            ));
        }
    }
    Ok(())
}

/// A registration or renewal period, restricted to the values INWX documents
/// (`1M` and `1Y`…`10Y`).
///
/// ```
/// use inwx_client::Period;
///
/// assert_eq!(Period::years(3)?.to_string(), "3Y");
/// assert_eq!(Period::ONE_MONTH.to_string(), "1M");
/// assert_eq!("2Y".parse::<Period>()?, Period::years(2)?);
/// assert!("4M".parse::<Period>().is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Period {
    /// One month — only some TLDs offer it.
    OneMonth,
    /// One to ten whole years.
    Years(u8),
}

impl Period {
    /// One month.
    pub const ONE_MONTH: Self = Self::OneMonth;

    /// A period of `years` years, from 1 to 10.
    ///
    /// ```
    /// use inwx_client::Period;
    /// assert!(Period::years(0).is_err());
    /// assert!(Period::years(10).is_ok());
    /// assert!(Period::years(11).is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `years` is outside `1..=10`.
    pub fn years(years: u8) -> Result<Self> {
        if (1..=10).contains(&years) {
            Ok(Self::Years(years))
        } else {
            Err(Error::validation(
                "period",
                format!("must be 1 to 10 years, got {years}"),
            ))
        }
    }
}

impl fmt::Display for Period {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OneMonth => formatter.write_str("1M"),
            Self::Years(years) => write!(formatter, "{years}Y"),
        }
    }
}

impl FromStr for Period {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let upper = input.trim().to_ascii_uppercase();
        if upper.as_str() == "1M" {
            Ok(Self::OneMonth)
        } else {
            let digits = upper.strip_suffix('Y').unwrap_or("");
            match digits.parse::<u8>() {
                Ok(years) => Self::years(years).map_err(|_| {
                    Error::validation(
                        "period",
                        format!("{input:?} is not a documented period (1M, 1Y..10Y)"),
                    )
                }),
                Err(_) => Err(Error::validation(
                    "period",
                    format!("{input:?} is not a documented period (1M, 1Y..10Y)"),
                )),
            }
        }
    }
}

impl Serialize for Period {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

/// What happens when a domain expires. Unknown values are carried verbatim.
///
/// ```
/// use inwx_client::RenewalMode;
///
/// assert_eq!("autorenew".parse::<RenewalMode>()?, RenewalMode::AutoRenew);
/// assert_eq!(RenewalMode::AutoRenew.to_string(), "AUTORENEW");
///
/// // A mode INWX adds later still survives a round trip.
/// let future: RenewalMode = "SOMETHING_NEW".parse()?;
/// assert_eq!(future.to_string(), "SOMETHING_NEW");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RenewalMode {
    /// Keep the domain and bill the renewal.
    AutoRenew,
    /// Let the domain expire and delete it.
    AutoDelete,
    /// Let the domain expire without deleting it.
    AutoExpire,
    /// A mode this crate does not know; carried verbatim, upper-cased.
    Other(String),
}

impl RenewalMode {
    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::RenewalMode;
    /// assert_eq!(RenewalMode::AutoExpire.as_str(), "AUTOEXPIRE");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::AutoRenew => "AUTORENEW",
            Self::AutoDelete => "AUTODELETE",
            Self::AutoExpire => "AUTOEXPIRE",
            Self::Other(raw) => raw,
        }
    }
}

impl fmt::Display for RenewalMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RenewalMode {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let upper = input.trim().to_ascii_uppercase();
        if upper.is_empty() {
            return Err(Error::validation("renewalMode", "must not be empty"));
        }
        Ok(match upper.as_str() {
            "AUTORENEW" => Self::AutoRenew,
            "AUTODELETE" => Self::AutoDelete,
            "AUTOEXPIRE" => Self::AutoExpire,
            _ => Self::Other(upper),
        })
    }
}

impl Serialize for RenewalMode {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RenewalMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(D::Error::custom)
    }
}

/// Kind of contact handle. Unknown values are carried verbatim.
///
/// ```
/// use inwx_client::ContactType;
///
/// assert_eq!(ContactType::parse("org").unwrap(), ContactType::Org);
/// assert_eq!(ContactType::Other("TRUSTEE".into()).to_string(), "TRUSTEE");
/// assert!(ContactType::parse("").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ContactType {
    /// Company or organisation.
    Org,
    /// Natural person.
    Person,
    /// Role address such as `hostmaster`.
    Role,
    /// A type this crate does not know; carried verbatim, upper-cased.
    Other(String),
}

impl ContactType {
    /// Parses a contact type, upper-casing it; unknown values become
    /// [`ContactType::Other`].
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the input is empty.
    pub fn parse(input: &str) -> Result<Self> {
        let upper = input.trim().to_ascii_uppercase();
        if upper.is_empty() {
            return Err(Error::validation("contact.type", "must not be empty"));
        }
        Ok(match upper.as_str() {
            "ORG" => Self::Org,
            "PERSON" => Self::Person,
            "ROLE" => Self::Role,
            _ => Self::Other(upper),
        })
    }

    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::ContactType;
    /// assert_eq!(ContactType::Role.as_str(), "ROLE");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Org => "ORG",
            Self::Person => "PERSON",
            Self::Role => "ROLE",
            Self::Other(raw) => raw,
        }
    }
}

impl fmt::Display for ContactType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ContactType {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl Serialize for ContactType {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ContactType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// For which action a price is quoted.
///
/// ```
/// use inwx_client::PriceType;
///
/// assert_eq!(PriceType::Renewal.as_str(), "renewal");
/// assert!("refund".parse::<PriceType>().is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PriceType {
    /// First registration.
    Reg,
    /// Renewal of an existing domain.
    Renewal,
    /// Inbound transfer.
    Transfer,
    /// Owner change.
    Trade,
    /// Update of the domain data.
    Update,
    /// Restore after deletion.
    Restore,
}

impl PriceType {
    /// Wire representation, as accepted by `domain.getdomainprice`.
    ///
    /// ```
    /// use inwx_client::PriceType;
    /// assert_eq!(PriceType::Reg.as_str(), "reg");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reg => "reg",
            Self::Renewal => "renewal",
            Self::Transfer => "transfer",
            Self::Trade => "trade",
            Self::Update => "update",
            Self::Restore => "restore",
        }
    }
}

impl fmt::Display for PriceType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for PriceType {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "reg" => Ok(Self::Reg),
            "renewal" => Ok(Self::Renewal),
            "transfer" => Ok(Self::Transfer),
            "trade" => Ok(Self::Trade),
            "update" => Ok(Self::Update),
            "restore" => Ok(Self::Restore),
            other => Err(Error::validation(
                "pricetype",
                format!("{other:?} is not one of reg, renewal, transfer, trade, update, restore"),
            )),
        }
    }
}

/// Rejects control characters in anything that will be sent as a header value
/// or a token, so a value cannot smuggle a second header.
pub(crate) fn reject_control_chars(field: &'static str, value: &str) -> Result<()> {
    if value.chars().any(char::is_control) {
        return Err(Error::validation(
            field,
            "must not contain control characters (header injection)",
        ));
    }
    Ok(())
}

/// A `token255` value: 1–255 characters, no newline, no control characters.
///
/// The INWX documentation types a large number of request fields this way
/// (redirect titles, nameserver-set names, hosting ids). Rejecting the
/// out-of-range values locally keeps a typo from becoming an `2005` from the
/// API after the request has already travelled.
pub(crate) fn validate_token(field: &'static str, value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::validation(field, "must not be empty"));
    }
    if trimmed.chars().count() > 255 {
        return Err(Error::validation(field, "must be at most 255 characters"));
    }
    reject_control_chars(field, trimmed)?;
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(Error::validation(
            field,
            "must not contain newline characters",
        ));
    }
    Ok(())
}

/// A `text`/`textNNNN` value: 1–`max` characters, newlines allowed.
pub(crate) fn validate_text(field: &'static str, value: &str, max: usize) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::validation(field, "must not be empty"));
    }
    if value.chars().count() > max {
        return Err(Error::validation(
            field,
            format!("must be at most {max} characters"),
        ));
    }
    // `\t` is not a control character the API rejects, `\0` and friends are.
    if value
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Err(Error::validation(
            field,
            "must not contain control characters",
        ));
    }
    Ok(())
}

/// A contact handle id — the `int` INWX uses for `registrant`, `admin`, `tech`,
/// `billing` and the certificate contacts.
///
/// Handles are positive; `0` and negatives are rejected before the request is
/// built, because the API answers them with `2303 Object does not exist` only
/// after the round trip.
///
/// ```
/// use inwx_client::Handle;
///
/// let handle = Handle::new(991)?;
/// assert_eq!(handle.get(), 991);
/// assert_eq!(handle.to_string(), "991");
/// assert!(Handle::new(0).is_err());
/// assert!(Handle::new(-1).is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Handle(i64);

impl Handle {
    /// Validates a handle id.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the id is not positive.
    pub fn new(id: i64) -> Result<Self> {
        if id <= 0 {
            return Err(Error::validation(
                "handle",
                format!("must be a positive contact handle, got {id}"),
            ));
        }
        Ok(Self(id))
    }

    /// The id as sent on the wire.
    ///
    /// ```
    /// use inwx_client::Handle;
    /// assert_eq!(Handle::new(7)?.get(), 7);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl TryFrom<i64> for Handle {
    type Error = Error;

    fn try_from(value: i64) -> Result<Self> {
        Self::new(value)
    }
}

impl From<Handle> for i64 {
    fn from(value: Handle) -> Self {
        value.0
    }
}

impl Serialize for Handle {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_i64(self.0)
    }
}

impl<'de> Deserialize<'de> for Handle {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let id = de::opt_i64(deserializer)?.ok_or_else(|| D::Error::custom("handle is missing"))?;
        Self::new(id).map_err(D::Error::custom)
    }
}

/// An email address, validated to the shape every INWX `email` parameter asks
/// for (`soaEmail`, `hostmaster`, `validationEmail`).
///
/// The check is deliberately structural — one `@`, a non-empty local part using
/// `[A-Za-z0-9._%+-]`, and a domain that passes [`Hostname`] validation. It
/// cannot prove the mailbox exists; it only keeps obviously malformed values
/// from being charged for.
///
/// ```
/// use inwx_client::Email;
///
/// assert_eq!(Email::parse("Hostmaster@Example.COM")?.as_str(), "Hostmaster@Example.COM");
/// for bad in ["", "hostmaster", "a@b", "a b@example.com", "@example.com", "a@"] {
///     assert!(Email::parse(bad).is_err(), "{bad:?}");
/// }
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Email(String);

impl Email {
    /// Validates an address.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the address is empty, longer than 255
    /// characters, has no single `@`, or either side is unusable.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(Error::validation("email", "must not be empty"));
        }
        if trimmed.len() > 255 {
            return Err(Error::validation("email", "must be at most 255 characters"));
        }
        reject_control_chars("email", trimmed)?;
        let (local, domain) = trimmed
            .split_once('@')
            .ok_or_else(|| Error::validation("email", format!("{trimmed:?} has no `@`")))?;
        if local.is_empty() {
            return Err(Error::validation("email", "must have a local part"));
        }
        if local.len() > 64 {
            return Err(Error::validation(
                "email",
                "local part must be at most 64 characters",
            ));
        }
        if !local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
        {
            return Err(Error::validation(
                "email",
                "local part may only contain letters, digits and ._%+-",
            ));
        }
        if domain.contains('@') {
            return Err(Error::validation("email", "must have exactly one `@`"));
        }
        Hostname::parse(domain)
            .map_err(|_| Error::validation("email", format!("{domain:?} is not a valid domain")))?;
        if !domain.contains('.') {
            return Err(Error::validation(
                "email",
                "domain must contain a dot (a TLD)",
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// The address as sent on the wire.
    ///
    /// ```
    /// use inwx_client::Email;
    /// assert_eq!(Email::parse("a@example.com")?.as_str(), "a@example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Email {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Email {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl Serialize for Email {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Email {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// A domain authorisation code (`authCode`, the EPP transfer code).
///
/// The value is a printable ASCII token; it is not trimmed down to nothing and
/// it never reaches a log line: `Debug` prints `<redacted>`, the same rule
/// [`Credentials`](crate::Credentials) follows.
///
/// ```
/// use inwx_client::AuthCode;
///
/// let code = AuthCode::new("aB3-xY9_42")?;
/// assert_eq!(code.as_str(), "aB3-xY9_42");
/// assert_eq!(format!("{code:?}"), "AuthCode(<redacted>)");
/// assert!(AuthCode::new("  ").is_err());
/// assert!(AuthCode::new("with space").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AuthCode(String);

impl AuthCode {
    /// Validates an authorisation code.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the code is empty, longer than 255
    /// characters, contains whitespace, or is not printable ASCII.
    pub fn new(code: impl Into<String>) -> Result<Self> {
        let raw = code.into();
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(Error::validation("authCode", "must not be empty"));
        }
        if trimmed.len() > 255 {
            return Err(Error::validation(
                "authCode",
                "must be at most 255 characters",
            ));
        }
        if !trimmed.is_ascii() {
            return Err(Error::validation("authCode", "must be printable ASCII"));
        }
        if trimmed.chars().any(char::is_whitespace) || trimmed.chars().any(char::is_control) {
            return Err(Error::validation(
                "authCode",
                "must not contain whitespace or control characters",
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// The code as sent on the wire.
    ///
    /// ```
    /// use inwx_client::AuthCode;
    /// assert_eq!(AuthCode::new("secret-1")?.as_str(), "secret-1");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AuthCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthCode(<redacted>)")
    }
}

impl fmt::Display for AuthCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl FromStr for AuthCode {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::new(input)
    }
}

impl Serialize for AuthCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// A new account password: validated, redacted everywhere it could be
/// printed, and wiped from memory when it is dropped.
///
/// Unlike [`AuthCode`] a password may contain spaces and non-ASCII
/// characters, so only emptiness and control characters are rejected; the
/// value is stored exactly as given (a leading or trailing space is part of
/// the secret, not padding). `Debug` and `Display` print `<redacted>` so a
/// password can never reach a log line, comparisons run in constant time, and
/// [`Zeroize`](zeroize::Zeroize) plus the `Drop` implementation overwrite the
/// bytes instead of leaving them in freed memory.
///
/// There is deliberately **no** `Deserialize`: a secret is an input, and
/// parsing one back out of a response would let a server plant a credential.
///
/// ```
/// use inwx_client::Password;
///
/// let password = Password::new("p4ss wörd")?;
/// assert_eq!(password.as_str(), "p4ss wörd");
/// assert_eq!(format!("{password:?}"), "Password(<redacted>)");
/// assert_eq!(password.to_string(), "<redacted>");
///
/// // Fail closed: an empty or blank secret is never accepted.
/// assert!(Password::new("").is_err());
/// assert!(Password::new("   ").is_err());
/// assert!(Password::new("no\nnewlines").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Clone)]
pub struct Password(String);

impl Password {
    /// Validates a password without changing it.
    ///
    /// Whitespace is only inspected to decide whether the value is blank; it
    /// is never trimmed away, because a space inside a password is part of it.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is blank, longer than
    /// [`MAX_PASSWORD_LEN`] characters, or contains a control character.
    ///
    /// ```
    /// use inwx_client::Password;
    ///
    /// let password = Password::new("  kept  ")?;
    /// assert_eq!(password.as_str(), "  kept  ");
    /// assert!(Password::new("x".repeat(256)).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        if raw.trim().is_empty() {
            return Err(Error::validation("password", "must not be empty"));
        }
        let length = raw.chars().count();
        if length > MAX_PASSWORD_LEN {
            return Err(Error::validation(
                "password",
                format!("must be at most {MAX_PASSWORD_LEN} characters, got {length}"),
            ));
        }
        if raw.chars().any(char::is_control) {
            return Err(Error::validation(
                "password",
                "must not contain control characters",
            ));
        }
        Ok(Self(raw))
    }

    /// The password as sent on the wire.
    ///
    /// Keep the returned `&str` short-lived: it borrows the buffer that
    /// `Drop` wipes.
    ///
    /// ```
    /// use inwx_client::Password;
    /// assert_eq!(Password::new("s3cret")?.as_str(), "s3cret");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Password(<redacted>)")
    }
}

impl fmt::Display for Password {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl FromStr for Password {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::new(input)
    }
}

/// Constant time, so comparing two passwords cannot leak how far apart they
/// are through an early return.
impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.as_bytes().ct_eq(other.0.as_bytes()))
    }
}

impl Eq for Password {}

impl Serialize for Password {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl zeroize::Zeroize for Password {
    /// Overwrites the secret and leaves an empty password behind.
    ///
    /// ```
    /// use inwx_client::Password;
    /// use zeroize::Zeroize;
    ///
    /// let mut password = Password::new("s3cret")?;
    /// password.zeroize();
    /// assert!(password.as_str().is_empty());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A point in time for the parameters INWX types as `timestamp`
/// (`2004-05-23T14:25:10`, ISO-8601).
///
/// Scheduled executions (`scDate`), accounting ranges and `dnssec.listkeys`
/// filters take these. The original spelling is kept for the wire; the parsed
/// value is what makes range validation (`dateFrom <= dateTo`) possible.
/// Parsing uses the `time` crate rather than a hand-rolled parser.
///
/// ```
/// use inwx_client::Timestamp;
///
/// let at = Timestamp::parse("2026-11-01T03:00:00")?;
/// assert_eq!(at.as_str(), "2026-11-01T03:00:00");
/// assert!(at > Timestamp::parse("2026-10-31T23:59:59")?);
///
/// // An offset is normalised for comparison but kept for the wire.
/// let zoned = Timestamp::parse("2026-11-01T04:00:00+01:00")?;
/// assert_eq!(zoned, at);
/// for bad in ["", "2026-13-01T00:00:00", "tomorrow", "2026-11-01"] {
///     assert!(Timestamp::parse(bad).is_err(), "{bad:?}");
/// }
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Eq)]
pub struct Timestamp {
    raw: String,
    at: time::PrimitiveDateTime,
}

impl Timestamp {
    /// Parses an ISO-8601 timestamp, with or without an offset.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not `YYYY-MM-DDTHH:MM:SS`,
    /// optionally followed by a fraction, `Z` or a `±HH:MM` offset.
    pub fn parse(input: &str) -> Result<Self> {
        let raw = input.trim();
        if raw.is_empty() {
            return Err(Error::validation("timestamp", "must not be empty"));
        }
        let at = parse_timestamp(raw).ok_or_else(|| {
            Error::validation(
                "timestamp",
                format!("{raw:?} is not an ISO-8601 timestamp (2026-11-01T03:00:00)"),
            )
        })?;
        Ok(Self {
            raw: raw.to_owned(),
            at,
        })
    }

    /// The timestamp as it will be sent.
    ///
    /// ```
    /// use inwx_client::Timestamp;
    /// assert_eq!(Timestamp::parse("2026-11-01T03:00:00")?.as_str(), "2026-11-01T03:00:00");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

/// Parses the two timestamp shapes the API documentation shows.
///
/// A `+HH:MM` value is converted to UTC so two spellings of the same instant
/// compare equal; a naive value is taken as UTC, which is the only assumption
/// that keeps ordering total.
fn parse_timestamp(raw: &str) -> Option<time::PrimitiveDateTime> {
    use time::format_description::well_known::Rfc3339;
    use time::macros::format_description;

    if let Ok(offset) = time::OffsetDateTime::parse(raw, &Rfc3339) {
        let utc = offset.to_offset(time::UtcOffset::UTC);
        return Some(time::PrimitiveDateTime::new(utc.date(), utc.time()));
    }
    let naive = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    time::PrimitiveDateTime::parse(raw, &naive).ok()
}

/// Timestamps are equal when they name the same instant, whatever offset was
/// written: `2026-11-01T04:00:00+01:00` equals `2026-11-01T03:00:00`.
impl PartialEq for Timestamp {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at
    }
}

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.at.cmp(&other.at)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.raw)
    }
}

impl FromStr for Timestamp {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// The document format the export and accounting endpoints accept
/// (`documentformat`: `RAW`, `PDF`, `CSV`).
///
/// ```
/// use inwx_client::DocumentFormat;
///
/// assert_eq!(DocumentFormat::Pdf.as_str(), "PDF");
/// assert_eq!("csv".parse::<DocumentFormat>()?, DocumentFormat::Csv);
/// assert!("xlsx".parse::<DocumentFormat>().is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DocumentFormat {
    /// Plain text (`raw`).
    Raw,
    /// PDF (`pdf`).
    Pdf,
    /// Comma separated values (`csv`).
    Csv,
}

impl DocumentFormat {
    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::DocumentFormat;
    /// assert_eq!(DocumentFormat::Raw.as_str(), "RAW");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "RAW",
            Self::Pdf => "PDF",
            Self::Csv => "CSV",
        }
    }
}

impl fmt::Display for DocumentFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for DocumentFormat {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        match input.trim().to_ascii_uppercase().as_str() {
            "RAW" => Ok(Self::Raw),
            "PDF" => Ok(Self::Pdf),
            "CSV" => Ok(Self::Csv),
            other => Err(Error::validation(
                "documentformat",
                format!("{other:?} is not one of RAW, PDF, CSV"),
            )),
        }
    }
}

impl Serialize for DocumentFormat {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DocumentFormat {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(D::Error::custom)
    }
}

/// A DynDNS username: 5–42 characters, as the `username` datatype requires.
pub(crate) fn validate_username(field: &'static str, value: &str) -> Result<()> {
    let trimmed = value.trim();
    let len = trimmed.chars().count();
    if !(5..=42).contains(&len) {
        return Err(Error::validation(
            field,
            format!("must be 5 to 42 characters, got {len}"),
        ));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    {
        return Err(Error::validation(
            field,
            "may only contain letters, digits and -_.",
        ));
    }
    Ok(())
}

/// Parses an IP address before it is put on the wire.
///
/// The `ip` datatype is used for `masterIp`, `web`, `ipAddress` and the hosting
/// answers; parsing it here keeps a typo from becoming a server-side range
/// error, and accepts both address families where the API does.
///
/// ```
/// use inwx_client::parse_ip;
///
/// assert!(parse_ip("203.0.113.7")?.is_ipv4());
/// assert!(parse_ip("2001:db8::1")?.is_ipv6());
/// assert!(parse_ip("203.0.113.7/32").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Validation`] when the text is not an IPv4 or IPv6 address.
pub fn parse_ip(text: &str) -> Result<std::net::IpAddr> {
    text.trim()
        .parse()
        .map_err(|_| Error::validation("ip", format!("{text:?} is not an IP address")))
}

/// A positive object id.
///
/// The reseller objects (`application`, `customer`, `document`, `host`,
/// `message`, `pdf`) all take a numeric id; `0` and negatives only come back as
/// `2303 Object does not exist` after the round trip, so they are refused here.
pub(crate) fn validate_id(field: &'static str, id: i64) -> Result<i64> {
    if id <= 0 {
        return Err(Error::validation(
            field,
            format!("must be a positive id, got {id}"),
        ));
    }
    Ok(id)
}

/// A page size: the API pages from one and rejects a limit of zero.
pub(crate) fn validate_page_limit(limit: u32) -> Result<u32> {
    if limit == 0 {
        return Err(Error::validation("pagelimit", "must be at least 1"));
    }
    Ok(limit)
}

/// An upper-case code token such as a document type or a verification mode:
/// `[A-Z0-9_.-]`, 1 to `max` characters. Input is trimmed and upper-cased, so a
/// caller can write `"invoice"` and get `INVOICE` on the wire.
pub(crate) fn validate_upper_token(field: &'static str, value: &str, max: usize) -> Result<String> {
    let upper = value.trim().to_ascii_uppercase();
    if upper.is_empty() {
        return Err(Error::validation(field, "must not be empty"));
    }
    if upper.chars().count() > max {
        return Err(Error::validation(
            field,
            format!(
                "must be at most {max} characters, got {}",
                upper.chars().count()
            ),
        ));
    }
    if !upper
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
    {
        return Err(Error::validation(
            field,
            format!("{value:?} may only contain letters, digits and _.-"),
        ));
    }
    Ok(upper)
}

/// A file name for an upload: no path, no control characters, at most 255
/// characters. A name with a slash in it would be a path, not a file name.
pub(crate) fn validate_filename(field: &'static str, value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return Err(Error::validation(field, "must be a file name"));
    }
    if trimmed.chars().count() > 255 {
        return Err(Error::validation(field, "must be at most 255 characters"));
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        return Err(Error::validation(
            field,
            "must not contain a path separator",
        ));
    }
    reject_control_chars(field, trimmed)?;
    Ok(trimmed.to_owned())
}

/// A two-letter ISO-3166 country code, upper-cased.
pub(crate) fn validate_country_code(field: &'static str, value: &str) -> Result<String> {
    let trimmed = value.trim().to_ascii_uppercase();
    if trimmed.len() != 2 || !trimmed.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(Error::validation(
            field,
            format!("{value:?} is not a two-letter ISO country code"),
        ));
    }
    Ok(trimmed)
}

/// Base64 with the standard alphabet and padding, which is what the API uses for
/// document bodies.
pub(crate) fn encode_base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decodes a base64 document body, refusing anything that is not base64 instead
/// of handing the caller a truncated file.
pub(crate) fn decode_base64(field: &'static str, encoded: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(encoded.trim().as_bytes())
        .map_err(|error| Error::validation(field, format!("is not valid base64: {error}")))
}

/// An integer read straight from a `Value`: a number, or a numeric string.
pub(crate) fn opt_i64_value(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// The rows of a list answer under `key`: an array is used as it arrives, a
/// single object becomes a one-row list (INWX drops the array when exactly one
/// object matches), anything else yields no rows.
pub(crate) fn list_rows(data: &Value, key: &str) -> Vec<Value> {
    match data.get(key) {
        Some(Value::Array(rows)) => rows.clone(),
        Some(single @ Value::Object(_)) => vec![single.clone()],
        _ => Vec::new(),
    }
}

/// Parses every row of a list answer, skipping the ones that do not fit the
/// model rather than failing the whole page.
pub(crate) fn parse_rows<T: serde::de::DeserializeOwned>(data: &Value, key: &str) -> Vec<T> {
    list_rows(data, key)
        .into_iter()
        .filter_map(|row| serde_json::from_value(row).ok())
        .collect()
}

/// Permissive deserialisers.
///
/// INWX is not consistent about scalar types: ids and booleans arrive as JSON
/// numbers in one method and as strings in another, and prices are `float` in
/// the docs but occasionally come back as `"12.50"`. These helpers accept both
/// shapes instead of failing the whole response.
pub(crate) mod de {
    use serde::de::Deserializer;
    use serde::Deserialize;
    use serde_json::Value;

    /// An optional integer from a number or a numeric string.
    pub(crate) fn opt_i64<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<i64>, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Ok(match value {
            Value::Number(number) => number.as_i64(),
            Value::String(text) => text.trim().parse().ok(),
            _ => None,
        })
    }

    /// An `i64`, falling back to `0` when the value is missing or unusable.
    pub(crate) fn i64_with_default<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<i64, D::Error> {
        Ok(opt_i64(deserializer)?.unwrap_or(0))
    }

    /// An `i32`, falling back to `0` when the value is missing or unusable.
    pub(crate) fn i32_with_default<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<i32, D::Error> {
        Ok(opt_i64(deserializer)?
            .and_then(|value| i32::try_from(value).ok())
            .unwrap_or(0))
    }

    /// An optional float from a number or a numeric string.
    pub(crate) fn opt_f64<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<f64>, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Ok(match value {
            Value::Number(number) => number.as_f64(),
            Value::String(text) => text.trim().parse().ok(),
            _ => None,
        })
    }

    /// An optional boolean from `true`/`false`, `1`/`0`, or their string forms.
    pub(crate) fn opt_bool<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<bool>, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Ok(match value {
            Value::Bool(flag) => Some(flag),
            Value::Number(number) => number.as_i64().map(|n| n != 0),
            Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" => Some(true),
                "0" | "false" | "no" => Some(false),
                _ => None,
            },
            _ => None,
        })
    }

    /// An optional string from a string, number or boolean.
    pub(crate) fn opt_string<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<String>, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Ok(match value {
            Value::String(text) => Some(text),
            Value::Number(number) => Some(number.to_string()),
            Value::Bool(flag) => Some(flag.to_string()),
            Value::Null => None,
            other => Some(other.to_string()),
        })
    }

    /// An optional record id from a string or a number.
    pub(crate) fn opt_record_id<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<crate::record::RecordId>, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Ok(match value {
            Value::String(text) if !text.is_empty() => Some(crate::record::RecordId::from(text)),
            Value::Number(number) => Some(crate::record::RecordId::from(number.to_string())),
            _ => None,
        })
    }

    /// An optional record type, carried permissively.
    pub(crate) fn opt_record_type<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<crate::record::RecordType>, D::Error> {
        let raw = opt_string(deserializer)?;
        match raw {
            Some(raw) if !raw.trim().is_empty() => Ok(crate::record::RecordType::parse(&raw).ok()),
            _ => Ok(None),
        }
    }

    /// A list of strings; a single string becomes a one-element list, anything
    /// else an empty one.
    pub(crate) fn vec_string<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Vec<String>, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Ok(match value {
            Value::Array(entries) => entries
                .into_iter()
                .filter_map(|entry| match entry {
                    Value::String(text) => Some(text),
                    Value::Number(number) => Some(number.to_string()),
                    _ => None,
                })
                .collect(),
            Value::String(text) if !text.is_empty() => vec![text],
            _ => Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_accepts_trailing_dot_and_whitespace() {
        assert_eq!(
            DomainName::parse("  Example.COM.  ").unwrap().as_str(),
            "example.com"
        );
    }

    #[test]
    fn domain_enforces_label_and_total_length_limits() {
        let max_label = "a".repeat(MAX_LABEL_LEN);
        assert!(DomainName::parse(&format!("{max_label}.com")).is_ok());

        let long_label = "a".repeat(MAX_LABEL_LEN + 1);
        assert!(DomainName::parse(&format!("{long_label}.com")).is_err());

        // Every label is legal on its own, so only the total-name limit can
        // distinguish these two inputs.
        let last_label_len = MAX_DOMAIN_LEN - (3 * MAX_LABEL_LEN + 3);
        let at_limit = format!(
            "{}.{}.{}.{}",
            "a".repeat(MAX_LABEL_LEN),
            "b".repeat(MAX_LABEL_LEN),
            "c".repeat(MAX_LABEL_LEN),
            "d".repeat(last_label_len)
        );
        assert_eq!(at_limit.len(), MAX_DOMAIN_LEN);
        assert_eq!(
            DomainName::parse(&at_limit)
                .ok()
                .as_ref()
                .map(DomainName::as_str),
            Some(at_limit.as_str())
        );
        assert_eq!(
            Hostname::parse(&at_limit)
                .ok()
                .as_ref()
                .map(Hostname::as_str),
            Some(at_limit.as_str())
        );

        let over_limit = format!(
            "{}.{}.{}.{}",
            "a".repeat(MAX_LABEL_LEN),
            "b".repeat(MAX_LABEL_LEN),
            "c".repeat(MAX_LABEL_LEN),
            "d".repeat(last_label_len + 1)
        );
        assert_eq!(over_limit.len(), MAX_DOMAIN_LEN + 1);
        for (expected_field, error) in [
            ("domain", DomainName::parse(&over_limit).unwrap_err()),
            ("hostname", Hostname::parse(&over_limit).unwrap_err()),
        ] {
            let Error::Validation { field, message } = error else {
                panic!("expected a validation error, got {error}");
            };
            assert_eq!(field, expected_field);
            assert_eq!(
                message,
                format!(
                    "must be at most {MAX_DOMAIN_LEN} characters, got {}",
                    over_limit.len()
                )
            );
        }
    }

    #[test]
    fn domain_rejects_control_characters() {
        assert!(DomainName::parse("exa\u{0}mple.com").is_err());
    }

    #[test]
    fn tld_and_sld_of_single_label_are_empty_but_unreachable() {
        let domain = DomainName::parse("example.com").unwrap();
        assert_eq!(domain.tld(), "com");
        assert_eq!(domain.sld(), "example");
    }

    #[test]
    fn hostname_allows_single_label() {
        assert_eq!(Hostname::parse("ns1").unwrap().as_str(), "ns1");
    }

    #[test]
    fn period_parsing_is_case_insensitive() {
        assert_eq!("3y".parse::<Period>().unwrap(), Period::Years(3));
        assert!("0Y".parse::<Period>().is_err());
        assert!("Y".parse::<Period>().is_err());
        assert!("".parse::<Period>().is_err());
    }

    #[test]
    fn renewal_mode_unknown_is_carried_upper_cased() {
        assert_eq!(
            "newMode".parse::<RenewalMode>().unwrap(),
            RenewalMode::Other("NEWMODE".into())
        );
        assert!("  ".parse::<RenewalMode>().is_err());
    }

    #[test]
    fn permissive_scalars_accept_both_shapes() {
        #[derive(Deserialize)]
        struct Sample {
            #[serde(default, deserialize_with = "de::opt_i64")]
            id: Option<i64>,
            #[serde(default, deserialize_with = "de::opt_bool")]
            flag: Option<bool>,
            #[serde(default, deserialize_with = "de::opt_f64")]
            price: Option<f64>,
            #[serde(default, deserialize_with = "de::opt_string")]
            text: Option<String>,
            #[serde(default, deserialize_with = "de::vec_string")]
            names: Vec<String>,
        }

        let from_numbers: Sample =
            serde_json::from_str(r#"{"id":7,"flag":1,"price":12.5,"text":42,"names":"ns1"}"#)
                .unwrap();
        assert_eq!(from_numbers.id, Some(7));
        assert_eq!(from_numbers.flag, Some(true));
        assert_eq!(from_numbers.price, Some(12.5));
        assert_eq!(from_numbers.text.as_deref(), Some("42"));
        assert_eq!(from_numbers.names, ["ns1"]);

        let from_strings: Sample = serde_json::from_str(
            r#"{"id":"7","flag":"0","price":"12.50","text":null,"names":["a",1,"b"]}"#,
        )
        .unwrap();
        assert_eq!(from_strings.id, Some(7));
        assert_eq!(from_strings.flag, Some(false));
        assert_eq!(from_strings.price, Some(12.5));
        assert!(from_strings.text.is_none());
        assert_eq!(from_strings.names, ["a", "1", "b"]);

        let odd: Sample = serde_json::from_str(r#"{"id":{},"flag":[],"names":{}}"#).unwrap();
        assert!(odd.id.is_none());
        assert!(odd.flag.is_none());
        assert_eq!(odd.names.len(), 0);
    }

    #[test]
    fn password_keeps_the_value_verbatim() {
        // A space is part of a secret, so nothing is trimmed, and unlike an
        // auth code a password may contain spaces and non-ASCII characters.
        for allowed in ["  kept  ", "p4ss wörd", "x"] {
            let password = Password::new(allowed).unwrap();
            assert_eq!(password.as_str(), allowed);
        }
    }

    #[test]
    fn password_rejects_blank_and_control_characters() {
        for blank in ["", " ", "  \n "] {
            let error = Password::new(blank).unwrap_err();
            let Error::Validation { field, message } = error else {
                panic!("expected a validation error, got {error}");
            };
            assert_eq!(field, "password");
            assert_eq!(message, "must not be empty");
        }

        for control in ["no\nnewline", "no\ttab", "no\0nul"] {
            let error = Password::new(control).unwrap_err();
            let Error::Validation { field, message } = error else {
                panic!("expected a validation error, got {error}");
            };
            assert_eq!(field, "password");
            assert_eq!(message, "must not contain control characters");
        }
    }

    #[test]
    fn password_enforces_the_length_limit() {
        let at_limit = Password::new("x".repeat(MAX_PASSWORD_LEN)).unwrap();
        assert_eq!(at_limit.as_str().chars().count(), MAX_PASSWORD_LEN);

        let over_limit_input = "x".repeat(MAX_PASSWORD_LEN + 1);
        let error = Password::new(over_limit_input.clone()).unwrap_err();
        let Error::Validation { field, message } = error else {
            panic!("expected a validation error, got {error}");
        };
        assert_eq!(field, "password");
        assert_eq!(
            message,
            format!(
                "must be at most {MAX_PASSWORD_LEN} characters, got {}",
                over_limit_input.chars().count()
            )
        );

        // The limit counts characters, not bytes, so a multi-byte secret is
        // measured the way the API measures it.
        assert!(Password::new("ö".repeat(MAX_PASSWORD_LEN)).is_ok());
        assert!(Password::new("ö".repeat(MAX_PASSWORD_LEN + 1)).is_err());
    }

    #[test]
    fn password_redacts_itself_in_debug_and_display() {
        let password = Password::new("s3cret").unwrap();
        assert_eq!(format!("{password:?}"), "Password(<redacted>)");
        assert_eq!(password.to_string(), "<redacted>");
        assert!(!format!("{password:?}").contains("s3cret"));
        assert!(!password.to_string().contains("s3cret"));
    }

    #[test]
    fn password_equality_compares_values() {
        let left = Password::new("s3cret").unwrap();
        assert_eq!(left, Password::new("s3cret").unwrap());
        assert_eq!(left, left.clone());
        assert_ne!(left, Password::new("s3creu").unwrap());
        assert_ne!(left, Password::new("s3cret ").unwrap());
    }

    #[test]
    fn password_parses_from_str() {
        assert_eq!(
            "s3cret".parse::<Password>().unwrap(),
            Password::new("s3cret").unwrap()
        );
        assert!("".parse::<Password>().is_err());
    }

    #[test]
    fn password_serializes_as_a_plain_string() {
        let password = Password::new("s3cret").unwrap();
        assert_eq!(
            serde_json::to_value(&password).unwrap(),
            Value::String("s3cret".into())
        );
    }

    #[test]
    fn password_can_be_zeroized_on_demand() {
        use zeroize::Zeroize;

        let mut password = Password::new("s3cret").unwrap();
        assert_eq!(password.as_str(), "s3cret");
        password.zeroize();
        assert_eq!(password.as_str(), "");
        // Wiping twice must not resurrect anything nor abort.
        password.zeroize();
        assert_eq!(password.as_str(), "");
    }
}
