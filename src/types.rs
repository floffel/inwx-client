//! Validated value types shared by every request and response.
//!
//! The types here exist so an invalid value never reaches the wire: a
//! [`DomainName`] is known to be a syntactically valid, punycode-encoded name,
//! a [`Period`] is one the API documents, and so on. Everything parses from
//! `&str` (or `TryFrom`) and renders back with `Display`.

use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Error, Result};

/// Longest legal DNS name in presentation form, without the trailing root dot.
pub const MAX_DOMAIN_LEN: usize = 253;

/// Longest legal single DNS label.
pub const MAX_LABEL_LEN: usize = 63;

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
    /// [`Error::Validation`] when a label is empty, too long, starts or ends
    /// with a hyphen, or contains a character outside `[a-z0-9-]`.
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
    fn domain_rejects_overlong_names() {
        let long_label = "a".repeat(64);
        assert!(DomainName::parse(&format!("{long_label}.com")).is_err());
        let long_name = format!("{}.com", "a".repeat(250));
        assert!(DomainName::parse(&long_name).is_err());
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
        assert!(odd.names.is_empty());
    }
}
