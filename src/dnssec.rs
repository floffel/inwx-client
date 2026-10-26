//! DNSSEC (`dnssec.*`): enabling automated signing and managing manual keys.
//!
//! INWX either manages the keys itself (`enable`/`disable`) or accepts manual
//! DNSKEY/DS records for a domain. Both halves are here. The presentation-format
//! strings are parsed and checked before they are sent: the API accepts only
//! `ZONE+SEP` keys (flag 257), so a `ZONE` key (256) is refused locally instead
//! of coming back as `2004` after the round trip.

use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, DomainName, Timestamp};

/// A DNSSEC signing algorithm (`dnssecAlgorithm`).
///
/// The variants are exactly the numbers the datatype chapter lists; an
/// unlisted number is refused, because the API only accepts the documented set.
///
/// ```
/// use inwx_client::DnssecAlgorithm;
///
/// assert_eq!(DnssecAlgorithm::EcdsaP256.as_u8(), 13);
/// assert_eq!(DnssecAlgorithm::from_u8(13)?, DnssecAlgorithm::EcdsaP256);
/// assert!(DnssecAlgorithm::from_u8(1).is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnssecAlgorithm {
    /// 5 — RSA/SHA-1 (legacy).
    RsaSha1,
    /// 7 — RSASHA1-NSEC3-SHA1.
    RsaSha1Nsec3,
    /// 8 — RSA/SHA-256.
    RsaSha256,
    /// 10 — RSA/SHA-512.
    RsaSha512,
    /// 13 — ECDSA Curve P-256 with SHA-256.
    EcdsaP256,
    /// 14 — ECDSA Curve P-384 with SHA-384.
    EcdsaP384,
    /// 15 — ED25519.
    Ed25519,
    /// 16 — ED448.
    Ed448,
}

impl DnssecAlgorithm {
    /// The numeric id on the wire.
    ///
    /// ```
    /// use inwx_client::DnssecAlgorithm;
    /// assert_eq!(DnssecAlgorithm::Ed25519.as_u8(), 15);
    /// ```
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::RsaSha1 => 5,
            Self::RsaSha1Nsec3 => 7,
            Self::RsaSha256 => 8,
            Self::RsaSha512 => 10,
            Self::EcdsaP256 => 13,
            Self::EcdsaP384 => 14,
            Self::Ed25519 => 15,
            Self::Ed448 => 16,
        }
    }

    /// Parses a numeric id.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a number the documentation does not list.
    ///
    /// ```
    /// use inwx_client::DnssecAlgorithm;
    /// assert!(DnssecAlgorithm::from_u8(16).is_ok());
    /// assert!(DnssecAlgorithm::from_u8(99).is_err());
    /// ```
    pub fn from_u8(value: u8) -> Result<Self> {
        Ok(match value {
            5 => Self::RsaSha1,
            7 => Self::RsaSha1Nsec3,
            8 => Self::RsaSha256,
            10 => Self::RsaSha512,
            13 => Self::EcdsaP256,
            14 => Self::EcdsaP384,
            15 => Self::Ed25519,
            16 => Self::Ed448,
            other => {
                return Err(Error::validation(
                    "dnssec.algorithm",
                    format!("{other} is not a documented DNSSEC algorithm"),
                ));
            }
        })
    }
}

impl fmt::Display for DnssecAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.as_u8())
    }
}

impl Serialize for DnssecAlgorithm {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for DnssecAlgorithm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = de::opt_i64(deserializer)?.unwrap_or_default();
        let value = u8::try_from(value)
            .map_err(|_| D::Error::custom(format!("algorithm {value} is out of range")))?;
        Self::from_u8(value).map_err(D::Error::custom)
    }
}

/// A DNSSEC digest type (`dnssecDigestType`).
///
/// ```
/// use inwx_client::DnssecDigestType;
///
/// assert_eq!(DnssecDigestType::Sha256.as_u8(), 2);
/// assert_eq!(DnssecDigestType::from_u8(4)?, DnssecDigestType::Sha384);
/// assert!(DnssecDigestType::from_u8(1).is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnssecDigestType {
    /// 2 — SHA-256 (the API default).
    Sha256,
    /// 4 — SHA-384.
    Sha384,
}

impl DnssecDigestType {
    /// The numeric id on the wire.
    ///
    /// ```
    /// use inwx_client::DnssecDigestType;
    /// assert_eq!(DnssecDigestType::Sha384.as_u8(), 4);
    /// ```
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Sha256 => 2,
            Self::Sha384 => 4,
        }
    }

    /// Parses a numeric id.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for any number other than 2 or 4.
    ///
    /// ```
    /// use inwx_client::DnssecDigestType;
    /// assert!(DnssecDigestType::from_u8(2).is_ok());
    /// assert!(DnssecDigestType::from_u8(3).is_err());
    /// ```
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            2 => Ok(Self::Sha256),
            4 => Ok(Self::Sha384),
            other => Err(Error::validation(
                "dnssec.digestType",
                format!("{other} is not a documented digest type (2, 4)"),
            )),
        }
    }
}

impl fmt::Display for DnssecDigestType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.as_u8())
    }
}

impl Serialize for DnssecDigestType {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for DnssecDigestType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = de::opt_i64(deserializer)?.unwrap_or_default();
        let value = u8::try_from(value)
            .map_err(|_| D::Error::custom(format!("digest type {value} is out of range")))?;
        Self::from_u8(value).map_err(D::Error::custom)
    }
}

/// A DNSSEC key flag (`dnssecFlag`).
///
/// ```
/// use inwx_client::DnssecFlag;
///
/// assert_eq!(DnssecFlag::ZoneSep.as_u16(), 257);
/// assert_eq!(DnssecFlag::from_u16(256)?, DnssecFlag::Zone);
/// assert!(DnssecFlag::from_u16(1).is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnssecFlag {
    /// 256 — ZONE.
    Zone,
    /// 257 — ZONE+SEP (the only flag `dnssec.adddnskey` accepts).
    ZoneSep,
}

impl DnssecFlag {
    /// The numeric id on the wire.
    ///
    /// ```
    /// use inwx_client::DnssecFlag;
    /// assert_eq!(DnssecFlag::Zone.as_u16(), 256);
    /// ```
    #[must_use]
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Zone => 256,
            Self::ZoneSep => 257,
        }
    }

    /// Parses a numeric id.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for anything other than 256 or 257.
    ///
    /// ```
    /// use inwx_client::DnssecFlag;
    /// assert!(DnssecFlag::from_u16(257).is_ok());
    /// assert!(DnssecFlag::from_u16(512).is_err());
    /// ```
    pub fn from_u16(value: u16) -> Result<Self> {
        match value {
            256 => Ok(Self::Zone),
            257 => Ok(Self::ZoneSep),
            other => Err(Error::validation(
                "dnssec.flag",
                format!("{other} is not a documented DNSKEY flag (256, 257)"),
            )),
        }
    }
}

impl fmt::Display for DnssecFlag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.as_u16())
    }
}

impl Serialize for DnssecFlag {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_u16(self.as_u16())
    }
}

impl<'de> Deserialize<'de> for DnssecFlag {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = de::opt_i64(deserializer)?.unwrap_or_default();
        let value = u16::try_from(value)
            .map_err(|_| D::Error::custom(format!("flag {value} is out of range")))?;
        Self::from_u16(value).map_err(D::Error::custom)
    }
}

/// The state of one domain's DNSSEC setup (`dnssecDomainStatus`).
///
/// Unknown values are carried, so a new state does not break the list.
///
/// ```
/// use inwx_client::DnssecDomainStatus;
///
/// assert_eq!("manual".parse::<DnssecDomainStatus>()?, DnssecDomainStatus::Manual);
/// assert_eq!(
///     DnssecDomainStatus::parse("SOMETHING")?,
///     DnssecDomainStatus::Other("SOMETHING".into())
/// );
/// assert!(DnssecDomainStatus::parse(" ").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnssecDomainStatus {
    /// Every key for the domain is scheduled for deletion.
    DeleteAll,
    /// Keys are managed manually through this API.
    Manual,
    /// A manual update is pending.
    Update,
    /// A status this crate does not know; carried verbatim, upper-cased.
    Other(String),
}

impl DnssecDomainStatus {
    /// Parses a status, upper-casing it.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the input is empty.
    ///
    /// ```
    /// use inwx_client::DnssecDomainStatus;
    /// assert_eq!(DnssecDomainStatus::parse("DELETE_ALL")?, DnssecDomainStatus::DeleteAll);
    /// assert!(DnssecDomainStatus::parse("").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn parse(input: &str) -> Result<Self> {
        let upper = input.trim().to_ascii_uppercase();
        if upper.is_empty() {
            return Err(Error::validation("dnssec.status", "must not be empty"));
        }
        Ok(match upper.as_str() {
            "DELETE_ALL" => Self::DeleteAll,
            "MANUAL" => Self::Manual,
            "UPDATE" => Self::Update,
            _ => Self::Other(upper),
        })
    }

    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::DnssecDomainStatus;
    /// assert_eq!(DnssecDomainStatus::Update.as_str(), "UPDATE");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::DeleteAll => "DELETE_ALL",
            Self::Manual => "MANUAL",
            Self::Update => "UPDATE",
            Self::Other(raw) => raw,
        }
    }
}

impl fmt::Display for DnssecDomainStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for DnssecDomainStatus {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl Serialize for DnssecDomainStatus {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DnssecDomainStatus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// The status of one manual DNSKEY (`dnssecKeyStatus`).
///
/// ```
/// use inwx_client::DnssecKeyStatus;
///
/// assert_eq!("ok".parse::<DnssecKeyStatus>()?, DnssecKeyStatus::Ok);
/// assert_eq!(DnssecKeyStatus::parse("ALIEN")?, DnssecKeyStatus::Other("ALIEN".into()));
/// assert!(DnssecKeyStatus::parse("").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnssecKeyStatus {
    /// Being created.
    Create,
    /// Waiting for the registry.
    Delayed,
    /// Published and accepted.
    Ok,
    /// Scheduled or already removed.
    Deleted,
    /// Ignored by the API.
    Ignore,
    /// A status this crate does not know; carried verbatim, upper-cased.
    Other(String),
}

impl DnssecKeyStatus {
    /// Parses a status, upper-casing it.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the input is empty.
    ///
    /// ```
    /// use inwx_client::DnssecKeyStatus;
    /// assert_eq!(DnssecKeyStatus::parse("delayed")?, DnssecKeyStatus::Delayed);
    /// assert!(DnssecKeyStatus::parse("  ").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn parse(input: &str) -> Result<Self> {
        let upper = input.trim().to_ascii_uppercase();
        if upper.is_empty() {
            return Err(Error::validation("dnssec.keyStatus", "must not be empty"));
        }
        Ok(match upper.as_str() {
            "CREATE" => Self::Create,
            "DELAYED" => Self::Delayed,
            "OK" => Self::Ok,
            "DELETED" => Self::Deleted,
            "IGNORE" => Self::Ignore,
            _ => Self::Other(upper),
        })
    }

    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::DnssecKeyStatus;
    /// assert_eq!(DnssecKeyStatus::Ignore.as_str(), "IGNORE");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Create => "CREATE",
            Self::Delayed => "DELAYED",
            Self::Ok => "OK",
            Self::Deleted => "DELETED",
            Self::Ignore => "IGNORE",
            Self::Other(raw) => raw,
        }
    }
}

impl fmt::Display for DnssecKeyStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for DnssecKeyStatus {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl Serialize for DnssecKeyStatus {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DnssecKeyStatus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = de::opt_string(deserializer)?;
        raw.map_or_else(
            || Err(D::Error::custom("dnssec key status is missing")),
            |raw| Self::parse(&raw).map_err(D::Error::custom),
        )
    }
}

/// One domain's DNSSEC state, from `dnssec.info`.
///
/// ```
/// use inwx_client::{DnssecDomainStatus, DnssecState};
///
/// let state: DnssecState = serde_json::from_str(
///     r#"{"domain":"example.com","keyCount":2,"dnssecStatus":"MANUAL"}"#,
/// )?;
/// assert_eq!(state.key_count, Some(2));
/// assert_eq!(state.status, DnssecDomainStatus::Manual);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DnssecState {
    /// The domain.
    pub domain: DomainName,
    /// Number of keys the API reports.
    #[serde(default, rename = "keyCount", deserialize_with = "de::opt_i64")]
    pub key_count: Option<i64>,
    /// DNSSEC status of the domain.
    #[serde(default = "default_domain_status", rename = "dnssecStatus")]
    pub status: DnssecDomainStatus,
}

/// `dnssec.info` omits the status for unsigned domains; `MANUAL` is the only
/// value that keeps a missing field from claiming "signed".
fn default_domain_status() -> DnssecDomainStatus {
    DnssecDomainStatus::Manual
}

/// A DNSKEY in presentation format (`dnskey`), checked before it is sent.
///
/// The documentation's example is
/// `domain.tld. IN DNSKEY 257 3 13 ac12c2…`. `dnssec.adddnskey` accepts only
/// `ZONE+SEP` keys (flag 257), so anything else is refused here rather than by
/// the API.
///
/// ```
/// use inwx_client::{DnsKey, DnssecAlgorithm, DnssecFlag};
///
/// let key = DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12c2")?;
/// assert_eq!(key.flag(), DnssecFlag::ZoneSep);
/// assert_eq!(key.algorithm(), DnssecAlgorithm::EcdsaP256);
/// assert_eq!(key.owner(), "example.com.");
/// assert_eq!(key.as_str(), "example.com. IN DNSKEY 257 3 13 ac12c2");
///
/// // A ZONE key (256) is not accepted by the API.
/// assert!(DnsKey::parse("example.com. IN DNSKEY 256 3 13 ac12c2").is_err());
/// assert!(DnsKey::parse("garbage").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsKey {
    raw: String,
    owner: String,
    flag: DnssecFlag,
    algorithm: DnssecAlgorithm,
}

impl DnsKey {
    /// Parses a DNSKEY presentation string.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the string is not
    /// `<owner> IN DNSKEY <flag> 3 <algorithm> <key>`, when the protocol is not
    /// `3`, when the flag is not 257, or when the algorithm is undocumented.
    ///
    /// ```
    /// use inwx_client::DnsKey;
    ///
    /// assert!(DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12c2").is_ok());
    /// assert!(DnsKey::parse("example.com. IN DNSKEY 257 2 13 ac12c2").is_err());
    /// assert!(DnsKey::parse("").is_err());
    /// ```
    pub fn parse(input: &str) -> Result<Self> {
        let raw = input.trim();
        if raw.is_empty() {
            return Err(Error::validation("dnssec.dnskey", "must not be empty"));
        }
        if raw.chars().count() > 1024 {
            return Err(Error::validation(
                "dnssec.dnskey",
                "must be at most 1024 characters",
            ));
        }
        let tokens = raw.split_whitespace().collect::<Vec<_>>();
        if tokens.len() < 7 {
            return Err(Error::validation(
                "dnssec.dnskey",
                "needs `<owner> IN DNSKEY <flag> 3 <algorithm> <key>`",
            ));
        }
        if !tokens[1].eq_ignore_ascii_case("IN") || !tokens[2].eq_ignore_ascii_case("DNSKEY") {
            return Err(Error::validation(
                "dnssec.dnskey",
                "the record class and type must be `IN DNSKEY`",
            ));
        }
        let flag: u16 = tokens[3].parse().map_err(|_| {
            Error::validation("dnssec.dnskey", format!("{:?} is not a flag", tokens[3]))
        })?;
        let flag = DnssecFlag::from_u16(flag)?;
        if flag != DnssecFlag::ZoneSep {
            return Err(Error::validation(
                "dnssec.dnskey",
                "only ZONE+SEP keys (flag 257) are accepted by dnssec.adddnskey",
            ));
        }
        if tokens[4] != "3" {
            return Err(Error::validation(
                "dnssec.dnskey",
                "the protocol must be 3 (DNSSEC)",
            ));
        }
        let algorithm: u8 = tokens[5].parse().map_err(|_| {
            Error::validation(
                "dnssec.dnskey",
                format!("{:?} is not an algorithm id", tokens[5]),
            )
        })?;
        Ok(Self {
            raw: raw.to_owned(),
            owner: tokens[0].to_owned(),
            flag,
            algorithm: DnssecAlgorithm::from_u8(algorithm)?,
        })
    }

    /// The presentation string as sent.
    ///
    /// ```
    /// use inwx_client::DnsKey;
    /// assert_eq!(
    ///     DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12c2")?.as_str(),
    ///     "example.com. IN DNSKEY 257 3 13 ac12c2"
    /// );
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The key owner as written (usually the zone with a trailing dot).
    ///
    /// ```
    /// use inwx_client::DnsKey;
    /// assert_eq!(DnsKey::parse("example.com. IN DNSKEY 257 3 13 k")?.owner(), "example.com.");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The key flag.
    ///
    /// ```
    /// use inwx_client::{DnsKey, DnssecFlag};
    /// assert_eq!(DnsKey::parse("a.de. IN DNSKEY 257 3 13 k")?.flag(), DnssecFlag::ZoneSep);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn flag(&self) -> DnssecFlag {
        self.flag
    }

    /// The algorithm.
    ///
    /// ```
    /// use inwx_client::{DnsKey, DnssecAlgorithm};
    /// assert_eq!(
    ///     DnsKey::parse("a.de. IN DNSKEY 257 3 8 k")?.algorithm(),
    ///     DnssecAlgorithm::RsaSha256
    /// );
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn algorithm(&self) -> DnssecAlgorithm {
        self.algorithm
    }
}

impl fmt::Display for DnsKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.raw)
    }
}

impl std::str::FromStr for DnsKey {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl Serialize for DnsKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

/// A DS record in presentation format (`ds`), checked before it is sent.
///
/// The documentation's example is `domain.tld. IN DS 1234 13 2 56DC12…`.
///
/// ```
/// use inwx_client::{DsRecord, DnssecAlgorithm, DnssecDigestType};
///
/// let ds = DsRecord::parse("example.com. IN DS 1234 13 2 56DC12")?;
/// assert_eq!(ds.key_tag(), 1234);
/// assert_eq!(ds.algorithm(), DnssecAlgorithm::EcdsaP256);
/// assert_eq!(ds.digest_type(), DnssecDigestType::Sha256);
/// assert!(DsRecord::parse("example.com. IN DS 1234 13 9 56DC12").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsRecord {
    raw: String,
    key_tag: u16,
    algorithm: DnssecAlgorithm,
    digest_type: DnssecDigestType,
}

impl DsRecord {
    /// Parses a DS presentation string.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the string is not
    /// `<owner> IN DS <keytag> <algorithm> <digesttype> <digest>`, or a number is
    /// outside the documented set.
    ///
    /// ```
    /// use inwx_client::DsRecord;
    /// assert!(DsRecord::parse("example.com. IN DS 1234 13 2 56DC12").is_ok());
    /// assert!(DsRecord::parse("example.com. IN DS 1234 13 56DC12").is_err());
    /// ```
    pub fn parse(input: &str) -> Result<Self> {
        let raw = input.trim();
        if raw.is_empty() {
            return Err(Error::validation("dnssec.ds", "must not be empty"));
        }
        let tokens = raw.split_whitespace().collect::<Vec<_>>();
        if tokens.len() < 7 {
            return Err(Error::validation(
                "dnssec.ds",
                "needs `<owner> IN DS <keytag> <algorithm> <digesttype> <digest>`",
            ));
        }
        if !tokens[1].eq_ignore_ascii_case("IN") || !tokens[2].eq_ignore_ascii_case("DS") {
            return Err(Error::validation(
                "dnssec.ds",
                "the record class and type must be `IN DS`",
            ));
        }
        let key_tag: u16 = tokens[3].parse().map_err(|_| {
            Error::validation("dnssec.ds", format!("{:?} is not a key tag", tokens[3]))
        })?;
        let algorithm: u8 = tokens[4].parse().map_err(|_| {
            Error::validation("dnssec.ds", format!("{:?} is not an algorithm", tokens[4]))
        })?;
        let digest_type: u8 = tokens[5].parse().map_err(|_| {
            Error::validation("dnssec.ds", format!("{:?} is not a digest type", tokens[5]))
        })?;
        if !tokens[6].chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::validation(
                "dnssec.ds",
                "the digest must be hexadecimal",
            ));
        }
        Ok(Self {
            raw: raw.to_owned(),
            key_tag,
            algorithm: DnssecAlgorithm::from_u8(algorithm)?,
            digest_type: DnssecDigestType::from_u8(digest_type)?,
        })
    }

    /// The presentation string as sent.
    ///
    /// ```
    /// use inwx_client::DsRecord;
    /// assert_eq!(
    ///     DsRecord::parse("example.com. IN DS 1234 13 2 56DC12")?.as_str(),
    ///     "example.com. IN DS 1234 13 2 56DC12"
    /// );
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The key tag.
    ///
    /// ```
    /// use inwx_client::DsRecord;
    /// assert_eq!(DsRecord::parse("a.de. IN DS 65535 13 2 AA")?.key_tag(), 65535);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// The algorithm of the referenced key.
    ///
    /// ```
    /// use inwx_client::{DsRecord, DnssecAlgorithm};
    /// assert_eq!(DsRecord::parse("a.de. IN DS 1 8 2 AA")?.algorithm(), DnssecAlgorithm::RsaSha256);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn algorithm(&self) -> DnssecAlgorithm {
        self.algorithm
    }

    /// The digest type.
    ///
    /// ```
    /// use inwx_client::{DsRecord, DnssecDigestType};
    /// assert_eq!(DsRecord::parse("a.de. IN DS 1 8 4 AA")?.digest_type(), DnssecDigestType::Sha384);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn digest_type(&self) -> DnssecDigestType {
        self.digest_type
    }
}

impl fmt::Display for DsRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.raw)
    }
}

impl std::str::FromStr for DsRecord {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl Serialize for DsRecord {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

/// The answer to `dnssec.adddnskey`.
///
/// ```
/// use inwx_client::DnsKeyPair;
///
/// let pair: DnsKeyPair = serde_json::from_str(
///     r#"{"dnskey":"example.com. IN DNSKEY 257 3 13 ac12","ds":"example.com. IN DS 1 13 2 AA"}"#,
/// )?;
/// assert!(pair.dnskey.starts_with("example.com."));
/// assert!(pair.ds.is_some());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DnsKeyPair {
    /// The key as stored.
    #[serde(default)]
    pub dnskey: String,
    /// The derived DS record, when one was calculated.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub ds: Option<String>,
}

/// One manually managed DNSKEY, from `dnssec.listkeys`.
///
/// ```
/// use inwx_client::DnssecKey;
///
/// let key: DnssecKey = serde_json::from_str(
///     r#"{"id":7,"ownerName":"example.com.","keyTag":1234,"flagId":257,
///         "algorithmId":13,"digestTypeId":2,"digest":"AA","status":"OK","active":1}"#,
/// )?;
/// assert_eq!(key.key_tag, Some(1234));
/// assert!(key.is_active());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DnssecKey {
    /// Key id, needed for `dnssec.deletednskey`.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// The domain that owns the key.
    #[serde(default, rename = "ownerName", deserialize_with = "de::opt_string")]
    pub owner_name: Option<String>,
    /// Domain id.
    #[serde(default, rename = "domainId", deserialize_with = "de::opt_i64")]
    pub domain_id: Option<i64>,
    /// Key tag.
    #[serde(default, rename = "keyTag", deserialize_with = "de::opt_i64")]
    pub key_tag: Option<i64>,
    /// Key flag.
    #[serde(default, rename = "flagId", deserialize_with = "de::opt_i64")]
    pub flag: Option<i64>,
    /// Algorithm id.
    #[serde(default, rename = "algorithmId", deserialize_with = "de::opt_i64")]
    pub algorithm: Option<i64>,
    /// Public key (base64).
    #[serde(default, rename = "publicKey", deserialize_with = "de::opt_string")]
    pub public_key: Option<String>,
    /// Digest type id.
    #[serde(default, rename = "digestTypeId", deserialize_with = "de::opt_i64")]
    pub digest_type: Option<i64>,
    /// Digest value.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub digest: Option<String>,
    /// Creation time.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub created: Option<String>,
    /// Key status.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
    /// `1` when the key is active, `0` when not.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub active: Option<i64>,
}

impl DnssecKey {
    /// Whether the API reports the key as active.
    ///
    /// ```
    /// use inwx_client::DnssecKey;
    ///
    /// let key: DnssecKey = serde_json::from_str(r#"{"id":1,"active":0}"#)?;
    /// assert!(!key.is_active());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active == Some(1)
    }
}

/// A `dnssec.adddnskey` request.
///
/// Either a DS record is supplied, or the API is asked to calculate one — never
/// both. The API documents `calculateDigest` as *overriding* `ds`, which would
/// silently discard the value the caller passed; this builder refuses the
/// combination instead.
///
/// ```
/// use inwx_client::{AddDnsKeyRequest, DnsKey, DnssecDigestType, DomainName};
///
/// let request = AddDnsKeyRequest::new(
///     DomainName::parse("example.com")?,
///     DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12c2")?,
/// )?
/// .calculating_digest(DnssecDigestType::Sha384)?;
///
/// let params = request.params();
/// assert_eq!(params["calculateDigest"], true);
/// assert_eq!(params["digestType"], 4);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddDnsKeyRequest {
    domain: DomainName,
    dnskey: DnsKey,
    ds: Option<DsRecord>,
    calculate_digest: Option<bool>,
    digest_type: Option<DnssecDigestType>,
}

impl AddDnsKeyRequest {
    /// A request for one key, without a DS record.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the key owner does not match the domain: the
    /// registry would reject a DNSKEY for a name the zone does not contain.
    ///
    /// ```
    /// use inwx_client::{AddDnsKeyRequest, DnsKey, DomainName};
    ///
    /// let key = DnsKey::parse("example.net. IN DNSKEY 257 3 13 ac12")?;
    /// assert!(AddDnsKeyRequest::new(DomainName::parse("example.com")?, key).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new(domain: DomainName, dnskey: DnsKey) -> Result<Self> {
        let owner = dnskey.owner().trim_end_matches('.');
        if !owner.eq_ignore_ascii_case(domain.as_str()) {
            return Err(Error::validation(
                "dnssec.dnskey",
                format!(
                    "the key belongs to {owner:?}, not to {domain}; a DNSKEY must be owned by its zone"
                ),
            ));
        }
        Ok(Self {
            domain,
            dnskey,
            ds: None,
            calculate_digest: None,
            digest_type: None,
        })
    }

    /// Supplies the matching DS record.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when a digest calculation was already requested.
    ///
    /// ```
    /// use inwx_client::{AddDnsKeyRequest, DnsKey, DsRecord, DnssecDigestType, DomainName};
    ///
    /// let request = AddDnsKeyRequest::new(
    ///     DomainName::parse("example.com")?,
    ///     DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12")?,
    /// )?
    /// .with_ds(DsRecord::parse("example.com. IN DS 1234 13 2 AA")?)?;
    /// assert_eq!(request.params()["ds"], "example.com. IN DS 1234 13 2 AA");
    ///
    /// // Asking for a calculated digest on top of it is refused, not ignored.
    /// assert!(request.calculating_digest(DnssecDigestType::Sha256).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_ds(mut self, ds: DsRecord) -> Result<Self> {
        if self.calculate_digest == Some(true) {
            return Err(Error::validation(
                "dnssec.ds",
                "cannot be combined with calculateDigest (the API would discard it)",
            ));
        }
        self.ds = Some(ds);
        Ok(self)
    }

    /// Asks the API to calculate the digest, optionally with a digest type.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when a DS record was already supplied.
    ///
    /// ```
    /// use inwx_client::{AddDnsKeyRequest, DnsKey, DnssecDigestType, DomainName};
    ///
    /// let request = AddDnsKeyRequest::new(
    ///     DomainName::parse("example.com")?,
    ///     DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12")?,
    /// )?
    /// .calculating_digest(DnssecDigestType::Sha256)?;
    /// assert_eq!(request.params()["digestType"], 2);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn calculating_digest(mut self, digest_type: DnssecDigestType) -> Result<Self> {
        if self.ds.is_some() {
            return Err(Error::validation(
                "dnssec.ds",
                "cannot be combined with calculateDigest (the API would discard it)",
            ));
        }
        self.calculate_digest = Some(true);
        self.digest_type = Some(digest_type);
        Ok(self)
    }

    /// The domain the key belongs to.
    ///
    /// ```
    /// use inwx_client::{AddDnsKeyRequest, DnsKey, DomainName};
    ///
    /// let request = AddDnsKeyRequest::new(
    ///     DomainName::parse("example.com")?,
    ///     DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12")?,
    /// )?;
    /// assert_eq!(request.domain().as_str(), "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// The `dnssec.adddnskey` parameters.
    ///
    /// ```
    /// use inwx_client::{AddDnsKeyRequest, DnsKey, DomainName};
    ///
    /// let params = AddDnsKeyRequest::new(
    ///     DomainName::parse("example.com")?,
    ///     DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12")?,
    /// )?
    /// .params();
    /// assert_eq!(params["domainName"], "example.com");
    /// assert!(params.get("ds").is_none());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut params = Map::new();
        params.insert("domainName".to_owned(), json!(self.domain.as_str()));
        params.insert("dnskey".to_owned(), json!(self.dnskey));
        if let Some(ds) = &self.ds {
            params.insert("ds".to_owned(), json!(ds));
        }
        if let Some(calculate) = self.calculate_digest {
            params.insert("calculateDigest".to_owned(), json!(calculate));
        }
        if let Some(digest_type) = self.digest_type {
            params.insert("digestType".to_owned(), json!(digest_type));
        }
        Value::Object(params)
    }
}

/// A `dnssec.listkeys` query.
///
/// Every filter is optional; an empty query asks for the first page of all keys.
///
/// ```
/// use inwx_client::{DnssecAlgorithm, DnssecKeyQuery};
///
/// let query = DnssecKeyQuery::new()
///     .with_domain("example.com")?
///     .with_algorithm(DnssecAlgorithm::EcdsaP256)
///     .with_page(2, 50);
/// let params = query.params();
/// assert_eq!(params["domainName"], "example.com");
/// assert_eq!(params["algorithmId"], 13);
/// assert_eq!(params["pagelimit"], 50);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnssecKeyQuery {
    params: Map<String, Value>,
}

impl DnssecKeyQuery {
    /// An empty query.
    ///
    /// ```
    /// use inwx_client::DnssecKeyQuery;
    /// assert!(DnssecKeyQuery::new().params().as_object().unwrap().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by domain name.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when a different domain was already filtered.
    ///
    /// ```
    /// use inwx_client::DnssecKeyQuery;
    /// assert!(DnssecKeyQuery::new().with_domain("example.com").is_ok());
    /// assert!(DnssecKeyQuery::new().with_domain(" ").is_err());
    /// ```
    pub fn with_domain(mut self, domain: &str) -> Result<Self> {
        let domain = DomainName::parse(domain)?;
        self.params
            .insert("domainName".to_owned(), json!(domain.as_str()));
        Ok(self)
    }

    /// Filters by key tag.
    ///
    /// ```
    /// use inwx_client::DnssecKeyQuery;
    /// assert_eq!(DnssecKeyQuery::new().with_key_tag(u16::MAX).params()["keyTag"], 65535);
    /// ```
    #[must_use]
    pub fn with_key_tag(mut self, tag: u16) -> Self {
        self.params.insert("keyTag".to_owned(), json!(tag));
        self
    }

    /// Filters by algorithm.
    ///
    /// ```
    /// use inwx_client::{DnssecAlgorithm, DnssecKeyQuery};
    /// assert_eq!(
    ///     DnssecKeyQuery::new().with_algorithm(DnssecAlgorithm::Ed448).params()["algorithmId"],
    ///     16
    /// );
    /// ```
    #[must_use]
    pub fn with_algorithm(mut self, algorithm: DnssecAlgorithm) -> Self {
        self.params
            .insert("algorithmId".to_owned(), json!(algorithm));
        self
    }

    /// Filters by key status.
    ///
    /// ```
    /// use inwx_client::{DnssecKeyQuery, DnssecKeyStatus};
    /// assert_eq!(
    ///     DnssecKeyQuery::new().with_status(&DnssecKeyStatus::Ok).params()["status"],
    ///     "OK"
    /// );
    /// ```
    #[must_use]
    pub fn with_status(mut self, status: &DnssecKeyStatus) -> Self {
        self.params.insert("status".to_owned(), json!(status));
        self
    }

    /// Filters by creation time (inclusive lower bound).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when both bounds are set and reversed.
    ///
    /// ```
    /// use inwx_client::{DnssecKeyQuery, Timestamp};
    ///
    /// let query = DnssecKeyQuery::new()
    ///     .created_after(&Timestamp::parse("2026-01-01T00:00:00")?)?;
    /// assert_eq!(query.params()["createdAfter"], "2026-01-01T00:00:00");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn created_after(mut self, at: &Timestamp) -> Result<Self> {
        if let Some(after) = self.params.get("createdBefore") {
            let before: Timestamp = serde_json::from_value(after.clone()).map_err(Error::from)?;
            if *at > before {
                return Err(Error::validation(
                    "createdAfter",
                    "must not be after createdBefore",
                ));
            }
        }
        self.params.insert("createdAfter".to_owned(), json!(at));
        Ok(self)
    }

    /// Filters by creation time (inclusive upper bound).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when both bounds are set and reversed.
    ///
    /// ```
    /// use inwx_client::{DnssecKeyQuery, Timestamp};
    ///
    /// let query = DnssecKeyQuery::new()
    ///     .created_before(&Timestamp::parse("2026-12-31T23:59:59")?)?;
    /// assert_eq!(query.params()["createdBefore"], "2026-12-31T23:59:59");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn created_before(mut self, at: &Timestamp) -> Result<Self> {
        if let Some(after) = self.params.get("createdAfter") {
            let after: Timestamp = serde_json::from_value(after.clone()).map_err(Error::from)?;
            if *at < after {
                return Err(Error::validation(
                    "createdBefore",
                    "must not be before createdAfter",
                ));
            }
        }
        self.params.insert("createdBefore".to_owned(), json!(at));
        Ok(self)
    }

    /// Restricts the answer to active (`true`) or inactive (`false`) keys.
    ///
    /// ```
    /// use inwx_client::DnssecKeyQuery;
    /// assert_eq!(DnssecKeyQuery::new().only_active(true).params()["active"], 1);
    /// ```
    #[must_use]
    pub fn only_active(mut self, active: bool) -> Self {
        self.params
            .insert("active".to_owned(), json!(i32::from(active)));
        self
    }

    /// Sets paging; `limit` 0 means "no limit" as the API documents it.
    ///
    /// ```
    /// use inwx_client::DnssecKeyQuery;
    /// let params = DnssecKeyQuery::new().with_page(3, 0).params();
    /// assert_eq!(params["page"], 3);
    /// assert_eq!(params["pagelimit"], 0);
    /// ```
    #[must_use]
    pub fn with_page(mut self, page: u32, limit: u32) -> Self {
        self.params.insert("page".to_owned(), json!(page.max(1)));
        self.params.insert("pagelimit".to_owned(), json!(limit));
        self
    }

    /// The `dnssec.listkeys` parameters.
    ///
    /// ```
    /// use inwx_client::DnssecKeyQuery;
    /// assert!(DnssecKeyQuery::new().params().as_object().unwrap().is_empty());
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        Value::Object(self.params.clone())
    }
}

impl<T: Transport> InwxClient<T> {
    /// Enables automated DNSSEC management for a domain (`dnssec.enablednssec`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client
    ///     .enable_dnssec(&DomainName::parse("example.com")?)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors — `2304` when the TLD does not support
    /// DNSSEC.
    pub async fn enable_dnssec(&self, domain: &DomainName) -> Result<()> {
        self.call(
            "dnssec.enablednssec",
            json!({ "domainName": domain.as_str() }),
        )
        .await?;
        Ok(())
    }

    /// Destroys every key and disables DNSSEC (`dnssec.disablednssec`).
    ///
    /// This is destructive: the documentation says all keys will be destroyed.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client
    ///     .disable_dnssec(&DomainName::parse("example.com")?)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn disable_dnssec(&self, domain: &DomainName) -> Result<()> {
        self.call(
            "dnssec.disablednssec",
            json!({ "domainName": domain.as_str() }),
        )
        .await?;
        Ok(())
    }

    /// Adds one manual DNSKEY (`dnssec.adddnskey`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{AddDnsKeyRequest, DnsKey, DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let request = AddDnsKeyRequest::new(
    ///     DomainName::parse("example.com")?,
    ///     DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12c2")?,
    /// )?;
    /// let pair = client.add_dns_key(&request).await?;
    /// println!("{}", pair.dnskey);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn add_dns_key(&self, request: &AddDnsKeyRequest) -> Result<DnsKeyPair> {
        let data = self.call("dnssec.adddnskey", request.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Deletes one manual DNSKEY by id (`dnssec.deletednskey`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.delete_dns_key(7).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn delete_dns_key(&self, key_id: i64) -> Result<()> {
        if key_id <= 0 {
            return Err(Error::validation(
                "key",
                format!("must be a positive DNSKEY id, got {key_id}"),
            ));
        }
        self.call("dnssec.deletednskey", json!({ "key": key_id }))
            .await?;
        Ok(())
    }

    /// Deletes every DNSKEY and DS record of a domain (`dnssec.deleteall`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.delete_all_dns_keys(&DomainName::parse("example.com")?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn delete_all_dns_keys(&self, domain: &DomainName) -> Result<()> {
        self.call("dnssec.deleteall", json!({ "domainName": domain.as_str() }))
            .await?;
        Ok(())
    }

    /// Reads the DNSSEC state of the account's domains (`dnssec.info`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for state in client.dnssec_info(None).await? {
    ///     println!("{} {:?}", state.domain, state.status);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty domain list (use `None` for "all"),
    /// plus the usual transport and API errors.
    pub async fn dnssec_info(&self, domains: Option<&[DomainName]>) -> Result<Vec<DnssecState>> {
        let params = match domains {
            None => json!({}),
            Some([]) => {
                return Err(Error::validation(
                    "domains",
                    "must not be empty; use None for every domain",
                ));
            }
            Some(domains) => json!({
                "domains": domains.iter().map(DomainName::as_str).collect::<Vec<_>>(),
            }),
        };
        let data = self.call("dnssec.info", params).await?;
        let entries = match data.get("data") {
            Some(Value::Array(entries)) => entries.clone(),
            _ => Vec::new(),
        };
        Ok(entries
            .into_iter()
            .filter_map(|entry| serde_json::from_value(entry).ok())
            .collect())
    }

    /// Lists manually managed DNSKEYs (`dnssec.listkeys`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DnssecKeyQuery, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let query = DnssecKeyQuery::new().with_domain("example.com")?;
    /// for key in client.list_dns_keys(&query).await? {
    ///     println!("{:?} {:?}", key.id, key.status);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn list_dns_keys(&self, query: &DnssecKeyQuery) -> Result<Vec<DnssecKey>> {
        let data = self.call("dnssec.listkeys", query.params()).await?;
        let entries = match data.get("dnskey") {
            Some(Value::Array(entries)) => entries.clone(),
            _ => Vec::new(),
        };
        Ok(entries
            .into_iter()
            .filter_map(|entry| serde_json::from_value(entry).ok())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_owner_must_match_the_domain() {
        let key = DnsKey::parse("example.net. IN DNSKEY 257 3 13 ac12").unwrap();
        assert!(AddDnsKeyRequest::new(DomainName::parse("example.com").unwrap(), key).is_err());
    }

    #[test]
    fn ds_and_calculated_digest_are_exclusive() {
        let request = AddDnsKeyRequest::new(
            DomainName::parse("example.com").unwrap(),
            DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12").unwrap(),
        )
        .unwrap()
        .with_ds(DsRecord::parse("example.com. IN DS 1234 13 2 AA").unwrap())
        .unwrap();
        assert!(request
            .calculating_digest(DnssecDigestType::Sha256)
            .is_err());
    }

    #[test]
    fn algorithms_outside_the_documented_set_are_refused() {
        assert!(DnssecAlgorithm::from_u8(1).is_err());
        assert!(DnssecAlgorithm::from_u8(6).is_err());
        assert!(DnssecAlgorithm::from_u8(16).is_ok());
    }

    #[test]
    fn presentation_parsing_is_whitespace_tolerant() {
        let key = DnsKey::parse("  example.com.   IN   DNSKEY   257 3 13 ac12  ").unwrap();
        assert_eq!(key.owner(), "example.com.");
        assert_eq!(key.as_str(), "example.com.   IN   DNSKEY   257 3 13 ac12");
    }

    #[test]
    fn queries_reject_reversed_ranges() {
        let after = Timestamp::parse("2026-05-01T00:00:00").unwrap();
        let before = Timestamp::parse("2026-01-01T00:00:00").unwrap();
        assert!(DnssecKeyQuery::new()
            .created_after(&after)
            .unwrap()
            .created_before(&before)
            .is_err());
    }

    #[test]
    fn queries_carry_every_filter() {
        let query = DnssecKeyQuery::new()
            .with_domain("example.com")
            .unwrap()
            .with_key_tag(1234)
            .with_algorithm(DnssecAlgorithm::Ed25519)
            .with_status(&DnssecKeyStatus::Delayed)
            .only_active(false)
            .with_page(0, 10);
        let params = query.params();
        assert_eq!(params["page"], 1);
        assert_eq!(params["active"], 0);
        assert_eq!(params["status"], "DELAYED");
        assert_eq!(params["algorithmId"], 15);
    }
}
