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
/// unlisted number is refused for a request, because the API only accepts the
/// documented set. A response is read leniently instead: a number this table
/// does not list becomes [`DnssecAlgorithm::Other`], so a key signed with a
/// later-assigned algorithm stays readable.
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
    /// A number this table does not list, carried as it arrived.
    ///
    /// Only a response produces this variant; a request still goes through
    /// [`DnssecAlgorithm::from_u8`], which refuses an undocumented id.
    Other(u8),
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
            Self::Other(raw) => raw,
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

    /// Parses a numeric id as it arrives in a response.
    ///
    /// Unlike [`DnssecAlgorithm::from_u8`] nothing is refused: a number this
    /// table does not list becomes [`DnssecAlgorithm::Other`], so a response
    /// never loses a key over an algorithm that was assigned after this crate
    /// was written.
    ///
    /// ```
    /// use inwx_client::DnssecAlgorithm;
    ///
    /// assert_eq!(DnssecAlgorithm::from_u8_lenient(16), DnssecAlgorithm::Ed448);
    /// assert_eq!(DnssecAlgorithm::from_u8_lenient(17), DnssecAlgorithm::Other(17));
    /// assert_eq!(DnssecAlgorithm::Other(17).as_u8(), 17);
    /// ```
    #[must_use]
    pub fn from_u8_lenient(value: u8) -> Self {
        match Self::from_u8(value) {
            Ok(known) => known,
            Err(_) => Self::Other(value),
        }
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
        let value =
            de::opt_i64(deserializer)?.ok_or_else(|| D::Error::custom("algorithm is missing"))?;
        let value = u8::try_from(value)
            .map_err(|_| D::Error::custom(format!("algorithm {value} is out of range")))?;
        Ok(Self::from_u8_lenient(value))
    }
}

/// A DNSSEC digest type (`dnssecDigestType`).
///
/// A request is checked against the documented set; a response is read
/// leniently, carrying an unlisted number as [`DnssecDigestType::Other`].
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
    /// A number this table does not list, carried as it arrived.
    Other(u8),
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
            Self::Other(raw) => raw,
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

    /// Parses a numeric id as it arrives in a response, carrying an unlisted
    /// number as [`DnssecDigestType::Other`] instead of refusing it.
    ///
    /// ```
    /// use inwx_client::DnssecDigestType;
    ///
    /// assert_eq!(DnssecDigestType::from_u8_lenient(4), DnssecDigestType::Sha384);
    /// assert_eq!(DnssecDigestType::from_u8_lenient(5), DnssecDigestType::Other(5));
    /// ```
    #[must_use]
    pub fn from_u8_lenient(value: u8) -> Self {
        match Self::from_u8(value) {
            Ok(known) => known,
            Err(_) => Self::Other(value),
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
        let value =
            de::opt_i64(deserializer)?.ok_or_else(|| D::Error::custom("digest type is missing"))?;
        let value = u8::try_from(value)
            .map_err(|_| D::Error::custom(format!("digest type {value} is out of range")))?;
        Ok(Self::from_u8_lenient(value))
    }
}

/// A DNSSEC key flag (`dnssecFlag`).
///
/// A request accepts the two documented flags only; a response is read
/// leniently, carrying anything else as [`DnssecFlag::Other`].
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
    /// A number this table does not list, carried as it arrived.
    Other(u16),
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
            Self::Other(raw) => raw,
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

    /// Parses a numeric id as it arrives in a response, carrying an unlisted
    /// number as [`DnssecFlag::Other`] instead of refusing it.
    ///
    /// ```
    /// use inwx_client::DnssecFlag;
    ///
    /// assert_eq!(DnssecFlag::from_u16_lenient(257), DnssecFlag::ZoneSep);
    /// assert_eq!(DnssecFlag::from_u16_lenient(258), DnssecFlag::Other(258));
    /// ```
    #[must_use]
    pub fn from_u16_lenient(value: u16) -> Self {
        match Self::from_u16(value) {
            Ok(known) => known,
            Err(_) => Self::Other(value),
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
        let value =
            de::opt_i64(deserializer)?.ok_or_else(|| D::Error::custom("flag is missing"))?;
        let value = u16::try_from(value)
            .map_err(|_| D::Error::custom(format!("flag {value} is out of range")))?;
        Ok(Self::from_u16_lenient(value))
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
/// `status` is an `Option` because `dnssec.info` leaves `dnssecStatus` out for a
/// domain without DNSSEC (and sends `null` for some records). An absent field is
/// `None` — "the API reported no status" — which is a different answer from
/// `Some(DnssecDomainStatus::Manual)`, "keys are managed manually through this
/// API". No value is invented for a field the API did not send.
///
/// ```
/// use inwx_client::{DnssecDomainStatus, DnssecState};
///
/// let state: DnssecState = serde_json::from_str(
///     r#"{"domain":"example.com","keyCount":2,"dnssecStatus":"MANUAL"}"#,
/// )?;
/// assert_eq!(state.key_count, Some(2));
/// assert_eq!(state.status, Some(DnssecDomainStatus::Manual));
///
/// // Unsigned: the field is absent, or present and `null`. Both are `None`,
/// // and both keep the record.
/// let absent: DnssecState = serde_json::from_str(r#"{"domain":"example.net"}"#)?;
/// assert_eq!(absent.status, None);
/// let null: DnssecState =
///     serde_json::from_str(r#"{"domain":"example.org","dnssecStatus":null}"#)?;
/// assert_eq!(null.status, None);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DnssecState {
    /// The domain.
    pub domain: DomainName,
    /// Number of keys the API reports.
    #[serde(default, rename = "keyCount", deserialize_with = "de::opt_i64")]
    pub key_count: Option<i64>,
    /// DNSSEC status of the domain, when the API reports one.
    #[serde(
        default,
        rename = "dnssecStatus",
        deserialize_with = "opt_domain_status"
    )]
    pub status: Option<DnssecDomainStatus>,
}

/// Reads `dnssecStatus`, which `dnssec.info` omits for a domain without DNSSEC
/// and sends as `null` in some answers.
///
/// Both shapes are `None`, so the two sides of the boundary behave the same: the
/// field carries what the API said and nothing else, a caller can tell a
/// reported `MANUAL` from an omitted field, and a `null` record is kept instead
/// of being dropped by the per-row parse of the list.
fn opt_domain_status<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<DnssecDomainStatus>, D::Error> {
    let raw = de::opt_string(deserializer)?;
    match raw.as_deref().map(str::trim) {
        Some(raw) if !raw.is_empty() => DnssecDomainStatus::parse(raw)
            .map(Some)
            .map_err(D::Error::custom),
        _ => Ok(None),
    }
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
        // One slice pattern instead of a length check plus `tokens[1..]`: the
        // bound and the field extraction cannot drift apart, so a short record
        // is an error instead of a panic.
        let Some([owner, class, kind, flag, protocol, algorithm, _key, ..]) = tokens.get(..) else {
            return Err(Error::validation(
                "dnssec.dnskey",
                "needs `<owner> IN DNSKEY <flag> 3 <algorithm> <key>`",
            ));
        };
        if !class.eq_ignore_ascii_case("IN") || !kind.eq_ignore_ascii_case("DNSKEY") {
            return Err(Error::validation(
                "dnssec.dnskey",
                "the record class and type must be `IN DNSKEY`",
            ));
        }
        let flag: u16 = flag
            .parse()
            .map_err(|_| Error::validation("dnssec.dnskey", format!("{flag:?} is not a flag")))?;
        let flag = DnssecFlag::from_u16(flag)?;
        if flag != DnssecFlag::ZoneSep {
            return Err(Error::validation(
                "dnssec.dnskey",
                "only ZONE+SEP keys (flag 257) are accepted by dnssec.adddnskey",
            ));
        }
        if *protocol != "3" {
            return Err(Error::validation(
                "dnssec.dnskey",
                "the protocol must be 3 (DNSSEC)",
            ));
        }
        let algorithm: u8 = algorithm.parse().map_err(|_| {
            Error::validation(
                "dnssec.dnskey",
                format!("{algorithm:?} is not an algorithm id"),
            )
        })?;
        Ok(Self {
            raw: raw.to_owned(),
            owner: owner.to_string(),
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
/// The documentation's example is `domain.tld. IN DS 1234 13 2 56DC12…`. The
/// owner is kept, not just skipped: the API keys the digest by the request's
/// `domainName`, so a DS for a foreign zone would be attached to the wrong
/// domain. [`AddDnsKeyRequest::with_ds`] compares the owner against the
/// request's domain for that reason.
///
/// ```
/// use inwx_client::{DsRecord, DnssecAlgorithm, DnssecDigestType};
///
/// let ds = DsRecord::parse("example.com. IN DS 1234 13 2 56DC12")?;
/// assert_eq!(ds.owner(), "example.com.");
/// assert_eq!(ds.key_tag(), 1234);
/// assert_eq!(ds.algorithm(), DnssecAlgorithm::EcdsaP256);
/// assert_eq!(ds.digest_type(), DnssecDigestType::Sha256);
/// assert!(DsRecord::parse("example.com. IN DS 1234 13 9 56DC12").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsRecord {
    raw: String,
    owner: String,
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
        // One slice pattern for the seven fields: the bound and the extraction
        // are the same step, so a short record is an error instead of a panic.
        let Some([owner, class, kind, key_tag, algorithm, digest_type, digest, ..]) =
            tokens.get(..)
        else {
            return Err(Error::validation(
                "dnssec.ds",
                "needs `<owner> IN DS <keytag> <algorithm> <digesttype> <digest>`",
            ));
        };
        if !class.eq_ignore_ascii_case("IN") || !kind.eq_ignore_ascii_case("DS") {
            return Err(Error::validation(
                "dnssec.ds",
                "the record class and type must be `IN DS`",
            ));
        }
        let key_tag: u16 = key_tag
            .parse()
            .map_err(|_| Error::validation("dnssec.ds", format!("{key_tag:?} is not a key tag")))?;
        let algorithm: u8 = algorithm.parse().map_err(|_| {
            Error::validation("dnssec.ds", format!("{algorithm:?} is not an algorithm"))
        })?;
        let digest_type: u8 = digest_type.parse().map_err(|_| {
            Error::validation("dnssec.ds", format!("{digest_type:?} is not a digest type"))
        })?;
        if !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::validation(
                "dnssec.ds",
                "the digest must be hexadecimal",
            ));
        }
        Ok(Self {
            raw: raw.to_owned(),
            owner: owner.to_string(),
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

    /// The record owner as written (usually the zone with a trailing dot).
    ///
    /// ```
    /// use inwx_client::DsRecord;
    /// assert_eq!(DsRecord::parse("example.com. IN DS 1234 13 2 AA")?.owner(), "example.com.");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
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
/// The numeric ids are read as the types they name, so a caller compares an
/// algorithm instead of remembering that `13` is ECDSA P-256. A number this
/// crate's table does not list is carried (`DnssecAlgorithm::Other` and
/// friends) rather than failing the row: an algorithm the registry assigned
/// after this crate was written must not make the key disappear from the
/// list.
///
/// ```
/// use inwx_client::{DnssecAlgorithm, DnssecDigestType, DnssecKey, DnssecKeyStatus};
///
/// let key: DnssecKey = serde_json::from_str(
///     r#"{"id":7,"ownerName":"example.com.","keyTag":1234,"flagId":257,
///         "algorithmId":13,"digestTypeId":2,"digest":"AA","status":"OK","active":1}"#,
/// )?;
/// assert_eq!(key.key_tag, Some(1234));
/// assert_eq!(key.algorithm, Some(DnssecAlgorithm::EcdsaP256));
/// assert_eq!(key.digest_type, Some(DnssecDigestType::Sha256));
/// assert_eq!(key.status, Some(DnssecKeyStatus::Ok));
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
    /// Key tag, the `0..=65535` value a DS record repeats.
    #[serde(default, rename = "keyTag", deserialize_with = "opt_key_tag")]
    pub key_tag: Option<u16>,
    /// Key flag; an undocumented flag arrives as [`DnssecFlag::Other`].
    #[serde(default, rename = "flagId", deserialize_with = "opt_flag")]
    pub flag: Option<DnssecFlag>,
    /// Signing algorithm; an undocumented id arrives as
    /// [`DnssecAlgorithm::Other`].
    #[serde(default, rename = "algorithmId", deserialize_with = "opt_algorithm")]
    pub algorithm: Option<DnssecAlgorithm>,
    /// Public key (base64).
    #[serde(default, rename = "publicKey", deserialize_with = "de::opt_string")]
    pub public_key: Option<String>,
    /// Digest type; an undocumented id arrives as
    /// [`DnssecDigestType::Other`].
    #[serde(default, rename = "digestTypeId", deserialize_with = "opt_digest_type")]
    pub digest_type: Option<DnssecDigestType>,
    /// Digest value.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub digest: Option<String>,
    /// Creation time.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub created: Option<String>,
    /// Key status; an unknown status arrives as [`DnssecKeyStatus::Other`].
    #[serde(default, deserialize_with = "opt_key_status")]
    pub status: Option<DnssecKeyStatus>,
    /// `1` when the key is active, `0` when not.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub active: Option<i64>,
}

/// `keyTag` from a number or a numeric string.
///
/// A tag outside `0..=65535` is a corrupt answer rather than an unknown id:
/// no registry publishes one, so the number cannot be carried and the row is
/// refused instead of reporting a tag the wire never held.
fn opt_key_tag<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<u16>, D::Error> {
    let Some(value) = de::opt_i64(deserializer)? else {
        return Ok(None);
    };
    u16::try_from(value)
        .map(Some)
        .map_err(|_| D::Error::custom(format!("key tag {value} is outside 0..=65535")))
}

/// `flagId` as a [`DnssecFlag`]; an undocumented flag is carried.
fn opt_flag<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<DnssecFlag>, D::Error> {
    let Some(value) = de::opt_i64(deserializer)? else {
        return Ok(None);
    };
    let value = u16::try_from(value)
        .map_err(|_| D::Error::custom(format!("flag {value} is out of the u16 range")))?;
    Ok(Some(DnssecFlag::from_u16_lenient(value)))
}

/// `algorithmId` as a [`DnssecAlgorithm`]; an undocumented id is carried.
fn opt_algorithm<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<DnssecAlgorithm>, D::Error> {
    let Some(value) = de::opt_i64(deserializer)? else {
        return Ok(None);
    };
    let value = u8::try_from(value)
        .map_err(|_| D::Error::custom(format!("algorithm {value} is out of the u8 range")))?;
    Ok(Some(DnssecAlgorithm::from_u8_lenient(value)))
}

/// `digestTypeId` as a [`DnssecDigestType`]; an undocumented id is carried.
fn opt_digest_type<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<DnssecDigestType>, D::Error> {
    let Some(value) = de::opt_i64(deserializer)? else {
        return Ok(None);
    };
    let value = u8::try_from(value)
        .map_err(|_| D::Error::custom(format!("digest type {value} is out of the u8 range")))?;
    Ok(Some(DnssecDigestType::from_u8_lenient(value)))
}

/// `status` as a [`DnssecKeyStatus`]; an unknown status is carried and an
/// empty one counts as missing.
fn opt_key_status<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<DnssecKeyStatus>, D::Error> {
    match de::opt_string(deserializer)? {
        Some(raw) if !raw.trim().is_empty() => Ok(Some(
            DnssecKeyStatus::parse(&raw).map_err(D::Error::custom)?,
        )),
        _ => Ok(None),
    }
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

/// Checks that a record's owner names the zone a request is sent for.
///
/// Shared by the DNSKEY and the DS validation so the two halves of the same
/// critical section cannot drift apart: both trim the presentation's trailing
/// dot and compare ASCII case-insensitively, because [`DomainName`] is stored
/// lower-cased and without a dot while a presentation record normally carries
/// both.
fn check_zone_owner(
    owner: &str,
    domain: &DomainName,
    field: &'static str,
    kind: &str,
) -> Result<()> {
    let owner = owner.trim_end_matches('.');
    if !owner.eq_ignore_ascii_case(domain.as_str()) {
        return Err(Error::validation(
            field,
            format!("the owner is {owner:?}, not {domain:?}; a {kind} must be owned by its zone"),
        ));
    }
    Ok(())
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
        check_zone_owner(dnskey.owner(), &domain, "dnssec.dnskey", "DNSKEY")?;
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
    /// [`Error::Validation`] when a digest calculation was already requested,
    /// or when the DS owner does not match the domain: the digest is sent under
    /// the request's `domainName`, so a record for a foreign zone (or a
    /// copy-pasted owner with a typo) would be published against the wrong
    /// domain.
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
    /// // A DS for another zone is refused, not attached to this domain.
    /// let foreign = DsRecord::parse("example.net. IN DS 1234 13 2 AA")?;
    /// assert!(AddDnsKeyRequest::new(
    ///     DomainName::parse("example.com")?,
    ///     DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12")?,
    /// )?
    /// .with_ds(foreign)
    /// .is_err());
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
        check_zone_owner(ds.owner(), &self.domain, "dnssec.ds", "DS record")?;
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
    fn state_without_a_reported_status_keeps_it_absent() {
        let state = |json: &str| serde_json::from_str::<DnssecState>(json).unwrap();

        // Absent, `null` and a blank string all mean "the API said nothing".
        for json in [
            r#"{"domain":"example.net"}"#,
            r#"{"domain":"example.net","dnssecStatus":null}"#,
            r#"{"domain":"example.net","dnssecStatus":""}"#,
            r#"{"domain":"example.net","dnssecStatus":"  "}"#,
        ] {
            assert_eq!(state(json).status, None, "{json}");
        }

        // A reported status is carried, and is never confused with `None`.
        for (wire, status) in [
            ("MANUAL", DnssecDomainStatus::Manual),
            ("manual", DnssecDomainStatus::Manual),
            ("UPDATE", DnssecDomainStatus::Update),
            ("DELETE_ALL", DnssecDomainStatus::DeleteAll),
        ] {
            let json = format!(r#"{{"domain":"example.net","dnssecStatus":"{wire}"}}"#);
            assert_eq!(state(&json).status, Some(status), "{wire}");
        }
    }

    #[test]
    fn key_owner_must_match_the_domain() {
        let key = DnsKey::parse("example.net. IN DNSKEY 257 3 13 ac12").unwrap();
        assert!(AddDnsKeyRequest::new(DomainName::parse("example.com").unwrap(), key).is_err());
    }

    #[test]
    fn ds_owner_must_match_the_domain() {
        let request = || {
            AddDnsKeyRequest::new(
                DomainName::parse("example.com").unwrap(),
                DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12").unwrap(),
            )
            .expect("request")
        };

        // A foreign zone is refused: the digest is keyed by `domainName`.
        let foreign = DsRecord::parse("example.net. IN DS 1234 13 2 AA").unwrap();
        let error = request().with_ds(foreign).unwrap_err();
        assert!(error.to_string().contains("example.net"), "{error}");

        // A parent or child of the domain is a different zone.
        for owner in ["com.", "sub.example.com.", "example.com.evil."] {
            let ds = DsRecord::parse(&format!("{owner} IN DS 1234 13 2 AA")).unwrap();
            assert!(request().with_ds(ds).is_err(), "{owner}");
        }

        // The trailing dot and the case are presentation noise, not a mismatch.
        for owner in ["example.com.", "example.com", "EXAMPLE.COM."] {
            let ds = DsRecord::parse(&format!("{owner} IN DS 1234 13 2 AA")).unwrap();
            assert!(request().with_ds(ds).is_ok(), "{owner}");
        }
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

    #[test]
    fn response_ids_are_typed_and_unknown_ones_are_carried() {
        let key: DnssecKey = serde_json::from_str(
            r#"{"keyTag":65535,"flagId":257,"algorithmId":13,"digestTypeId":2,"status":"ok"}"#,
        )
        .expect("row");
        assert_eq!(key.key_tag, Some(u16::MAX));
        assert_eq!(key.flag, Some(DnssecFlag::ZoneSep));
        assert_eq!(key.algorithm, Some(DnssecAlgorithm::EcdsaP256));
        assert_eq!(key.digest_type, Some(DnssecDigestType::Sha256));
        assert_eq!(key.status, Some(DnssecKeyStatus::Ok));

        // One step past the table on every field: carried, not dropped.
        let unknown: DnssecKey = serde_json::from_str(
            r#"{"flagId":258,"algorithmId":17,"digestTypeId":5,"status":"BOGUS"}"#,
        )
        .expect("row");
        assert_eq!(unknown.flag, Some(DnssecFlag::Other(258)));
        assert_eq!(unknown.algorithm, Some(DnssecAlgorithm::Other(17)));
        assert_eq!(unknown.digest_type, Some(DnssecDigestType::Other(5)));
        assert_eq!(unknown.status, Some(DnssecKeyStatus::Other("BOGUS".into())));
    }

    #[test]
    fn key_tag_is_refused_past_its_boundary() {
        let at_limit: DnssecKey = serde_json::from_str(r#"{"keyTag":65535}"#).expect("row");
        assert_eq!(at_limit.key_tag, Some(u16::MAX));

        let past_limit = serde_json::from_str::<DnssecKey>(r#"{"keyTag":65536}"#).unwrap_err();
        assert!(
            past_limit.to_string().contains("outside 0..=65535"),
            "{past_limit}"
        );
    }

    #[test]
    fn a_missing_numeric_id_says_so_instead_of_claiming_zero() {
        let algorithm = serde_json::from_str::<DnssecAlgorithm>("null").unwrap_err();
        assert!(
            algorithm.to_string().contains("algorithm is missing"),
            "{algorithm}"
        );
        let digest = serde_json::from_str::<DnssecDigestType>("null").unwrap_err();
        assert!(
            digest.to_string().contains("digest type is missing"),
            "{digest}"
        );
        let flag = serde_json::from_str::<DnssecFlag>("null").unwrap_err();
        assert!(flag.to_string().contains("flag is missing"), "{flag}");

        // In a row an absent id is absent, not zero.
        let key: DnssecKey = serde_json::from_str(r#"{"id":7}"#).expect("row");
        assert_eq!(key.algorithm, None);
        assert_eq!(key.key_tag, None);
        assert_eq!(key.status, None);
    }

    #[test]
    fn numeric_strings_are_accepted_for_response_ids() {
        let key: DnssecKey =
            serde_json::from_str(r#"{"keyTag":"1234","algorithmId":"13","flagId":"257"}"#)
                .expect("row");
        assert_eq!(key.key_tag, Some(1234));
        assert_eq!(key.algorithm, Some(DnssecAlgorithm::EcdsaP256));
        assert_eq!(key.flag, Some(DnssecFlag::ZoneSep));
    }
}
