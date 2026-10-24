//! DNS records: the record type enum, typed record payloads, and the CRUD calls.
//!
//! A record is validated before it is sent: an `A` record must carry an IPv4
//! address, `AAAA` an IPv6 address, `MX`/`SRV`/`CNAME`/`NS` a host name, and
//! every TTL must fit the `int` the API asks for. The reward is that a typo is
//! a local error instead of an `2004 Parameter value range error` from a
//! registrar that has already been charged.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, reject_control_chars, DomainName, Hostname, MAX_DOMAIN_LEN};

/// Largest TTL the API accepts: the parameter is documented as `int`, so the
/// ceiling is `i32::MAX`, not an arbitrary registrar policy.
pub const MAX_TTL: u32 = i32::MAX as u32;

/// Default TTL the API uses when the parameter is omitted.
pub const DEFAULT_TTL: u32 = 3600;

/// A DNS record type.
///
/// The known variants are the ones INWX documents in `recordType`; anything
/// else is carried in [`RecordType::Other`] instead of being rejected, so a new
/// type (or a typo the API accepts) survives a round trip.
///
/// ```
/// use inwx_client::RecordType;
///
/// assert_eq!(RecordType::parse("aaaa")?, RecordType::Aaaa);
/// assert_eq!(RecordType::Mx.to_string(), "MX");
/// assert_eq!("HTTPS".parse::<RecordType>()?, RecordType::Https);
///
/// // Unknown types are carried, not dropped.
/// assert_eq!(RecordType::parse("NEWTYPE")?, RecordType::Other("NEWTYPE".into()));
/// assert!(RecordType::parse("   ").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// IPv4 address.
    A,
    /// IPv6 address.
    Aaaa,
    /// AFS database location.
    Afsdb,
    /// Provider-specific alias (INWX `ALIAS`).
    Alias,
    /// Certificate Authority Authorization.
    Caa,
    /// Certificate or CRL.
    Cert,
    /// Canonical name.
    Cname,
    /// Host information.
    Hinfo,
    /// HTTPS service binding.
    Https,
    /// `IPsec` key.
    Ipseckey,
    /// Geographical location.
    Loc,
    /// Mail exchanger.
    Mx,
    /// Naming authority pointer.
    Naptr,
    /// Name server.
    Ns,
    /// `OpenPGP` key.
    Openpgpkey,
    /// Pointer (reverse DNS).
    Ptr,
    /// Responsible person.
    Rp,
    /// S/MIME certificate association.
    Smimea,
    /// Start of authority.
    Soa,
    /// Service locator.
    Srv,
    /// SSH key fingerprint.
    Sshfp,
    /// Service binding.
    Svcb,
    /// TLS certificate association.
    Tlsa,
    /// Free-form text.
    Txt,
    /// URI.
    Uri,
    /// HTTP redirect managed by INWX.
    Url,
    /// A type this crate does not know; carried verbatim, upper-cased.
    Other(String),
}

impl RecordType {
    /// Every type INWX documents, in the order the API lists them.
    ///
    /// ```
    /// use inwx_client::RecordType;
    ///
    /// assert!(RecordType::ALL.contains(&RecordType::Tlsa));
    /// assert_eq!(RecordType::ALL.len(), 26);
    /// ```
    pub const ALL: &'static [Self] = &[
        Self::A,
        Self::Aaaa,
        Self::Afsdb,
        Self::Alias,
        Self::Caa,
        Self::Cert,
        Self::Cname,
        Self::Hinfo,
        Self::Https,
        Self::Ipseckey,
        Self::Loc,
        Self::Mx,
        Self::Naptr,
        Self::Ns,
        Self::Openpgpkey,
        Self::Ptr,
        Self::Rp,
        Self::Smimea,
        Self::Soa,
        Self::Srv,
        Self::Sshfp,
        Self::Svcb,
        Self::Tlsa,
        Self::Txt,
        Self::Uri,
        Self::Url,
    ];

    /// Parses a type name case-insensitively; unknown names become
    /// [`RecordType::Other`].
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the input is empty.
    pub fn parse(input: &str) -> Result<Self> {
        let upper = input.trim().to_ascii_uppercase();
        if upper.is_empty() {
            return Err(Error::validation("record.type", "must not be empty"));
        }
        Ok(match upper.as_str() {
            "A" => Self::A,
            "AAAA" => Self::Aaaa,
            "AFSDB" => Self::Afsdb,
            "ALIAS" => Self::Alias,
            "CAA" => Self::Caa,
            "CERT" => Self::Cert,
            "CNAME" => Self::Cname,
            "HINFO" => Self::Hinfo,
            "HTTPS" => Self::Https,
            "IPSECKEY" => Self::Ipseckey,
            "LOC" => Self::Loc,
            "MX" => Self::Mx,
            "NAPTR" => Self::Naptr,
            "NS" => Self::Ns,
            "OPENPGPKEY" => Self::Openpgpkey,
            "PTR" => Self::Ptr,
            "RP" => Self::Rp,
            "SMIMEA" => Self::Smimea,
            "SOA" => Self::Soa,
            "SRV" => Self::Srv,
            "SSHFP" => Self::Sshfp,
            "SVCB" => Self::Svcb,
            "TLSA" => Self::Tlsa,
            "TXT" => Self::Txt,
            "URI" => Self::Uri,
            "URL" => Self::Url,
            _ => Self::Other(upper),
        })
    }

    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::RecordType;
    /// assert_eq!(RecordType::Aaaa.as_str(), "AAAA");
    /// assert_eq!(RecordType::Other("WEIRD".into()).as_str(), "WEIRD");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Afsdb => "AFSDB",
            Self::Alias => "ALIAS",
            Self::Caa => "CAA",
            Self::Cert => "CERT",
            Self::Cname => "CNAME",
            Self::Hinfo => "HINFO",
            Self::Https => "HTTPS",
            Self::Ipseckey => "IPSECKEY",
            Self::Loc => "LOC",
            Self::Mx => "MX",
            Self::Naptr => "NAPTR",
            Self::Ns => "NS",
            Self::Openpgpkey => "OPENPGPKEY",
            Self::Ptr => "PTR",
            Self::Rp => "RP",
            Self::Smimea => "SMIMEA",
            Self::Soa => "SOA",
            Self::Srv => "SRV",
            Self::Sshfp => "SSHFP",
            Self::Svcb => "SVCB",
            Self::Tlsa => "TLSA",
            Self::Txt => "TXT",
            Self::Uri => "URI",
            Self::Url => "URL",
            Self::Other(raw) => raw,
        }
    }

    /// Whether the content of this record type is an IP address rather than a
    /// host name or free text.
    ///
    /// ```
    /// use inwx_client::RecordType;
    ///
    /// assert!(RecordType::A.is_address());
    /// assert!(!RecordType::Mx.is_address());
    /// ```
    #[must_use]
    pub fn is_address(&self) -> bool {
        matches!(self, Self::A | Self::Aaaa)
    }

    /// Whether the content of this record type must be a host name.
    ///
    /// ```
    /// use inwx_client::RecordType;
    ///
    /// assert!(RecordType::Cname.requires_hostname());
    /// assert!(!RecordType::Txt.requires_hostname());
    /// ```
    #[must_use]
    pub fn requires_hostname(&self) -> bool {
        matches!(
            self,
            Self::Cname | Self::Mx | Self::Ns | Self::Ptr | Self::Srv | Self::Alias
        )
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RecordType {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl Serialize for RecordType {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RecordType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// A record id.
///
/// INWX types record ids as `token255`, so they arrive as JSON **strings** even
/// though they look like numbers. Holding them in a `String` newtype means a
/// response round-trips unchanged, while `From<i64>` keeps the convenient
/// `delete_record(1)` form working.
///
/// ```
/// use inwx_client::RecordId;
///
/// let from_number = RecordId::from(4711);
/// let from_text = RecordId::from("4711");
/// assert_eq!(from_number, from_text);
/// assert_eq!(from_number.to_string(), "4711");
/// assert!(RecordId::parse("").is_err());
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordId(String);

impl RecordId {
    /// Wraps a record id after checking it is a usable token.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the id is empty, longer than 64 characters or
    /// contains control characters.
    pub fn parse(input: impl Into<String>) -> Result<Self> {
        let raw = input.into();
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(Error::validation("record.id", "must not be empty"));
        }
        if trimmed.len() > 64 {
            return Err(Error::validation(
                "record.id",
                "must be at most 64 characters",
            ));
        }
        reject_control_chars("record.id", trimmed)?;
        Ok(Self(trimmed.to_owned()))
    }

    /// The id as sent on the wire.
    ///
    /// ```
    /// use inwx_client::RecordId;
    /// assert_eq!(RecordId::from(42).as_str(), "42");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<i64> for RecordId {
    fn from(id: i64) -> Self {
        Self(id.to_string())
    }
}

impl From<&str> for RecordId {
    fn from(id: &str) -> Self {
        Self(id.to_owned())
    }
}

impl From<String> for RecordId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

impl fmt::Display for RecordId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for RecordId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RecordId({:?})", self.0)
    }
}

impl Serialize for RecordId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RecordId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(text) => Ok(Self(text)),
            Value::Number(number) => Ok(Self(number.to_string())),
            other => Err(D::Error::custom(format!(
                "record id must be a string or number, got {other}"
            ))),
        }
    }
}

/// A record as returned by `nameserver.info`.
///
/// ```
/// use inwx_client::{DnsRecord, RecordType};
///
/// let record: DnsRecord = serde_json::from_str(
///     r#"{"id":"88","name":"www","type":"A","content":"203.0.113.7","ttl":3600,"prio":0}"#,
/// )?;
/// assert_eq!(record.record_type, RecordType::A);
/// assert_eq!(record.ip().unwrap().to_string(), "203.0.113.7");
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    /// Record id, needed to update or delete it.
    pub id: RecordId,
    /// Relative name; `@` is the zone apex.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// Record type.
    #[serde(rename = "type")]
    pub record_type: RecordType,
    /// Record content: address, host name or free text.
    #[serde(default)]
    pub content: String,
    /// Time to live in seconds; `None` when the zone did not report one.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub ttl: Option<i64>,
    /// Priority, for `MX` and `SRV`; `None` when the zone did not report one.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub prio: Option<i64>,
}

impl DnsRecord {
    /// The relative name, or `@` when the API sent none (zone apex).
    ///
    /// ```
    /// use inwx_client::DnsRecord;
    ///
    /// let record: DnsRecord = serde_json::from_str(
    ///     r#"{"id":1,"type":"TXT","content":"v=spf1 -all"}"#,
    /// )?;
    /// assert_eq!(record.name_or_apex(), "@");
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn name_or_apex(&self) -> &str {
        match self.name.as_deref() {
            Some(name) if !name.is_empty() => name,
            _ => "@",
        }
    }

    /// TTL in seconds, falling back to the API default of
    /// [`DEFAULT_TTL`] when the zone did not report one.
    ///
    /// ```
    /// use inwx_client::{DnsRecord, DEFAULT_TTL};
    ///
    /// let record: DnsRecord = serde_json::from_str(r#"{"id":1,"type":"TXT","content":"x"}"#)?;
    /// assert_eq!(record.ttl_seconds(), DEFAULT_TTL as i64);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn ttl_seconds(&self) -> i64 {
        self.ttl.unwrap_or(i64::from(DEFAULT_TTL))
    }

    /// Priority, falling back to `0` when absent.
    ///
    /// ```
    /// use inwx_client::DnsRecord;
    ///
    /// let mx: DnsRecord = serde_json::from_str(
    ///     r#"{"id":1,"type":"MX","content":"mx.example.com","prio":10}"#,
    /// )?;
    /// assert_eq!(mx.priority(), 10);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn priority(&self) -> i64 {
        self.prio.unwrap_or(0)
    }

    /// The parsed address for `A` and `AAAA` records, `None` for every other
    /// type or when the content is not a valid address.
    ///
    /// ```
    /// use inwx_client::DnsRecord;
    ///
    /// let aaaa: DnsRecord = serde_json::from_str(
    ///     r#"{"id":2,"type":"AAAA","content":"2001:db8::1"}"#,
    /// )?;
    /// assert!(aaaa.ip().unwrap().is_ipv6());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        match self.record_type {
            RecordType::A | RecordType::Aaaa => self.content.parse().ok(),
            _ => None,
        }
    }
}

/// A record to create.
///
/// Build it through a constructor (`RecordSpec::a`, `::mx`, …) or the generic
/// [`RecordSpec::new`], which validates the content against the record type.
///
/// ```
/// use inwx_client::{RecordSpec, RecordType};
///
/// let spec = RecordSpec::a("www", "203.0.113.7")?.with_ttl(300)?;
/// assert_eq!(spec.record_type(), RecordType::A);
/// assert_eq!(spec.ttl(), 300);
///
/// // The same through the generic constructor:
/// let generic = RecordSpec::new(RecordType::Txt, "@", "v=spf1 -all")?;
/// assert_eq!(generic.params()["content"], "v=spf1 -all");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordSpec {
    #[serde(rename = "type")]
    record_type: RecordType,
    name: String,
    content: String,
    ttl: u32,
    prio: u16,
}

impl RecordSpec {
    /// A generic record, with the content validated against the type.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name is unusable, or when the content is
    /// not the shape the type requires (an IPv4 literal for `A`, an IPv6
    /// literal for `AAAA`, a host name for `CNAME`/`MX`/`NS`/`PTR`/`SRV`, a
    /// non-empty string otherwise).
    pub fn new(
        record_type: RecordType,
        name: impl Into<String>,
        content: impl Into<String>,
    ) -> Result<Self> {
        let spec = Self {
            record_type,
            name: name.into(),
            content: content.into(),
            ttl: DEFAULT_TTL,
            prio: 0,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// An `A` record from an IPv4 address.
    ///
    /// ```
    /// use inwx_client::RecordSpec;
    ///
    /// let spec = RecordSpec::a("www", "203.0.113.7")?;
    /// assert_eq!(spec.params()["content"], "203.0.113.7");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable record name or content.
    pub fn a(name: impl Into<String>, address: impl fmt::Display) -> Result<Self> {
        Self::new(RecordType::A, name, address.to_string())
    }

    /// An `AAAA` record from an IPv6 address.
    ///
    /// ```
    /// use inwx_client::RecordSpec;
    ///
    /// let spec = RecordSpec::aaaa("www", "2001:db8::1")?;
    /// assert_eq!(spec.params()["content"], "2001:db8::1");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable record name or content.
    pub fn aaaa(name: impl Into<String>, address: impl fmt::Display) -> Result<Self> {
        Self::new(RecordType::Aaaa, name, address.to_string())
    }

    /// A `CNAME` record pointing at `target`.
    ///
    /// ```
    /// use inwx_client::{Hostname, RecordSpec};
    ///
    /// let spec = RecordSpec::cname("shop", &Hostname::parse("stores.example.net")?)?;
    /// assert_eq!(spec.params()["content"], "stores.example.net");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable record name.
    pub fn cname(name: impl Into<String>, target: &Hostname) -> Result<Self> {
        Self::new(RecordType::Cname, name, target.as_str())
    }

    /// An `MX` record with an explicit priority.
    ///
    /// ```
    /// use inwx_client::{Hostname, RecordSpec};
    ///
    /// let spec = RecordSpec::mx("@", 10, &Hostname::parse("mail.example.com")?)?;
    /// assert_eq!(spec.params()["prio"], 10);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable record name.
    pub fn mx(name: impl Into<String>, priority: u16, target: &Hostname) -> Result<Self> {
        Self::new(RecordType::Mx, name, target.as_str()).map(|spec| Self {
            prio: priority,
            ..spec
        })
    }

    /// A `TXT` record.
    ///
    /// ```
    /// use inwx_client::RecordSpec;
    ///
    /// let spec = RecordSpec::txt("@", "v=spf1 -all")?;
    /// assert_eq!(spec.params()["type"], "TXT");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the text is empty or longer than 1024
    /// characters (the documented content limit).
    pub fn txt(name: impl Into<String>, text: impl Into<String>) -> Result<Self> {
        Self::new(RecordType::Txt, name, text)
    }

    /// Sets the TTL.
    ///
    /// ```
    /// use inwx_client::{RecordSpec, MAX_TTL};
    ///
    /// let spec = RecordSpec::txt("@", "hi")?.with_ttl(60)?;
    /// assert_eq!(spec.ttl(), 60);
    /// assert!(RecordSpec::txt("@", "hi")?.with_ttl(MAX_TTL).is_ok());
    /// assert!(RecordSpec::txt("@", "hi")?.with_ttl(MAX_TTL + 1).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `ttl` exceeds [`MAX_TTL`].
    pub fn with_ttl(mut self, ttl: u32) -> Result<Self> {
        if ttl > MAX_TTL {
            return Err(Error::validation(
                "record.ttl",
                format!("must be 0..={MAX_TTL} seconds, got {ttl}"),
            ));
        }
        self.ttl = ttl;
        Ok(self)
    }

    /// Sets the priority (`MX`, `SRV`).
    ///
    /// ```
    /// use inwx_client::RecordSpec;
    ///
    /// let spec = RecordSpec::txt("@", "hi")?.with_prio(5);
    /// assert_eq!(spec.params()["prio"], 5);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_prio(mut self, priority: u16) -> Self {
        self.prio = priority;
        self
    }

    /// The validated record type.
    ///
    /// ```
    /// use inwx_client::{RecordSpec, RecordType};
    /// assert_eq!(RecordSpec::txt("@", "hi")?.record_type(), RecordType::Txt);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn record_type(&self) -> RecordType {
        self.record_type.clone()
    }

    /// The relative record name.
    ///
    /// ```
    /// use inwx_client::RecordSpec;
    /// assert_eq!(RecordSpec::txt("_acme-challenge", "x")?.name(), "_acme-challenge");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The record content.
    ///
    /// ```
    /// use inwx_client::RecordSpec;
    /// assert_eq!(RecordSpec::txt("@", "hello")?.content(), "hello");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// The TTL in seconds.
    ///
    /// ```
    /// use inwx_client::{RecordSpec, DEFAULT_TTL};
    /// assert_eq!(RecordSpec::txt("@", "hi")?.ttl(), DEFAULT_TTL);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// The request parameters for `nameserver.createRecord`.
    ///
    /// ```
    /// use inwx_client::RecordSpec;
    ///
    /// let params = RecordSpec::mx("@", 10, &inwx_client::Hostname::parse("mx.example.com")?)?.params();
    /// assert_eq!(params["type"], "MX");
    /// assert_eq!(params["name"], "@");
    /// assert_eq!(params["ttl"], 3600);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        json!({
            "type": self.record_type,
            "name": self.name,
            "content": self.content,
            "ttl": self.ttl,
            "prio": self.prio,
        })
    }

    /// Re-checks the invariant [`RecordSpec::new`] establishes, so builders
    /// that mutate a spec cannot produce an invalid one.
    ///
    /// ```
    /// use inwx_client::RecordSpec;
    /// assert!(RecordSpec::a("www", "203.0.113.7")?.validate().is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] on a bad name, content or TTL.
    pub fn validate(&self) -> Result<()> {
        validate_record_name("record.name", &self.name)?;
        if self.ttl > MAX_TTL {
            return Err(Error::validation(
                "record.ttl",
                format!("must be 0..={MAX_TTL} seconds, got {}", self.ttl),
            ));
        }
        validate_content(&self.record_type, &self.content)
    }
}

/// Validates the content of a record against its type.
fn validate_content(record_type: &RecordType, content: &str) -> Result<()> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(Error::validation("record.content", "must not be empty"));
    }
    if trimmed.len() > 1024 {
        return Err(Error::validation(
            "record.content",
            "must be at most 1024 characters",
        ));
    }
    reject_control_chars("record.content", trimmed)?;
    match record_type {
        RecordType::A => trimmed.parse::<Ipv4Addr>().map(|_| ()).map_err(|_| {
            Error::validation(
                "record.content",
                format!("{trimmed:?} is not an IPv4 address (a AAAA record carries IPv6)"),
            )
        }),
        RecordType::Aaaa => trimmed.parse::<Ipv6Addr>().map(|_| ()).map_err(|_| {
            Error::validation(
                "record.content",
                format!("{trimmed:?} is not an IPv6 address (an A record carries IPv4)"),
            )
        }),
        other if other.requires_hostname() => {
            if trimmed.parse::<std::net::IpAddr>().is_ok() {
                return Err(Error::validation(
                    "record.content",
                    format!("a {other} record needs a host name, not the address {trimmed:?}"),
                ));
            }
            Hostname::parse(trimmed).map(|_| ()).map_err(|_| {
                Error::validation(
                    "record.content",
                    format!("{trimmed:?} is not a valid host name for a {other} record"),
                )
            })
        }
        _ => Ok(()),
    }
}

/// Record names may be relative (`www`), the apex (`@`), a wildcard (`*`) or a
/// service label (`_acme-challenge`); they may not contain whitespace or
/// control characters.
fn validate_record_name(field: &'static str, name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(Error::validation(
            field,
            "must not be empty (use `@` for the zone apex)",
        ));
    }
    if trimmed.len() > MAX_DOMAIN_LEN {
        return Err(Error::validation(field, "must be at most 253 characters"));
    }
    reject_control_chars(field, trimmed)?;
    if trimmed.chars().any(char::is_whitespace) {
        return Err(Error::validation(field, "must not contain whitespace"));
    }
    if trimmed.starts_with('.') || trimmed.ends_with('.') {
        return Err(Error::validation(
            field,
            "must not start or end with a dot (record names are relative)",
        ));
    }
    Ok(())
}

/// A record update. Unset fields are left untouched by the API, so a partial
/// update only sends what changed.
///
/// ```
/// use inwx_client::{RecordId, RecordUpdate};
///
/// let update = RecordUpdate::new([RecordId::from(88)])
///     .content("203.0.113.9")
///     .with_ttl(600)?;
/// let params = update.params()?;
/// assert_eq!(params["id"][0], "88");
/// assert_eq!(params["content"], "203.0.113.9");
/// assert_eq!(params["ttl"], 600);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordUpdate {
    ids: Vec<RecordId>,
    name: Option<String>,
    record_type: Option<RecordType>,
    content: Option<String>,
    ttl: Option<u32>,
    prio: Option<u16>,
}

impl RecordUpdate {
    /// A no-op update for the given records; add at least one change before
    /// calling [`RecordUpdate::params`].
    ///
    /// ```
    /// use inwx_client::{RecordId, RecordUpdate};
    /// assert!(RecordUpdate::new([RecordId::from(1)]).params().is_err());
    /// ```
    pub fn new(ids: impl IntoIterator<Item = RecordId>) -> Self {
        Self {
            ids: ids.into_iter().collect(),
            name: None,
            record_type: None,
            content: None,
            ttl: None,
            prio: None,
        }
    }

    /// Sets the record name.
    ///
    /// ```
    /// use inwx_client::{RecordId, RecordUpdate};
    ///
    /// let params = RecordUpdate::new([RecordId::from(1)]).name("api").params()?;
    /// assert_eq!(params["name"], "api");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the record type.
    ///
    /// ```
    /// use inwx_client::{RecordId, RecordType, RecordUpdate};
    ///
    /// let params = RecordUpdate::new([RecordId::from(1)])
    ///     .record_type(RecordType::Txt)
    ///     .params()?;
    /// assert_eq!(params["type"], "TXT");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn record_type(mut self, record_type: RecordType) -> Self {
        self.record_type = Some(record_type);
        self
    }

    /// Sets the record content.
    ///
    /// ```
    /// use inwx_client::{RecordId, RecordUpdate};
    ///
    /// let params = RecordUpdate::new([RecordId::from(1)]).content("v=spf1 -all").params()?;
    /// assert_eq!(params["content"], "v=spf1 -all");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = Some(content.into());
        self
    }

    /// Sets the TTL.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `ttl` exceeds [`MAX_TTL`].
    pub fn with_ttl(mut self, ttl: u32) -> Result<Self> {
        if ttl > MAX_TTL {
            return Err(Error::validation(
                "record.ttl",
                format!("must be 0..={MAX_TTL} seconds, got {ttl}"),
            ));
        }
        self.ttl = Some(ttl);
        Ok(self)
    }

    /// Sets the priority.
    ///
    /// ```
    /// use inwx_client::{RecordId, RecordUpdate};
    ///
    /// let params = RecordUpdate::new([RecordId::from(1)]).prio(20).params()?;
    /// assert_eq!(params["prio"], 20);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn prio(mut self, priority: u16) -> Self {
        self.prio = Some(priority);
        self
    }

    /// The request parameters for `nameserver.updateRecord`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when no record id or no change was supplied, or
    /// when a changed name/content does not validate.
    pub fn params(&self) -> Result<Value> {
        if self.ids.is_empty() {
            return Err(Error::validation(
                "record.id",
                "at least one id is required",
            ));
        }
        if self.name.is_none()
            && self.record_type.is_none()
            && self.content.is_none()
            && self.ttl.is_none()
            && self.prio.is_none()
        {
            return Err(Error::validation(
                "record",
                "an update needs at least one changed field",
            ));
        }
        let mut params = Map::new();
        params.insert(
            "id".to_owned(),
            Value::Array(
                self.ids
                    .iter()
                    .map(|id| Value::String(id.as_str().to_owned()))
                    .collect(),
            ),
        );
        if let Some(name) = &self.name {
            validate_record_name("record.name", name)?;
            params.insert("name".to_owned(), Value::String(name.clone()));
        }
        if let Some(record_type) = &self.record_type {
            params.insert(
                "type".to_owned(),
                Value::String(record_type.as_str().to_owned()),
            );
        }
        if let Some(content) = &self.content {
            if let Some(record_type) = &self.record_type {
                validate_content(record_type, content)?;
            }
            params.insert("content".to_owned(), Value::String(content.clone()));
        }
        if let Some(ttl) = self.ttl {
            params.insert("ttl".to_owned(), json!(ttl));
        }
        if let Some(prio) = self.prio {
            params.insert("prio".to_owned(), json!(prio));
        }
        Ok(Value::Object(params))
    }
}

impl<T: Transport> InwxClient<T> {
    /// Lists every record in a zone via `nameserver.info`.
    ///
    /// The documented method for reading a zone is `nameserver.info`; it
    /// returns the record list plus the zone metadata. The crate exposes the
    /// records here and the metadata through
    /// [`zone_info`](InwxClient::zone_info).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let records = client.list_records(&DomainName::parse("example.com")?).await?;
    /// for record in records {
    ///     println!("{} {} {}", record.name_or_apex(), record.record_type, record.content);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Api`] for a rejected command, [`Error::Transport`] when the
    /// request never completed, [`Error::Json`] for an unparseable answer.
    pub async fn list_records(&self, zone: &DomainName) -> Result<Vec<DnsRecord>> {
        let data = self
            .call("nameserver.info", json!({ "domain": zone.as_str() }))
            .await?;
        let records = data
            .get("record")
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        Ok(serde_json::from_value(records).unwrap_or_default())
    }

    /// Creates one record via `nameserver.createRecord` and returns its id.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, RecordSpec, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let zone = DomainName::parse("example.com")?;
    /// let spec = RecordSpec::a("www", "203.0.113.7")?;
    /// let id = client.create_record(&zone, &spec).await?;
    /// println!("created {id}");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::MissingField`] when the answer carries no `id`, plus the usual
    /// transport and API errors.
    pub async fn create_record(&self, zone: &DomainName, spec: &RecordSpec) -> Result<RecordId> {
        let params = with_zone(zone, &spec.params());
        let data = self.call("nameserver.createRecord", params).await?;
        id_from(&data, "nameserver.createRecord")
    }

    /// Creates several records in one call, returning their ids in order.
    ///
    /// INWX has no batch endpoint: this is `n` sequential calls with
    /// `nameserver.createRecord`. It stops at the first failure, so a partial
    /// result is reported as an error — records already created stay created.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, RecordSpec, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let zone = DomainName::parse("example.com")?;
    /// let records = [
    ///     RecordSpec::a("www", "203.0.113.7")?,
    ///     RecordSpec::txt("@", "v=spf1 -all")?,
    /// ];
    /// let ids = client.create_records(&zone, &records).await?;
    /// assert_eq!(ids.len(), 2);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The first error from any of the individual calls.
    pub async fn create_records(
        &self,
        zone: &DomainName,
        specs: &[RecordSpec],
    ) -> Result<Vec<RecordId>> {
        let mut ids = Vec::with_capacity(specs.len());
        for spec in specs {
            ids.push(self.create_record(zone, spec).await?);
        }
        Ok(ids)
    }

    /// Updates one or more records via `nameserver.updateRecord`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, RecordId, RecordUpdate, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let update = RecordUpdate::new([RecordId::from(88)]).content("203.0.113.9").with_ttl(600)?;
    /// client.update_record(&update).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`RecordUpdate::params`], plus the usual
    /// transport and API errors.
    pub async fn update_record(&self, update: &RecordUpdate) -> Result<()> {
        let params = update.params()?;
        self.call("nameserver.updateRecord", params).await?;
        Ok(())
    }

    /// Deletes a record via `nameserver.deleteRecord`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, RecordId, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.delete_record(&RecordId::from(88)).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn delete_record(&self, id: &RecordId) -> Result<()> {
        self.call("nameserver.deleteRecord", json!({ "id": id }))
            .await?;
        Ok(())
    }

    /// Replaces every record of `record_type` at `name`: deletes what is there,
    /// then creates `spec`.
    ///
    /// Useful for the single-valued types (`A`, `AAAA`, `CNAME`, `MX` with one
    /// target) where a leftover record would shadow the new one. Not atomic —
    /// two calls, no transaction — so a failure can leave the name without a
    /// record. Prefer [`create_record`](InwxClient::create_record) +
    /// [`delete_record`](InwxClient::delete_record) when that matters.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, RecordSpec, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let zone = DomainName::parse("example.com")?;
    /// let spec = RecordSpec::a("www", "203.0.113.7")?;
    /// client.replace_record(&zone, &spec).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The first error from the list, delete or create call.
    pub async fn replace_record(&self, zone: &DomainName, spec: &RecordSpec) -> Result<RecordId> {
        let name = spec.name().to_owned();
        let record_type = spec.record_type();
        for existing in self.list_records(zone).await? {
            if existing.record_type == record_type && existing.name_or_apex() == name {
                self.delete_record(&existing.id).await?;
            }
        }
        self.create_record(zone, spec).await
    }
}

/// Adds the zone reference to an already built parameter object.
fn with_zone(zone: &DomainName, params: &Value) -> Value {
    let mut params = params.as_object().cloned().unwrap_or_default();
    params.insert("domain".to_owned(), Value::String(zone.to_string()));
    Value::Object(params)
}

/// Pulls the `id` field out of a create answer.
fn id_from(data: &Value, method: &'static str) -> Result<RecordId> {
    let raw = data
        .get("id")
        .ok_or(Error::MissingField {
            method,
            field: "resData.id",
        })?
        .clone();
    match RecordId::deserialize(raw) {
        Ok(id) => Ok(id),
        Err(_) => Err(Error::MissingField {
            method,
            field: "resData.id",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_documented_type_round_trips() {
        for record_type in RecordType::ALL {
            let text = record_type.to_string();
            assert_eq!(&RecordType::parse(&text).unwrap(), record_type);
            assert_eq!(text, record_type.as_str());
        }
    }

    #[test]
    fn a_with_ipv6_is_rejected() {
        let err = RecordSpec::a("www", "2001:db8::1").unwrap_err();
        assert!(err.is_validation());
    }

    #[test]
    fn aaaa_parses_ipv4_literal_as_error() {
        let err = RecordSpec::aaaa("www", "203.0.113.7").unwrap_err();
        assert!(matches!(
            err,
            Error::Validation {
                field: "record.content",
                ..
            }
        ));
    }

    #[test]
    fn cname_requires_hostname() {
        assert!(RecordSpec::new(RecordType::Cname, "a", "not a host").is_err());
        assert!(RecordSpec::new(RecordType::Cname, "a", "target.example.com").is_ok());
    }

    #[test]
    fn apex_and_wildcard_names_are_allowed() {
        assert!(RecordSpec::txt("@", "x").is_ok());
        assert!(RecordSpec::txt("*", "x").is_ok());
        assert!(RecordSpec::txt("_acme-challenge.www", "x").is_ok());
        assert!(RecordSpec::txt("has space", "x").is_err());
        assert!(RecordSpec::txt("", "x").is_err());
        assert!(RecordSpec::txt(".leading", "x").is_err());
        assert!(RecordSpec::txt("trailing.", "x").is_err());
    }

    #[test]
    fn ttl_boundary() {
        assert!(RecordSpec::txt("@", "x").unwrap().with_ttl(MAX_TTL).is_ok());
        assert!(RecordSpec::txt("@", "x")
            .unwrap()
            .with_ttl(MAX_TTL + 1)
            .is_err());
    }

    #[test]
    fn record_id_accepts_numbers_and_strings() {
        let record: DnsRecord =
            serde_json::from_str(r#"{"id":77,"type":"A","content":"203.0.113.1"}"#).unwrap();
        assert_eq!(record.id, RecordId::from("77"));
        assert_eq!(record.ttl_seconds(), i64::from(DEFAULT_TTL));
        assert_eq!(record.priority(), 0);
    }

    #[test]
    fn record_id_rejects_objects() {
        let bad =
            serde_json::from_str::<DnsRecord>(r#"{"id":{"a":1},"type":"A","content":"1.2.3.4"}"#);
        assert!(bad.is_err());
    }

    #[test]
    fn unknown_record_type_is_carried() {
        let record: DnsRecord =
            serde_json::from_str(r#"{"id":"1","type":"brandnew","content":"x"}"#).unwrap();
        assert_eq!(record.record_type, RecordType::Other("BRANDNEW".into()));
        assert!(record.ip().is_none());
    }

    #[test]
    fn update_requires_a_change() {
        let update = RecordUpdate::new([RecordId::from(1)]);
        assert!(update.params().is_err());
        assert!(RecordUpdate::new([]).name("x").params().is_err());
    }

    #[test]
    fn update_validates_content_only_with_a_type() {
        let update = RecordUpdate::new([RecordId::from(1)])
            .record_type(RecordType::A)
            .content("nope");
        assert!(update.params().is_err());
    }

    #[test]
    fn zone_params_carry_domain() {
        let zone = DomainName::parse("example.com").unwrap();
        let params = with_zone(&zone, &RecordSpec::txt("@", "x").unwrap().params());
        assert_eq!(params["domain"], "example.com");
        assert_eq!(params["type"], "TXT");
    }

    #[test]
    fn name_or_apex_handles_missing_and_empty() {
        let record: DnsRecord =
            serde_json::from_str(r#"{"id":"1","type":"TXT","content":"x","name":""}"#).unwrap();
        assert_eq!(record.name_or_apex(), "@");
    }
}
