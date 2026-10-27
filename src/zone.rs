//! The zone lifecycle (`nameserver.create`, `nameserver.update`,
//! `nameserver.delete`, `nameserver.clone`, `nameserver.export*`).
//!
//! The record surface lives in [`crate::record`]; this module is about the zone
//! itself — which kind it is, which nameservers it delegates to, and how its
//! web/mail forwarding is configured. Every builder rejects what the API would
//! reject, so a broken zone stays a local error.
//!
//! # Why `ZoneUpdate` cannot carry records
//!
//! `nameserver.update` has no record parameters at all (Table 2.211): records
//! are added with `nameserver.createRecord` and changed with
//! `nameserver.updateRecord`. [`ZoneUpdate`] therefore sends zone attributes
//! only and can never delete a record as a side effect — the failure mode of a
//! "replace the whole zone" helper. [`ZoneUpdate::with_nameservers`] does
//! replace the delegation set, because the API has no add/remove variant for
//! it; that is called out on the method.
//!
//! # What stayed unverified
//!
//! Whether `nameserver.create` accepts a `MASTER` zone without `ns` is not
//! documented beyond "optional" — INWX then uses its own nameservers. That is
//! modelled as an accepted request and marked *unverified* in
//! `docs/contracts.md`.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::nameserver::{ZoneInfo, ZoneListPage};
use crate::transport::Transport;
use crate::types::{
    de, validate_text, validate_token, DocumentFormat, DomainName, Email, Hostname,
};

/// The kind of nameserver entry a zone is (`nsType`: `MASTER` or `SLAVE`).
///
/// An unknown value is carried instead of rejected, so a future entry type does
/// not break parsing.
///
/// ```
/// use inwx_client::ZoneType;
///
/// assert_eq!(ZoneType::Master.to_string(), "MASTER");
/// assert_eq!("slave".parse::<ZoneType>()?, ZoneType::Slave);
/// assert_eq!(ZoneType::parse("PRIMARY")?, ZoneType::Other("PRIMARY".into()));
/// assert!(ZoneType::parse("  ").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ZoneType {
    /// INWX hosts the zone; records are created through the API.
    Master,
    /// The zone is transferred from another nameserver (`masterIp`).
    Slave,
    /// A type this crate does not know; carried verbatim, upper-cased.
    Other(String),
}

impl ZoneType {
    /// Parses an `nsType`, upper-casing it; unknown values become
    /// [`ZoneType::Other`].
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the input is empty.
    pub fn parse(input: &str) -> Result<Self> {
        let upper = input.trim().to_ascii_uppercase();
        if upper.is_empty() {
            return Err(Error::validation("zone.type", "must not be empty"));
        }
        Ok(match upper.as_str() {
            "MASTER" => Self::Master,
            "SLAVE" => Self::Slave,
            _ => Self::Other(upper),
        })
    }

    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::ZoneType;
    /// assert_eq!(ZoneType::Slave.as_str(), "SLAVE");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Master => "MASTER",
            Self::Slave => "SLAVE",
            Self::Other(raw) => raw,
        }
    }
}

impl fmt::Display for ZoneType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ZoneType {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl Serialize for ZoneType {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ZoneType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// How a web forward is delivered (`urlRedirectType`).
///
/// The three values are the ones the `urlRedirectType` datatype lists;
/// `HEADER301`/`HEADER302` are HTTP redirects, `FRAME` renders the target inside
/// a frame (and is the only type that uses a title, description, favicon or
/// keywords).
///
/// ```
/// use inwx_client::UrlRedirectType;
///
/// assert_eq!(UrlRedirectType::Header301.as_str(), "HEADER301");
/// assert_eq!("frame".parse::<UrlRedirectType>()?, UrlRedirectType::Frame);
/// assert!("HEADER200".parse::<UrlRedirectType>().is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UrlRedirectType {
    /// HTTP 301 (permanent) redirect.
    Header301,
    /// HTTP 302 (temporary) redirect.
    Header302,
    /// Frame redirect, with title/description/favicon/keywords.
    Frame,
}

impl UrlRedirectType {
    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::UrlRedirectType;
    /// assert_eq!(UrlRedirectType::Header302.as_str(), "HEADER302");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Header301 => "HEADER301",
            Self::Header302 => "HEADER302",
            Self::Frame => "FRAME",
        }
    }

    /// Whether the type renders the target in a frame.
    ///
    /// Only a frame redirect has a title, description, favicon and keywords;
    /// the API ignores the four for a header redirect, and sending them would
    /// suggest a configuration that never takes effect.
    ///
    /// ```
    /// use inwx_client::UrlRedirectType;
    /// assert!(UrlRedirectType::Frame.supports_frame_metadata());
    /// assert!(!UrlRedirectType::Header301.supports_frame_metadata());
    /// ```
    #[must_use]
    pub fn supports_frame_metadata(self) -> bool {
        matches!(self, Self::Frame)
    }
}

impl fmt::Display for UrlRedirectType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for UrlRedirectType {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        match input.trim().to_ascii_uppercase().as_str() {
            "HEADER301" => Ok(Self::Header301),
            "HEADER302" => Ok(Self::Header302),
            "FRAME" => Ok(Self::Frame),
            other => Err(Error::validation(
                "urlRedirectType",
                format!("{other:?} is not one of HEADER301, HEADER302, FRAME"),
            )),
        }
    }
}

impl Serialize for UrlRedirectType {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for UrlRedirectType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(D::Error::custom)
    }
}

/// The nameserver set and forwarding configuration of one zone
/// (`nameserver.create`, Table 2.195).
///
/// Build it with [`ZoneCreate::master`] or [`ZoneCreate::slave`], add what the
/// zone needs, then hand it to
/// [`InwxClient::create_zone`](crate::InwxClient::create_zone).
///
/// ```
/// use inwx_client::{DomainName, Hostname, ZoneCreate, ZoneType};
///
/// let zone = ZoneCreate::master(DomainName::parse("tenant.example.com")?)?
///     .with_nameservers(&[
///         Hostname::parse("ns1.example.net")?,
///         Hostname::parse("ns2.example.net")?,
///     ])?
///     .with_soa_email(inwx_client::Email::parse("hostmaster@example.net")?)?;
///
/// let params = zone.params()?;
/// assert_eq!(params["domain"], "tenant.example.com");
/// assert_eq!(params["type"], "MASTER");
/// assert_eq!(params["ns"][1], "ns2.example.net");
/// assert_eq!(params["soaEmail"], "hostmaster@example.net");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ZoneCreate {
    domain: DomainName,
    zone_type: ZoneType,
    nameservers: Vec<Hostname>,
    master_ip: Option<IpAddr>,
    web: Option<String>,
    mail: Option<String>,
    soa_email: Option<Email>,
    redirect_type: Option<UrlRedirectType>,
    redirect_title: Option<String>,
    redirect_description: Option<String>,
    redirect_favicon: Option<String>,
    redirect_keywords: Option<String>,
    testing: bool,
    ignore_existing: bool,
}

impl ZoneCreate {
    /// A zone of any documented type.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `zone_type` is a [`ZoneType::Other`] value
    /// this crate cannot reason about: creating an unknown entry type would
    /// send a configuration nobody can verify.
    pub fn new(domain: DomainName, zone_type: ZoneType) -> Result<Self> {
        if matches!(zone_type, ZoneType::Other(_)) {
            return Err(Error::validation(
                "zone.type",
                format!(
                    "{} is not a documented zone type (MASTER, SLAVE)",
                    zone_type.as_str()
                ),
            ));
        }
        Ok(Self {
            domain,
            zone_type,
            nameservers: Vec::new(),
            master_ip: None,
            web: None,
            mail: None,
            soa_email: None,
            redirect_type: None,
            redirect_title: None,
            redirect_description: None,
            redirect_favicon: None,
            redirect_keywords: None,
            testing: false,
            ignore_existing: false,
        })
    }

    /// A primary zone (`type=MASTER`), where INWX hosts the records.
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneCreate};
    ///
    /// let zone = ZoneCreate::master(DomainName::parse("example.com")?)?;
    /// assert_eq!(zone.params()?["type"], "MASTER");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name is unusable — it already is not, so
    /// in practice this cannot fail; the signature keeps the constructor
    /// consistent with the fallible ones.
    pub fn master(domain: DomainName) -> Result<Self> {
        Self::new(domain, ZoneType::Master)
    }

    /// A secondary zone (`type=SLAVE`) transferring from `master_ip`.
    ///
    /// The master address is required here rather than at
    /// [`ZoneCreate::params`], so a slave zone cannot be built without the one
    /// value that makes it work.
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneCreate};
    ///
    /// let zone = ZoneCreate::slave(DomainName::parse("example.com")?, inwx_client::parse_ip("198.51.100.7")?)?;
    /// assert_eq!(zone.params()?["masterIp"], "198.51.100.7");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the zone type is rejected by
    /// [`ZoneCreate::new`].
    pub fn slave(domain: DomainName, master_ip: IpAddr) -> Result<Self> {
        Ok(Self {
            master_ip: Some(master_ip),
            ..Self::new(domain, ZoneType::Slave)?
        })
    }

    /// The zone being created.
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneCreate};
    /// let zone = ZoneCreate::master(DomainName::parse("a.de")?)?;
    /// assert_eq!(zone.domain().as_str(), "a.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// The zone type.
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneCreate, ZoneType};
    /// let zone = ZoneCreate::master(DomainName::parse("a.de")?)?;
    /// assert_eq!(zone.zone_type(), ZoneType::Master);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn zone_type(&self) -> ZoneType {
        self.zone_type.clone()
    }

    /// Sets the delegated nameservers (`ns`).
    ///
    /// Duplicates are rejected: INWX would accept them and the zone would
    /// advertise the same server twice.
    ///
    /// ```
    /// use inwx_client::{DomainName, Hostname, ZoneCreate};
    ///
    /// let zone = ZoneCreate::master(DomainName::parse("a.de")?)?
    ///     .with_nameservers(&[Hostname::parse("ns1.example.net")?])?;
    /// assert_eq!(zone.params()?["ns"][0], "ns1.example.net");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty list or a duplicate entry.
    pub fn with_nameservers(mut self, nameservers: &[Hostname]) -> Result<Self> {
        if nameservers.is_empty() {
            return Err(Error::validation(
                "zone.ns",
                "must list at least one nameserver",
            ));
        }
        for (index, nameserver) in nameservers.iter().enumerate() {
            if nameservers[..index].contains(nameserver) {
                return Err(Error::validation(
                    "zone.ns",
                    format!("{nameserver} is listed twice"),
                ));
            }
        }
        self.nameservers = nameservers.to_vec();
        Ok(self)
    }

    /// Sets the master address of a slave zone.
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneCreate};
    ///
    /// let zone = ZoneCreate::slave(DomainName::parse("a.de")?, inwx_client::parse_ip("198.51.100.7")?)?;
    /// assert_eq!(zone.params()?["masterIp"], "198.51.100.7");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_master_ip(mut self, master_ip: IpAddr) -> Self {
        self.master_ip = Some(master_ip);
        self
    }

    /// Sets the web forwarding target (`web`, `token0255`).
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneCreate};
    ///
    /// let zone = ZoneCreate::master(DomainName::parse("a.de")?)?.with_web("https://example.net")?;
    /// assert_eq!(zone.params()?["web"], "https://example.net");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty, longer than 255
    /// characters or contains a newline.
    pub fn with_web(mut self, web: impl Into<String>) -> Result<Self> {
        let web = web.into();
        validate_token("zone.web", &web)?;
        self.web = Some(web.trim().to_owned());
        Ok(self)
    }

    /// Sets the mail forwarding target (`mail`, `text0255`).
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneCreate};
    ///
    /// let zone = ZoneCreate::master(DomainName::parse("a.de")?)?.with_mail("mx.example.net")?;
    /// assert_eq!(zone.params()?["mail"], "mx.example.net");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or longer than 255
    /// characters.
    pub fn with_mail(mut self, mail: impl Into<String>) -> Result<Self> {
        let mail = mail.into();
        validate_text("zone.mail", &mail, 255)?;
        self.mail = Some(mail.trim().to_owned());
        Ok(self)
    }

    /// Sets the SOA contact address (`soaEmail`).
    ///
    /// `nameserver.update` has no `soaEmail` parameter (Table 2.211), so this
    /// can only be set at creation time — a second reason to get it right here.
    ///
    /// ```
    /// use inwx_client::{DomainName, Email, ZoneCreate};
    ///
    /// let zone = ZoneCreate::master(DomainName::parse("a.de")?)?
    ///     .with_soa_email(Email::parse("hostmaster@example.net")?)?;
    /// assert_eq!(zone.params()?["soaEmail"], "hostmaster@example.net");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`Email::parse`].
    pub fn with_soa_email(mut self, email: Email) -> Result<Self> {
        validate_text("zone.soaEmail", email.as_str(), 255)?;
        self.soa_email = Some(email);
        Ok(self)
    }

    /// Sets the web forward type (`urlRedirectType`).
    ///
    /// ```
    /// use inwx_client::{DomainName, UrlRedirectType, ZoneCreate};
    ///
    /// let zone = ZoneCreate::master(DomainName::parse("a.de")?)?
    ///     .with_web("https://example.net")?
    ///     .with_redirect_type(UrlRedirectType::Header301)?;
    /// assert_eq!(zone.params()?["urlRedirectType"], "HEADER301");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when no [`ZoneCreate::with_web`] target has been
    /// set: a redirect type without a target describes nothing.
    pub fn with_redirect_type(mut self, redirect_type: UrlRedirectType) -> Result<Self> {
        if self.web.is_none() {
            return Err(Error::validation(
                "zone.urlRedirectType",
                "needs a `web` target first (with_web)",
            ));
        }
        self.redirect_type = Some(redirect_type);
        Ok(self)
    }

    /// Sets the frame title (`urlRedirectTitle`).
    ///
    /// ```
    /// use inwx_client::{DomainName, UrlRedirectType, ZoneCreate};
    ///
    /// let zone = ZoneCreate::master(DomainName::parse("a.de")?)?
    ///     .with_web("https://example.net")?
    ///     .with_redirect_type(UrlRedirectType::Frame)?
    ///     .with_frame_title("Tenant")?;
    /// assert_eq!(zone.params()?["urlRedirectTitle"], "Tenant");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the redirect type is not
    /// [`UrlRedirectType::Frame`], or the value is unusable.
    pub fn with_frame_title(mut self, title: impl Into<String>) -> Result<Self> {
        let title = title.into();
        self.require_frame("zone.urlRedirectTitle")?;
        validate_token("zone.urlRedirectTitle", &title)?;
        self.redirect_title = Some(title.trim().to_owned());
        Ok(self)
    }

    /// Sets the frame description (`urlRedirectDescription`).
    ///
    /// ```
    /// use inwx_client::{DomainName, UrlRedirectType, ZoneCreate};
    ///
    /// let zone = ZoneCreate::master(DomainName::parse("a.de")?)?
    ///     .with_web("https://example.net")?
    ///     .with_redirect_type(UrlRedirectType::Frame)?
    ///     .with_frame_description("Tenant portal")?;
    /// assert_eq!(zone.params()?["urlRedirectDescription"], "Tenant portal");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the redirect type is not
    /// [`UrlRedirectType::Frame`], or the value is unusable.
    pub fn with_frame_description(mut self, description: impl Into<String>) -> Result<Self> {
        let description = description.into();
        self.require_frame("zone.urlRedirectDescription")?;
        validate_token("zone.urlRedirectDescription", &description)?;
        self.redirect_description = Some(description.trim().to_owned());
        Ok(self)
    }

    /// Sets the frame favicon (`urlRedirectFavIcon`).
    ///
    /// ```
    /// use inwx_client::{DomainName, UrlRedirectType, ZoneCreate};
    ///
    /// let zone = ZoneCreate::master(DomainName::parse("a.de")?)?
    ///     .with_web("https://example.net")?
    ///     .with_redirect_type(UrlRedirectType::Frame)?
    ///     .with_frame_favicon("https://example.net/favicon.ico")?;
    /// assert_eq!(zone.params()?["urlRedirectFavIcon"], "https://example.net/favicon.ico");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the redirect type is not
    /// [`UrlRedirectType::Frame`], or the value is unusable.
    pub fn with_frame_favicon(mut self, favicon: impl Into<String>) -> Result<Self> {
        let favicon = favicon.into();
        self.require_frame("zone.urlRedirectFavIcon")?;
        validate_token("zone.urlRedirectFavIcon", &favicon)?;
        self.redirect_favicon = Some(favicon.trim().to_owned());
        Ok(self)
    }

    /// Sets the frame keywords (`urlRedirectKeywords`).
    ///
    /// ```
    /// use inwx_client::{DomainName, UrlRedirectType, ZoneCreate};
    ///
    /// let zone = ZoneCreate::master(DomainName::parse("a.de")?)?
    ///     .with_web("https://example.net")?
    ///     .with_redirect_type(UrlRedirectType::Frame)?
    ///     .with_frame_keywords("tenant, portal")?;
    /// assert_eq!(zone.params()?["urlRedirectKeywords"], "tenant, portal");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the redirect type is not
    /// [`UrlRedirectType::Frame`], or the value is unusable.
    pub fn with_frame_keywords(mut self, keywords: impl Into<String>) -> Result<Self> {
        let keywords = keywords.into();
        self.require_frame("zone.urlRedirectKeywords")?;
        validate_token("zone.urlRedirectKeywords", &keywords)?;
        self.redirect_keywords = Some(keywords.trim().to_owned());
        Ok(self)
    }

    /// Runs the command in testing mode (`testing=true`): the API validates but
    /// creates nothing.
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneCreate};
    /// let zone = ZoneCreate::master(DomainName::parse("a.de")?)?.dry_run();
    /// assert_eq!(zone.params()?["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.testing = true;
        self
    }

    /// Keeps an existing zone instead of failing with `2302` (`ignoreExisting`).
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneCreate};
    /// let zone = ZoneCreate::master(DomainName::parse("a.de")?)?.ignore_existing();
    /// assert_eq!(zone.params()?["ignoreExisting"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn ignore_existing(mut self) -> Self {
        self.ignore_existing = true;
        self
    }

    fn require_frame(&self, field: &'static str) -> Result<()> {
        match self.redirect_type {
            Some(UrlRedirectType::Frame) => Ok(()),
            Some(other) => Err(Error::validation(
                field,
                format!("is only used by a FRAME redirect, not {}", other.as_str()),
            )),
            None => Err(Error::validation(
                field,
                "needs a FRAME redirect type first (with_redirect_type)",
            )),
        }
    }

    /// The `nameserver.create` parameters.
    ///
    /// Re-checks the invariants the setters establish, so a combination built in
    /// any order still cannot reach the wire broken: a slave zone without
    /// `masterIp`, or a primary zone carrying one, is rejected here.
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneCreate, ZoneType};
    ///
    /// let zone = ZoneCreate::new(DomainName::parse("a.de")?, ZoneType::Master)?;
    /// let params = zone.params()?;
    /// assert_eq!(params["domain"], "a.de");
    /// assert_eq!(params["testing"], false);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the request is internally inconsistent — a
    /// `SLAVE` zone without `masterIp`, a `MASTER` zone with one, or a frame
    /// field without a frame redirect.
    pub fn params(&self) -> Result<Value> {
        match (&self.zone_type, self.master_ip) {
            (ZoneType::Slave, None) => {
                return Err(Error::validation(
                    "zone.masterIp",
                    "a SLAVE zone needs the master address",
                ));
            }
            (ZoneType::Master, Some(_)) => {
                return Err(Error::validation(
                    "zone.masterIp",
                    "a MASTER zone has no master address (use with_master_ip on a slave)",
                ));
            }
            _ => {}
        }
        let frame_metadata = self.redirect_title.is_some()
            || self.redirect_description.is_some()
            || self.redirect_favicon.is_some()
            || self.redirect_keywords.is_some();
        if frame_metadata
            && !self
                .redirect_type
                .is_some_and(UrlRedirectType::supports_frame_metadata)
        {
            return Err(Error::validation(
                "zone.urlRedirectType",
                "frame metadata needs a FRAME redirect type",
            ));
        }
        if self.domain.as_str().len() > 253 {
            return Err(Error::validation(
                "domain",
                "must be at most 253 characters",
            ));
        }
        Ok(self.params_unchecked())
    }

    /// Serialises without re-validating; `params` has already done it.
    fn params_unchecked(&self) -> Value {
        let mut params = Map::new();
        params.insert("domain".to_owned(), json!(self.domain));
        params.insert("type".to_owned(), json!(self.zone_type));
        if !self.nameservers.is_empty() {
            params.insert("ns".to_owned(), json!(self.nameservers));
        }
        if let Some(ip) = self.master_ip {
            params.insert("masterIp".to_owned(), json!(ip.to_string()));
        }
        if let Some(web) = &self.web {
            params.insert("web".to_owned(), json!(web));
        }
        if let Some(mail) = &self.mail {
            params.insert("mail".to_owned(), json!(mail));
        }
        if let Some(email) = &self.soa_email {
            params.insert("soaEmail".to_owned(), json!(email));
        }
        if let Some(kind) = self.redirect_type {
            params.insert("urlRedirectType".to_owned(), json!(kind));
        }
        if let Some(title) = &self.redirect_title {
            params.insert("urlRedirectTitle".to_owned(), json!(title));
        }
        if let Some(description) = &self.redirect_description {
            params.insert("urlRedirectDescription".to_owned(), json!(description));
        }
        if let Some(favicon) = &self.redirect_favicon {
            params.insert("urlRedirectFavIcon".to_owned(), json!(favicon));
        }
        if let Some(keywords) = &self.redirect_keywords {
            params.insert("urlRedirectKeywords".to_owned(), json!(keywords));
        }
        params.insert("testing".to_owned(), json!(self.testing));
        if self.ignore_existing {
            params.insert("ignoreExisting".to_owned(), json!(true));
        }
        Value::Object(params)
    }
}

/// A change to an existing zone (`nameserver.update`, Table 2.211).
///
/// Only the fields that were set are sent; the API leaves the rest alone. There
/// is deliberately no record parameter: this request cannot delete a DNS
/// record, and a zone with ten thousand records is not re-uploaded to change one
/// nameserver.
///
/// ```
/// use inwx_client::{DomainName, Hostname, ZoneUpdate};
///
/// let update = ZoneUpdate::new(DomainName::parse("example.com")?)
///     .with_nameservers(&[Hostname::parse("ns3.example.net")?])?;
/// let params = update.params()?;
/// assert_eq!(params["ns"][0], "ns3.example.net");
/// assert!(params.get("record").is_none());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ZoneUpdate {
    domain: DomainName,
    zone_type: Option<ZoneType>,
    nameservers: Option<Vec<Hostname>>,
    master_ip: Option<IpAddr>,
    web: Option<String>,
    mail: Option<String>,
    redirect_type: Option<UrlRedirectType>,
    redirect_title: Option<String>,
    redirect_description: Option<String>,
    redirect_favicon: Option<String>,
    redirect_keywords: Option<String>,
    testing: bool,
}

impl ZoneUpdate {
    /// An empty update for `domain`.
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneUpdate};
    /// // Nothing set yet: sending this would be an empty command.
    /// assert!(ZoneUpdate::new(DomainName::parse("a.de")?).params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn new(domain: DomainName) -> Self {
        Self {
            domain,
            zone_type: None,
            nameservers: None,
            master_ip: None,
            web: None,
            mail: None,
            redirect_type: None,
            redirect_title: None,
            redirect_description: None,
            redirect_favicon: None,
            redirect_keywords: None,
            testing: false,
        }
    }

    /// The zone being updated.
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneUpdate};
    /// assert_eq!(ZoneUpdate::new(DomainName::parse("a.de")?).domain().as_str(), "a.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// Switches the zone type (`type`).
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneType, ZoneUpdate};
    ///
    /// let update = ZoneUpdate::new(DomainName::parse("a.de")?).with_zone_type(ZoneType::Slave);
    /// assert_eq!(update.params().unwrap()["type"], "SLAVE");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_zone_type(mut self, zone_type: ZoneType) -> Self {
        self.zone_type = Some(zone_type);
        self
    }

    /// **Replaces** the delegated nameservers (`ns`).
    ///
    /// The API has no add/remove variant, so this is the whole set: a name left
    /// out stops being delegated. That is an explicit act here rather than a
    /// silent side effect elsewhere, and it never touches the zone's records.
    ///
    /// ```
    /// use inwx_client::{DomainName, Hostname, ZoneUpdate};
    ///
    /// let update = ZoneUpdate::new(DomainName::parse("a.de")?)
    ///     .with_nameservers(&[Hostname::parse("ns1.example.net")?])?;
    /// assert_eq!(update.params()?["ns"][0], "ns1.example.net");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty list or a duplicate entry.
    pub fn with_nameservers(mut self, nameservers: &[Hostname]) -> Result<Self> {
        if nameservers.is_empty() {
            return Err(Error::validation(
                "zone.ns",
                "must list at least one nameserver",
            ));
        }
        for (index, nameserver) in nameservers.iter().enumerate() {
            if nameservers[..index].contains(nameserver) {
                return Err(Error::validation(
                    "zone.ns",
                    format!("{nameserver} is listed twice"),
                ));
            }
        }
        self.nameservers = Some(nameservers.to_vec());
        Ok(self)
    }

    /// Sets the master address (`masterIp`).
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneUpdate};
    ///
    /// let update = ZoneUpdate::new(DomainName::parse("a.de")?)
    ///     .with_master_ip(inwx_client::parse_ip("198.51.100.7")?);
    /// assert_eq!(update.params()?["masterIp"], "198.51.100.7");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_master_ip(mut self, master_ip: IpAddr) -> Self {
        self.master_ip = Some(master_ip);
        self
    }

    /// Sets the web forwarding target (`web`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is unusable.
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneUpdate};
    ///
    /// let update = ZoneUpdate::new(DomainName::parse("a.de")?).with_web("https://example.net")?;
    /// assert_eq!(update.params()?["web"], "https://example.net");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_web(mut self, web: impl Into<String>) -> Result<Self> {
        let web = web.into();
        validate_token("zone.web", &web)?;
        self.web = Some(web.trim().to_owned());
        Ok(self)
    }

    /// Sets the mail forwarding target (`mail`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is unusable.
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneUpdate};
    ///
    /// let update = ZoneUpdate::new(DomainName::parse("a.de")?).with_mail("mx.example.net")?;
    /// assert_eq!(update.params()?["mail"], "mx.example.net");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_mail(mut self, mail: impl Into<String>) -> Result<Self> {
        let mail = mail.into();
        validate_text("zone.mail", &mail, 255)?;
        self.mail = Some(mail.trim().to_owned());
        Ok(self)
    }

    /// Sets the web forward type (`urlRedirectType`).
    ///
    /// ```
    /// use inwx_client::{DomainName, UrlRedirectType, ZoneUpdate};
    ///
    /// let update = ZoneUpdate::new(DomainName::parse("a.de")?)
    ///     .with_web("https://example.net")?
    ///     .with_redirect_type(UrlRedirectType::Header302)?;
    /// assert_eq!(update.params()?["urlRedirectType"], "HEADER302");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when no web target has been set in this update.
    pub fn with_redirect_type(mut self, redirect_type: UrlRedirectType) -> Result<Self> {
        if self.web.is_none() {
            return Err(Error::validation(
                "zone.urlRedirectType",
                "needs a `web` target in the same update (with_web)",
            ));
        }
        self.redirect_type = Some(redirect_type);
        Ok(self)
    }

    /// Sets the frame title (`urlRedirectTitle`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the redirect type is not `FRAME`.
    ///
    /// ```
    /// use inwx_client::{DomainName, UrlRedirectType, ZoneUpdate};
    ///
    /// let update = ZoneUpdate::new(DomainName::parse("a.de")?)
    ///     .with_web("https://example.net")?
    ///     .with_redirect_type(UrlRedirectType::Frame)?
    ///     .with_frame_title("Tenant")?;
    /// assert_eq!(update.params()?["urlRedirectTitle"], "Tenant");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_frame_title(mut self, title: impl Into<String>) -> Result<Self> {
        let title = title.into();
        self.require_frame("zone.urlRedirectTitle")?;
        validate_token("zone.urlRedirectTitle", &title)?;
        self.redirect_title = Some(title.trim().to_owned());
        Ok(self)
    }

    /// Sets the frame description (`urlRedirectDescription`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the redirect type is not `FRAME`.
    ///
    /// ```
    /// use inwx_client::{DomainName, UrlRedirectType, ZoneUpdate};
    ///
    /// let update = ZoneUpdate::new(DomainName::parse("a.de")?)
    ///     .with_web("https://example.net")?
    ///     .with_redirect_type(UrlRedirectType::Frame)?
    ///     .with_frame_description("Tenant portal")?;
    /// assert!(update.params()?.get("urlRedirectDescription").is_some());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_frame_description(mut self, description: impl Into<String>) -> Result<Self> {
        let description = description.into();
        self.require_frame("zone.urlRedirectDescription")?;
        validate_token("zone.urlRedirectDescription", &description)?;
        self.redirect_description = Some(description.trim().to_owned());
        Ok(self)
    }

    /// Sets the frame favicon (`urlRedirectFavIcon`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the redirect type is not `FRAME`.
    ///
    /// ```
    /// use inwx_client::{DomainName, UrlRedirectType, ZoneUpdate};
    ///
    /// let update = ZoneUpdate::new(DomainName::parse("a.de")?)
    ///     .with_web("https://example.net")?
    ///     .with_redirect_type(UrlRedirectType::Frame)?
    ///     .with_frame_favicon("https://example.net/favicon.ico")?;
    /// assert!(update.params()?.get("urlRedirectFavIcon").is_some());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_frame_favicon(mut self, favicon: impl Into<String>) -> Result<Self> {
        let favicon = favicon.into();
        self.require_frame("zone.urlRedirectFavIcon")?;
        validate_token("zone.urlRedirectFavIcon", &favicon)?;
        self.redirect_favicon = Some(favicon.trim().to_owned());
        Ok(self)
    }

    /// Sets the frame keywords (`urlRedirectKeywords`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the redirect type is not `FRAME`.
    ///
    /// ```
    /// use inwx_client::{DomainName, UrlRedirectType, ZoneUpdate};
    ///
    /// let update = ZoneUpdate::new(DomainName::parse("a.de")?)
    ///     .with_web("https://example.net")?
    ///     .with_redirect_type(UrlRedirectType::Frame)?
    ///     .with_frame_keywords("tenant")?;
    /// assert!(update.params()?.get("urlRedirectKeywords").is_some());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_frame_keywords(mut self, keywords: impl Into<String>) -> Result<Self> {
        let keywords = keywords.into();
        self.require_frame("zone.urlRedirectKeywords")?;
        validate_token("zone.urlRedirectKeywords", &keywords)?;
        self.redirect_keywords = Some(keywords.trim().to_owned());
        Ok(self)
    }

    /// Runs the command in testing mode (`testing=true`).
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneType, ZoneUpdate};
    /// let update = ZoneUpdate::new(DomainName::parse("a.de")?)
    ///     .with_zone_type(ZoneType::Slave)
    ///     .dry_run();
    /// assert_eq!(update.params().unwrap()["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.testing = true;
        self
    }

    fn require_frame(&self, field: &'static str) -> Result<()> {
        match self.redirect_type {
            Some(UrlRedirectType::Frame) => Ok(()),
            Some(other) => Err(Error::validation(
                field,
                format!("is only used by a FRAME redirect, not {}", other.as_str()),
            )),
            None => Err(Error::validation(
                field,
                "needs a FRAME redirect type in the same update (with_redirect_type)",
            )),
        }
    }

    /// Whether any change has been set.
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneType, ZoneUpdate};
    ///
    /// assert!(!ZoneUpdate::new(DomainName::parse("a.de")?).has_changes());
    /// assert!(ZoneUpdate::new(DomainName::parse("a.de")?).with_zone_type(ZoneType::Master).has_changes());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.zone_type.is_some()
            || self.nameservers.is_some()
            || self.master_ip.is_some()
            || self.web.is_some()
            || self.mail.is_some()
            || self.redirect_type.is_some()
            || self.redirect_title.is_some()
            || self.redirect_description.is_some()
            || self.redirect_favicon.is_some()
            || self.redirect_keywords.is_some()
    }

    /// The `nameserver.update` parameters.
    ///
    /// ```
    /// use inwx_client::{DomainName, ZoneType, ZoneUpdate};
    ///
    /// let params = ZoneUpdate::new(DomainName::parse("a.de")?)
    ///     .with_zone_type(ZoneType::Master)
    ///     .params()?;
    /// assert_eq!(params["domain"], "a.de");
    /// // An untouched field is absent, not `null`: the API patches.
    /// assert!(params.get("web").is_none());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when nothing was set (an empty update is a
    /// guaranteed `2003`), or when a frame field lacks its `FRAME` type.
    pub fn params(&self) -> Result<Value> {
        if !self.has_changes() {
            return Err(Error::validation(
                "zone.update",
                "sets no field; add a change or skip the call",
            ));
        }
        let frame_metadata = self.redirect_title.is_some()
            || self.redirect_description.is_some()
            || self.redirect_favicon.is_some()
            || self.redirect_keywords.is_some();
        if frame_metadata
            && !self
                .redirect_type
                .is_some_and(UrlRedirectType::supports_frame_metadata)
        {
            return Err(Error::validation(
                "zone.urlRedirectType",
                "frame metadata needs a FRAME redirect type",
            ));
        }
        let mut params = Map::new();
        params.insert("domain".to_owned(), json!(self.domain));
        if let Some(zone_type) = &self.zone_type {
            params.insert("type".to_owned(), json!(zone_type));
        }
        if let Some(nameservers) = &self.nameservers {
            params.insert("ns".to_owned(), json!(nameservers));
        }
        if let Some(ip) = self.master_ip {
            params.insert("masterIp".to_owned(), json!(ip.to_string()));
        }
        if let Some(web) = &self.web {
            params.insert("web".to_owned(), json!(web));
        }
        if let Some(mail) = &self.mail {
            params.insert("mail".to_owned(), json!(mail));
        }
        if let Some(kind) = self.redirect_type {
            params.insert("urlRedirectType".to_owned(), json!(kind));
        }
        if let Some(title) = &self.redirect_title {
            params.insert("urlRedirectTitle".to_owned(), json!(title));
        }
        if let Some(description) = &self.redirect_description {
            params.insert("urlRedirectDescription".to_owned(), json!(description));
        }
        if let Some(favicon) = &self.redirect_favicon {
            params.insert("urlRedirectFavIcon".to_owned(), json!(favicon));
        }
        if let Some(keywords) = &self.redirect_keywords {
            params.insert("urlRedirectKeywords".to_owned(), json!(keywords));
        }
        if self.testing {
            params.insert("testing".to_owned(), json!(true));
        }
        Ok(Value::Object(params))
    }
}

/// The exported zone file returned by `nameserver.export`.
///
/// ```
/// use inwx_client::ZoneExport;
///
/// let export: ZoneExport = serde_json::from_str(r#"{"export":"example.com. 3600 IN A 203.0.113.7"}"#)?;
/// assert!(export.text.contains("203.0.113.7"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ZoneExport {
    /// The zone in the requested format (zone file by default, CSV when
    /// `zonefile=false`).
    #[serde(default, rename = "export")]
    pub text: String,
}

/// The record export returned by `nameserver.exportrecords`.
///
/// ```
/// use inwx_client::RecordExport;
///
/// let export: RecordExport = serde_json::from_str(r#"{"count":2,"data":"name,type\nwww,A"}"#)?;
/// assert_eq!(export.count, Some(2));
/// assert!(export.data.starts_with("name,type"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct RecordExport {
    /// Number of exported entries, when the API reports it.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// CSV data in clear text (the only format the API supports here).
    #[serde(default)]
    pub data: String,
}

impl<T: Transport> InwxClient<T> {
    /// Creates a zone (`nameserver.create`) and returns its `roId`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, Hostname, InwxClient, ReqwestTransport, ZoneCreate};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let zone = ZoneCreate::master(DomainName::parse("tenant.example.com")?)?
    ///     .with_nameservers(&[
    ///         Hostname::parse("ns1.example.net")?,
    ///         Hostname::parse("ns2.example.net")?,
    ///     ])?;
    /// let ro_id = client.create_zone(&zone).await?;
    /// println!("zone {ro_id}");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`ZoneCreate::params`], then the usual
    /// transport and API errors — `2302` when the zone already exists (unless
    /// [`ZoneCreate::ignore_existing`] was set).
    pub async fn create_zone(&self, zone: &ZoneCreate) -> Result<i64> {
        let data = self.call("nameserver.create", zone.params()?).await?;
        data.get("roId")
            .and_then(Value::as_i64)
            .ok_or(Error::MissingField {
                method: "nameserver.create",
                field: "resData.roId",
            })
    }

    /// Updates a zone (`nameserver.update`).
    ///
    /// Sends only the fields the [`ZoneUpdate`] carries. Records are untouched:
    /// see [`ZoneUpdate`] for why that is structural and not a promise.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, Hostname, InwxClient, ReqwestTransport, ZoneUpdate};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let update = ZoneUpdate::new(DomainName::parse("tenant.example.com")?)
    ///     .with_nameservers(&[Hostname::parse("ns1.example.net")?])?;
    /// client.update_zone(&update).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`ZoneUpdate::params`], then the usual
    /// transport and API errors.
    pub async fn update_zone(&self, update: &ZoneUpdate) -> Result<()> {
        self.call("nameserver.update", update.params()?).await?;
        Ok(())
    }

    /// Deletes a zone (`nameserver.delete`) in testing mode: the API checks the
    /// request and deletes nothing.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client
    ///     .delete_zone_dry_run(&DomainName::parse("tenant.example.com")?)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn delete_zone_dry_run(&self, domain: &DomainName) -> Result<()> {
        self.call(
            "nameserver.delete",
            json!({ "domain": domain.as_str(), "testing": true }),
        )
        .await?;
        Ok(())
    }

    /// Copies every record of one zone into another (`nameserver.clone`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let target = client
    ///     .clone_zone(
    ///         &DomainName::parse("example.com")?,
    ///         &DomainName::parse("example.net")?,
    ///     )
    ///     .await?;
    /// println!("new zone {target}");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when source and target are the same zone (the copy
    /// would duplicate every record of itself), plus the usual transport and API
    /// errors.
    pub async fn clone_zone(&self, source: &DomainName, target: &DomainName) -> Result<i64> {
        if source == target {
            return Err(Error::validation(
                "targetDomain",
                "must differ from sourceDomain",
            ));
        }
        let data = self
            .call(
                "nameserver.clone",
                json!({ "sourceDomain": source.as_str(), "targetDomain": target.as_str() }),
            )
            .await?;
        data.get("roId")
            .and_then(Value::as_i64)
            .ok_or(Error::MissingField {
                method: "nameserver.clone",
                field: "resData.roId",
            })
    }

    /// Exports a zone as a zone file (`nameserver.export`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let zip = client
    ///     .export_zone(&DomainName::parse("example.com")?, true)
    ///     .await?;
    /// println!("{}", zip.text);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn export_zone(&self, domain: &DomainName, zonefile: bool) -> Result<ZoneExport> {
        let data = self
            .call(
                "nameserver.export",
                json!({ "domain": domain.as_str(), "zonefile": zonefile }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Exports the zone list as a file listing (`nameserver.exportlist`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DocumentFormat, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let page = client.export_zone_list(DocumentFormat::Csv, "*", 1, 20).await?;
    /// println!("{} zones", page.zones.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the page limit is zero, plus the usual
    /// transport and API errors.
    pub async fn export_zone_list(
        &self,
        format: DocumentFormat,
        filter: &str,
        page: u32,
        limit: u32,
    ) -> Result<ZoneListPage> {
        if limit == 0 {
            return Err(Error::validation("pagelimit", "must be at least 1"));
        }
        let data = self
            .call(
                "nameserver.exportlist",
                json!({
                    "format": format,
                    "domain": filter,
                    "wide": 1,
                    "page": page.max(1),
                    "pagelimit": limit,
                }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Exports records as CSV (`nameserver.exportrecords`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DocumentFormat, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let csv = client.export_records(DocumentFormat::Csv, "*", 1, 100).await?;
    /// println!("{}", csv.data);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the filter is empty, plus the usual transport
    /// and API errors.
    pub async fn export_records(
        &self,
        format: DocumentFormat,
        name_filter: &str,
        page: u32,
        limit: u32,
    ) -> Result<RecordExport> {
        let name = name_filter.trim();
        if name.is_empty() {
            return Err(Error::validation("name", "must not be empty (use `*`)"));
        }
        let data = self
            .call(
                "nameserver.exportrecords",
                json!({
                    "format": format,
                    "name": name,
                    "page": page,
                    "limit": limit,
                }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Reads a zone and fails when it is not a `MASTER` zone.
    ///
    /// A convenience for the tenant-domain flow: creating records in a `SLAVE`
    /// zone silently does nothing useful (the master overwrites them on the next
    /// transfer), so callers often want this check before writing.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let zone = client.require_master_zone(&DomainName::parse("example.com")?).await?;
    /// println!("{} records", zone.records.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `nameserver.info` reports a non-`MASTER`
    /// zone, plus the usual transport and API errors.
    pub async fn require_master_zone(&self, domain: &DomainName) -> Result<ZoneInfo> {
        let zone = self.zone_info(domain).await?;
        if zone.is_master() {
            Ok(zone)
        } else {
            Err(Error::validation(
                "zone.type",
                format!(
                    "{} is a {} zone; its records are managed by the master",
                    domain,
                    zone.zone_type.as_deref().unwrap_or("non-MASTER")
                ),
            ))
        }
    }

    /// Reads the zone list filtered by a domain pattern (`nameserver.list`).
    ///
    /// For more than one page use
    /// [`InwxClient::list_all_zones`](crate::InwxClient::list_all_zones) with
    /// [`ZoneListing::with_filter`](crate::ZoneListing::with_filter), which
    /// sends the same parameters and walks the result.
    ///
    /// `nameserver.list` accepts a `domain` filter with `*` wildcards; the plain
    /// [`InwxClient::list_zones`](crate::InwxClient::list_zones) does not expose
    /// it.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for zone in client.find_zones("tenant-*").await?.zones {
    ///     println!("{}", zone.domain);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the filter is empty, plus the usual transport
    /// and API errors.
    pub async fn find_zones(&self, filter: &str) -> Result<ZoneListPage> {
        let filter = filter.trim();
        if filter.is_empty() {
            return Err(Error::validation("domain", "must not be empty (use `*`)"));
        }
        let data = self
            .call(
                "nameserver.list",
                json!({ "domain": filter, "wide": 1, "page": 1, "pagelimit": 100 }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn zone(name: &str) -> DomainName {
        DomainName::parse(name).unwrap()
    }

    #[test]
    fn master_rejects_a_master_ip() {
        let create = ZoneCreate::master(zone("example.com"))
            .unwrap()
            .with_master_ip("198.51.100.7".parse().unwrap());
        assert!(create.params().is_err());
    }

    #[test]
    fn slave_without_a_master_ip_is_rejected() {
        let create = ZoneCreate::new(zone("example.com"), ZoneType::Slave).unwrap();
        assert!(create.params().is_err());
    }

    #[test]
    fn duplicate_nameservers_are_rejected() {
        let ns = Hostname::parse("ns1.example.net").unwrap();
        let duplicate = [ns.clone(), ns];
        assert!(ZoneCreate::master(zone("example.com"))
            .unwrap()
            .with_nameservers(&duplicate)
            .is_err());
        assert!(ZoneUpdate::new(zone("example.com"))
            .with_nameservers(&duplicate)
            .is_err());
    }

    #[test]
    fn frame_metadata_needs_a_frame_redirect() {
        let header = ZoneCreate::master(zone("example.com"))
            .unwrap()
            .with_web("https://example.net")
            .unwrap()
            .with_redirect_type(UrlRedirectType::Header301)
            .unwrap();
        assert!(header.with_frame_title("no").is_err());

        let no_type = ZoneCreate::master(zone("example.com"))
            .unwrap()
            .with_frame_title("no");
        assert!(no_type.is_err());
    }

    #[test]
    fn unknown_zone_types_cannot_be_created() {
        assert!(ZoneCreate::new(zone("example.com"), ZoneType::Other("PRIMARY".into())).is_err());
    }
}
