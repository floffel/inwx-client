//! Nameserver sets (`nameserverset.*`): reusable sets of nameservers that can
//! be assigned to domains.
//!
//! A set is a named group of primary, secondary or external nameservers with an
//! optional hostmaster address and web/mail forwarding. The API validates the
//! set's type, and this crate validates the parts it can check without a round
//! trip: a set needs at least one nameserver, no duplicates, a usable
//! hostmaster address, and a name that fits `token0255`.
//!
//! ```
//! use inwx_client::{Hostname, NameserverSetCreate, NameserverSetType};
//!
//! let request = NameserverSetCreate::new(
//!     NameserverSetType::Primary,
//!     &[
//!         Hostname::parse("ns1.example.net")?,
//!         Hostname::parse("ns2.example.net")?,
//!     ],
//! )?
//! .with_name("tenant-default")?
//! .with_hostmaster(inwx_client::Email::parse("hostmaster@example.net")?)?;
//!
//! assert_eq!(request.params()["type"], "PRIMARY");
//! assert_eq!(request.params()["ns"][1], "ns2.example.net");
//! # Ok::<(), inwx_client::Error>(())
//! ```

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, validate_token, Email, Hostname};

/// The kind of nameserver set (`nsSetType`: `PRIMARY`, `SECONDARY`, `EXTERNAL`).
///
/// ```
/// use inwx_client::NameserverSetType;
///
/// assert_eq!(NameserverSetType::Primary.to_string(), "PRIMARY");
/// assert_eq!("secondary".parse::<NameserverSetType>()?, NameserverSetType::Secondary);
/// assert_eq!(
///     NameserverSetType::parse("HIDDEN")?,
///     NameserverSetType::Other("HIDDEN".into())
/// );
/// assert!(NameserverSetType::parse("").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NameserverSetType {
    /// Zone is hosted by INWX.
    Primary,
    /// Zone is transferred from a master.
    Secondary,
    /// External nameservers.
    External,
    /// A type this crate does not know; carried verbatim, upper-cased.
    Other(String),
}

impl NameserverSetType {
    /// Parses an `nsSetType`, upper-casing it.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the input is empty.
    ///
    /// ```
    /// use inwx_client::NameserverSetType;
    /// assert_eq!(NameserverSetType::parse("EXTERNAL")?, NameserverSetType::External);
    /// assert!(NameserverSetType::parse(" ").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn parse(input: &str) -> Result<Self> {
        let upper = input.trim().to_ascii_uppercase();
        if upper.is_empty() {
            return Err(Error::validation("nameserverset.type", "must not be empty"));
        }
        Ok(match upper.as_str() {
            "PRIMARY" => Self::Primary,
            "SECONDARY" => Self::Secondary,
            "EXTERNAL" => Self::External,
            _ => Self::Other(upper),
        })
    }

    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::NameserverSetType;
    /// assert_eq!(NameserverSetType::Secondary.as_str(), "SECONDARY");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Primary => "PRIMARY",
            Self::Secondary => "SECONDARY",
            Self::External => "EXTERNAL",
            Self::Other(raw) => raw,
        }
    }
}

impl fmt::Display for NameserverSetType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for NameserverSetType {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl Serialize for NameserverSetType {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for NameserverSetType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// A nameserver set as returned by `nameserverset.info` and `nameserverset.list`.
///
/// ```
/// use inwx_client::{NameserverSet, NameserverSetType};
///
/// let set: NameserverSet = serde_json::from_str(
///     r#"{"id":9,"name":"tenant-default","ns":["ns1.example.net","ns2.example.net"],
///         "type":"PRIMARY","hostmaster":"hostmaster@example.net","visible":true}"#,
/// )?;
/// assert_eq!(set.nameservers.len(), 2);
/// assert_eq!(set.set_type, NameserverSetType::Primary);
/// assert_eq!(set.visible, Some(true));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct NameserverSet {
    /// Set id.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Repository object id.
    #[serde(default, rename = "roId", deserialize_with = "de::opt_i64")]
    pub ro_id: Option<i64>,
    /// Human readable name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// The nameservers in the set.
    #[serde(default, rename = "ns", deserialize_with = "de::vec_string")]
    pub nameservers: Vec<String>,
    /// Set type.
    #[serde(default = "default_set_type", rename = "type")]
    pub set_type: NameserverSetType,
    /// Hostmaster address.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub hostmaster: Option<String>,
    /// Whether the set is visible in the UI.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub visible: Option<bool>,
    /// Priority.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub prio: Option<i64>,
    /// Web forwarding target.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub web: Option<String>,
    /// Mail forwarding target.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub mail: Option<String>,
    /// Master address of a secondary set.
    #[serde(default, rename = "masterIp", deserialize_with = "de::opt_string")]
    pub master_ip: Option<String>,
    /// Whether the set is read-only.
    #[serde(default, rename = "readOnly", deserialize_with = "de::opt_bool")]
    pub read_only: Option<bool>,
}

/// A missing `type` in a list answer means the set is a primary one, which is
/// the only type the UI creates by default.
fn default_set_type() -> NameserverSetType {
    NameserverSetType::Primary
}

/// The `nameserverset.create` request.
///
/// ```
/// use inwx_client::{Hostname, NameserverSetCreate, NameserverSetType};
///
/// let request = NameserverSetCreate::new(
///     NameserverSetType::Primary,
///     &[Hostname::parse("ns1.example.net")?],
/// )?;
/// assert_eq!(request.params()["type"], "PRIMARY");
/// assert_eq!(request.params()["visible"], true);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameserverSetCreate {
    set_type: NameserverSetType,
    nameservers: Vec<Hostname>,
    name: Option<String>,
    hostmaster: Option<Email>,
    visible: bool,
    prio: Option<i16>,
    web: Option<String>,
    mail: Option<String>,
    master_ip: Option<IpAddr>,
    testing: bool,
}

impl NameserverSetCreate {
    /// A set of `set_type` with `nameservers`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or duplicate nameserver list, or an
    /// undocumented type (an unknown type cannot be created on purpose).
    ///
    /// ```
    /// use inwx_client::{Hostname, NameserverSetCreate, NameserverSetType};
    ///
    /// assert!(NameserverSetCreate::new(NameserverSetType::Primary, &[]).is_err());
    ///
    /// let ns = Hostname::parse("ns1.example.net")?;
    /// assert!(NameserverSetCreate::new(NameserverSetType::Primary, &[ns.clone(), ns]).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new(set_type: NameserverSetType, nameservers: &[Hostname]) -> Result<Self> {
        if matches!(set_type, NameserverSetType::Other(_)) {
            return Err(Error::validation(
                "nameserverset.type",
                format!(
                    "{} is not a documented set type (PRIMARY, SECONDARY, EXTERNAL)",
                    set_type.as_str()
                ),
            ));
        }
        validate_nameservers(nameservers)?;
        Ok(Self {
            set_type,
            nameservers: nameservers.to_vec(),
            name: None,
            hostmaster: None,
            visible: true,
            prio: None,
            web: None,
            mail: None,
            master_ip: None,
            testing: false,
        })
    }

    /// Sets the set's name (`token0255`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name is unusable.
    ///
    /// ```
    /// use inwx_client::{Hostname, NameserverSetCreate, NameserverSetType};
    ///
    /// let request = NameserverSetCreate::new(
    ///     NameserverSetType::Primary,
    ///     &[Hostname::parse("ns1.example.net")?],
    /// )?
    /// .with_name("tenant-default")?;
    /// assert_eq!(request.params()["name"], "tenant-default");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_name(mut self, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_token("nameserverset.name", &name)?;
        self.name = Some(name.trim().to_owned());
        Ok(self)
    }

    /// Sets the hostmaster address.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`Email::parse`].
    ///
    /// ```
    /// use inwx_client::{Email, Hostname, NameserverSetCreate, NameserverSetType};
    ///
    /// let request = NameserverSetCreate::new(
    ///     NameserverSetType::Primary,
    ///     &[Hostname::parse("ns1.example.net")?],
    /// )?
    /// .with_hostmaster(Email::parse("hostmaster@example.net")?)?;
    /// assert_eq!(request.params()["hostmaster"], "hostmaster@example.net");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_hostmaster(mut self, hostmaster: Email) -> Result<Self> {
        validate_token("nameserverset.hostmaster", hostmaster.as_str())?;
        self.hostmaster = Some(hostmaster);
        Ok(self)
    }

    /// Sets whether the set is visible in the UI (`visible`, default `true`).
    ///
    /// ```
    /// use inwx_client::{Hostname, NameserverSetCreate, NameserverSetType};
    ///
    /// let request = NameserverSetCreate::new(
    ///     NameserverSetType::Primary,
    ///     &[Hostname::parse("ns1.example.net")?],
    /// )?
    /// .with_visibility(false);
    /// assert_eq!(request.params()["visible"], false);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_visibility(mut self, visible: bool) -> Self {
        self.visible = visible;
        self
    }

    /// Sets the set's priority (`prio`).
    ///
    /// ```
    /// use inwx_client::{Hostname, NameserverSetCreate, NameserverSetType};
    ///
    /// let request = NameserverSetCreate::new(
    ///     NameserverSetType::Primary,
    ///     &[Hostname::parse("ns1.example.net")?],
    /// )?
    /// .with_priority(5);
    /// assert_eq!(request.params()["prio"], 5);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_priority(mut self, prio: i16) -> Self {
        self.prio = Some(prio);
        self
    }

    /// Sets the web forwarding target (`web`, `ip_url`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is unusable.
    ///
    /// ```
    /// use inwx_client::{Hostname, NameserverSetCreate, NameserverSetType};
    ///
    /// let request = NameserverSetCreate::new(
    ///     NameserverSetType::Primary,
    ///     &[Hostname::parse("ns1.example.net")?],
    /// )?
    /// .with_web("https://example.net")?;
    /// assert_eq!(request.params()["web"], "https://example.net");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_web(mut self, web: impl Into<String>) -> Result<Self> {
        let web = web.into();
        validate_token("nameserverset.web", &web)?;
        self.web = Some(web.trim().to_owned());
        Ok(self)
    }

    /// Sets the mail forwarding target (`mail`, `text0255`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is unusable.
    ///
    /// ```
    /// use inwx_client::{Hostname, NameserverSetCreate, NameserverSetType};
    ///
    /// let request = NameserverSetCreate::new(
    ///     NameserverSetType::Primary,
    ///     &[Hostname::parse("ns1.example.net")?],
    /// )?
    /// .with_mail("mx.example.net")?;
    /// assert_eq!(request.params()["mail"], "mx.example.net");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_mail(mut self, mail: impl Into<String>) -> Result<Self> {
        let mail = mail.into();
        validate_token("nameserverset.mail", &mail)?;
        self.mail = Some(mail.trim().to_owned());
        Ok(self)
    }

    /// Sets the master address of a secondary set (`masterIp`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the set type is not
    /// [`NameserverSetType::Secondary`]: only a secondary set has a master.
    ///
    /// ```
    /// use inwx_client::{Hostname, NameserverSetCreate, NameserverSetType};
    ///
    /// let secondary = NameserverSetCreate::new(
    ///     NameserverSetType::Secondary,
    ///     &[Hostname::parse("ns1.example.net")?],
    /// )?
    /// .with_master_ip(inwx_client::parse_ip("198.51.100.7")?)?;
    /// assert_eq!(secondary.params()["masterIp"], "198.51.100.7");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_master_ip(mut self, master_ip: IpAddr) -> Result<Self> {
        if self.set_type != NameserverSetType::Secondary {
            return Err(Error::validation(
                "nameserverset.masterIp",
                "only a SECONDARY set has a master address",
            ));
        }
        self.master_ip = Some(master_ip);
        Ok(self)
    }

    /// Runs the command in testing mode (`testing=true`).
    ///
    /// ```
    /// use inwx_client::{Hostname, NameserverSetCreate, NameserverSetType};
    ///
    /// let request = NameserverSetCreate::new(
    ///     NameserverSetType::Primary,
    ///     &[Hostname::parse("ns1.example.net")?],
    /// )?
    /// .dry_run();
    /// assert_eq!(request.params()["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.testing = true;
        self
    }

    /// The `nameserverset.create` parameters.
    ///
    /// ```
    /// use inwx_client::{Hostname, NameserverSetCreate, NameserverSetType};
    ///
    /// let params = NameserverSetCreate::new(
    ///     NameserverSetType::External,
    ///     &[Hostname::parse("ns1.example.net")?],
    /// )?
    /// .params();
    /// assert_eq!(params["ns"][0], "ns1.example.net");
    /// assert_eq!(params["type"], "EXTERNAL");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut params = Map::new();
        params.insert("type".to_owned(), json!(self.set_type));
        params.insert("ns".to_owned(), json!(self.nameservers));
        params.insert("visible".to_owned(), json!(self.visible));
        params.insert("testing".to_owned(), json!(self.testing));
        if let Some(name) = &self.name {
            params.insert("name".to_owned(), json!(name));
        }
        if let Some(hostmaster) = &self.hostmaster {
            params.insert("hostmaster".to_owned(), json!(hostmaster));
        }
        if let Some(prio) = self.prio {
            params.insert("prio".to_owned(), json!(prio));
        }
        if let Some(web) = &self.web {
            params.insert("web".to_owned(), json!(web));
        }
        if let Some(mail) = &self.mail {
            params.insert("mail".to_owned(), json!(mail));
        }
        if let Some(ip) = self.master_ip {
            params.insert("masterIp".to_owned(), json!(ip.to_string()));
        }
        Value::Object(params)
    }
}

/// The `nameserverset.update` request: only the fields that were set are sent.
///
/// ```
/// use inwx_client::{Hostname, NameserverSetUpdate};
///
/// let update = NameserverSetUpdate::new(9)?
///     .with_nameservers(&[Hostname::parse("ns1.example.net")?])?;
/// let params = update.params()?;
/// assert_eq!(params["id"], 9);
/// assert_eq!(params["ns"][0], "ns1.example.net");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameserverSetUpdate {
    id: i64,
    set_type: Option<NameserverSetType>,
    nameservers: Option<Vec<Hostname>>,
    name: Option<String>,
    hostmaster: Option<Email>,
    visible: Option<bool>,
    prio: Option<i16>,
    web: Option<String>,
    mail: Option<String>,
    master_ip: Option<IpAddr>,
    testing: bool,
}

impl NameserverSetUpdate {
    /// An empty update for set `id`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::NameserverSetUpdate;
    ///
    /// assert!(NameserverSetUpdate::new(9).is_ok());
    /// assert!(NameserverSetUpdate::new(0).is_err());
    /// assert!(NameserverSetUpdate::new(9).unwrap().params().is_err());
    /// ```
    pub fn new(id: i64) -> Result<Self> {
        if id <= 0 {
            return Err(Error::validation(
                "nameserverset.id",
                format!("must be a positive id, got {id}"),
            ));
        }
        Ok(Self {
            id,
            set_type: None,
            nameservers: None,
            name: None,
            hostmaster: None,
            visible: None,
            prio: None,
            web: None,
            mail: None,
            master_ip: None,
            testing: false,
        })
    }

    /// Sets the set type.
    ///
    /// ```
    /// use inwx_client::{NameserverSetType, NameserverSetUpdate};
    ///
    /// let update = NameserverSetUpdate::new(9)?.with_set_type(NameserverSetType::External);
    /// assert_eq!(update.params()?["type"], "EXTERNAL");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_set_type(mut self, set_type: NameserverSetType) -> Self {
        self.set_type = Some(set_type);
        self
    }

    /// Replaces the nameservers.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or duplicate list.
    ///
    /// ```
    /// use inwx_client::{Hostname, NameserverSetUpdate};
    ///
    /// let update = NameserverSetUpdate::new(9)?
    ///     .with_nameservers(&[Hostname::parse("ns1.example.net")?])?;
    /// assert_eq!(update.params()?["ns"][0], "ns1.example.net");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_nameservers(mut self, nameservers: &[Hostname]) -> Result<Self> {
        validate_nameservers(nameservers)?;
        self.nameservers = Some(nameservers.to_vec());
        Ok(self)
    }

    /// Sets the name.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name is unusable.
    ///
    /// ```
    /// use inwx_client::NameserverSetUpdate;
    ///
    /// let update = NameserverSetUpdate::new(9)?.with_name("renamed")?;
    /// assert_eq!(update.params()?["name"], "renamed");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_name(mut self, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_token("nameserverset.name", &name)?;
        self.name = Some(name.trim().to_owned());
        Ok(self)
    }

    /// Sets the hostmaster address.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`Email::parse`].
    ///
    /// ```
    /// use inwx_client::{Email, NameserverSetUpdate};
    ///
    /// let update = NameserverSetUpdate::new(9)?
    ///     .with_hostmaster(Email::parse("hostmaster@example.net")?)?;
    /// assert_eq!(update.params()?["hostmaster"], "hostmaster@example.net");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_hostmaster(mut self, hostmaster: Email) -> Result<Self> {
        self.hostmaster = Some(hostmaster);
        Ok(self)
    }

    /// Sets the visibility.
    ///
    /// ```
    /// use inwx_client::NameserverSetUpdate;
    ///
    /// let update = NameserverSetUpdate::new(9)?.with_visibility(false);
    /// assert_eq!(update.params()?["visible"], false);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_visibility(mut self, visible: bool) -> Self {
        self.visible = Some(visible);
        self
    }

    /// Sets the priority.
    ///
    /// ```
    /// use inwx_client::NameserverSetUpdate;
    ///
    /// let update = NameserverSetUpdate::new(9)?.with_priority(3);
    /// assert_eq!(update.params()?["prio"], 3);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_priority(mut self, prio: i16) -> Self {
        self.prio = Some(prio);
        self
    }

    /// Sets the web forwarding target.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is unusable.
    ///
    /// ```
    /// use inwx_client::NameserverSetUpdate;
    ///
    /// let update = NameserverSetUpdate::new(9)?.with_web("https://example.net")?;
    /// assert_eq!(update.params()?["web"], "https://example.net");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_web(mut self, web: impl Into<String>) -> Result<Self> {
        let web = web.into();
        validate_token("nameserverset.web", &web)?;
        self.web = Some(web.trim().to_owned());
        Ok(self)
    }

    /// Sets the mail forwarding target.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is unusable.
    ///
    /// ```
    /// use inwx_client::NameserverSetUpdate;
    ///
    /// let update = NameserverSetUpdate::new(9)?.with_mail("mx.example.net")?;
    /// assert_eq!(update.params()?["mail"], "mx.example.net");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_mail(mut self, mail: impl Into<String>) -> Result<Self> {
        let mail = mail.into();
        validate_token("nameserverset.mail", &mail)?;
        self.mail = Some(mail.trim().to_owned());
        Ok(self)
    }

    /// Sets the master address.
    ///
    /// ```
    /// use inwx_client::NameserverSetUpdate;
    ///
    /// let update = NameserverSetUpdate::new(9)?.with_master_ip(inwx_client::parse_ip("198.51.100.7")?);
    /// assert_eq!(update.params()?["masterIp"], "198.51.100.7");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_master_ip(mut self, master_ip: IpAddr) -> Self {
        self.master_ip = Some(master_ip);
        self
    }

    /// Runs the command in testing mode (`testing=true`).
    ///
    /// ```
    /// use inwx_client::NameserverSetUpdate;
    ///
    /// let update = NameserverSetUpdate::new(9)?.with_visibility(true).dry_run();
    /// assert_eq!(update.params()?["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.testing = true;
        self
    }

    /// Whether any change has been set.
    ///
    /// ```
    /// use inwx_client::NameserverSetUpdate;
    /// assert!(!NameserverSetUpdate::new(9)?.has_changes());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.set_type.is_some()
            || self.nameservers.is_some()
            || self.name.is_some()
            || self.hostmaster.is_some()
            || self.visible.is_some()
            || self.prio.is_some()
            || self.web.is_some()
            || self.mail.is_some()
            || self.master_ip.is_some()
    }

    /// The `nameserverset.update` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when nothing was set.
    ///
    /// ```
    /// use inwx_client::NameserverSetUpdate;
    ///
    /// let update = NameserverSetUpdate::new(9)?.with_visibility(false);
    /// assert_eq!(update.params()?["id"], 9);
    /// assert!(NameserverSetUpdate::new(9)?.params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        if !self.has_changes() {
            return Err(Error::validation(
                "nameserverset.update",
                "sets no field; add a change or skip the call",
            ));
        }
        let mut params = Map::new();
        params.insert("id".to_owned(), json!(self.id));
        if let Some(set_type) = &self.set_type {
            params.insert("type".to_owned(), json!(set_type));
        }
        if let Some(nameservers) = &self.nameservers {
            params.insert("ns".to_owned(), json!(nameservers));
        }
        if let Some(name) = &self.name {
            params.insert("name".to_owned(), json!(name));
        }
        if let Some(hostmaster) = &self.hostmaster {
            params.insert("hostmaster".to_owned(), json!(hostmaster));
        }
        if let Some(visible) = self.visible {
            params.insert("visible".to_owned(), json!(visible));
        }
        if let Some(prio) = self.prio {
            params.insert("prio".to_owned(), json!(prio));
        }
        if let Some(web) = &self.web {
            params.insert("web".to_owned(), json!(web));
        }
        if let Some(mail) = &self.mail {
            params.insert("mail".to_owned(), json!(mail));
        }
        if let Some(ip) = self.master_ip {
            params.insert("masterIp".to_owned(), json!(ip.to_string()));
        }
        if self.testing {
            params.insert("testing".to_owned(), json!(true));
        }
        Ok(Value::Object(params))
    }
}

/// Rejects an empty nameserver list or a duplicate entry.
fn validate_nameservers(nameservers: &[Hostname]) -> Result<()> {
    if nameservers.is_empty() {
        return Err(Error::validation(
            "nameserverset.ns",
            "must list at least one nameserver",
        ));
    }
    for (index, nameserver) in nameservers.iter().enumerate() {
        if nameservers[..index].contains(nameserver) {
            return Err(Error::validation(
                "nameserverset.ns",
                format!("{nameserver} is listed twice"),
            ));
        }
    }
    Ok(())
}

impl<T: Transport> InwxClient<T> {
    /// Creates a nameserver set (`nameserverset.create`) and returns its id.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{Hostname, InwxClient, NameserverSetCreate, NameserverSetType, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let request = NameserverSetCreate::new(
    ///     NameserverSetType::Primary,
    ///     &[Hostname::parse("ns1.example.net")?],
    /// )?;
    /// let id = client.create_nameserver_set(&request).await?;
    /// println!("set {id}");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::MissingField`] when the answer carries no `id`, plus the usual
    /// transport and API errors.
    pub async fn create_nameserver_set(&self, request: &NameserverSetCreate) -> Result<i64> {
        let data = self.call("nameserverset.create", request.params()).await?;
        data.get("id")
            .and_then(Value::as_i64)
            .ok_or(Error::MissingField {
                method: "nameserverset.create",
                field: "resData.id",
            })
    }

    /// Updates a nameserver set (`nameserverset.update`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, NameserverSetUpdate, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let update = NameserverSetUpdate::new(9)?.with_name("renamed")?;
    /// client.update_nameserver_set(&update).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`NameserverSetUpdate::params`], plus the
    /// usual transport and API errors.
    pub async fn update_nameserver_set(&self, request: &NameserverSetUpdate) -> Result<()> {
        self.call("nameserverset.update", request.params()?).await?;
        Ok(())
    }

    /// Deletes a nameserver set (`nameserverset.delete`).
    ///
    /// Domains that still use the set are not deleted with it; the API refuses
    /// the call while they do.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.delete_nameserver_set(9).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn delete_nameserver_set(&self, id: i64) -> Result<()> {
        if id <= 0 {
            return Err(Error::validation(
                "nameserverset.id",
                format!("must be a positive id, got {id}"),
            ));
        }
        self.call("nameserverset.delete", json!({ "id": id }))
            .await?;
        Ok(())
    }

    /// Reads one nameserver set (`nameserverset.info`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let set = client.nameserver_set_info(9).await?;
    /// println!("{}", set.nameservers.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors — `2303` when the set does not exist.
    pub async fn nameserver_set_info(&self, id: i64) -> Result<NameserverSet> {
        if id <= 0 {
            return Err(Error::validation(
                "nameserverset.id",
                format!("must be a positive id, got {id}"),
            ));
        }
        let data = self.call("nameserverset.info", json!({ "id": id })).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Lists nameserver sets (`nameserverset.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for set in client.list_nameserver_sets(true, 1, 20).await? {
    ///     println!("{:?} {}", set.id, set.nameservers.len());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the page limit is zero, plus the usual
    /// transport and API errors.
    pub async fn list_nameserver_sets(
        &self,
        wide: bool,
        page: u32,
        limit: u32,
    ) -> Result<Vec<NameserverSet>> {
        if limit == 0 {
            return Err(Error::validation("pagelimit", "must be at least 1"));
        }
        let data = self
            .call(
                "nameserverset.list",
                json!({ "wide": wide, "page": page.max(1), "pagelimit": limit }),
            )
            .await?;
        let entries = match data.get("nsset") {
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

    fn ns(name: &str) -> Hostname {
        Hostname::parse(name).unwrap()
    }

    #[test]
    fn create_requires_a_nameserver() {
        assert!(NameserverSetCreate::new(NameserverSetType::Primary, &[]).is_err());
    }

    #[test]
    fn create_rejects_unknown_types() {
        let not_documented = NameserverSetType::Other("PRIVATE".into());
        assert!(NameserverSetCreate::new(not_documented, &[ns("ns1.example.net")]).is_err());
    }

    #[test]
    fn master_ip_is_only_for_secondary_sets() {
        let primary =
            NameserverSetCreate::new(NameserverSetType::Primary, &[ns("ns1.example.net")]).unwrap();
        assert!(primary
            .with_master_ip("198.51.100.7".parse().unwrap())
            .is_err());
    }

    #[test]
    fn updates_need_a_change() {
        assert!(NameserverSetUpdate::new(9).unwrap().params().is_err());
        assert!(NameserverSetUpdate::new(9)
            .unwrap()
            .with_visibility(true)
            .params()
            .is_ok());
    }

    #[test]
    fn ids_must_be_positive() {
        assert!(NameserverSetUpdate::new(-3).is_err());
    }
}
