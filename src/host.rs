//! Host objects (`host.*`): the child name servers (glue records) of a domain.
//!
//! A host is `ns1.example.com` plus the addresses a registry should hold for it.
//! Six methods: check, create, delete, info, list, update. Two rules the API
//! only enforces at the registry are checked here instead: a host name belongs
//! inside its own domain, and a host carries at most
//! [`MAX_HOST_ADDRESSES`] addresses.
//!
//! ```
//! use inwx_client::{DomainName, HostCreate, Hostname};
//!
//! let create = HostCreate::new(
//!     DomainName::parse("example.com")?,
//!     Hostname::parse("ns1.example.com")?,
//!     &[inwx_client::parse_ip("198.51.100.1")?],
//! )?;
//!
//! let params = create.params()?;
//! assert_eq!(params["domainName"], "example.com");
//! assert_eq!(params["name"], "ns1.example.com");
//! assert_eq!(params["ip"][0], "198.51.100.1");
//! # Ok::<(), inwx_client::Error>(())
//! ```

use std::net::IpAddr;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{
    de, parse_rows, validate_id, validate_page_limit, validate_token, DomainName, Hostname,
    MAX_DOMAIN_LEN,
};

/// Largest number of addresses a host (glue record) can carry.
///
/// The registry host protocol reserves thirteen address slots for a child name
/// server, so a fourteenth address is refused here instead of being truncated by
/// the registry.
///
/// ```
/// use inwx_client::{DomainName, HostCreate, Hostname, MAX_HOST_ADDRESSES};
///
/// let domain = DomainName::parse("example.com")?;
/// let name = Hostname::parse("ns1")?;
/// let addresses: Vec<_> = (0..MAX_HOST_ADDRESSES)
///     .map(|index| inwx_client::parse_ip(&format!("198.51.100.{}", index + 1)).unwrap())
///     .collect();
///
/// assert!(HostCreate::new(domain.clone(), name.clone(), &addresses).is_ok());
/// let one_too_many =
///     [addresses.as_slice(), &[inwx_client::parse_ip("2001:db8::1").unwrap()]].concat();
/// assert!(HostCreate::new(domain, name, &one_too_many).is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
pub const MAX_HOST_ADDRESSES: usize = 13;

/// One host object (`host.info`, `host.list`).
///
/// ```
/// use inwx_client::HostRecord;
///
/// let record: HostRecord = serde_json::from_str(
///     r#"{"hostId":3001,"name":"ns1.example.com","domainName":"example.com",
///         "ip":["198.51.100.1","2001:db8::1"],"status":"ACTIVE"}"#,
/// )?;
/// assert_eq!(record.id, Some(3001));
/// assert_eq!(record.addresses.len(), 2);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct HostRecord {
    /// Host id, used by `delete`, `info` and `update`.
    #[serde(
        default,
        rename = "hostId",
        alias = "id",
        deserialize_with = "de::opt_i64"
    )]
    pub id: Option<i64>,
    /// Host name, as stored.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// Domain the host belongs to.
    #[serde(
        default,
        rename = "domainName",
        alias = "domain",
        deserialize_with = "de::opt_string"
    )]
    pub domain: Option<String>,
    /// Addresses registered for the host.
    #[serde(
        default,
        rename = "ip",
        alias = "addresses",
        deserialize_with = "de::vec_string"
    )]
    pub addresses: Vec<String>,
    /// State of the host, carried verbatim.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
    /// Creation date, as text.
    #[serde(
        default,
        rename = "createdAt",
        alias = "created_at",
        deserialize_with = "de::opt_string"
    )]
    pub created_at: Option<String>,
}

/// The `host.check` request.
///
/// ```
/// use inwx_client::{DomainName, HostCheck, Hostname};
///
/// let check = HostCheck::new(
///     DomainName::parse("example.com")?,
///     Hostname::parse("ns1.example.com")?,
/// )?;
/// assert_eq!(check.params()?["name"], "ns1.example.com");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCheck {
    domain: DomainName,
    name: Hostname,
}

impl HostCheck {
    /// Checks `name` inside `domain`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when a fully qualified name does not belong to
    /// `domain`.
    ///
    /// ```
    /// use inwx_client::{DomainName, HostCheck, Hostname};
    ///
    /// assert!(HostCheck::new(DomainName::parse("example.com")?, Hostname::parse("ns1")?).is_ok());
    /// assert!(HostCheck::new(
    ///     DomainName::parse("example.com")?,
    ///     Hostname::parse("ns1.example.org")?,
    /// ).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new(domain: DomainName, name: Hostname) -> Result<Self> {
        check_host_name(&domain, &name)?;
        Ok(Self { domain, name })
    }

    /// The `host.check` parameters.
    ///
    /// # Errors
    ///
    /// Never fails today: every value is validated when it is set, so the
    /// parameters are always sendable. The `Result` keeps the shape of the
    /// builders that can refuse a value.
    ///
    /// ```
    /// use inwx_client::{DomainName, HostCheck, Hostname};
    ///
    /// let params = HostCheck::new(DomainName::parse("example.com")?, Hostname::parse("ns1")?)?
    ///     .params()?;
    /// assert_eq!(params["domainName"], "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut params = Map::new();
        params.insert("domainName".to_owned(), json!(self.domain.as_str()));
        params.insert("name".to_owned(), json!(self.name.as_str()));
        Ok(Value::Object(params))
    }
}

/// Whether a host could be created (`host.check`).
///
/// ```
/// use inwx_client::HostCheckResult;
///
/// let result: HostCheckResult =
///     serde_json::from_str(r#"{"available":0,"reason":"host already exists"}"#)?;
/// assert!(!result.is_available());
/// assert_eq!(result.reason.as_deref(), Some("host already exists"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct HostCheckResult {
    /// Whether the host is free.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub available: Option<bool>,
    /// Explanation, when the API sends one.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub reason: Option<String>,
}

impl HostCheckResult {
    /// Whether the host can be created; unknown counts as not possible.
    ///
    /// ```
    /// use inwx_client::HostCheckResult;
    ///
    /// let free: HostCheckResult = serde_json::from_str(r#"{"available":"1"}"#)?;
    /// assert!(free.is_available());
    /// assert!(!HostCheckResult::default().is_available());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.available.unwrap_or(false)
    }
}

/// The `host.create` request.
///
/// ```
/// use inwx_client::{DomainName, HostCreate, Hostname};
///
/// let create = HostCreate::new(
///     DomainName::parse("example.com")?,
///     Hostname::parse("ns2")?,
///     &[inwx_client::parse_ip("198.51.100.2")?],
/// )?;
/// assert_eq!(create.params()?["name"], "ns2");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCreate {
    domain: DomainName,
    name: Hostname,
    addresses: Vec<IpAddr>,
    testing: bool,
}

impl HostCreate {
    /// Creates `name` inside `domain` with `addresses`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name does not belong to the domain, when
    /// the address list is empty, holds more than [`MAX_HOST_ADDRESSES`]
    /// entries or contains a duplicate.
    ///
    /// ```
    /// use inwx_client::{DomainName, HostCreate, Hostname};
    ///
    /// let domain = DomainName::parse("example.com")?;
    /// let name = Hostname::parse("ns1")?;
    /// let one = [inwx_client::parse_ip("198.51.100.1")?];
    ///
    /// assert!(HostCreate::new(domain.clone(), name.clone(), &[]).is_err());
    /// assert!(HostCreate::new(domain.clone(), name.clone(), &one).is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new(domain: DomainName, name: Hostname, addresses: &[IpAddr]) -> Result<Self> {
        check_host_name(&domain, &name)?;
        check_addresses(addresses)?;
        Ok(Self {
            domain,
            name,
            addresses: addresses.to_vec(),
            testing: false,
        })
    }

    /// Marks the call as a dry run (`testing`).
    ///
    /// ```
    /// use inwx_client::{DomainName, HostCreate, Hostname};
    ///
    /// let create = HostCreate::new(
    ///     DomainName::parse("example.com")?,
    ///     Hostname::parse("ns1")?,
    ///     &[inwx_client::parse_ip("198.51.100.1")?],
    /// )
    /// .unwrap()
    /// .with_testing(true);
    /// assert_eq!(create.params()?["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_testing(mut self, testing: bool) -> Self {
        self.testing = testing;
        self
    }

    /// The `host.create` parameters.
    ///
    /// # Errors
    ///
    /// Never fails today: every value is validated when it is set, so the
    /// parameters are always sendable. The `Result` keeps the shape of the
    /// builders that can refuse a value.
    ///
    /// ```
    /// use inwx_client::{DomainName, HostCreate, Hostname};
    ///
    /// let params = HostCreate::new(
    ///     DomainName::parse("example.com")?,
    ///     Hostname::parse("ns1")?,
    ///     &[inwx_client::parse_ip("198.51.100.1")?],
    /// )?
    /// .params()?;
    /// assert_eq!(params["ip"].as_array().map(Vec::len), Some(1));
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut params = Map::new();
        params.insert("domainName".to_owned(), json!(self.domain.as_str()));
        params.insert("name".to_owned(), json!(self.name.as_str()));
        params.insert(
            "ip".to_owned(),
            Value::Array(
                self.addresses
                    .iter()
                    .map(|address| json!(address.to_string()))
                    .collect(),
            ),
        );
        if self.testing {
            params.insert("testing".to_owned(), json!(true));
        }
        Ok(Value::Object(params))
    }
}

/// The `host.update` request: the addresses and/or the name of an existing host.
///
/// ```
/// use inwx_client::HostUpdate;
///
/// let update = HostUpdate::new(3001)?
///     .with_addresses(&[inwx_client::parse_ip("198.51.100.9")?])?;
/// let params = update.params()?;
/// assert_eq!(params["hostId"], 3001);
/// assert_eq!(params["ip"][0], "198.51.100.9");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostUpdate {
    host_id: i64,
    name: Option<Hostname>,
    addresses: Option<Vec<IpAddr>>,
    testing: bool,
}

impl HostUpdate {
    /// Updates the host with `host_id`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::HostUpdate;
    /// assert!(HostUpdate::new(1).is_ok());
    /// assert!(HostUpdate::new(0).is_err());
    /// ```
    pub fn new(host_id: i64) -> Result<Self> {
        Ok(Self {
            host_id: validate_id("host.id", host_id)?,
            name: None,
            addresses: None,
            testing: false,
        })
    }

    /// Renames the host.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when the name is empty or too long.
    ///
    /// ```
    /// use inwx_client::{HostUpdate, Hostname};
    ///
    /// let update = HostUpdate::new(1)?.with_name(Hostname::parse("ns3")?)?;
    /// assert_eq!(update.params()?["name"], "ns3");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_name(mut self, name: Hostname) -> Result<Self> {
        validate_token("host.name", name.as_str())?;
        self.name = Some(name);
        Ok(self)
    }

    /// Replaces the addresses.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty list, more than
    /// [`MAX_HOST_ADDRESSES`] entries or a duplicate.
    ///
    /// ```
    /// use inwx_client::HostUpdate;
    ///
    /// let update = HostUpdate::new(1)?
    ///     .with_addresses(&[inwx_client::parse_ip("198.51.100.1")?])?;
    /// assert!(update.params().is_ok());
    /// assert!(HostUpdate::new(1)?.with_addresses(&[]).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_addresses(mut self, addresses: &[IpAddr]) -> Result<Self> {
        check_addresses(addresses)?;
        self.addresses = Some(addresses.to_vec());
        Ok(self)
    }

    /// Marks the call as a dry run (`testing`).
    ///
    /// ```
    /// use inwx_client::HostUpdate;
    ///
    /// let update = HostUpdate::new(1).unwrap().with_testing(true);
    /// assert!(update.params().is_err()); // testing alone is not a change
    /// ```
    #[must_use]
    pub fn with_testing(mut self, testing: bool) -> Self {
        self.testing = testing;
        self
    }

    /// The `host.update` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when nothing would change.
    ///
    /// ```
    /// use inwx_client::HostUpdate;
    ///
    /// assert!(HostUpdate::new(1)?.params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        if self.name.is_none() && self.addresses.is_none() {
            return Err(Error::validation(
                "host.update",
                "needs a new name or new addresses",
            ));
        }
        let mut params = Map::new();
        params.insert("hostId".to_owned(), json!(self.host_id));
        if let Some(name) = &self.name {
            params.insert("name".to_owned(), json!(name.as_str()));
        }
        if let Some(addresses) = &self.addresses {
            params.insert(
                "ip".to_owned(),
                Value::Array(
                    addresses
                        .iter()
                        .map(|address| json!(address.to_string()))
                        .collect(),
                ),
            );
        }
        if self.testing {
            params.insert("testing".to_owned(), json!(true));
        }
        Ok(Value::Object(params))
    }
}

/// A search + paging for `host.list`.
///
/// ```
/// use inwx_client::{DomainName, HostQuery};
///
/// let query = HostQuery::new().with_domain(DomainName::parse("example.com")?)
///     .with_page(1, 20)?;
/// let params = query.params()?;
/// assert_eq!(params["domainName"], "example.com");
/// assert_eq!(params["pagelimit"], 20);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostQuery {
    domain: Option<DomainName>,
    name: Option<String>,
    page: Option<u32>,
    limit: Option<u32>,
}

impl HostQuery {
    /// An unfiltered query.
    ///
    /// ```
    /// use inwx_client::HostQuery;
    /// assert!(HostQuery::new().params().unwrap().is_object());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restricts the list to one domain.
    ///
    /// ```
    /// use inwx_client::{DomainName, HostQuery};
    ///
    /// let query = HostQuery::new().with_domain(DomainName::parse("example.com")?);
    /// assert_eq!(query.params()?["domainName"], "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_domain(mut self, domain: DomainName) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Filters by host name.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name is empty or too long.
    ///
    /// ```
    /// use inwx_client::HostQuery;
    ///
    /// assert_eq!(HostQuery::new().with_name("ns1")?.params()?["name"], "ns1");
    /// assert!(HostQuery::new().with_name(" ").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_name(mut self, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_token("host.name", &name)?;
        self.name = Some(name.trim().to_owned());
        Ok(self)
    }

    /// Sets the page (1-based) and the page size.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the page size is zero.
    ///
    /// ```
    /// use inwx_client::HostQuery;
    ///
    /// assert_eq!(HostQuery::new().with_page(1, 1)?.params()?["pagelimit"], 1);
    /// assert!(HostQuery::new().with_page(1, 0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_page(mut self, page: u32, limit: u32) -> Result<Self> {
        self.limit = Some(validate_page_limit(limit)?);
        self.page = Some(page.max(1));
        Ok(self)
    }

    /// The `host.list` parameters.
    ///
    /// # Errors
    ///
    /// Never fails today: every value is validated when it is set, so the
    /// parameters are always sendable. The `Result` keeps the shape of the
    /// builders that can refuse a value.
    ///
    /// ```
    /// use inwx_client::HostQuery;
    /// assert!(HostQuery::new().params().unwrap().is_object());
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut params = Map::new();
        if let Some(domain) = &self.domain {
            params.insert("domainName".to_owned(), json!(domain.as_str()));
        }
        if let Some(name) = &self.name {
            params.insert("name".to_owned(), json!(name));
        }
        params.insert("page".to_owned(), json!(self.page.unwrap_or(1)));
        params.insert("pagelimit".to_owned(), json!(self.limit.unwrap_or(50)));
        Ok(Value::Object(params))
    }
}

/// A host name must be a label of the domain it is created under.
///
/// A single label (`ns1`) is the usual spelling and becomes `ns1.example.com`;
/// a fully qualified name is accepted only when it really ends in the domain —
/// `ns1.example.org` under `example.com` is a lame delegation the registry would
/// refuse after the round trip.
fn check_host_name(domain: &DomainName, name: &Hostname) -> Result<()> {
    let name = name.as_str();
    let domain = domain.as_str();
    if name.contains('.') {
        let suffix = format!(".{domain}");
        if !name.ends_with(&suffix) {
            return Err(Error::validation(
                "host.name",
                format!("{name:?} is not inside {domain:?}"),
            ));
        }
    } else if name.len() + 1 + domain.len() > MAX_DOMAIN_LEN {
        return Err(Error::validation(
            "host.name",
            format!("{name:?} below {domain:?} is longer than {MAX_DOMAIN_LEN} characters"),
        ));
    }
    Ok(())
}

/// A host needs at least one address, at most [`MAX_HOST_ADDRESSES`], and no
/// address twice.
fn check_addresses(addresses: &[IpAddr]) -> Result<()> {
    if addresses.is_empty() {
        return Err(Error::validation(
            "host.ip",
            "a host needs at least one address",
        ));
    }
    if addresses.len() > MAX_HOST_ADDRESSES {
        return Err(Error::validation(
            "host.ip",
            format!(
                "a host carries at most {MAX_HOST_ADDRESSES} addresses, got {}",
                addresses.len()
            ),
        ));
    }
    let mut seen: Vec<IpAddr> = Vec::with_capacity(addresses.len());
    for address in addresses {
        if seen.contains(address) {
            return Err(Error::validation(
                "host.ip",
                format!("{address} is listed twice"),
            ));
        }
        seen.push(*address);
    }
    Ok(())
}

impl<T: Transport> InwxClient<T> {
    /// Asks whether a host can be created (`host.check`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, HostCheck, Hostname, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let check = HostCheck::new(
    ///     DomainName::parse("example.com")?,
    ///     Hostname::parse("ns1.example.com")?,
    /// )?;
    /// println!("{}", client.check_host(&check).await?.is_available());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a name outside the domain, plus the usual
    /// transport and API errors.
    pub async fn check_host(&self, check: &HostCheck) -> Result<HostCheckResult> {
        let params = check.params()?;
        let data = self.call("host.check", params).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Creates a host (`host.create`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, HostCreate, Hostname, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let create = HostCreate::new(
    ///     DomainName::parse("example.com")?,
    ///     Hostname::parse("ns1")?,
    ///     &[inwx_client::parse_ip("198.51.100.1")?],
    /// )?;
    /// let host = client.create_host(&create).await?;
    /// println!("{:?}", host.id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a bad name or address list, plus the usual
    /// transport and API errors.
    pub async fn create_host(&self, create: &HostCreate) -> Result<HostRecord> {
        let params = create.params()?;
        let data = self.call("host.create", params).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Deletes a host (`host.delete`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.delete_host(3001).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn delete_host(&self, host_id: i64) -> Result<()> {
        validate_id("host.id", host_id)?;
        self.call("host.delete", json!({ "hostId": host_id }))
            .await?;
        Ok(())
    }

    /// Reads one host (`host.info`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let host = client.host_info(3001).await?;
    /// println!("{:?} {:?}", host.name, host.addresses);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors — `2303` when the host does not exist.
    pub async fn host_info(&self, host_id: i64) -> Result<HostRecord> {
        validate_id("host.id", host_id)?;
        let data = self.call("host.info", json!({ "hostId": host_id })).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Lists hosts (`host.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, HostQuery, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let query = HostQuery::new().with_domain(DomainName::parse("example.com")?);
    /// for host in client.list_hosts(&query).await? {
    ///     println!("{:?} {:?}", host.name, host.addresses);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the query carries a bad filter or page size,
    /// plus the usual transport and API errors.
    pub async fn list_hosts(&self, query: &HostQuery) -> Result<Vec<HostRecord>> {
        let params = query.params()?;
        let data = self.call("host.list", params).await?;
        Ok(parse_rows(&data, "host"))
    }

    /// Changes a host (`host.update`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{HostUpdate, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let update = HostUpdate::new(3001)?
    ///     .with_addresses(&[inwx_client::parse_ip("198.51.100.9")?])?;
    /// client.update_host(&update).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, a bad address list or an
    /// update with no field, plus the usual transport and API errors.
    pub async fn update_host(&self, update: &HostUpdate) -> Result<()> {
        let params = update.params()?;
        self.call("host.update", params).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(name: &str) -> DomainName {
        DomainName::parse(name).unwrap()
    }

    fn host(name: &str) -> Hostname {
        Hostname::parse(name).unwrap()
    }

    fn addresses(count: usize) -> Vec<IpAddr> {
        (1..=count)
            .map(|index| {
                format!("198.51.100.{index}")
                    .parse()
                    .unwrap_or_else(|_| panic!("test address {index}"))
            })
            .collect()
    }

    #[test]
    fn thirteen_addresses_are_accepted_and_fourteen_are_not() {
        assert!(HostCreate::new(domain("example.com"), host("ns1"), &addresses(13)).is_ok());
        assert!(HostCreate::new(domain("example.com"), host("ns1"), &addresses(14)).is_err());
        assert!(HostCreate::new(domain("example.com"), host("ns1"), &addresses(0)).is_err());
    }

    #[test]
    fn an_address_may_not_appear_twice() {
        let one = addresses(1);
        let both = [one[0], one[0]];
        assert!(HostCreate::new(domain("example.com"), host("ns1"), &both).is_err());
    }

    #[test]
    fn a_host_name_belongs_to_its_domain() {
        assert!(HostCreate::new(domain("example.com"), host("ns1"), &addresses(1)).is_ok());
        assert!(HostCreate::new(
            domain("example.com"),
            host("ns1.example.com"),
            &addresses(1)
        )
        .is_ok());
        assert!(HostCreate::new(
            domain("example.com"),
            host("ns1.example.org"),
            &addresses(1)
        )
        .is_err());
        assert!(HostCheck::new(domain("example.com"), host("sub.example.com")).is_ok());
        assert!(HostCheck::new(domain("example.com"), host("sub.example.org")).is_err());
    }

    #[test]
    fn a_label_of_63_bytes_still_fits_and_64_does_not() {
        let ok = "a".repeat(63);
        assert!(HostCreate::new(domain("example.com"), host(&ok), &addresses(1)).is_ok());
        assert!(Hostname::parse(&"a".repeat(64)).is_err());
    }

    #[test]
    fn ids_must_be_positive() {
        assert!(HostUpdate::new(1).is_ok());
        assert!(HostUpdate::new(0).is_err());
        assert!(HostUpdate::new(-4).is_err());
    }

    #[test]
    fn an_update_needs_a_change() {
        assert!(HostUpdate::new(1).unwrap().params().is_err());
        assert!(HostUpdate::new(1)
            .unwrap()
            .with_addresses(&addresses(1))
            .unwrap()
            .params()
            .is_ok());
    }

    #[test]
    fn a_page_limit_of_one_is_accepted_and_zero_is_not() {
        assert!(HostQuery::new().with_page(1, 1).is_ok());
        assert!(HostQuery::new().with_page(1, 0).is_err());
    }

    #[test]
    fn hosts_are_parsed_permissively() {
        let record: HostRecord =
            serde_json::from_str(r#"{"hostId":"3","ip":"198.51.100.1"}"#).unwrap();
        assert_eq!(record.id, Some(3));
        assert_eq!(record.addresses, ["198.51.100.1"]);

        let single: Vec<HostRecord> = parse_rows(&json!({"host": {"id": 1}}), "host");
        assert_eq!(single.len(), 1);
        assert_eq!(
            parse_rows::<HostRecord>(&json!({"host": null}), "host").len(),
            0
        );
    }
}
