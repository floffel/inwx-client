//! Host objects (`host.*`): a hostname a reseller registers for a customer.
//!
//! This is the reseller/partner `host` object, not `hosting.*` (which models
//! hosting packages). Six methods: `check`, `create`, `delete`, `info`, `list`,
//! `update`.
//!
//! The object is described in the API documentation chapter 2 §2.12. Host names
//! go through [`Hostname`], so an unterminated label or an over-long name fails
//! locally instead of turning into a broken glue record.
//!
//! ```
//! use inwx_client::Host;
//!
//! let host: Host = serde_json::from_str(
//!     r#"{"id":44,"name":"ns1.example.com","customer":4711,"state":"DONE"}"#,
//! )?;
//! assert_eq!(host.id, Some(44));
//! assert_eq!(host.name.as_deref(), Some("ns1.example.com"));
//! # Ok::<(), serde_json::Error>(())
//! ```

use std::net::IpAddr;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::params::{self, ExtraFields};
use crate::transport::Transport;
use crate::types::{de, parse_ip, validate_token, CheckOutcome, Hostname};

/// Keys owned by [`HostCreate`].
const CREATE_KEYS: &[&str] = &["name", "customer", "ipAddress", "testing"];
/// Keys owned by [`HostUpdate`].
const UPDATE_KEYS: &[&str] = &["hostId", "name", "customer", "ipAddress"];

/// One host object.
///
/// ```
/// use inwx_client::Host;
///
/// let camel: Host =
///     serde_json::from_str(r#"{"id":"44","customerNo":"110069","validationDate":"2026-11-01"}"#)?;
/// let snake: Host =
///     serde_json::from_str(r#"{"id":44,"customer_no":"110069","validation_date":"2026-11-01"}"#)?;
/// assert_eq!(camel, snake);
/// assert_eq!(camel.validation_date.as_deref(), Some("2026-11-01"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Host {
    /// Host id, used by `info`, `update` and `delete`.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Host name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// Customer the host belongs to.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub customer: Option<i64>,
    /// Customer number of that customer.
    #[serde(
        default,
        rename = "customerNo",
        alias = "customer_no",
        deserialize_with = "de::opt_string"
    )]
    pub customer_no: Option<String>,
    /// IP address the host is registered with, as text.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub ip_address: Option<String>,
    /// State of the host object.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub state: Option<String>,
    /// Date the host was validated, when validation applies.
    #[serde(
        default,
        rename = "validationDate",
        alias = "validation_date",
        deserialize_with = "de::opt_string"
    )]
    pub validation_date: Option<String>,
    /// Creation timestamp.
    #[serde(
        default,
        rename = "createdAt",
        alias = "created_at",
        deserialize_with = "de::opt_string"
    )]
    pub created_at: Option<String>,
    /// Fields this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// One page of `host.list`.
///
/// ```
/// use inwx_client::HostListPage;
///
/// let page: HostListPage = serde_json::from_str(r#"{"count":1,"host":[{"id":44}]}"#)?;
/// assert_eq!(page.count, Some(1));
/// assert_eq!(page.len(), 1);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct HostListPage {
    /// Total number of hosts, not just this page.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The hosts on this page.
    #[serde(default, rename = "host", alias = "hosts")]
    pub hosts: Vec<Host>,
}

impl HostListPage {
    /// Number of hosts on this page.
    ///
    /// ```
    /// use inwx_client::HostListPage;
    /// let page: HostListPage = serde_json::from_str(r#"{"host":[{"id":1}]}"#)?;
    /// assert_eq!(page.len(), 1);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    /// Whether this page carries no host at all.
    ///
    /// ```
    /// use inwx_client::HostListPage;
    /// assert!(HostListPage::default().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

/// The filter behind `host.list`.
///
/// ```
/// use inwx_client::HostListQuery;
///
/// let query = HostListQuery::new().with_page(2, 50)?;
/// assert_eq!(query.params()["page"], 2);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostListQuery {
    customer: Option<i64>,
    name: Option<String>,
    state: Option<String>,
    page: Option<u32>,
    limit: Option<u32>,
}

impl HostListQuery {
    /// All hosts of the reseller account.
    ///
    /// ```
    /// use inwx_client::HostListQuery;
    /// assert_eq!(HostListQuery::new().params(), serde_json::json!({}));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by customer id.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::HostListQuery;
    /// assert!(HostListQuery::new().with_customer(4711).is_ok());
    /// assert!(HostListQuery::new().with_customer(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer(mut self, customer: i64) -> Result<Self> {
        self.customer = Some(params::object_id("customerId", customer)?);
        Ok(self)
    }

    /// Filters by host name.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::HostListQuery;
    /// assert_eq!(
    ///     HostListQuery::new().with_name("ns1.example.com")?.params()["name"],
    ///     "ns1.example.com"
    /// );
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_name(mut self, name: &str) -> Result<Self> {
        validate_token("host.name", name)?;
        self.name = Some(name.trim().to_owned());
        Ok(self)
    }

    /// Filters by state.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::HostListQuery;
    /// assert!(HostListQuery::new().with_state("DONE").is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_state(mut self, state: &str) -> Result<Self> {
        validate_token("host.state", state)?;
        self.state = Some(state.trim().to_owned());
        Ok(self)
    }

    /// Sets the page (1-based) and the page size.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the limit is `0` or above the crate's own
    /// ceiling of 1000 entries per page.
    ///
    /// ```
    /// use inwx_client::HostListQuery;
    /// assert!(HostListQuery::new().with_page(1, 1).is_ok());
    /// assert!(HostListQuery::new().with_page(1, 1_000).is_ok());
    /// assert!(HostListQuery::new().with_page(1, 1_001).is_err());
    /// assert!(HostListQuery::new().with_page(1, 0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_page(mut self, page: u32, limit: u32) -> Result<Self> {
        let (page, limit) = params::paging(page, limit)?;
        self.page = Some(page);
        self.limit = Some(limit);
        Ok(self)
    }

    /// The `host.list` parameters.
    ///
    /// ```
    /// use inwx_client::HostListQuery;
    /// let params = HostListQuery::new().with_page(3, 10).unwrap().params();
    /// assert_eq!(params["pagelimit"], 10);
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut map = Map::new();
        if let Some(customer) = self.customer {
            map.insert("customer".to_owned(), json!(customer));
        }
        if let Some(name) = &self.name {
            map.insert("name".to_owned(), json!(name));
        }
        if let Some(state) = &self.state {
            map.insert("state".to_owned(), json!(state));
        }
        if let Some(page) = self.page {
            map.insert("page".to_owned(), json!(page));
        }
        if let Some(limit) = self.limit {
            map.insert("pagelimit".to_owned(), json!(limit));
        }
        Value::Object(map)
    }
}

/// A new host object (`host.create`).
///
/// The name is required — a host without one cannot exist — and goes through
/// [`Hostname`].
///
/// ```
/// use inwx_client::{HostCreate, Hostname};
///
/// let create = HostCreate::new(Hostname::parse("ns1.example.com")?)?
///     .with_customer(4711)?
///     .with_ip("203.0.113.7")?;
/// let params = create.params();
/// assert_eq!(params["name"], "ns1.example.com");
/// assert_eq!(params["ipAddress"], "203.0.113.7");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct HostCreate {
    name: Hostname,
    customer: Option<i64>,
    ip_address: Option<String>,
    testing: bool,
    fields: ExtraFields,
}

impl HostCreate {
    /// Names the host.
    ///
    /// # Errors
    ///
    /// Never today; the signature leaves room for the checks the API enforces on
    /// an unusable name.
    ///
    /// ```
    /// use inwx_client::{HostCreate, Hostname};
    /// assert!(HostCreate::new(Hostname::parse("ns1.example.com")?).is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new(name: Hostname) -> Result<Self> {
        Ok(Self {
            name,
            customer: None,
            ip_address: None,
            testing: false,
            fields: ExtraFields::default(),
        })
    }

    /// Attaches the host to a customer.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::{HostCreate, Hostname};
    /// let create = HostCreate::new(Hostname::parse("ns1")?)?.with_customer(4711)?;
    /// assert_eq!(create.params()["customer"], 4711);
    /// assert!(HostCreate::new(Hostname::parse("ns1")?)?.with_customer(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer(mut self, customer: i64) -> Result<Self> {
        self.customer = Some(params::object_id("customerId", customer)?);
        Ok(self)
    }

    /// Sets the glue address, either address family.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the text is not an IP address.
    ///
    /// ```
    /// use inwx_client::{HostCreate, Hostname};
    /// let create = HostCreate::new(Hostname::parse("ns1")?)?.with_ip("2001:db8::1")?;
    /// assert_eq!(create.params()["ipAddress"], "2001:db8::1");
    /// assert!(HostCreate::new(Hostname::parse("ns1")?)?.with_ip("203.0.113").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_ip(mut self, ip: &str) -> Result<Self> {
        let parsed: IpAddr = parse_ip(ip)?;
        self.ip_address = Some(parsed.to_string());
        Ok(self)
    }

    /// Adds a parameter this crate does not model.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `key` is not a parameter name, or when a typed
    /// setter already owns it.
    ///
    /// ```
    /// use inwx_client::{HostCreate, Hostname};
    /// let create = HostCreate::new(Hostname::parse("ns1")?)?.with_field("validationDate", "2026-11-01")?;
    /// assert_eq!(create.params()["validationDate"], "2026-11-01");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_field(mut self, key: &str, value: impl Into<Value>) -> Result<Self> {
        self.fields.set(key, value.into(), CREATE_KEYS)?;
        Ok(self)
    }

    /// Runs the create in testing mode (`testing=true`), which books nothing.
    ///
    /// ```
    /// use inwx_client::{HostCreate, Hostname};
    /// let create = HostCreate::new(Hostname::parse("ns1")?)?.dry_run();
    /// assert_eq!(create.params()["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.testing = true;
        self
    }

    /// The `host.create` parameters.
    ///
    /// ```
    /// use inwx_client::{HostCreate, Hostname};
    /// let params = HostCreate::new(Hostname::parse("ns1.example.com").unwrap()).unwrap().params();
    /// assert_eq!(params["name"], "ns1.example.com");
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut map = Map::new();
        map.insert("name".to_owned(), json!(self.name.as_str()));
        if let Some(customer) = self.customer {
            map.insert("customer".to_owned(), json!(customer));
        }
        if let Some(ip_address) = &self.ip_address {
            map.insert("ipAddress".to_owned(), json!(ip_address));
        }
        self.fields.write_into(&mut map);
        if self.testing {
            map.insert("testing".to_owned(), json!(true));
        }
        Value::Object(map)
    }
}

/// A change to a host object (`host.update`).
///
/// ```
/// use inwx_client::{HostUpdate, Hostname};
///
/// let update = HostUpdate::new(44)?.with_ip("203.0.113.9")?;
/// let params = update.params()?;
/// assert_eq!(params["hostId"], 44);
/// assert_eq!(params["ipAddress"], "203.0.113.9");
/// assert!(HostUpdate::new(44).unwrap().params().is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct HostUpdate {
    host_id: i64,
    name: Option<String>,
    customer: Option<i64>,
    ip_address: Option<String>,
    fields: ExtraFields,
}

impl HostUpdate {
    /// Targets one host object.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::HostUpdate;
    /// assert!(HostUpdate::new(44).is_ok());
    /// assert!(HostUpdate::new(0).is_err());
    /// ```
    pub fn new(host_id: i64) -> Result<Self> {
        Ok(Self {
            host_id: params::object_id("hostId", host_id)?,
            name: None,
            customer: None,
            ip_address: None,
            fields: ExtraFields::default(),
        })
    }

    /// Renames the host.
    ///
    /// # Errors
    ///
    /// Never today; [`Hostname`] has already checked the name.
    ///
    /// ```
    /// use inwx_client::{Hostname, HostUpdate};
    /// let update = HostUpdate::new(44)?.with_name(&Hostname::parse("ns2.example.com")?);
    /// assert_eq!(update.params()?["name"], "ns2.example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_name(mut self, name: &Hostname) -> Self {
        self.name = Some(name.as_str().to_owned());
        self
    }

    /// Moves the host to another customer.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::HostUpdate;
    /// assert!(HostUpdate::new(44)?.with_customer(1).is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer(mut self, customer: i64) -> Result<Self> {
        self.customer = Some(params::object_id("customerId", customer)?);
        Ok(self)
    }

    /// Changes the glue address.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the text is not an IP address.
    ///
    /// ```
    /// use inwx_client::HostUpdate;
    /// assert!(HostUpdate::new(44)?.with_ip("203.0.113.9").is_ok());
    /// assert!(HostUpdate::new(44)?.with_ip("nope").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_ip(mut self, ip: &str) -> Result<Self> {
        let parsed: IpAddr = parse_ip(ip)?;
        self.ip_address = Some(parsed.to_string());
        Ok(self)
    }

    /// Changes a parameter this crate does not model.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `key` is not a parameter name, or when a typed
    /// setter already owns it.
    ///
    /// ```
    /// use inwx_client::HostUpdate;
    /// let update = HostUpdate::new(44)?.with_field("validationDate", "2026-11-01")?;
    /// assert_eq!(update.params()?["validationDate"], "2026-11-01");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_field(mut self, key: &str, value: impl Into<Value>) -> Result<Self> {
        self.fields.set(key, value.into(), UPDATE_KEYS)?;
        Ok(self)
    }

    /// The `host.update` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when no field was changed.
    ///
    /// ```
    /// use inwx_client::HostUpdate;
    /// assert!(HostUpdate::new(44)?.params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut map = Map::new();
        if let Some(name) = &self.name {
            map.insert("name".to_owned(), json!(name));
        }
        if let Some(customer) = self.customer {
            map.insert("customer".to_owned(), json!(customer));
        }
        if let Some(ip_address) = &self.ip_address {
            map.insert("ipAddress".to_owned(), json!(ip_address));
        }
        self.fields.write_into(&mut map);
        params::require_payload("host.update.params", map.len())?;
        map.insert("hostId".to_owned(), json!(self.host_id));
        Ok(Value::Object(map))
    }
}

impl<T: Transport> InwxClient<T> {
    /// Asks whether a host name can be registered (`host.check`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{Hostname, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let outcome = client.check_host(&Hostname::parse("ns1.example.com")?).await?;
    /// println!("{:?}", outcome.is_available());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors; [`Hostname`] has already checked the
    /// name.
    pub async fn check_host(&self, name: &Hostname) -> Result<CheckOutcome> {
        let data = self
            .call("host.check", json!({ "name": name.as_str() }))
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Registers a host object (`host.create`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{HostCreate, Hostname, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let create = HostCreate::new(Hostname::parse("ns1.example.com")?)?
    ///     .with_customer(4711)?
    ///     .with_ip("203.0.113.7")?;
    /// let host = client.create_host(&create).await?;
    /// println!("{:?}", host.id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors; [`HostCreate`] validates the name, the
    /// customer id and the address.
    pub async fn create_host(&self, create: &HostCreate) -> Result<Host> {
        let data = self.call("host.create", create.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Reads one host object (`host.info`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let host = client.host_info(44).await?;
    /// println!("{:?} {:?}", host.name, host.ip_address);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn host_info(&self, host_id: i64) -> Result<Host> {
        let id = params::object_id("hostId", host_id)?;
        let data = self.call("host.info", json!({ "hostId": id })).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Lists host objects (`host.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{HostListQuery, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let page = client
    ///     .list_hosts(&HostListQuery::new().with_page(1, 50)?)
    ///     .await?;
    /// println!("{} of {:?}", page.len(), page.count);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors; the query itself validates its
    /// filters.
    pub async fn list_hosts(&self, query: &HostListQuery) -> Result<HostListPage> {
        let data = self.call("host.list", query.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Changes a host object (`host.update`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{HostUpdate, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let update = HostUpdate::new(44)?.with_ip("203.0.113.9")?;
    /// let host = client.update_host(&update).await?;
    /// println!("{:?}", host.ip_address);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id or an update without a
    /// changed field, plus the usual transport and API errors.
    pub async fn update_host(&self, update: &HostUpdate) -> Result<Host> {
        let data = self.call("host.update", update.params()?).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Deletes a host object (`host.delete`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.delete_host(44).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn delete_host(&self, host_id: i64) -> Result<()> {
        let id = params::object_id("hostId", host_id)?;
        self.call("host.delete", json!({ "hostId": id })).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_update_without_a_change_is_refused() {
        assert!(HostUpdate::new(44).unwrap().params().is_err());
        assert!(HostUpdate::new(44)
            .unwrap()
            .with_customer(1)
            .unwrap()
            .params()
            .is_ok());
    }

    #[test]
    fn ids_stop_at_zero() {
        assert!(HostUpdate::new(1).is_ok());
        assert!(HostUpdate::new(0).is_err());
        assert!(HostUpdate::new(-1).is_err());
        assert!(HostListQuery::new().with_customer(1).is_ok());
        assert!(HostListQuery::new().with_customer(0).is_err());
    }

    #[test]
    fn glue_addresses_must_parse() {
        let create = HostCreate::new(Hostname::parse("ns1.example.com").unwrap()).unwrap();
        assert!(create.clone().with_ip("203.0.113.7").is_ok());
        assert!(create.clone().with_ip("2001:db8::1").is_ok());
        assert!(create.with_ip("203.0.113.").is_err());
    }

    #[test]
    fn host_names_are_validated_by_the_shared_type() {
        assert!(Hostname::parse("ns1.example.com").is_ok());
        assert!(Hostname::parse(&format!("{}.com", "a".repeat(254))).is_err());
    }

    #[test]
    fn page_limit_pair_is_one_and_one_thousand() {
        assert!(HostListQuery::new().with_page(1, 1).is_ok());
        assert!(HostListQuery::new().with_page(1, 1_000).is_ok());
        assert!(HostListQuery::new().with_page(1, 1_001).is_err());
        assert!(HostListQuery::new().with_page(1, 0).is_err());
    }

    #[test]
    fn tokens_stop_at_255_characters() {
        assert!(HostListQuery::new().with_name(&"a".repeat(255)).is_ok());
        assert!(HostListQuery::new().with_name(&"a".repeat(256)).is_err());
    }

    #[test]
    fn reserved_keys_cannot_be_overridden_by_hand() {
        let update = HostUpdate::new(44).unwrap();
        assert!(update.clone().with_field("hostId", 1).is_err());
        assert!(update.with_field("validationDate", "x").is_ok());
    }

    #[test]
    fn testing_is_only_added_when_asked_for() {
        let create = HostCreate::new(Hostname::parse("ns1").unwrap()).unwrap();
        assert!(create.params().get("testing").is_none());
        assert_eq!(create.dry_run().params()["testing"], true);
    }

    #[test]
    fn unknown_fields_survive_parsing() {
        let host: Host = serde_json::from_str(r#"{"id":1,"brandNew":true}"#).unwrap();
        assert_eq!(host.rest["brandNew"], true);
    }
}
