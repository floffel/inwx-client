//! Nameserver zones (`nameserver.*`): zone metadata, the zone list, and the
//! delegation check.
//!
//! Records themselves live in [`crate::record`]; this module is about the zone
//! around them. Creating or updating a zone (`nameserver.create`,
//! `nameserver.update`, `nameserver.clone`, `nameserver.export`) is deliberately
//! out of scope — see the README — but reachable through
//! [`InwxClient::call`](crate::InwxClient::call).

use std::collections::VecDeque;
use std::fmt;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::pagination::{Pagination, Walk};
use crate::record::DnsRecord;
use crate::transport::Transport;
use crate::types::{de, DomainName, Hostname};

/// A zone as described by `nameserver.info`, including its records.
///
/// ```
/// use inwx_client::ZoneInfo;
///
/// let zone: ZoneInfo = serde_json::from_str(
///     r#"{"roId":7,"domain":"example.com","type":"MASTER","count":2,"record":[
///         {"id":"1","name":"@","type":"A","content":"203.0.113.7","ttl":3600},
///         {"id":"2","name":"www","type":"CNAME","content":"example.com"}
///     ]}"#,
/// )?;
/// assert_eq!(zone.records.len(), 2);
/// assert!(zone.is_master());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct ZoneInfo {
    /// Zone id (`roId`), usable instead of the domain name.
    #[serde(default, rename = "roId", deserialize_with = "de::opt_i64")]
    pub ro_id: Option<i64>,
    /// Zone name.
    #[serde(default)]
    pub domain: String,
    /// `MASTER` or `SLAVE`.
    #[serde(default, rename = "type", deserialize_with = "de::opt_string")]
    pub zone_type: Option<String>,
    /// Master IP for slave zones.
    #[serde(default, rename = "masterIp", deserialize_with = "de::opt_string")]
    pub master_ip: Option<String>,
    /// Serial of the SOA record as the nameserver knows it.
    #[serde(default, rename = "SOAserial", deserialize_with = "de::opt_string")]
    pub soa_serial: Option<String>,
    /// Timestamp of the last zone check.
    #[serde(default, rename = "lastZoneCheck", deserialize_with = "de::opt_string")]
    pub last_zone_check: Option<String>,
    /// Number of records the API reports.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The records in the zone.
    #[serde(default, rename = "record")]
    pub records: Vec<DnsRecord>,
}

impl ZoneInfo {
    /// Whether this is a primary zone.
    ///
    /// ```
    /// use inwx_client::ZoneInfo;
    ///
    /// let slave: ZoneInfo = serde_json::from_str(r#"{"domain":"x.de","type":"SLAVE"}"#)?;
    /// assert!(!slave.is_master());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_master(&self) -> bool {
        self.zone_type.as_deref() == Some("MASTER")
    }
}

/// One entry of `nameserver.list`.
///
/// ```
/// use inwx_client::ZoneSummary;
///
/// let zone: ZoneSummary = serde_json::from_str(
///     r#"{"roId":7,"domain":"example.com","type":"MASTER","web":"203.0.113.7"}"#,
/// )?;
/// assert_eq!(zone.domain.as_str(), "example.com");
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ZoneSummary {
    /// Zone id.
    #[serde(default, rename = "roId", deserialize_with = "de::opt_i64")]
    pub ro_id: Option<i64>,
    /// Zone name, validated like any other domain name.
    pub domain: DomainName,
    /// `MASTER` or `SLAVE`.
    #[serde(default, rename = "type", deserialize_with = "de::opt_string")]
    pub zone_type: Option<String>,
    /// Master IP for slave zones.
    #[serde(default, rename = "masterIp", deserialize_with = "de::opt_string")]
    pub master_ip: Option<String>,
    /// Web redirection target, if the zone is a web forward.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub web: Option<String>,
    /// Mail redirection target.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub mail: Option<String>,
    /// URL forwarding target.
    #[serde(default, rename = "url", deserialize_with = "de::opt_string")]
    pub url: Option<String>,
}

/// One page of `nameserver.list`.
///
/// ```
/// use inwx_client::ZoneListPage;
///
/// let page: ZoneListPage = serde_json::from_str(
///     r#"{"count":1,"domains":[{"domain":"example.com","type":"MASTER"}]}"#,
/// )?;
/// assert_eq!(page.zones[0].domain.as_str(), "example.com");
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct ZoneListPage {
    /// Total number of zones matching the filter.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The zones on this page.
    #[serde(default, rename = "domains")]
    pub zones: Vec<ZoneSummary>,
}

/// The result of checking one nameserver (`nameserver.check`).
///
/// ```
/// use inwx_client::NameserverCheck;
///
/// let check: NameserverCheck = serde_json::from_str(
///     r#"{"ns":"ns1.example.com","status":"OK","message":["serial 2026010101"]}"#,
/// )?;
/// assert!(check.is_ok());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct NameserverCheck {
    /// The nameserver that was checked.
    #[serde(default, rename = "ns", deserialize_with = "de::opt_string")]
    pub nameserver: Option<String>,
    /// Status string, `OK` when the nameserver answers as expected.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
    /// Human readable check messages.
    #[serde(default, deserialize_with = "de::vec_string")]
    pub message: Vec<String>,
}

impl NameserverCheck {
    /// Whether the nameserver answered correctly.
    ///
    /// ```
    /// use inwx_client::NameserverCheck;
    ///
    /// let unknown: NameserverCheck = serde_json::from_str(r#"{"ns":"ns1.example.com"}"#)?;
    /// assert!(!unknown.is_ok());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.status.as_deref() == Some("OK")
    }
}

impl<T: Transport> InwxClient<T> {
    /// Reads a zone with its records (`nameserver.info`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let zone = client.zone_info(&DomainName::parse("example.com")?).await?;
    /// println!("{} records, serial {:?}", zone.records.len(), zone.soa_serial);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors — `2303` when the account has no zone
    /// for that domain.
    pub async fn zone_info(&self, domain: &DomainName) -> Result<ZoneInfo> {
        let data = self
            .call("nameserver.info", json!({ "domain": domain.as_str() }))
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Lists the account's zones (`nameserver.list`), first page.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for zone in client.list_zones().await?.zones {
    ///     println!("{}", zone.domain);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn list_zones(&self) -> Result<ZoneListPage> {
        self.list_zones_page(1, 100).await
    }

    /// Lists one page of zones (`nameserver.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let page = client.list_zones_page(2, 25).await?;
    /// println!("{} of {:?}", page.zones.len(), page.count);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the page size is zero, plus the usual
    /// transport and API errors.
    pub async fn list_zones_page(&self, page: u32, limit: u32) -> Result<ZoneListPage> {
        if limit == 0 {
            return Err(Error::validation("pagelimit", "must be at least 1"));
        }
        let data = self
            .call(
                "nameserver.list",
                json!({ "page": page.max(1), "pagelimit": limit }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Walks every page of `nameserver.list` with bounded automatic pagination.
    ///
    /// `list_zones` returns one page and stops there; this returns a
    /// [`ZonePager`] that keeps fetching until the provider runs out of zones or
    /// the bounds in `paging` are reached.
    ///
    /// ```
    /// # use std::sync::{Arc, Mutex};
    /// # use inwx_client::transport::{Request, Response, Transport};
    /// # use inwx_client::{InwxClient, Pagination, Result};
    /// # #[derive(Clone)]
    /// # struct Scripted(Arc<Mutex<Vec<&'static str>>>);
    /// # impl Transport for Scripted {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         let body = self.0.lock().unwrap().remove(0);
    /// #         Ok(Response::new(200, std::iter::empty(), body.as_bytes().to_vec()))
    /// #     }
    /// # }
    /// # fn demo() -> Result<usize> {
    /// let transport = Scripted(Arc::new(Mutex::new(vec![
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":3,"domains":[{"domain":"a.de"},{"domain":"b.de"}]}}"#,
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":3,"domains":[{"domain":"c.de"}]}}"#,
    /// ])));
    /// let client = InwxClient::new(transport).with_session("domrobot=test")?;
    /// let mut pager = client.paginate_zones(&Pagination::new().with_page_size(2)?);
    /// let runtime = tokio::runtime::Runtime::new().unwrap();
    /// let first = runtime.block_on(pager.next_page())?.expect("one page");
    /// assert_eq!(first.zones.len(), 2);
    /// assert_eq!(pager.pages_fetched(), 1);
    /// # Ok(first.zones.len())
    /// # }
    /// # assert_eq!(demo().unwrap(), 2);
    /// ```
    #[must_use]
    pub fn paginate_zones(&self, paging: &Pagination) -> ZonePager<'_, T> {
        ZonePager::new(self, paging)
    }

    /// Collects every zone of `nameserver.list` that the bounds allow.
    ///
    /// Reaching [`Pagination::max_items`] truncates the answer without saying so
    /// here, so a bounded scan that has to be complete should be driven through
    /// [`paginate_zones`](Self::paginate_zones) instead.
    ///
    /// ```
    /// # use std::sync::{Arc, Mutex};
    /// # use inwx_client::transport::{Request, Response, Transport};
    /// # use inwx_client::{InwxClient, Pagination, Result};
    /// # #[derive(Clone)]
    /// # struct Scripted(Arc<Mutex<Vec<&'static str>>>);
    /// # impl Transport for Scripted {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         let body = self.0.lock().unwrap().remove(0);
    /// #         Ok(Response::new(200, std::iter::empty(), body.as_bytes().to_vec()))
    /// #     }
    /// # }
    /// # fn demo() -> Result<Vec<String>> {
    /// let transport = Scripted(Arc::new(Mutex::new(vec![
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":3,"domains":[{"domain":"a.de"},{"domain":"b.de"}]}}"#,
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":3,"domains":[{"domain":"c.de"}]}}"#,
    /// ])));
    /// let client = InwxClient::new(transport).with_session("domrobot=test")?;
    /// let paging = Pagination::new().with_page_size(2)?;
    /// let runtime = tokio::runtime::Runtime::new().unwrap();
    /// let zones = runtime.block_on(client.all_zones(&paging))?;
    /// let names: Vec<String> = zones.iter().map(|zone| zone.domain.to_string()).collect();
    /// assert_eq!(names, ["a.de", "b.de", "c.de"]);
    /// # Ok(names)
    /// # }
    /// # assert_eq!(demo().unwrap(), ["a.de", "b.de", "c.de"]);
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Pagination`] when the request cap is reached while the provider
    /// still has more zones, plus the usual transport and API errors.
    pub async fn all_zones(&self, paging: &Pagination) -> Result<Vec<ZoneSummary>> {
        self.paginate_zones(paging).collect().await
    }

    /// Deletes a zone (`nameserver.delete`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.delete_zone(&DomainName::parse("example.com")?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors. Deleting the zone of a registered
    /// domain leaves it undelegated.
    pub async fn delete_zone(&self, domain: &DomainName) -> Result<()> {
        self.call("nameserver.delete", json!({ "domain": domain.as_str() }))
            .await?;
        Ok(())
    }

    /// Asks INWX to check whether the given nameservers answer correctly
    /// (`nameserver.check`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, Hostname, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let checks = client
    ///     .check_delegation(
    ///         &DomainName::parse("example.com")?,
    ///         &[Hostname::parse("ns1.example.com")?],
    ///     )
    ///     .await?;
    /// assert!(checks.iter().all(inwx_client::NameserverCheck::is_ok));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty nameserver list, plus the usual
    /// transport and API errors.
    pub async fn check_delegation(
        &self,
        domain: &DomainName,
        nameservers: &[Hostname],
    ) -> Result<Vec<NameserverCheck>> {
        if nameservers.is_empty() {
            return Err(Error::validation(
                "nameserver",
                "at least one nameserver is required",
            ));
        }
        let data = self
            .call(
                "nameserver.check",
                json!({
                    "domain": domain.as_str(),
                    "ns": nameservers.iter().map(Hostname::as_str).collect::<Vec<_>>(),
                }),
            )
            .await?;
        let entries = match data.get("details") {
            Some(Value::Array(entries)) => entries.clone(),
            _ => Vec::new(),
        };
        Ok(entries
            .into_iter()
            .filter_map(|entry| serde_json::from_value(entry).ok())
            .collect())
    }
}

/// Walks the pages of `nameserver.list` until the provider runs out of zones or
/// the bounds of the [`Pagination`] it was built with are reached.
///
/// Obtained from [`InwxClient::paginate_zones`]. A pager is a cursor, not a
/// [`std::iter::Iterator`]: every step is an `.await`, and a synchronous
/// iterator cannot do I/O. Use [`next_item`](Self::next_item) zone by zone,
/// [`next_page`](Self::next_page) page by page, or
/// [`collect`](Self::collect) for everything the bounds allow.
///
/// The pager owns `page` and `pagelimit`, which is why it exists next to the
/// single-page [`InwxClient::list_zones_page`].
///
/// ```
/// # use std::sync::{Arc, Mutex};
/// # use inwx_client::transport::{Request, Response, Transport};
/// # use inwx_client::{InwxClient, Pagination, Result};
/// # #[derive(Clone)]
/// # struct Scripted(Arc<Mutex<Vec<&'static str>>>);
/// # impl Transport for Scripted {
/// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
/// #         let body = self.0.lock().unwrap().remove(0);
/// #         Ok(Response::new(200, std::iter::empty(), body.as_bytes().to_vec()))
/// #     }
/// # }
/// # fn demo() -> Result<Vec<String>> {
/// let transport = Scripted(Arc::new(Mutex::new(vec![
///     r#"{"code":1000,"msg":"ok","resData":{"count":3,"domains":[{"domain":"a.de"},{"domain":"b.de"}]}}"#,
///     r#"{"code":1000,"msg":"ok","resData":{"count":3,"domains":[{"domain":"c.de"}]}}"#,
/// ])));
/// let client = InwxClient::new(transport).with_session("domrobot=test")?;
/// let mut pager = client.paginate_zones(&Pagination::new().with_page_size(2)?);
///
/// let runtime = tokio::runtime::Runtime::new().unwrap();
/// let mut names = Vec::new();
/// while let Some(zone) = runtime.block_on(pager.next_item())? {
///     names.push(zone.domain.to_string());
/// }
/// assert_eq!(names, ["a.de", "b.de", "c.de"]);
/// assert_eq!(pager.pages_fetched(), 2);
/// assert!(!pager.is_truncated());
/// # Ok(names)
/// # }
/// # assert_eq!(demo().unwrap(), ["a.de", "b.de", "c.de"]);
/// ```
pub struct ZonePager<'c, T: Transport> {
    client: &'c InwxClient<T>,
    walk: Walk,
    buffer: VecDeque<ZoneSummary>,
}

/// `Debug` shows where the walk stands; the client is left to its own
/// redacting `Debug`, so no cookie can leak through a pager.
impl<T: Transport> fmt::Debug for ZonePager<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZonePager")
            .field("pages_fetched", &self.walk.pages())
            .field("items_read", &self.walk.items())
            .field("buffered", &self.buffer.len())
            .field("finished", &self.walk.is_finished())
            .field("truncated", &self.walk.is_truncated())
            .finish_non_exhaustive()
    }
}

impl<'c, T: Transport> ZonePager<'c, T> {
    pub(crate) fn new(client: &'c InwxClient<T>, paging: &Pagination) -> Self {
        Self {
            client,
            walk: paging.walk(),
            buffer: VecDeque::new(),
        }
    }

    /// Fetches the next page, or `None` when the walk is over.
    ///
    /// Zones of the page are buffered for [`next_item`](Self::next_item), so
    /// mixing the two methods never reads a zone twice.
    ///
    /// ```
    /// # use std::sync::{Arc, Mutex};
    /// # use inwx_client::transport::{Request, Response, Transport};
    /// # use inwx_client::{InwxClient, Pagination, Result};
    /// # #[derive(Clone)]
    /// # struct Scripted(Arc<Mutex<Vec<&'static str>>>);
    /// # impl Transport for Scripted {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         let body = self.0.lock().unwrap().remove(0);
    /// #         Ok(Response::new(200, std::iter::empty(), body.as_bytes().to_vec()))
    /// #     }
    /// # }
    /// # fn demo() -> Result<usize> {
    /// let transport = Scripted(Arc::new(Mutex::new(vec![
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":3,"domains":[{"domain":"a.de"},{"domain":"b.de"}]}}"#,
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":3,"domains":[{"domain":"c.de"}]}}"#,
    /// ])));
    /// let client = InwxClient::new(transport).with_session("domrobot=test")?;
    /// let mut pager = client.paginate_zones(&Pagination::new().with_page_size(2)?);
    /// let runtime = tokio::runtime::Runtime::new().unwrap();
    /// let page = runtime.block_on(pager.next_page())?.expect("one page");
    /// assert_eq!(page.zones.len(), 2);
    /// assert_eq!(pager.pages_fetched(), 1);
    /// # Ok(page.zones.len())
    /// # }
    /// # assert_eq!(demo().unwrap(), 2);
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Pagination`] when the request cap is reached while the provider
    /// still has more zones; the pages read so far stay buffered. Plus the usual
    /// transport and API errors.
    pub async fn next_page(&mut self) -> Result<Option<ZoneListPage>> {
        if self.walk.is_finished() {
            return Ok(None);
        }
        let (page, limit) = self.walk.request();
        let page = self.client.list_zones_page(page, limit).await?;
        let kept = self.walk.keep(limit, page.zones.len());
        self.buffer.extend(page.zones.iter().take(kept).cloned());
        self.walk.absorb(limit, page.count, kept)?;
        Ok(Some(page))
    }

    /// Reads the next zone, fetching as many pages as it takes.
    ///
    /// ```
    /// # use std::sync::{Arc, Mutex};
    /// # use inwx_client::transport::{Request, Response, Transport};
    /// # use inwx_client::{InwxClient, Pagination, Result};
    /// # #[derive(Clone)]
    /// # struct Scripted(Arc<Mutex<Vec<&'static str>>>);
    /// # impl Transport for Scripted {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         let body = self.0.lock().unwrap().remove(0);
    /// #         Ok(Response::new(200, std::iter::empty(), body.as_bytes().to_vec()))
    /// #     }
    /// # }
    /// # fn demo() -> Result<Option<String>> {
    /// let transport = Scripted(Arc::new(Mutex::new(vec![
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":1,"domains":[{"domain":"a.de"}]}}"#,
    /// ])));
    /// let client = InwxClient::new(transport).with_session("domrobot=test")?;
    /// let mut pager = client.paginate_zones(&Pagination::new());
    /// let runtime = tokio::runtime::Runtime::new().unwrap();
    /// let first = runtime
    ///     .block_on(pager.next_item())?
    ///     .map(|zone| zone.domain.to_string());
    /// let second = runtime.block_on(pager.next_item())?;
    /// assert_eq!(first.as_deref(), Some("a.de"));
    /// assert!(second.is_none());
    /// # Ok(first)
    /// # }
    /// # assert_eq!(demo().unwrap().as_deref(), Some("a.de"));
    /// ```
    ///
    /// # Errors
    ///
    /// The same as [`next_page`](Self::next_page).
    pub async fn next_item(&mut self) -> Result<Option<ZoneSummary>> {
        loop {
            if let Some(zone) = self.buffer.pop_front() {
                return Ok(Some(zone));
            }
            if self.walk.is_finished() {
                return Ok(None);
            }
            self.next_page().await?;
        }
    }

    /// Reads every zone the bounds allow and returns them in provider order.
    ///
    /// Hitting the item cap is not an error: the walk stops and
    /// [`is_truncated`](Self::is_truncated) says so. Hitting the request cap is
    /// an error, because a silently short list cannot be told apart from a
    /// complete one.
    ///
    /// ```
    /// # use std::sync::{Arc, Mutex};
    /// # use inwx_client::transport::{Request, Response, Transport};
    /// # use inwx_client::{InwxClient, Pagination, Result};
    /// # #[derive(Clone)]
    /// # struct Scripted(Arc<Mutex<Vec<&'static str>>>);
    /// # impl Transport for Scripted {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         let body = self.0.lock().unwrap().remove(0);
    /// #         Ok(Response::new(200, std::iter::empty(), body.as_bytes().to_vec()))
    /// #     }
    /// # }
    /// # fn demo() -> Result<usize> {
    /// let transport = Scripted(Arc::new(Mutex::new(vec![
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":3,"domains":[{"domain":"a.de"},{"domain":"b.de"}]}}"#,
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":3,"domains":[{"domain":"c.de"}]}}"#,
    /// ])));
    /// let client = InwxClient::new(transport).with_session("domrobot=test")?;
    /// let mut pager = client.paginate_zones(&Pagination::new().with_page_size(2)?);
    /// let runtime = tokio::runtime::Runtime::new().unwrap();
    /// let zones = runtime.block_on(pager.collect())?;
    /// assert_eq!(zones.len(), 3);
    /// # Ok(zones.len())
    /// # }
    /// # assert_eq!(demo().unwrap(), 3);
    /// ```
    ///
    /// # Errors
    ///
    /// The same as [`next_page`](Self::next_page).
    pub async fn collect(&mut self) -> Result<Vec<ZoneSummary>> {
        let mut zones = Vec::new();
        while let Some(zone) = self.next_item().await? {
            zones.push(zone);
        }
        Ok(zones)
    }

    /// Requests made so far.
    ///
    /// ```
    /// # use inwx_client::{InwxClient, Pagination, Result, Transport};
    /// # use inwx_client::transport::{Request, Response};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!("nothing is fetched here")
    /// #     }
    /// # }
    /// # fn demo() -> Result<()> {
    /// let client = InwxClient::new(Never).with_session("domrobot=test")?;
    /// let pager = client.paginate_zones(&Pagination::new());
    /// assert_eq!(pager.pages_fetched(), 0);
    /// # Ok(())
    /// # }
    /// # demo().unwrap();
    /// ```
    #[must_use]
    pub fn pages_fetched(&self) -> u32 {
        self.walk.pages()
    }

    /// Zones read so far, including the ones still buffered.
    ///
    /// ```
    /// # use inwx_client::{InwxClient, Pagination, Result, Transport};
    /// # use inwx_client::transport::{Request, Response};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!("nothing is fetched here")
    /// #     }
    /// # }
    /// # fn demo() -> Result<()> {
    /// let client = InwxClient::new(Never).with_session("domrobot=test")?;
    /// let pager = client.paginate_zones(&Pagination::new());
    /// assert_eq!(pager.items_read(), 0);
    /// # Ok(())
    /// # }
    /// # demo().unwrap();
    /// ```
    #[must_use]
    pub fn items_read(&self) -> usize {
        self.walk.items()
    }

    /// Whether the walk is over, for any reason.
    ///
    /// ```
    /// # use inwx_client::{InwxClient, Pagination, Result, Transport};
    /// # use inwx_client::transport::{Request, Response};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!("nothing is fetched here")
    /// #     }
    /// # }
    /// # fn demo() -> Result<()> {
    /// let client = InwxClient::new(Never).with_session("domrobot=test")?;
    /// let pager = client.paginate_zones(&Pagination::new());
    /// assert!(!pager.is_finished());
    /// # Ok(())
    /// # }
    /// # demo().unwrap();
    /// ```
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.walk.is_finished()
    }

    /// Whether the walk stopped although the provider had more to give, because
    /// [`Pagination::max_items`] was reached.
    ///
    /// ```
    /// # use inwx_client::{InwxClient, Pagination, Result, Transport};
    /// # use inwx_client::transport::{Request, Response};
    /// # struct Never;
    /// # impl Transport for Never {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         unreachable!("nothing is fetched here")
    /// #     }
    /// # }
    /// # fn demo() -> Result<()> {
    /// let client = InwxClient::new(Never).with_session("domrobot=test")?;
    /// let pager = client.paginate_zones(&Pagination::new());
    /// assert!(!pager.is_truncated());
    /// # Ok(())
    /// # }
    /// # demo().unwrap();
    /// ```
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.walk.is_truncated()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_info_tolerates_missing_metadata() {
        let zone: ZoneInfo = serde_json::from_str(r#"{"domain":"x.de"}"#).unwrap();
        assert!(!zone.is_master());
        assert_eq!(zone.records.len(), 0);
    }

    #[test]
    fn checks_parse_a_single_message_string() {
        let check: NameserverCheck =
            serde_json::from_str(r#"{"ns":"ns1.x.de","status":"OK","message":"fine"}"#).unwrap();
        assert_eq!(check.message, ["fine"]);
        assert!(check.is_ok());
    }
}
