//! Nameserver zones (`nameserver.*`): zone metadata, the zone list, and the
//! delegation check.
//!
//! Records themselves live in [`crate::record`]; this module is about the zone
//! around them. Creating or updating a zone (`nameserver.create`,
//! `nameserver.update`, `nameserver.clone`, `nameserver.export`) is deliberately
//! out of scope — see the README — but reachable through
//! [`InwxClient::call`](crate::InwxClient::call).

use serde::Deserialize;
use serde_json::{json, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::pagination::{self, Listing, Page, Pages, Pagination};
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

/// The page rules [`Pages`] needs to walk `nameserver.list`.
///
/// ```
/// use inwx_client::{Page, ZoneListPage};
///
/// let page: ZoneListPage = serde_json::from_str(
///     r#"{"domains":[{"domain":"a.de"},{"domain":"b.de"}]}"#,
/// )?;
/// assert_eq!(page.total(), None);
/// assert_eq!(page.len(), 2);
/// # Ok::<(), serde_json::Error>(())
/// ```
impl Page for ZoneListPage {
    type Item = ZoneSummary;

    fn total(&self) -> Option<i64> {
        self.count
    }

    fn len(&self) -> usize {
        self.zones.len()
    }

    fn truncate_to(&mut self, len: usize) {
        self.zones.truncate(len);
    }

    fn into_items(self) -> Vec<ZoneSummary> {
        self.zones
    }
}

/// The `nameserver.list` command, ready to be walked page by page with
/// [`Pages`].
///
/// Without a filter the request carries only `page` and `pagelimit`, exactly
/// like [`InwxClient::list_zones`]. With one it
/// carries `domain` and `wide` like
/// [`InwxClient::find_zones`], so a filtered
/// search can be paginated too.
///
/// ```
/// use inwx_client::{Listing, ZoneListing};
///
/// assert_eq!(<ZoneListing as Listing>::METHOD, "nameserver.list");
/// assert_eq!(
///     ZoneListing::new().params(2, 25),
///     serde_json::json!({"page": 2, "pagelimit": 25})
/// );
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZoneListing {
    filter: Option<String>,
}

impl ZoneListing {
    /// Every zone of the account.
    ///
    /// ```
    /// use inwx_client::ZoneListing;
    ///
    /// assert_eq!(ZoneListing::new().filter(), None);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Only zones whose name matches `filter`, which may contain `*`
    /// wildcards.
    ///
    /// ```
    /// use inwx_client::{Listing, ZoneListing};
    ///
    /// let listing = ZoneListing::with_filter("tenant-*")?;
    /// assert_eq!(listing.filter(), Some("tenant-*"));
    /// assert_eq!(
    ///     listing.params(1, 10),
    ///     serde_json::json!({"domain": "tenant-*", "wide": 1, "page": 1, "pagelimit": 10})
    /// );
    /// assert!(ZoneListing::with_filter("   ").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the filter is
    /// empty — `*` is the documented way to ask for everything.
    pub fn with_filter(filter: &str) -> Result<Self> {
        let filter = filter.trim();
        if filter.is_empty() {
            return Err(Error::validation("domain", "must not be empty (use `*`)"));
        }
        Ok(Self {
            filter: Some(filter.to_owned()),
        })
    }

    /// The filter the walk is using, when it has one.
    ///
    /// ```
    /// use inwx_client::ZoneListing;
    ///
    /// assert_eq!(ZoneListing::new().filter(), None);
    /// assert_eq!(ZoneListing::with_filter("*").unwrap().filter(), Some("*"));
    /// ```
    #[must_use]
    pub fn filter(&self) -> Option<&str> {
        self.filter.as_deref()
    }
}

impl Listing for ZoneListing {
    type Page = ZoneListPage;

    const METHOD: &'static str = "nameserver.list";

    fn params(&self, page: u32, page_size: u32) -> Value {
        let params = match &self.filter {
            Some(filter) => json!({ "domain": filter, "wide": 1 }),
            None => json!({}),
        };
        pagination::with_paging(params, page, page_size)
    }
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
    /// For more than one page use
    /// [`InwxClient::list_all_zones`], which walks them.
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
    /// [`InwxClient::list_all_zones`] does the same requests in order and
    /// stops at a bound, so a caller does not have to count pages.
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

    /// Walks every page of the account's zones (`nameserver.list`).
    ///
    /// [`InwxClient::list_zones`] answers the
    /// first page only; this is the cursor for accounts with more zones than
    /// fit into one request. The bound in `pagination` decides how far the walk
    /// goes, and it is checked before the first request.
    ///
    /// ```
    /// # use inwx_client::{
    /// #     InwxClient, Pagination, Result, ZoneListing,
    /// #     transport::{Request, Response, Transport},
    /// # };
    /// # use std::sync::{Arc, Mutex};
    /// #[derive(Clone)]
    /// struct Scripted(Arc<Mutex<Vec<&'static str>>>);
    ///
    /// impl Transport for Scripted {
    ///     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    ///         let body = self.0.lock().unwrap().remove(0);
    ///         Ok(Response::new(200, std::iter::empty(), body.as_bytes().to_vec()))
    ///     }
    /// }
    ///
    /// # async fn demo() -> Result<Vec<String>> {
    /// let transport = Scripted(Arc::new(Mutex::new(vec![
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":3,"domains":[{"domain":"a.de"},{"domain":"b.de"}]}}"#,
    ///     r#"{"code":1000,"msg":"ok","resData":{"domains":[{"domain":"c.de"}]}}"#,
    /// ])));
    /// let client = InwxClient::new(transport).with_session("domrobot=test")?;
    /// let listing = ZoneListing::with_filter("*")?;
    /// let names = client
    ///     .list_all_zones(&listing, &Pagination::new().with_page_size(2)?)
    ///     .collect_all()
    ///     .await?
    ///     .iter()
    ///     .map(|zone| zone.domain.to_string())
    ///     .collect();
    /// # Ok(names)
    /// # }
    /// # assert_eq!(
    /// #     tokio::runtime::Runtime::new().unwrap().block_on(demo()).unwrap(),
    /// #     ["a.de", "b.de", "c.de"]
    /// # );
    /// ```
    ///
    /// # Errors
    ///
    /// The bound is validated when it is built (see
    /// [`Pagination::with_page_size`]) and
    /// so is the listing's filter
    /// ([`ZoneListing::with_filter`]); the walk itself reports the usual
    /// transport and API errors.
    pub fn list_all_zones(
        &self,
        listing: &ZoneListing,
        pagination: &Pagination,
    ) -> Pages<'_, T, ZoneListing> {
        Pages::new(self, listing.clone(), *pagination)
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
