//! Domains: availability, registration, renewal, contacts, nameservers, whois.
//!
//! Everything here is documented INWX surface (`domain.*`); the request builders
//! validate before the call, the response types parse permissively.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, DomainName, Hostname, Period, RenewalMode};

/// The answer to one `domain.check` entry.
///
/// INWX reports availability as `avail: 1` plus a `status` string (`free`,
/// `registered`, `invalid`, …). Both are kept: `is_available` accepts either, so
/// a TLD whose status string changes still classifies correctly.
///
/// ```
/// use inwx_client::DomainCheck;
///
/// let free: DomainCheck = serde_json::from_str(
///     r#"{"domain":"example.com","avail":1,"status":"free","price":8.9}"#,
/// )?;
/// assert!(free.is_available());
/// assert_eq!(free.price, Some(8.9));
///
/// let taken: DomainCheck = serde_json::from_str(
///     r#"{"domain":"example.com","avail":0,"status":"registered"}"#,
/// )?;
/// assert!(!taken.is_available());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DomainCheck {
    /// The domain that was checked.
    pub domain: String,
    /// Raw `avail` flag: `1` for available, `0` for taken.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub avail: Option<i64>,
    /// Availability status, for example `free` or `registered`.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
    /// Why a domain is not available, when the API says so.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub reason: Option<String>,
    /// Premium registration price, when the name is a premium domain.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub premium: Option<f64>,
    /// Registration or transfer price for this TLD.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub price: Option<f64>,
}

impl DomainCheck {
    /// Whether the domain can be registered.
    ///
    /// ```
    /// use inwx_client::DomainCheck;
    ///
    /// // `status` alone is enough when `avail` is missing.
    /// let check: DomainCheck = serde_json::from_str(r#"{"domain":"x.de","status":"free"}"#)?;
    /// assert!(check.is_available());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.avail == Some(1) || self.status.as_deref() == Some("free")
    }
}

/// Details of a registered domain (`domain.info` / `domain.list`).
///
/// Every field is optional on the wire — `domain.list` omits what `domain.info`
/// returns unless `wide` is set — so nothing here can fail a parse.
///
/// ```
/// use inwx_client::{DomainInfo, RenewalMode};
///
/// let info: DomainInfo = serde_json::from_str(
///     r#"{"roId":42,"domain":"example.com","status":"ok","exDate":"2027-01-31",
///         "transferLock":1,"renewalMode":"AUTORENEW","ns":["ns1.example.com"]}"#,
/// )?;
/// assert_eq!(info.ro_id, Some(42));
/// assert_eq!(info.renewal_mode, Some(RenewalMode::AutoRenew));
/// assert!(info.transfer_lock.unwrap());
/// assert_eq!(info.nameservers, ["ns1.example.com"]);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct DomainInfo {
    /// Repository object id (`roId`).
    #[serde(default, rename = "roId", deserialize_with = "de::opt_i64")]
    pub ro_id: Option<i64>,
    /// Domain name, in ACE form.
    #[serde(default)]
    pub domain: String,
    /// ASCII-compatible encoding of the name (`domain-ace`).
    #[serde(default, rename = "domain-ace", deserialize_with = "de::opt_string")]
    pub domain_ace: Option<String>,
    /// Registrar status, for example `ok`.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
    /// Registration period, for example `1Y`.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub period: Option<String>,
    /// Creation timestamp (`crDate`).
    #[serde(default, rename = "crDate", deserialize_with = "de::opt_string")]
    pub created_at: Option<String>,
    /// Expiry timestamp (`exDate`).
    #[serde(default, rename = "exDate", deserialize_with = "de::opt_string")]
    pub expires_at: Option<String>,
    /// Last update timestamp (`upDate`).
    #[serde(default, rename = "upDate", deserialize_with = "de::opt_string")]
    pub updated_at: Option<String>,
    /// Next renewal timestamp (`reDate`).
    #[serde(default, rename = "reDate", deserialize_with = "de::opt_string")]
    pub renews_at: Option<String>,
    /// Whether the transfer lock is set.
    #[serde(default, rename = "transferLock", deserialize_with = "de::opt_bool")]
    pub transfer_lock: Option<bool>,
    /// Renewal behaviour after expiry.
    #[serde(default, rename = "renewalMode")]
    pub renewal_mode: Option<RenewalMode>,
    /// Authorization code, only present with `wide=1`.
    #[serde(default, rename = "authCode", deserialize_with = "de::opt_string")]
    pub auth_code: Option<String>,
    /// Registrant contact handle.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub registrant: Option<i64>,
    /// Administrative contact handle.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub admin: Option<i64>,
    /// Technical contact handle.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub tech: Option<i64>,
    /// Billing contact handle.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub billing: Option<i64>,
    /// Delegated nameservers (`ns`).
    #[serde(default, rename = "ns", deserialize_with = "de::vec_string")]
    pub nameservers: Vec<String>,
    /// Whether the domain is delegated at all (`noDelegation`, inverted).
    #[serde(default, rename = "noDelegation", deserialize_with = "de::opt_bool")]
    pub no_delegation: Option<bool>,
    /// Contact verification status.
    #[serde(
        default,
        rename = "verificationStatus",
        deserialize_with = "de::opt_string"
    )]
    pub verification_status: Option<String>,
}

impl DomainInfo {
    /// Whether the domain is delegated to nameservers.
    ///
    /// ```
    /// use inwx_client::DomainInfo;
    ///
    /// let info: DomainInfo = serde_json::from_str(r#"{"domain":"example.com","ns":["ns1.example.com"]}"#)?;
    /// assert!(info.is_delegated());
    ///
    /// let parked: DomainInfo = serde_json::from_str(r#"{"domain":"example.com","noDelegation":1}"#)?;
    /// assert!(!parked.is_delegated());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_delegated(&self) -> bool {
        self.no_delegation != Some(true) && !self.nameservers.is_empty()
    }

    /// The registrant handle, if the API reported one.
    ///
    /// ```
    /// use inwx_client::DomainInfo;
    /// let info: DomainInfo = serde_json::from_str(r#"{"domain":"x.de","registrant":991}"#)?;
    /// assert_eq!(info.registrant_handle(), Some(991));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn registrant_handle(&self) -> Option<i64> {
        self.registrant
    }
}

/// One page of `domain.list`.
///
/// ```
/// use inwx_client::DomainListPage;
///
/// let page: DomainListPage = serde_json::from_str(
///     r#"{"count":2,"domain":[{"domain":"a.de"},{"domain":"b.com"}]}"#,
/// )?;
/// assert_eq!(page.len(), 2);
/// assert_eq!(page.count, Some(2));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct DomainListPage {
    /// Total number of domains matching the filter, not just this page.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The domains on this page.
    #[serde(default, rename = "domain")]
    pub domains: Vec<DomainInfo>,
}

impl DomainListPage {
    /// Number of domains on this page.
    ///
    /// ```
    /// use inwx_client::DomainListPage;
    /// let page: DomainListPage = serde_json::from_str(r#"{"domain":[]}"#)?;
    /// assert_eq!(page.len(), 0);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    /// Whether this page is empty.
    ///
    /// ```
    /// use inwx_client::DomainListPage;
    /// assert_eq!(DomainListPage::default().len(), 0);
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Whether more pages exist, comparing the page length to `count`.
    ///
    /// ```
    /// use inwx_client::DomainListPage;
    ///
    /// let page: DomainListPage = serde_json::from_str(
    ///     r#"{"count":40,"domain":[{"domain":"a.de"}]}"#,
    /// )?;
    /// assert!(page.has_more());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.count
            .is_some_and(|count| i64::try_from(self.domains.len()).unwrap_or(i64::MAX) < count)
    }
}

/// A request to register a domain (`domain.create`).
///
/// `registrant` is required by the API; `admin`, `tech` and `billing` fall back
/// to the account defaults when omitted.
///
/// ```
/// use inwx_client::{DomainCreate, DomainName, Hostname, Period};
///
/// let request = DomainCreate::new(DomainName::parse("example.com")?, 991)?
///     .with_period(Period::years(2)?)
///     .with_nameservers(&[
///         Hostname::parse("ns1.example.com")?,
///         Hostname::parse("ns2.example.com")?,
///     ]);
/// let params = request.params();
/// assert_eq!(params["domain"], "example.com");
/// assert_eq!(params["period"], "2Y");
/// assert_eq!(params["ns"][1], "ns2.example.com");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct DomainCreate {
    domain: DomainName,
    registrant: i64,
    admin: Option<i64>,
    tech: Option<i64>,
    billing: Option<i64>,
    period: Option<Period>,
    nameservers: Vec<Hostname>,
    transfer_lock: Option<bool>,
    renewal_mode: Option<RenewalMode>,
    agreed_price: Option<f64>,
    voucher: Option<String>,
}

impl DomainCreate {
    /// A registration with the registrant handle and nothing else.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the handle is not a positive id.
    pub fn new(domain: DomainName, registrant: i64) -> Result<Self> {
        if registrant <= 0 {
            return Err(Error::validation(
                "registrant",
                format!("must be a positive contact handle, got {registrant}"),
            ));
        }
        Ok(Self {
            domain,
            registrant,
            admin: None,
            tech: None,
            billing: None,
            period: None,
            nameservers: Vec::new(),
            transfer_lock: None,
            renewal_mode: None,
            agreed_price: None,
            voucher: None,
        })
    }

    /// Sets the registration period (default: the TLD's minimum).
    ///
    /// ```
    /// use inwx_client::{DomainCreate, DomainName, Period};
    ///
    /// let request = DomainCreate::new(DomainName::parse("a.de")?, 1)?.with_period(Period::ONE_MONTH);
    /// assert_eq!(request.params()["period"], "1M");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_period(mut self, period: Period) -> Self {
        self.period = Some(period);
        self
    }

    /// Sets the administrative contact handle.
    ///
    /// ```
    /// use inwx_client::{DomainCreate, DomainName};
    ///
    /// let request = DomainCreate::new(DomainName::parse("a.de")?, 1)?.with_admin(2);
    /// assert_eq!(request.params()["admin"], 2);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_admin(mut self, handle: i64) -> Self {
        self.admin = Some(handle);
        self
    }

    /// Sets the technical contact handle.
    ///
    /// ```
    /// use inwx_client::{DomainCreate, DomainName};
    ///
    /// let request = DomainCreate::new(DomainName::parse("a.de")?, 1)?.with_tech(3);
    /// assert_eq!(request.params()["tech"], 3);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_tech(mut self, handle: i64) -> Self {
        self.tech = Some(handle);
        self
    }

    /// Sets the billing contact handle.
    ///
    /// ```
    /// use inwx_client::{DomainCreate, DomainName};
    ///
    /// let request = DomainCreate::new(DomainName::parse("a.de")?, 1)?.with_billing(4);
    /// assert_eq!(request.params()["billing"], 4);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_billing(mut self, handle: i64) -> Self {
        self.billing = Some(handle);
        self
    }

    /// Sets the nameservers to delegate to.
    ///
    /// ```
    /// use inwx_client::{DomainCreate, DomainName, Hostname};
    ///
    /// let request = DomainCreate::new(DomainName::parse("a.de")?, 1)?
    ///     .with_nameservers(&[Hostname::parse("ns1.example.com")?]);
    /// assert_eq!(request.params()["ns"][0], "ns1.example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_nameservers(mut self, nameservers: &[Hostname]) -> Self {
        self.nameservers = nameservers.to_vec();
        self
    }

    /// Sets the transfer lock (the API defaults it to on).
    ///
    /// ```
    /// use inwx_client::{DomainCreate, DomainName};
    ///
    /// let request = DomainCreate::new(DomainName::parse("a.de")?, 1)?.with_transfer_lock(false);
    /// assert_eq!(request.params()["transferLock"], false);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_transfer_lock(mut self, locked: bool) -> Self {
        self.transfer_lock = Some(locked);
        self
    }

    /// Sets what happens at expiry.
    ///
    /// ```
    /// use inwx_client::{DomainCreate, DomainName, RenewalMode};
    ///
    /// let request = DomainCreate::new(DomainName::parse("a.de")?, 1)?
    ///     .with_renewal_mode(RenewalMode::AutoExpire);
    /// assert_eq!(request.params()["renewalMode"], "AUTOEXPIRE");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_renewal_mode(mut self, mode: RenewalMode) -> Self {
        self.renewal_mode = Some(mode);
        self
    }

    /// Sets the price the caller agreed to for a premium domain.
    ///
    /// Required by accounts that enabled `isPremiumAgreedPriceRequired`.
    ///
    /// ```
    /// use inwx_client::{DomainCreate, DomainName};
    ///
    /// let request = DomainCreate::new(DomainName::parse("premium.de")?, 1)?.with_agreed_price(250.0);
    /// assert_eq!(request.params()["agreedPrice"], 250.0);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_agreed_price(mut self, price: f64) -> Self {
        self.agreed_price = Some(price);
        self
    }

    /// Sets a voucher code.
    ///
    /// ```
    /// use inwx_client::{DomainCreate, DomainName};
    ///
    /// let request = DomainCreate::new(DomainName::parse("a.de")?, 1)?.with_voucher("SUMMER26");
    /// assert_eq!(request.params()["voucher"], "SUMMER26");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_voucher(mut self, voucher: impl Into<String>) -> Self {
        self.voucher = Some(voucher.into());
        self
    }

    /// The domain being registered.
    ///
    /// ```
    /// use inwx_client::{DomainCreate, DomainName};
    /// let request = DomainCreate::new(DomainName::parse("a.de")?, 1)?;
    /// assert_eq!(request.domain().as_str(), "a.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// The `domain.create` parameters.
    ///
    /// ```
    /// use inwx_client::{DomainCreate, DomainName};
    ///
    /// let params = DomainCreate::new(DomainName::parse("a.de")?, 7)?.params();
    /// assert_eq!(params["registrant"], 7);
    /// assert_eq!(params["domain"], "a.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut params = Map::new();
        params.insert("domain".to_owned(), json!(self.domain));
        params.insert("registrant".to_owned(), json!(self.registrant));
        if let Some(handle) = self.admin {
            params.insert("admin".to_owned(), json!(handle));
        }
        if let Some(handle) = self.tech {
            params.insert("tech".to_owned(), json!(handle));
        }
        if let Some(handle) = self.billing {
            params.insert("billing".to_owned(), json!(handle));
        }
        if let Some(period) = self.period {
            params.insert("period".to_owned(), json!(period));
        }
        if !self.nameservers.is_empty() {
            params.insert("ns".to_owned(), json!(self.nameservers));
        }
        if let Some(locked) = self.transfer_lock {
            params.insert("transferLock".to_owned(), json!(locked));
        }
        if let Some(mode) = &self.renewal_mode {
            params.insert("renewalMode".to_owned(), json!(mode));
        }
        if let Some(price) = self.agreed_price {
            params.insert("agreedPrice".to_owned(), json!(price));
        }
        if let Some(voucher) = &self.voucher {
            params.insert("voucher".to_owned(), json!(voucher));
        }
        Value::Object(params)
    }
}

/// A change to an existing domain (`domain.update`).
///
/// Only the fields that were set are sent; everything else stays as it is.
///
/// ```
/// use inwx_client::{DomainName, DomainUpdate, RenewalMode};
///
/// let update = DomainUpdate::new(DomainName::parse("example.com")?)
///     .with_transfer_lock(true)
///     .with_renewal_mode(RenewalMode::AutoRenew);
/// let params = update.params()?;
/// assert_eq!(params["transferLock"], true);
/// assert_eq!(params["renewalMode"], "AUTORENEW");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct DomainUpdate {
    domain: DomainName,
    registrant: Option<i64>,
    admin: Option<i64>,
    tech: Option<i64>,
    billing: Option<i64>,
    period: Option<Period>,
    nameservers: Option<Vec<Hostname>>,
    transfer_lock: Option<bool>,
    renewal_mode: Option<RenewalMode>,
    auth_code: Option<String>,
}

impl DomainUpdate {
    /// An empty update for `domain`; add at least one change before calling
    /// [`DomainUpdate::params`].
    ///
    /// ```
    /// use inwx_client::{DomainName, DomainUpdate};
    /// assert!(DomainUpdate::new(DomainName::parse("a.de")?).params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn new(domain: DomainName) -> Self {
        Self {
            domain,
            registrant: None,
            admin: None,
            tech: None,
            billing: None,
            period: None,
            nameservers: None,
            transfer_lock: None,
            renewal_mode: None,
            auth_code: None,
        }
    }

    /// Changes the owner handle.
    ///
    /// ```
    /// use inwx_client::{DomainName, DomainUpdate};
    /// let params = DomainUpdate::new(DomainName::parse("a.de")?).with_registrant(5).params()?;
    /// assert_eq!(params["registrant"], 5);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_registrant(mut self, handle: i64) -> Self {
        self.registrant = Some(handle);
        self
    }

    /// Changes the administrative handle.
    ///
    /// ```
    /// use inwx_client::{DomainName, DomainUpdate};
    /// let params = DomainUpdate::new(DomainName::parse("a.de")?).with_admin(5).params()?;
    /// assert_eq!(params["admin"], 5);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_admin(mut self, handle: i64) -> Self {
        self.admin = Some(handle);
        self
    }

    /// Changes the technical handle.
    ///
    /// ```
    /// use inwx_client::{DomainName, DomainUpdate};
    /// let params = DomainUpdate::new(DomainName::parse("a.de")?).with_tech(5).params()?;
    /// assert_eq!(params["tech"], 5);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_tech(mut self, handle: i64) -> Self {
        self.tech = Some(handle);
        self
    }

    /// Changes the billing handle.
    ///
    /// ```
    /// use inwx_client::{DomainName, DomainUpdate};
    /// let params = DomainUpdate::new(DomainName::parse("a.de")?).with_billing(5).params()?;
    /// assert_eq!(params["billing"], 5);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_billing(mut self, handle: i64) -> Self {
        self.billing = Some(handle);
        self
    }

    /// Replaces the nameserver set.
    ///
    /// ```
    /// use inwx_client::{DomainName, DomainUpdate, Hostname};
    /// let params = DomainUpdate::new(DomainName::parse("a.de")?)
    ///     .with_nameservers(&[Hostname::parse("ns1.example.com")?])
    ///     .params()?;
    /// assert_eq!(params["ns"][0], "ns1.example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_nameservers(mut self, nameservers: &[Hostname]) -> Self {
        self.nameservers = Some(nameservers.to_vec());
        self
    }

    /// Sets or clears the transfer lock.
    ///
    /// ```
    /// use inwx_client::{DomainName, DomainUpdate};
    /// let params = DomainUpdate::new(DomainName::parse("a.de")?).with_transfer_lock(false).params()?;
    /// assert_eq!(params["transferLock"], false);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_transfer_lock(mut self, locked: bool) -> Self {
        self.transfer_lock = Some(locked);
        self
    }

    /// Sets the renewal behaviour.
    ///
    /// ```
    /// use inwx_client::{DomainName, DomainUpdate, RenewalMode};
    /// let params = DomainUpdate::new(DomainName::parse("a.de")?)
    ///     .with_renewal_mode(RenewalMode::AutoDelete)
    ///     .params()?;
    /// assert_eq!(params["renewalMode"], "AUTODELETE");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_renewal_mode(mut self, mode: RenewalMode) -> Self {
        self.renewal_mode = Some(mode);
        self
    }

    /// Sets the authorization code (for TLDs that require one on update).
    ///
    /// ```
    /// use inwx_client::{DomainName, DomainUpdate};
    /// let params = DomainUpdate::new(DomainName::parse("a.de")?).with_auth_code("ABC123").params()?;
    /// assert_eq!(params["authCode"], "ABC123");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_auth_code(mut self, auth_code: impl Into<String>) -> Self {
        self.auth_code = Some(auth_code.into());
        self
    }

    /// Sets the registration period.
    ///
    /// ```
    /// use inwx_client::{DomainName, DomainUpdate, Period};
    /// let params = DomainUpdate::new(DomainName::parse("a.de")?)
    ///     .with_period(Period::years(3)?)
    ///     .params()?;
    /// assert_eq!(params["period"], "3Y");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_period(mut self, period: Period) -> Self {
        self.period = Some(period);
        self
    }

    /// The `domain.update` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when nothing was changed.
    pub fn params(&self) -> Result<Value> {
        if self.registrant.is_none()
            && self.admin.is_none()
            && self.tech.is_none()
            && self.billing.is_none()
            && self.period.is_none()
            && self.nameservers.is_none()
            && self.transfer_lock.is_none()
            && self.renewal_mode.is_none()
            && self.auth_code.is_none()
        {
            return Err(Error::validation(
                "domain",
                "an update needs at least one changed field",
            ));
        }
        let mut params = Map::new();
        params.insert("domain".to_owned(), json!(self.domain));
        if let Some(handle) = self.registrant {
            params.insert("registrant".to_owned(), json!(handle));
        }
        if let Some(handle) = self.admin {
            params.insert("admin".to_owned(), json!(handle));
        }
        if let Some(handle) = self.tech {
            params.insert("tech".to_owned(), json!(handle));
        }
        if let Some(handle) = self.billing {
            params.insert("billing".to_owned(), json!(handle));
        }
        if let Some(period) = self.period {
            params.insert("period".to_owned(), json!(period));
        }
        if let Some(nameservers) = &self.nameservers {
            params.insert("ns".to_owned(), json!(nameservers));
        }
        if let Some(locked) = self.transfer_lock {
            params.insert("transferLock".to_owned(), json!(locked));
        }
        if let Some(mode) = &self.renewal_mode {
            params.insert("renewalMode".to_owned(), json!(mode));
        }
        if let Some(auth_code) = &self.auth_code {
            params.insert("authCode".to_owned(), json!(auth_code));
        }
        Ok(Value::Object(params))
    }
}

/// A filter + paging for `domain.list`.
///
/// ```
/// use inwx_client::DomainListQuery;
///
/// let query = DomainListQuery::new().with_filter("example").with_page(2, 50);
/// let params = query.params();
/// assert_eq!(params["page"], 2);
/// assert_eq!(params["pagelimit"], 50);
/// assert_eq!(params["domain"][0], "example");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DomainListQuery {
    filter: Option<String>,
    status: Vec<String>,
    page: Option<u32>,
    limit: Option<u32>,
}

impl DomainListQuery {
    /// An unfiltered query for the first page.
    ///
    /// ```
    /// use inwx_client::DomainListQuery;
    /// assert_eq!(DomainListQuery::new().params(), serde_json::json!({}));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by a substring of the domain name.
    ///
    /// ```
    /// use inwx_client::DomainListQuery;
    /// let params = DomainListQuery::new().with_filter("acme").params();
    /// assert_eq!(params["domain"][0], "acme");
    /// ```
    #[must_use]
    pub fn with_filter(mut self, filter: impl Into<String>) -> Self {
        self.filter = Some(filter.into());
        self
    }

    /// Filters by registrar status, for example `ok` or `hold`.
    ///
    /// ```
    /// use inwx_client::DomainListQuery;
    /// let params = DomainListQuery::new().with_status(["ok"]).params();
    /// assert_eq!(params["status"][0], "ok");
    /// ```
    #[must_use]
    pub fn with_status(mut self, status: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.status = status.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the page (1-based) and the page size.
    ///
    /// ```
    /// use inwx_client::DomainListQuery;
    /// let params = DomainListQuery::new().with_page(3, 10).params();
    /// assert_eq!(params["page"], 3);
    /// ```
    #[must_use]
    pub fn with_page(mut self, page: u32, limit: u32) -> Self {
        self.page = Some(page);
        self.limit = Some(limit);
        self
    }

    /// The `domain.list` parameters.
    ///
    /// ```
    /// use inwx_client::DomainListQuery;
    /// assert_eq!(DomainListQuery::new().params(), serde_json::json!({}));
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut params = Map::new();
        if let Some(filter) = &self.filter {
            params.insert("domain".to_owned(), json!([filter]));
        }
        if !self.status.is_empty() {
            params.insert("status".to_owned(), json!(self.status));
        }
        if let Some(page) = self.page {
            params.insert("page".to_owned(), json!(page));
        }
        if let Some(limit) = self.limit {
            params.insert("pagelimit".to_owned(), json!(limit));
        }
        Value::Object(params)
    }
}

/// A manual renewal (`domain.renew`).
///
/// The API requires the current expiry date alongside the period, so a renewal
/// cannot silently stack on a domain that was renewed in the meantime.
///
/// ```
/// use inwx_client::{DomainName, DomainRenew, Period};
///
/// let renew = DomainRenew::new(DomainName::parse("example.com")?, Period::years(1)?, "2027-01-31")?;
/// let params = renew.params();
/// assert_eq!(params["period"], "1Y");
/// assert_eq!(params["expiration"], "2027-01-31");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRenew {
    domain: DomainName,
    period: Period,
    expiration: String,
}

impl DomainRenew {
    /// A renewal of `domain` for `period`, effective from `expiration`.
    ///
    /// `expiration` is the date the API reported (`exDate`), in the same
    /// format — it is opaque here and passed through unchanged.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the expiration date is empty or contains
    /// control characters.
    pub fn new(domain: DomainName, period: Period, expiration: impl Into<String>) -> Result<Self> {
        let expiration = expiration.into();
        if expiration.trim().is_empty() {
            return Err(Error::validation("expiration", "must not be empty"));
        }
        crate::types::reject_control_chars("expiration", &expiration)?;
        Ok(Self {
            domain,
            period,
            expiration,
        })
    }

    /// The `domain.renew` parameters.
    ///
    /// ```
    /// use inwx_client::{DomainName, DomainRenew, Period};
    ///
    /// let params = DomainRenew::new(DomainName::parse("a.de")?, Period::years(2)?, "2027-02-01")?.params();
    /// assert_eq!(params["domain"], "a.de");
    /// assert_eq!(params["period"], "2Y");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        json!({
            "domain": self.domain,
            "period": self.period,
            "expiration": self.expiration,
        })
    }
}

/// The outcome of a successful `domain.create`.
///
/// ```
/// use inwx_client::Registration;
///
/// let registration: Registration = serde_json::from_str(
///     r#"{"roId":42,"price":8.9,"currency":"EUR"}"#,
/// )?;
/// assert_eq!(registration.ro_id, 42);
/// assert_eq!(registration.currency.as_deref(), Some("EUR"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Registration {
    /// Repository object id of the new domain.
    #[serde(default, rename = "roId", deserialize_with = "de::i64_with_default")]
    pub ro_id: i64,
    /// Amount charged, when the API reports it.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub price: Option<f64>,
    /// Currency of `price`.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
}

/// The outcome of a successful `domain.renew`.
///
/// ```
/// use inwx_client::RenewalResult;
///
/// let renewal: RenewalResult = serde_json::from_str(
///     r#"{"exDate":"2028-01-31","reDate":"2027-01-31","price":8.9}"#,
/// )?;
/// assert_eq!(renewal.expires_at.as_deref(), Some("2028-01-31"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct RenewalResult {
    /// New expiry date.
    #[serde(default, rename = "exDate", deserialize_with = "de::opt_string")]
    pub expires_at: Option<String>,
    /// Next renewal date.
    #[serde(default, rename = "reDate", deserialize_with = "de::opt_string")]
    pub renews_at: Option<String>,
    /// Amount charged.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub price: Option<f64>,
    /// Currency of `price`.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
}

/// The parameters shared by `domain.setClientHold` and `domain.removeClientHold`.
///
/// Both take the same two fields, so the body is built in one place and the two
/// request types cannot drift apart.
fn client_hold_params(domain: &DomainName, testing: bool) -> Value {
    let mut params = Map::new();
    params.insert("domain".to_owned(), json!(domain));
    params.insert("testing".to_owned(), json!(testing));
    Value::Object(params)
}

/// Parses a clientHold answer, tolerating the empty `resData` INWX sends for a
/// command that changed nothing measurable.
fn parse_client_hold(data: Value) -> Result<ClientHoldResult> {
    if data.is_null() {
        return Ok(ClientHoldResult::default());
    }
    serde_json::from_value(data).map_err(Error::from)
}

/// A request to park a domain at the registry (`domain.setClientHold`).
///
/// `clientHold` is the ICANN status that pulls a domain out of the registry
/// zone: it stops resolving, and it blocks most registry operations until
/// [`RemoveClientHold`] lifts it again. Only the name is needed; the hold itself
/// carries no parameters.
///
/// The command is idempotent in effect — holding a held domain is not an
/// error — but it is still a mutation, so the client never replays it after an
/// uncertain transport failure (see [`set_client_hold`](InwxClient::set_client_hold)).
///
/// ```
/// use inwx_client::{DomainName, SetClientHold};
///
/// let request = SetClientHold::new(DomainName::parse("example.com")?);
/// let params = request.params();
/// assert_eq!(params["domain"], "example.com");
/// assert_eq!(params["testing"], false);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetClientHold {
    domain: DomainName,
    testing: bool,
}

impl SetClientHold {
    /// A hold request for `domain`, sent for real unless [`Self::dry_run`] is
    /// added.
    ///
    /// ```
    /// use inwx_client::{DomainName, SetClientHold};
    ///
    /// let request = SetClientHold::new(DomainName::parse("example.com")?);
    /// assert_eq!(request.domain().as_str(), "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn new(domain: DomainName) -> Self {
        Self {
            domain,
            testing: false,
        }
    }

    /// The domain the hold applies to.
    ///
    /// ```
    /// use inwx_client::{DomainName, SetClientHold};
    ///
    /// let request = SetClientHold::new(DomainName::parse("a.de")?);
    /// assert_eq!(request.domain(), &DomainName::parse("a.de")?);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// Runs the command in testing mode (`testing=true`): the API validates but
    /// holds nothing.
    ///
    /// ```
    /// use inwx_client::{DomainName, SetClientHold};
    ///
    /// let request = SetClientHold::new(DomainName::parse("a.de")?).dry_run();
    /// assert_eq!(request.params()["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.testing = true;
        self
    }

    /// The `domain.setClientHold` parameters: `domain` plus the explicit
    /// `testing` flag.
    ///
    /// ```
    /// use inwx_client::{DomainName, SetClientHold};
    ///
    /// let params = SetClientHold::new(DomainName::parse("a.de")?).params();
    /// assert_eq!(params["domain"], "a.de");
    /// assert_eq!(params["testing"], false);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        client_hold_params(&self.domain, self.testing)
    }
}

/// A request to lift a registry hold (`domain.removeClientHold`).
///
/// INWX documents that removal only succeeds when the hold was set by the same
/// account — a hold placed by another registrar or by INWX support has to go
/// through that party, and the API rejects the command otherwise.
///
/// ```
/// use inwx_client::{DomainName, RemoveClientHold};
///
/// let request = RemoveClientHold::new(DomainName::parse("example.com")?).dry_run();
/// let params = request.params();
/// assert_eq!(params["domain"], "example.com");
/// assert_eq!(params["testing"], true);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveClientHold {
    domain: DomainName,
    testing: bool,
}

impl RemoveClientHold {
    /// A release request for `domain`, sent for real unless [`Self::dry_run`]
    /// is added.
    ///
    /// ```
    /// use inwx_client::{DomainName, RemoveClientHold};
    ///
    /// let request = RemoveClientHold::new(DomainName::parse("example.com")?);
    /// assert_eq!(request.domain().as_str(), "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn new(domain: DomainName) -> Self {
        Self {
            domain,
            testing: false,
        }
    }

    /// The domain the release applies to.
    ///
    /// ```
    /// use inwx_client::{DomainName, RemoveClientHold};
    ///
    /// let request = RemoveClientHold::new(DomainName::parse("a.de")?);
    /// assert_eq!(request.domain(), &DomainName::parse("a.de")?);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// Runs the command in testing mode (`testing=true`): the API validates but
    /// releases nothing.
    ///
    /// ```
    /// use inwx_client::{DomainName, RemoveClientHold};
    ///
    /// let request = RemoveClientHold::new(DomainName::parse("a.de")?).dry_run();
    /// assert_eq!(request.params()["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.testing = true;
        self
    }

    /// The `domain.removeClientHold` parameters: `domain` plus the explicit
    /// `testing` flag.
    ///
    /// ```
    /// use inwx_client::{DomainName, RemoveClientHold};
    ///
    /// let params = RemoveClientHold::new(DomainName::parse("a.de")?).params();
    /// assert_eq!(params["domain"], "a.de");
    /// assert_eq!(params["testing"], false);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        client_hold_params(&self.domain, self.testing)
    }
}

/// What a `domain.setClientHold` / `domain.removeClientHold` call reports.
///
/// The documented answer is the repository object id of the domain. It is
/// optional here because a no-op answer can carry an empty `resData`, and it is
/// read permissively because INWX also sends ids as strings.
///
/// ```
/// use inwx_client::ClientHoldResult;
///
/// let held: ClientHoldResult = serde_json::from_str(r#"{"roId":42,"brandNew":"field"}"#)?;
/// assert_eq!(held.ro_id, Some(42));
///
/// // The same id as a string, and an answer that carries nothing at all.
/// let stringy: ClientHoldResult = serde_json::from_str(r#"{"roId":"42"}"#)?;
/// assert_eq!(stringy, held);
/// assert_eq!(ClientHoldResult::default().ro_id, None);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ClientHoldResult {
    /// Repository object id of the domain, when the API reports it.
    #[serde(default, rename = "roId", deserialize_with = "de::opt_i64")]
    pub ro_id: Option<i64>,
}

impl<T: Transport> InwxClient<T> {
    /// Checks one or more domains for availability (`domain.check`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let names = [DomainName::parse("example.com")?, DomainName::parse("example.de")?];
    /// for check in client.check_domains(&names).await? {
    ///     println!("{} {}", check.domain, check.is_available());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty list, plus the usual transport and API
    /// errors.
    pub async fn check_domains(&self, domains: &[DomainName]) -> Result<Vec<DomainCheck>> {
        if domains.is_empty() {
            return Err(Error::validation(
                "domain",
                "at least one domain is required",
            ));
        }
        let names = domains.iter().map(DomainName::as_str).collect::<Vec<_>>();
        let data = self
            .call("domain.check", json!({ "domain": names, "wide": 1 }))
            .await?;
        let entries = match data.get("domain") {
            Some(Value::Array(entries)) => entries.clone(),
            Some(single @ Value::Object(_)) => vec![single.clone()],
            _ => Vec::new(),
        };
        Ok(entries
            .into_iter()
            .filter_map(|entry| serde_json::from_value(entry).ok())
            .collect())
    }

    /// Checks a single domain (`domain.check`).
    ///
    /// Returns [`Error::MissingField`] when the API answers with an empty list,
    /// which happens for a malformed name rather than for a taken domain.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let check = client.check_domain(&DomainName::parse("example.com")?).await?;
    /// assert!(check.is_available());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::MissingField`] when the answer carries no entry, plus the usual
    /// transport and API errors.
    pub async fn check_domain(&self, domain: &DomainName) -> Result<DomainCheck> {
        let mut checks = self.check_domains(std::slice::from_ref(domain)).await?;
        if checks.is_empty() {
            return Err(Error::MissingField {
                method: "domain.check",
                field: "resData.domain[0]",
            });
        }
        Ok(checks.remove(0))
    }

    /// Registers a domain (`domain.create`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainCreate, DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let request = DomainCreate::new(DomainName::parse("example.com")?, 991)?;
    /// let registration = client.register_domain(&request).await?;
    /// println!("roId {}", registration.ro_id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors. A synchronous registration answers
    /// with code `1000`; an asynchronous one answers `1001` (action pending),
    /// which this crate treats as success.
    pub async fn register_domain(&self, request: &DomainCreate) -> Result<Registration> {
        let data = self.call("domain.create", request.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Reads domain details (`domain.info`), including the auth code.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let info = client.domain_info(&DomainName::parse("example.com")?).await?;
    /// println!("{:?} {:?}", info.status, info.expires_at);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn domain_info(&self, domain: &DomainName) -> Result<DomainInfo> {
        let data = self
            .call(
                "domain.info",
                json!({ "domain": domain.as_str(), "wide": 1 }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Lists the account's domains (`domain.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainListQuery, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let page = client.list_domains(&DomainListQuery::new().with_page(1, 100)).await?;
    /// for domain in &page.domains {
    ///     println!("{}", domain.domain);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn list_domains(&self, query: &DomainListQuery) -> Result<DomainListPage> {
        let data = self.call("domain.list", query.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Changes contacts, nameservers, lock or renewal mode (`domain.update`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, DomainUpdate, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let update = DomainUpdate::new(DomainName::parse("example.com")?).with_transfer_lock(true);
    /// client.update_domain(&update).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`DomainUpdate::params`], plus the usual
    /// transport and API errors.
    pub async fn update_domain(&self, update: &DomainUpdate) -> Result<()> {
        self.call("domain.update", update.params()?).await?;
        Ok(())
    }

    /// Renews a domain for another period (`domain.renew`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, DomainRenew, InwxClient, Period, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let domain = DomainName::parse("example.com")?;
    /// let expires = client.domain_info(&domain).await?.expires_at.unwrap_or_default();
    /// let renewal = client
    ///     .renew_domain(&DomainRenew::new(domain, Period::years(1)?, expires)?)
    ///     .await?;
    /// println!("now expires {:?}", renewal.expires_at);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn renew_domain(&self, request: &DomainRenew) -> Result<RenewalResult> {
        let data = self.call("domain.renew", request.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Deletes a domain immediately (`domain.delete`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.delete_domain(&DomainName::parse("example.com")?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors — including `2304`, which means the
    /// domain is in a state that forbids deletion.
    pub async fn delete_domain(&self, domain: &DomainName) -> Result<()> {
        self.call("domain.delete", json!({ "domain": domain.as_str() }))
            .await?;
        Ok(())
    }

    /// Sets what happens when the domain expires (`domain.update`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, RenewalMode, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client
    ///     .set_renewal_mode(&DomainName::parse("example.com")?, RenewalMode::AutoRenew)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn set_renewal_mode(&self, domain: &DomainName, mode: RenewalMode) -> Result<()> {
        self.update_domain(&DomainUpdate::new(domain.clone()).with_renewal_mode(mode))
            .await
    }

    /// Locks or unlocks the transfer (`domain.update`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.set_transfer_lock(&DomainName::parse("example.com")?, true).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn set_transfer_lock(&self, domain: &DomainName, locked: bool) -> Result<()> {
        self.update_domain(&DomainUpdate::new(domain.clone()).with_transfer_lock(locked))
            .await
    }

    /// Puts the domain on registry hold (`domain.setClientHold`).
    ///
    /// The registry removes the domain from its zone, so it stops resolving and
    /// most registry operations are blocked until
    /// [`remove_client_hold`](Self::remove_client_hold) lifts the hold. `testing`
    /// is off unless the request opts in with
    /// [`SetClientHold::dry_run`], which validates without touching the domain.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport, SetClientHold};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let held = client
    ///     .set_client_hold(&SetClientHold::new(DomainName::parse("example.com")?))
    ///     .await?;
    /// println!("roId {:?}", held.ro_id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Never retried automatically: this is a mutating command, so an
    /// [`Error::Uncertain`] transport failure (timeout, reset mid-response) is
    /// handed back with exactly one attempt made, because the hold may already
    /// be set. Check the current state with [`Self::domain_info`] before
    /// retrying. On top of that, the usual transport, API and JSON errors —
    /// `2303` when the domain is not in this account.
    pub async fn set_client_hold(&self, request: &SetClientHold) -> Result<ClientHoldResult> {
        let data = self.call("domain.setClientHold", request.params()).await?;
        parse_client_hold(data)
    }

    /// Lifts a registry hold set by this account (`domain.removeClientHold`).
    ///
    /// INWX documents that removal only succeeds when the same account set the
    /// hold; a hold placed by another registrar or by INWX support has to be
    /// released by that party, and the API rejects the command otherwise.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, RemoveClientHold, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let released = client
    ///     .remove_client_hold(&RemoveClientHold::new(DomainName::parse("example.com")?))
    ///     .await?;
    /// println!("roId {:?}", released.ro_id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Same policy as [`Self::set_client_hold`]: a mutating command is never
    /// replayed, so [`Error::Uncertain`] comes back after a single attempt and
    /// [`Self::domain_info`] decides whether the hold is already gone. Plus the
    /// usual transport, API and JSON errors.
    pub async fn remove_client_hold(&self, request: &RemoveClientHold) -> Result<ClientHoldResult> {
        let data = self
            .call("domain.removeClientHold", request.params())
            .await?;
        parse_client_hold(data)
    }

    /// Reads the authorization code (`domain.info` with `wide=1`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let code = client.auth_code(&DomainName::parse("example.com")?).await?;
    /// println!("{code}");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::MissingField`] when the TLD has no auth code, plus the usual
    /// transport and API errors.
    pub async fn auth_code(&self, domain: &DomainName) -> Result<String> {
        let info = self.domain_info(domain).await?;
        info.auth_code.ok_or(Error::MissingField {
            method: "domain.info",
            field: "resData.authCode",
        })
    }

    /// Reads the raw whois output (`domain.whois`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let whois = client.whois(&DomainName::parse("example.com")?).await?;
    /// println!("{whois}");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::MissingField`] when the answer carries no `whois` field, plus
    /// the usual transport and API errors.
    pub async fn whois(&self, domain: &DomainName) -> Result<String> {
        let data = self
            .call("domain.whois", json!({ "domain": domain.as_str() }))
            .await?;
        data.get("whois")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(Error::MissingField {
                method: "domain.whois",
                field: "resData.whois",
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_uses_both_signals() {
        let by_flag: DomainCheck =
            serde_json::from_str(r#"{"domain":"x.de","avail":1,"status":"invalid"}"#).unwrap();
        assert!(by_flag.is_available());

        let by_status: DomainCheck =
            serde_json::from_str(r#"{"domain":"x.de","status":"free"}"#).unwrap();
        assert!(by_status.is_available());

        let taken: DomainCheck =
            serde_json::from_str(r#"{"domain":"x.de","avail":"0","status":"registered"}"#).unwrap();
        assert!(!taken.is_available());
    }

    #[test]
    fn domain_info_survives_sparse_payloads() {
        let info: DomainInfo = serde_json::from_str(r"{}").unwrap();
        assert!(info.ro_id.is_none());
        assert_eq!(info.nameservers.len(), 0);
        assert!(!info.is_delegated());
    }

    #[test]
    fn list_page_paging() {
        let page: DomainListPage =
            serde_json::from_str(r#"{"count":3,"domain":[{"domain":"a.de"},{"domain":"b.de"}]}"#)
                .unwrap();
        assert_eq!(page.len(), 2);
        assert!(page.has_more());
        let full: DomainListPage =
            serde_json::from_str(r#"{"count":1,"domain":[{"domain":"a.de"}]}"#).unwrap();
        assert!(!full.has_more());
    }

    #[test]
    fn create_requires_positive_registrant() {
        let domain = DomainName::parse("a.de").unwrap();
        assert!(DomainCreate::new(domain.clone(), 0).is_err());
        assert!(DomainCreate::new(domain, -1).is_err());
    }

    #[test]
    fn create_omits_unset_fields() {
        let params = DomainCreate::new(DomainName::parse("a.de").unwrap(), 1)
            .unwrap()
            .params();
        assert!(params.get("ns").is_none());
        assert!(params.get("period").is_none());
        assert!(params.get("transferLock").is_none());
    }

    #[test]
    fn update_requires_a_change() {
        let update = DomainUpdate::new(DomainName::parse("a.de").unwrap());
        assert!(update.params().is_err());
    }

    #[test]
    fn renew_requires_expiration() {
        let domain = DomainName::parse("a.de").unwrap();
        let period = Period::years(1).unwrap();
        assert!(DomainRenew::new(domain.clone(), period, "  ").is_err());
        assert!(DomainRenew::new(domain, period, "2027-01-31\nX: 1").is_err());
    }

    #[test]
    fn query_builder_sets_only_requested_fields() {
        assert_eq!(DomainListQuery::new().params(), json!({}));
        let params = DomainListQuery::new()
            .with_filter("acme")
            .with_status(["ok", "hold"])
            .with_page(2, 10)
            .params();
        assert_eq!(params["status"][1], "hold");
        assert_eq!(params["pagelimit"], 10);
    }

    #[test]
    fn registration_accepts_numeric_strings() {
        let registration: Registration =
            serde_json::from_str(r#"{"roId":"42","price":"8.90"}"#).unwrap();
        assert_eq!(registration.ro_id, 42);
        assert_eq!(registration.price, Some(8.9));
    }

    #[test]
    fn client_hold_requests_always_carry_both_fields() {
        let domain = DomainName::parse("a.de").unwrap();
        for params in [
            SetClientHold::new(domain.clone()).params(),
            RemoveClientHold::new(domain.clone()).params(),
        ] {
            let object = params.as_object().unwrap();
            assert_eq!(object.len(), 2, "{params}");
            assert_eq!(object["domain"], json!("a.de"));
            assert_eq!(object["testing"], json!(false));
        }

        // `testing` is sent explicitly even when it equals the API default, so
        // a production call can never silently become a dry run (or the reverse)
        // because the server default changed.
        assert!(SetClientHold::new(domain).params().get("testing").is_some());
    }

    #[test]
    fn dry_run_flips_only_the_testing_flag() {
        let domain = DomainName::parse("a.de").unwrap();
        // The two request types are deliberately distinct, so each pair is
        // checked on its own.
        let set = SetClientHold::new(domain.clone());
        let set_dry = set.clone().dry_run();
        assert_eq!(set.domain(), set_dry.domain());
        assert_eq!(set.params()["domain"], set_dry.params()["domain"]);
        assert_eq!(set.params()["testing"], json!(false));
        assert_eq!(set_dry.params()["testing"], json!(true));
        assert_ne!(set, set_dry);

        let remove = RemoveClientHold::new(domain.clone());
        let remove_dry = remove.clone().dry_run();
        assert_eq!(remove.domain(), remove_dry.domain());
        assert_eq!(remove.params()["domain"], remove_dry.params()["domain"]);
        assert_eq!(remove.params()["testing"], json!(false));
        assert_eq!(remove_dry.params()["testing"], json!(true));
        assert_ne!(remove, remove_dry);

        // Both methods send the same shape, so they cannot drift apart.
        assert_eq!(set.params(), remove.params());
    }

    #[test]
    fn client_hold_result_is_permissive() {
        let numeric: ClientHoldResult =
            serde_json::from_str(r#"{"roId":42,"brandNewField":[1,2]}"#).unwrap();
        assert_eq!(numeric.ro_id, Some(42));

        let stringy: ClientHoldResult = serde_json::from_str(r#"{"roId":" 42 "}"#).unwrap();
        assert_eq!(stringy, numeric);

        // Missing, null and unusable values all decode as "no id reported"
        // rather than failing a command the registry already carried out.
        for body in [
            r"{}",
            r#"{"roId":null}"#,
            r#"{"roId":true}"#,
            r#"{"roId":{"nested":1}}"#,
            r#"{"roId":"not-a-number"}"#,
        ] {
            let parsed: ClientHoldResult = serde_json::from_str(body).unwrap();
            assert_eq!(parsed.ro_id, None, "{body}");
        }
        assert_eq!(
            ClientHoldResult::default(),
            ClientHoldResult { ro_id: None }
        );
    }

    #[test]
    fn an_empty_client_hold_answer_is_the_default_result() {
        assert_eq!(
            parse_client_hold(Value::Null).unwrap(),
            ClientHoldResult::default()
        );
        assert_eq!(
            parse_client_hold(json!({"roId": "42", "extra": true})).unwrap(),
            ClientHoldResult { ro_id: Some(42) }
        );
        // Something that is not an object at all is a decoding error, not a
        // silently empty result.
        assert!(parse_client_hold(json!("nope")).is_err());
    }
}
