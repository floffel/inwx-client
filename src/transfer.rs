//! Ownership changes: transfer in, trade, push, restore and the transfer
//! answers (`domain.transfer`, `domain.trade`, `domain.push`,
//! `domain.restore`, `domain.transfercancel`, `domain.transferOut`).
//!
//! These commands move a domain between registrars or accounts, change the
//! legal owner, or spend money on a restore. Several of them cannot be undone
//! and none of them can be tested for free, so a request cannot be built without
//! an explicit acknowledgement:
//!
//! ```
//! use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
//!
//! let intent = Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("example.com")?);
//! let request = TransferRequest::builder(intent)
//!     .auth_code(inwx_client::AuthCode::new("aB3-xY9_42")?)
//!     .with_registrant(inwx_client::Handle::new(991)?)
//!     .call()?;
//! assert_eq!(request.params()?["domain"], "example.com");
//! # Ok::<(), inwx_client::Error>(())
//! ```
//!
//! The acknowledgement names both the action and the domain. Passing a
//! `Trade` acknowledgement to [`TransferRequest::new`], or an acknowledgement
//! for `example.com` to a request that was meant for `example.net`, fails
//! locally — the two mistakes that cost a domain. State the request's intended
//! domain with `for_domain` (or `new_for_domain`) and it is checked against
//! the acknowledgement at construction time:
//!
//! ```
//! use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
//!
//! let intent = Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("example.com")?);
//! let request = TransferRequest::builder(intent)
//!     .for_domain(DomainName::parse("example.net")?)
//!     .call();
//! assert!(request.is_err());
//! # Ok::<(), inwx_client::Error>(())
//! ```
//!
//! # Money and state
//!
//! `domain.transfer`, `domain.trade` and `domain.restore` may charge the
//! account; the answers carry `price` and `currency` whenever the API reports
//! them. A transfer can also come back as `1001` (action pending), which this
//! crate returns as [`Error::Pending`] with the server transaction id — see
//! [`crate::rpc::classify_code`]. If the registry instead reports `2300`
//! (`Object pending transfer`) when a transfer is already in progress,
//! [`InwxClient::transfer_domain`] returns
//! [`Error::TransferPending`] after the single submission; it never resubmits
//! the transfer. Poll `domain.info` or the request list for the outcome.

use std::collections::BTreeMap;
use std::fmt;

use bon::bon;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{
    de, reject_control_chars, validate_token, AuthCode, DomainName, Handle, Hostname, Period,
    RenewalMode, Timestamp,
};

/// The irreversible action an [`Irreversible`] acknowledgement states.
///
/// One variant per command in this module, so an acknowledgement issued for one
/// operation cannot authorise another.
///
/// ```
/// use inwx_client::ActionKind;
///
/// assert_eq!(ActionKind::Transfer.as_str(), "domain.transfer");
/// assert_eq!(ActionKind::Push.to_string(), "domain.push");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ActionKind {
    /// `domain.transfer` — pull a domain in from another registrar.
    Transfer,
    /// `domain.trade` — change the legal owner.
    Trade,
    /// `domain.push` — hand the domain back to the registry.
    Push,
    /// `domain.restore` — bring back an expired or deleted domain.
    Restore,
    /// `domain.transfercancel` — cancel an inbound transfer.
    TransferCancel,
    /// `domain.transferOut` — accept or deny an outbound transfer request.
    TransferOut,
    /// `accounting.refund` — move money out of the account balance.
    Refund,
}

impl ActionKind {
    /// The JSON-RPC method this action performs.
    ///
    /// ```
    /// use inwx_client::ActionKind;
    /// assert_eq!(ActionKind::Restore.as_str(), "domain.restore");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "domain.transfer",
            Self::Trade => "domain.trade",
            Self::Push => "domain.push",
            Self::Restore => "domain.restore",
            Self::TransferCancel => "domain.transfercancel",
            Self::TransferOut => "domain.transferOut",
            Self::Refund => "accounting.refund",
        }
    }
}

impl fmt::Display for ActionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Proof that the caller stated which irreversible action they are about to
/// perform, on which object.
///
/// There is no `Default` and no public field: the only way to obtain one is
/// [`Irreversible::acknowledge`], which takes the action and the domain. Every
/// builder in this module (and
/// [`InwxClient::refund`](crate::InwxClient::refund)) requires one and checks
/// that it matches, so a request that moves ownership or money cannot be
/// constructed by accident — for example by copy-pasting a block and changing
/// the domain.
///
/// ```
/// use inwx_client::{ActionKind, DomainName, Irreversible};
///
/// let intent = Irreversible::acknowledge(ActionKind::Trade, &DomainName::parse("example.com")?);
/// assert_eq!(intent.action(), ActionKind::Trade);
/// assert_eq!(intent.domain().as_str(), "example.com");
/// assert_eq!(format!("{intent:?}"), "Irreversible(domain.trade on example.com)");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Irreversible {
    action: ActionKind,
    domain: DomainName,
}

/// `Debug` names the action and the object — no secret is involved, and the
/// line is what an audit log should carry.
impl fmt::Debug for Irreversible {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Irreversible({} on {})",
            self.action, self.domain
        )
    }
}

impl Irreversible {
    /// States the intent to perform `action` on `domain`.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible};
    ///
    /// let intent = Irreversible::acknowledge(ActionKind::Push, &DomainName::parse("a.de")?);
    /// assert_eq!(intent.domain().as_str(), "a.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn acknowledge(action: ActionKind, domain: &DomainName) -> Self {
        Self {
            action,
            domain: domain.clone(),
        }
    }

    /// The acknowledged action.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible};
    /// let intent = Irreversible::acknowledge(ActionKind::Trade, &DomainName::parse("a.de")?);
    /// assert_eq!(intent.action(), ActionKind::Trade);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn action(&self) -> ActionKind {
        self.action
    }

    /// The acknowledged domain.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible};
    /// let intent = Irreversible::acknowledge(ActionKind::Trade, &DomainName::parse("a.de")?);
    /// assert_eq!(intent.domain().as_str(), "a.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// Checks that this acknowledgement names `expected` and `domain`.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible};
    ///
    /// let intent = Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?);
    /// intent.verify(ActionKind::Transfer, &DomainName::parse("a.de")?)?;
    /// assert!(intent.verify(ActionKind::Transfer, &DomainName::parse("b.de")?).is_err());
    /// assert!(intent.verify(ActionKind::Trade, &DomainName::parse("a.de")?).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the action or the domain differs.
    pub fn verify(&self, expected: ActionKind, domain: &DomainName) -> Result<()> {
        if self.action != expected {
            return Err(Error::validation(
                "intent",
                format!(
                    "this acknowledgement names {} but the request performs {expected}",
                    self.action
                ),
            ));
        }
        if &self.domain != domain {
            return Err(Error::validation(
                "intent",
                format!(
                    "this acknowledgement is for {} but the request is for {domain}",
                    self.domain
                ),
            ));
        }
        Ok(())
    }

    /// Consumes the acknowledgement after checking it names `expected` and
    /// `domain`.
    fn into_domain_for(self, expected: ActionKind, domain: DomainName) -> Result<DomainName> {
        self.verify(expected, &domain)?;
        Ok(domain)
    }

    /// Consumes the acknowledgement after checking it names `expected` on its
    /// own domain.
    fn into_domain(self, expected: ActionKind) -> Result<DomainName> {
        let domain = self.domain.clone();
        self.into_domain_for(expected, domain)
    }
}

/// The answer to an outbound transfer request (`transferAnswer`).
///
/// ```
/// use inwx_client::TransferAnswer;
///
/// assert_eq!(TransferAnswer::Ack.as_str(), "ACK");
/// assert_eq!("nack".parse::<TransferAnswer>()?, TransferAnswer::Nack);
/// assert!("maybe".parse::<TransferAnswer>().is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferAnswer {
    /// Acknowledge the transfer.
    Ack,
    /// Deny the transfer.
    Nack,
}

impl TransferAnswer {
    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::TransferAnswer;
    /// assert_eq!(TransferAnswer::Nack.as_str(), "NACK");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ack => "ACK",
            Self::Nack => "NACK",
        }
    }
}

impl fmt::Display for TransferAnswer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for TransferAnswer {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl std::str::FromStr for TransferAnswer {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        match input.trim().to_ascii_uppercase().as_str() {
            "ACK" => Ok(Self::Ack),
            "NACK" => Ok(Self::Nack),
            other => Err(Error::validation(
                "answer",
                format!("{other:?} is not ACK or NACK"),
            )),
        }
    }
}

/// Per-TLD extra data (`extData`).
///
/// The API documents a handful of generic flags and a long tail of registrar
/// specific keys. The four documented generic keys have builders; anything else
/// goes through [`ExtData::set`], which validates the shape (an upper-case
/// token) but not the meaning, because the meaning belongs to the TLD's rules
/// (`domain.getRules` answers those).
///
/// ```
/// use inwx_client::ExtData;
///
/// let mut extra = ExtData::new();
/// extra.no_domain_check(true);
/// extra.birth_date("1990-05-23")?;
/// extra.set("SPORTS-ORGANISATION", "sports club")?;
///
/// let params = extra.params();
/// assert_eq!(params["NO-DOMAIN-CHECK"], true);
/// assert_eq!(params["BIRTH-DATE"], "1990-05-23");
/// assert_eq!(params["SPORTS-ORGANISATION"], "sports club");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExtData {
    entries: BTreeMap<String, Value>,
}

impl ExtData {
    /// An empty set of extra data.
    ///
    /// ```
    /// use inwx_client::ExtData;
    /// assert!(ExtData::new().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether nothing is set.
    ///
    /// ```
    /// use inwx_client::ExtData;
    /// let mut extra = ExtData::new();
    /// extra.no_host_check(false);
    /// assert!(!extra.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Skips the registry's domain check (`NO-DOMAIN-CHECK`).
    ///
    /// ```
    /// use inwx_client::ExtData;
    /// let mut extra = ExtData::new();
    /// extra.no_domain_check(true);
    /// assert_eq!(extra.params()["NO-DOMAIN-CHECK"], true);
    /// ```
    pub fn no_domain_check(&mut self, skip: bool) {
        self.entries
            .insert("NO-DOMAIN-CHECK".to_owned(), json!(skip));
    }

    /// Skips the registry's host check (`NO-HOST-CHECK`).
    ///
    /// ```
    /// use inwx_client::ExtData;
    /// let mut extra = ExtData::new();
    /// extra.no_host_check(true);
    /// assert_eq!(extra.params()["NO-HOST-CHECK"], true);
    /// ```
    pub fn no_host_check(&mut self, skip: bool) {
        self.entries.insert("NO-HOST-CHECK".to_owned(), json!(skip));
    }

    /// Sets the registrant's birth date (`BIRTH-DATE`, a `date`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] unless the value is `YYYY-MM-DD`.
    ///
    /// ```
    /// use inwx_client::ExtData;
    /// let mut extra = ExtData::new();
    /// extra.birth_date("1990-05-23")?;
    /// assert_eq!(extra.params()["BIRTH-DATE"], "1990-05-23");
    /// assert!(extra.birth_date("23.05.1990").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn birth_date(&mut self, date: &str) -> Result<()> {
        let trimmed = date.trim();
        let format = time::macros::format_description!("[year]-[month]-[day]");
        if time::Date::parse(trimmed, &format).is_err() {
            return Err(Error::validation(
                "extData.BIRTH-DATE",
                format!("{trimmed:?} is not a YYYY-MM-DD date"),
            ));
        }
        self.entries.insert("BIRTH-DATE".to_owned(), json!(trimmed));
        Ok(())
    }

    /// Sets the registrant's birth city (`BIRTH-CITY`, `text64`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or longer than 64
    /// characters.
    ///
    /// ```
    /// use inwx_client::ExtData;
    /// let mut extra = ExtData::new();
    /// extra.birth_city("Munich")?;
    /// assert_eq!(extra.params()["BIRTH-CITY"], "Munich");
    /// assert!(extra.birth_city("").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn birth_city(&mut self, city: &str) -> Result<()> {
        let trimmed = city.trim();
        if trimmed.is_empty() || trimmed.chars().count() > 64 {
            return Err(Error::validation(
                "extData.BIRTH-CITY",
                "must be 1 to 64 characters",
            ));
        }
        reject_control_chars("extData.BIRTH-CITY", trimmed)?;
        self.entries.insert("BIRTH-CITY".to_owned(), json!(trimmed));
        Ok(())
    }

    /// Sets an arbitrary documented key.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the key is not an upper-case token of 1–64
    /// characters (`A-Z`, `0-9`, `-`), the key is one of the documented typed
    /// keys, or the value is empty.
    ///
    /// ```
    /// use inwx_client::ExtData;
    /// let mut extra = ExtData::new();
    /// extra.set("TRADEMARK", "Example GmbH")?;
    /// assert_eq!(extra.params()["TRADEMARK"], "Example GmbH");
    /// assert!(extra.set("lower case", "x").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let key = key.trim();
        if key.is_empty() || key.len() > 64 {
            return Err(Error::validation(
                "extData",
                "the key must be 1 to 64 characters",
            ));
        }
        if !key
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(Error::validation(
                "extData",
                format!("{key:?} must be an upper-case A-Z, 0-9, - token"),
            ));
        }
        if is_reserved_ext_data_key(key) {
            return Err(Error::validation(
                "extData",
                format!("{key:?} must be set with its typed builder"),
            ));
        }
        if value.trim().is_empty() {
            return Err(Error::validation("extData", "the value must not be empty"));
        }
        reject_control_chars("extData", value)?;
        self.entries.insert(key.to_owned(), json!(value));
        Ok(())
    }

    /// The `extData` object as it goes on the wire.
    ///
    /// ```
    /// use inwx_client::ExtData;
    /// let mut extra = ExtData::new();
    /// extra.no_domain_check(true);
    /// assert_eq!(extra.params().as_object().unwrap().len(), 1);
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        Value::Object(
            self.entries
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Map<String, Value>>(),
        )
    }
}

fn is_reserved_ext_data_key(key: &str) -> bool {
    matches!(
        key,
        "NO-DOMAIN-CHECK" | "NO-HOST-CHECK" | "BIRTH-DATE" | "BIRTH-CITY"
    )
}

/// What a completed transfer, trade or push cost.
///
/// ```
/// use inwx_client::OwnershipResult;
///
/// let result: OwnershipResult = serde_json::from_str(
///     r#"{"roId":42,"price":12.5,"currency":"EUR","notifications":["TECH"]}"#,
/// )?;
/// assert_eq!(result.ro_id, Some(42));
/// assert_eq!(result.price, Some(12.5));
/// assert_eq!(result.notifications, ["TECH"]);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct OwnershipResult {
    /// Repository object id of the domain, when the API reports it.
    #[serde(default, rename = "roId", deserialize_with = "de::opt_i64")]
    pub ro_id: Option<i64>,
    /// Amount charged, when the API reports it.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub price: Option<f64>,
    /// Currency of `price`.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// Contact types the registry did not require.
    #[serde(default, deserialize_with = "de::vec_string")]
    pub notifications: Vec<String>,
}

/// The answer to a successful `domain.restore`.
///
/// ```
/// use inwx_client::RestoreResult;
///
/// let restored: RestoreResult = serde_json::from_str(
///     r#"{"domain":"münchen.de","domainAce":"xn--mnchen-3ya.de"}"#,
/// )?;
/// assert_eq!(restored.domain_ace.as_deref(), Some("xn--mnchen-3ya.de"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct RestoreResult {
    /// The domain as the registry spells it (may be unicode).
    #[serde(default, deserialize_with = "de::opt_string")]
    pub domain: Option<String>,
    /// The ASCII (punycode) spelling.
    #[serde(default, rename = "domainAce", deserialize_with = "de::opt_string")]
    pub domain_ace: Option<String>,
}

/// A `domain.transfer` request.
///
/// Built from an [`Irreversible`] acknowledgement, so the domain and the action
/// are stated before anything else exists. The auth code is the EPP code from
/// the losing registrar; without it the registry rejects the transfer, but not
/// every TLD uses one, so it stays optional.
///
/// ```
/// use inwx_client::{
///     ActionKind, AuthCode, DomainName, Handle, Irreversible, TransferRequest,
/// };
///
/// let request = TransferRequest::builder(Irreversible::acknowledge(
///     ActionKind::Transfer,
///     &DomainName::parse("example.com")?,
/// ))
/// .auth_code(AuthCode::new("aB3-xY9_42")?)
/// .with_registrant(Handle::new(991)?)
/// .with_transfer_lock(false)
/// .with_period(inwx_client::Period::years(2)?)
/// .call()?;
///
/// let params = request.params()?;
/// assert_eq!(params["authCode"], "aB3-xY9_42");
/// assert_eq!(params["registrant"], 991);
/// assert_eq!(params["period"], "2Y");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TransferRequest {
    domain: DomainName,
    auth_code: Option<AuthCode>,
    registrant: Option<Handle>,
    admin: Option<Handle>,
    tech: Option<Handle>,
    billing: Option<Handle>,
    nameservers: Option<Vec<Hostname>>,
    ns_takeover: Option<bool>,
    contact_takeover: Option<bool>,
    transfer_lock: Option<bool>,
    renewal_mode: Option<RenewalMode>,
    period: Option<Period>,
    whois_provider: Option<String>,
    whois_url: Option<String>,
    sc_date: Option<Timestamp>,
    ext_data: Option<ExtData>,
    voucher: Option<String>,
    agreed_price: Option<f64>,
    asynchron: Option<bool>,
    testing: bool,
}

#[bon::bon]
impl TransferRequest {
    /// Starts a transfer for the domain named in `intent`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] unless `intent` acknowledges
    /// [`ActionKind::Transfer`].
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
    ///
    /// let wrong = Irreversible::acknowledge(ActionKind::Trade, &DomainName::parse("a.de")?);
    /// assert!(TransferRequest::new(wrong).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[builder(
        start_fn(name = builder, vis = "pub"),
        builder_type(
            name = TransferRequestBuilder,
            vis = "pub",
            doc {
                /// Builder for [`TransferRequest`].
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
                ///
                /// let request = TransferRequest::builder(
                ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                /// )
                /// .call()?;
                /// assert_eq!(request.domain().as_str(), "a.de");
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ),
        finish_fn(doc {
            /// Finishes building the transfer request.
            ///
            /// # Errors
            ///
            /// [`Error::Validation`] unless the acknowledgement names
            /// [`ActionKind::Transfer`].
            ///
            /// ```
            /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
            ///
            /// let request = TransferRequest::builder(
            ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
            /// )
            /// .call()?;
            /// assert_eq!(request.domain().as_str(), "a.de");
            /// # Ok::<(), inwx_client::Error>(())
            /// ```
        })
    )]
    #[allow(clippy::too_many_arguments)]
    fn create(
        #[builder(start_fn)] intent: Irreversible,
        #[builder(setters(
            name = for_domain,
            option_fn(vis = ""),
            doc {
                /// Sets the domain this request is meant for and checks it
                /// against the acknowledgement.
                ///
                /// # Errors
                ///
                /// [`Error::Validation`] when it differs from `intent`.
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
                ///
                /// let intent = Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?);
                /// assert!(TransferRequest::builder(intent.clone())
                ///     .for_domain(DomainName::parse("b.de")?)
                ///     .call()
                ///     .is_err());
                /// assert!(TransferRequest::builder(intent)
                ///     .for_domain(DomainName::parse("a.de")?)
                ///     .call()
                ///     .is_ok());
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        for_domain: Option<DomainName>,
        #[builder(setters(
            name = auth_code,
            option_fn(vis = ""),
            doc {
                /// Sets the authorisation code (`authCode`).
                ///
                /// ```
                /// use inwx_client::{ActionKind, AuthCode, DomainName, Irreversible, TransferRequest};
                ///
                /// let request = TransferRequest::builder(
                ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                /// )
                /// .auth_code(AuthCode::new("code-42")?)
                /// .call()?;
                /// assert_eq!(request.params()?["authCode"], "code-42");
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        auth_code: Option<AuthCode>,
        #[builder(setters(
            name = with_registrant,
            option_fn(vis = ""),
            doc {
                /// Sets the registrant handle for the transferred domain.
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TransferRequest};
                ///
                /// let request = TransferRequest::builder(
                ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                /// )
                /// .with_registrant(Handle::new(7)?)
                /// .call()?;
                /// assert_eq!(request.params()?["registrant"], 7);
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        registrant: Option<Handle>,
        #[builder(setters(
            name = with_admin,
            option_fn(vis = ""),
            doc {
                /// Sets the administrative contact handle.
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TransferRequest};
                ///
                /// let request = TransferRequest::builder(
                ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                /// )
                /// .with_admin(Handle::new(8)?)
                /// .call()?;
                /// assert_eq!(request.params()?["admin"], 8);
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        admin: Option<Handle>,
        #[builder(setters(
            name = with_tech,
            option_fn(vis = ""),
            doc {
                /// Sets the technical contact handle.
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TransferRequest};
                ///
                /// let request = TransferRequest::builder(
                ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                /// )
                /// .with_tech(Handle::new(9)?)
                /// .call()?;
                /// assert_eq!(request.params()?["tech"], 9);
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        tech: Option<Handle>,
        #[builder(setters(
            name = with_billing,
            option_fn(vis = ""),
            doc {
                /// Sets the billing contact handle.
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TransferRequest};
                ///
                /// let request = TransferRequest::builder(
                ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                /// )
                /// .with_billing(Handle::new(10)?)
                /// .call()?;
                /// assert_eq!(request.params()?["billing"], 10);
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        billing: Option<Handle>,
        #[builder(
            with = |nameservers: &[Hostname]| -> Result<_> {
                validate_nameservers(nameservers)?;
                Ok(nameservers.to_vec())
            },
            setters(
                name = with_nameservers,
                option_fn(vis = ""),
                doc {
                    /// Sets the nameservers to use after the transfer.
                    ///
                    /// # Errors
                    ///
                    /// [`Error::Validation`] for an empty or duplicate list.
                    ///
                    /// ```
                    /// use inwx_client::{ActionKind, DomainName, Hostname, Irreversible, TransferRequest};
                    ///
                    /// let request = TransferRequest::builder(
                    ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                    /// )
                    /// .with_nameservers(&[Hostname::parse("ns1.example.net")?])?
                    /// .call()?;
                    /// assert_eq!(request.params()?["ns"][0], "ns1.example.net");
                    /// # Ok::<(), inwx_client::Error>(())
                    /// ```
                }
            )
        )]
        nameservers: Option<Vec<Hostname>>,
        #[builder(with = || true, setters(
            name = keeping_nameservers,
            option_fn(vis = ""),
            doc {
                /// Keeps the nameservers the domain currently uses (`nsTakeover`).
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
                ///
                /// let request = TransferRequest::builder(
                ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                /// )
                /// .keeping_nameservers()
                /// .call()?;
                /// assert_eq!(request.params()?["nsTakeover"], true);
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        ns_takeover: Option<bool>,
        #[builder(setters(
            name = with_contact_takeover,
            option_fn(vis = ""),
            doc {
                /// Transfers the gTLD data along with the domain (`contactTakeover`).
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
                ///
                /// let request = TransferRequest::builder(
                ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                /// )
                /// .with_contact_takeover(true)
                /// .call()?;
                /// assert_eq!(request.params()?["contactTakeover"], true);
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        contact_takeover: Option<bool>,
        #[builder(setters(
            name = with_transfer_lock,
            option_fn(vis = ""),
            doc {
                /// Sets the transfer lock (`transferLock`; the API defaults it to on).
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
                ///
                /// let request = TransferRequest::builder(
                ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                /// )
                /// .with_transfer_lock(false)
                /// .call()?;
                /// assert_eq!(request.params()?["transferLock"], false);
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        transfer_lock: Option<bool>,
        #[builder(setters(
            name = with_renewal_mode,
            option_fn(vis = ""),
            doc {
                /// Sets what happens at expiry.
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Irreversible, RenewalMode, TransferRequest};
                ///
                /// let request = TransferRequest::builder(
                ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                /// )
                /// .with_renewal_mode(RenewalMode::AutoRenew)
                /// .call()?;
                /// assert_eq!(request.params()?["renewalMode"], "AUTORENEW");
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        renewal_mode: Option<RenewalMode>,
        #[builder(setters(
            name = with_period,
            option_fn(vis = ""),
            doc {
                /// Sets the registration period bought with the transfer.
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Irreversible, Period, TransferRequest};
                ///
                /// let request = TransferRequest::builder(
                ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                /// )
                /// .with_period(Period::years(1)?)
                /// .call()?;
                /// assert_eq!(request.params()?["period"], "1Y");
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        period: Option<Period>,
        #[builder(
            with = |provider: impl Into<String>| -> Result<_> {
                let provider = provider.into();
                validate_token("whoisProvider", &provider)?;
                Ok(provider.trim().to_owned())
            },
            setters(
                name = with_whois_provider,
                option_fn(vis = ""),
                doc {
                    /// Sets the whois provider handed to the registry (`whoisProvider`).
                    ///
                    /// # Errors
                    ///
                    /// [`Error::Validation`] when the value is unusable.
                    ///
                    /// ```
                    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
                    ///
                    /// let request = TransferRequest::builder(
                    ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                    /// )
                    /// .with_whois_provider("Example Whois")?
                    /// .call()?;
                    /// assert_eq!(request.params()?["whoisProvider"], "Example Whois");
                    /// # Ok::<(), inwx_client::Error>(())
                    /// ```
                }
            )
        )]
        whois_provider: Option<String>,
        #[builder(
            with = |url: impl Into<String>| -> Result<_> {
                let url = url.into();
                validate_token("whoisUrl", &url)?;
                Ok(url.trim().to_owned())
            },
            setters(
                name = with_whois_url,
                option_fn(vis = ""),
                doc {
                    /// Sets the whois URL handed to the registry (`whoisUrl`).
                    ///
                    /// # Errors
                    ///
                    /// [`Error::Validation`] when the value is unusable.
                    ///
                    /// ```
                    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
                    ///
                    /// let request = TransferRequest::builder(
                    ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                    /// )
                    /// .with_whois_url("https://whois.example.net")?
                    /// .call()?;
                    /// assert_eq!(request.params()?["whoisUrl"], "https://whois.example.net");
                    /// # Ok::<(), inwx_client::Error>(())
                    /// ```
                }
            )
        )]
        whois_url: Option<String>,
        #[builder(setters(
            name = scheduled_at,
            option_fn(vis = ""),
            doc {
                /// Schedules the transfer for a later date (`scDate`).
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Irreversible, Timestamp, TransferRequest};
                ///
                /// let request = TransferRequest::builder(
                ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                /// )
                /// .scheduled_at(Timestamp::parse("2026-11-01T03:00:00")?)
                /// .call()?;
                /// assert_eq!(request.params()?["scDate"], "2026-11-01T03:00:00");
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        sc_date: Option<Timestamp>,
        #[builder(setters(
            name = with_ext_data,
            option_fn(vis = ""),
            doc {
                /// Sets the TLD-specific extra data.
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, ExtData, Irreversible, TransferRequest};
                ///
                /// let mut extra = ExtData::new();
                /// extra.no_domain_check(true);
                /// let request = TransferRequest::builder(
                ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                /// )
                /// .with_ext_data(extra)
                /// .call()?;
                /// assert_eq!(request.params()?["extData"]["NO-DOMAIN-CHECK"], true);
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        ext_data: Option<ExtData>,
        #[builder(
            with = |voucher: impl Into<String>| -> Result<_> {
                let voucher = voucher.into();
                validate_token("voucher", &voucher)?;
                Ok(voucher.trim().to_owned())
            },
            setters(
                name = with_voucher,
                option_fn(vis = ""),
                doc {
                    /// Sets a voucher code.
                    ///
                    /// # Errors
                    ///
                    /// [`Error::Validation`] when the value is unusable.
                    ///
                    /// ```
                    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
                    ///
                    /// let request = TransferRequest::builder(
                    ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                    /// )
                    /// .with_voucher("SUMMER26")?
                    /// .call()?;
                    /// assert_eq!(request.params()?["voucher"], "SUMMER26");
                    /// # Ok::<(), inwx_client::Error>(())
                    /// ```
                }
            )
        )]
        voucher: Option<String>,
        #[builder(
            with = |price: f64| -> Result<_> {
                validate_price(price)?;
                Ok(price)
            },
            setters(
                name = with_agreed_price,
                option_fn(vis = ""),
                doc {
                    /// Sets the price agreed for a premium transfer.
                    ///
                    /// # Errors
                    ///
                    /// [`Error::Validation`] unless the price is finite and positive.
                    ///
                    /// ```
                    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
                    ///
                    /// let request = TransferRequest::builder(
                    ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                    /// )
                    /// .with_agreed_price(250.0)?
                    /// .call()?;
                    /// assert_eq!(request.params()?["agreedPrice"], 250.0);
                    /// # Ok::<(), inwx_client::Error>(())
                    /// ```
                }
            )
        )]
        agreed_price: Option<f64>,
        #[builder(with = || true, setters(
            name = asynchronous,
            option_fn(vis = ""),
            doc {
                /// Asks the API to answer before the registry does (`asynchron`).
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
                ///
                /// let request = TransferRequest::builder(
                ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                /// )
                /// .asynchronous()
                /// .call()?;
                /// assert_eq!(request.params()?["asynchron"], true);
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        asynchron: Option<bool>,
        #[builder(with = || true, default, setters(
            name = dry_run,
            option_fn(vis = ""),
            doc {
                /// Runs the command in testing mode (`testing=true`).
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
                ///
                /// let request = TransferRequest::builder(
                ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
                /// )
                /// .dry_run()
                /// .call()?;
                /// assert_eq!(request.params()?["testing"], true);
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        testing: bool,
    ) -> Result<Self> {
        let domain = match for_domain {
            Some(domain) => intent.into_domain_for(ActionKind::Transfer, domain)?,
            None => intent.into_domain(ActionKind::Transfer)?,
        };
        Ok(Self {
            domain,
            auth_code,
            registrant,
            admin,
            tech,
            billing,
            nameservers,
            ns_takeover,
            contact_takeover,
            transfer_lock,
            renewal_mode,
            period,
            whois_provider,
            whois_url,
            sc_date,
            ext_data,
            voucher,
            agreed_price,
            asynchron,
            testing,
        })
    }

    /// Starts a transfer for the domain named in `intent`.
    ///
    /// This is the compatibility constructor for callers that do not set any
    /// optional transfer options. Use [`TransferRequest::builder`] when options
    /// are needed.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] unless `intent` acknowledges
    /// [`ActionKind::Transfer`].
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
    ///
    /// let request = TransferRequest::new(
    ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
    /// )?;
    /// assert_eq!(request.domain().as_str(), "a.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new(intent: Irreversible) -> Result<Self> {
        Self::builder(intent).call()
    }

    /// Starts a transfer for `domain`, checking it against `intent`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] unless `intent` acknowledges
    /// [`ActionKind::Transfer`] for `domain`.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
    ///
    /// let intent = Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?);
    /// assert!(TransferRequest::new_for_domain(intent.clone(), DomainName::parse("b.de")?).is_err());
    /// assert!(TransferRequest::new_for_domain(intent, DomainName::parse("a.de")?).is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new_for_domain(intent: Irreversible, domain: DomainName) -> Result<Self> {
        Self::builder(intent).for_domain(domain).call()
    }

    /// The domain being transferred.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferRequest};
    ///
    /// let request = TransferRequest::builder(
    ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
    /// )
    /// .call()?;
    /// assert_eq!(request.domain().as_str(), "a.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// The `domain.transfer` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `nsTakeover` and an explicit nameserver list
    /// are both set — the API documents them as alternatives, and sending both
    /// leaves the outcome to the server.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Hostname, Irreversible, TransferRequest};
    ///
    /// let request = TransferRequest::builder(
    ///     Irreversible::acknowledge(ActionKind::Transfer, &DomainName::parse("a.de")?),
    /// )
    /// .keeping_nameservers()
    /// .with_nameservers(&[Hostname::parse("ns1.example.net")?])?
    /// .call()?;
    /// assert!(request.params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        if self.ns_takeover == Some(true) && self.nameservers.is_some() {
            return Err(Error::validation(
                "nsTakeover",
                "cannot be combined with an explicit nameserver list",
            ));
        }
        let mut params = base_params(&self.domain, self.testing);
        if let Some(code) = &self.auth_code {
            params.insert("authCode".to_owned(), json!(code));
        }
        insert_handles(
            &mut params,
            &[
                ("registrant", self.registrant),
                ("admin", self.admin),
                ("tech", self.tech),
                ("billing", self.billing),
            ],
        );
        if let Some(nameservers) = &self.nameservers {
            params.insert("ns".to_owned(), json!(nameservers));
        }
        if let Some(takeover) = self.ns_takeover {
            params.insert("nsTakeover".to_owned(), json!(takeover));
        }
        if let Some(takeover) = self.contact_takeover {
            params.insert("contactTakeover".to_owned(), json!(takeover));
        }
        if let Some(locked) = self.transfer_lock {
            params.insert("transferLock".to_owned(), json!(locked));
        }
        if let Some(mode) = &self.renewal_mode {
            params.insert("renewalMode".to_owned(), json!(mode));
        }
        if let Some(period) = self.period {
            params.insert("period".to_owned(), json!(period));
        }
        if let Some(provider) = &self.whois_provider {
            params.insert("whoisProvider".to_owned(), json!(provider));
        }
        if let Some(url) = &self.whois_url {
            params.insert("whoisUrl".to_owned(), json!(url));
        }
        if let Some(at) = &self.sc_date {
            params.insert("scDate".to_owned(), json!(at));
        }
        if let Some(extra) = &self.ext_data {
            params.insert("extData".to_owned(), extra.params());
        }
        if let Some(voucher) = &self.voucher {
            params.insert("voucher".to_owned(), json!(voucher));
        }
        if let Some(price) = self.agreed_price {
            params.insert("agreedPrice".to_owned(), json!(price));
        }
        if let Some(asynchron) = self.asynchron {
            params.insert("asynchron".to_owned(), json!(asynchron));
        }
        Ok(Value::Object(params))
    }
}

/// A `domain.trade` request (owner change).
///
/// The registrant is mandatory — a trade without a new owner is not a trade —
/// and every other contact defaults to the current one. It is a required member
/// of the builder, so a trade without a registrant does not compile:
///
/// ```
/// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TradeRequest};
///
/// let trade = TradeRequest::builder(Irreversible::acknowledge(
///         ActionKind::Trade,
///         &DomainName::parse("example.com")?,
///     ))
///     .with_registrant(Handle::new(1201)?)
///     .with_admin(Handle::new(1202)?)
///     .build()?;
///
/// assert_eq!(trade.params()?["registrant"], 1201);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TradeRequest {
    domain: DomainName,
    registrant: Handle,
    admin: Option<Handle>,
    tech: Option<Handle>,
    billing: Option<Handle>,
    nameservers: Option<Vec<Hostname>>,
    auth_code: Option<AuthCode>,
    whois_provider: Option<String>,
    whois_url: Option<String>,
    sc_date: Option<Timestamp>,
    ext_data: Option<ExtData>,
    asynchron: Option<bool>,
    testing: bool,
}

#[bon]
impl TradeRequest {
    /// Starts an owner change for the domain named in `intent`.
    ///
    /// The `registrant` is a required member, so a trade without a new owner is
    /// not representable — it fails to compile instead of failing later in
    /// [`TradeRequest::params`]:
    ///
    /// ```compile_fail
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TradeRequest};
    ///
    /// // No `.with_registrant(..)`: the builder has no `build` without it.
    /// let _ = TradeRequest::builder(Irreversible::acknowledge(
    ///         ActionKind::Trade,
    ///         &DomainName::parse("example.com")?,
    ///     ))
    ///     .build();
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] unless `intent` acknowledges [`ActionKind::Trade`],
    /// or when a validating setter such as
    /// [`with_nameservers`](TradeRequestBuilder::with_nameservers) rejects its
    /// value.
    #[builder(finish_fn(doc {
        /// Finishes the trade request.
        ///
        /// # Errors
        ///
        /// [`Error::Validation`] unless the `intent` acknowledgement names
        /// [`ActionKind::Trade`], or when a validating setter rejected its value.
    }))]
    pub fn new(
        #[builder(start_fn)] intent: Irreversible,
        #[builder(setters(
            name = for_domain,
            option_fn(vis = ""),
            doc {
                /// Sets the domain this request is meant for and checks it
                /// against the acknowledgement.
                ///
                /// # Errors
                ///
                /// [`Error::Validation`] when it differs from `intent`.
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TradeRequest};
                ///
                /// let intent = Irreversible::acknowledge(ActionKind::Trade, &DomainName::parse("a.de")?);
                /// assert!(TradeRequest::builder(intent.clone())
                ///     .for_domain(DomainName::parse("b.de")?)
                ///     .with_registrant(Handle::new(1)?)
                ///     .build()
                ///     .is_err());
                /// assert!(TradeRequest::builder(intent)
                ///     .for_domain(DomainName::parse("a.de")?)
                ///     .with_registrant(Handle::new(1)?)
                ///     .build()
                ///     .is_ok());
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        for_domain: Option<DomainName>,
        /// The new owner (`registrant`); a required member of the builder.
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TradeRequest};
        ///
        /// let trade = TradeRequest::builder(Irreversible::acknowledge(
        ///         ActionKind::Trade,
        ///         &DomainName::parse("a.de")?,
        ///     ))
        ///     .with_registrant(Handle::new(991)?)
        ///     .build()?;
        /// assert_eq!(trade.params()?["registrant"], 991);
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(setters(name = with_registrant))]
        registrant: Handle,
        /// The administrative contact handle.
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TradeRequest};
        ///
        /// let trade = TradeRequest::builder(Irreversible::acknowledge(
        ///         ActionKind::Trade,
        ///         &DomainName::parse("a.de")?,
        ///     ))
        ///     .with_registrant(Handle::new(1)?)
        ///     .with_admin(Handle::new(2)?)
        ///     .build()?;
        /// assert_eq!(trade.params()?["admin"], 2);
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(setters(name = with_admin, option_fn(vis = "")))]
        admin: Option<Handle>,
        /// The technical contact handle.
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TradeRequest};
        ///
        /// let trade = TradeRequest::builder(Irreversible::acknowledge(
        ///         ActionKind::Trade,
        ///         &DomainName::parse("a.de")?,
        ///     ))
        ///     .with_registrant(Handle::new(1)?)
        ///     .with_tech(Handle::new(3)?)
        ///     .build()?;
        /// assert_eq!(trade.params()?["tech"], 3);
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(setters(name = with_tech, option_fn(vis = "")))]
        tech: Option<Handle>,
        /// The billing contact handle.
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TradeRequest};
        ///
        /// let trade = TradeRequest::builder(Irreversible::acknowledge(
        ///         ActionKind::Trade,
        ///         &DomainName::parse("a.de")?,
        ///     ))
        ///     .with_registrant(Handle::new(1)?)
        ///     .with_billing(Handle::new(4)?)
        ///     .build()?;
        /// assert_eq!(trade.params()?["billing"], 4);
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(setters(name = with_billing, option_fn(vis = "")))]
        billing: Option<Handle>,
        /// The nameservers to set after the trade.
        ///
        /// # Errors
        ///
        /// [`Error::Validation`] for an empty or duplicate list.
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, Handle, Hostname, Irreversible, TradeRequest};
        ///
        /// let trade = TradeRequest::builder(Irreversible::acknowledge(
        ///         ActionKind::Trade,
        ///         &DomainName::parse("a.de")?,
        ///     ))
        ///     .with_registrant(Handle::new(1)?)
        ///     .with_nameservers(&[Hostname::parse("ns1.example.net")?])?
        ///     .build()?;
        /// assert_eq!(trade.params()?["ns"][0], "ns1.example.net");
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(
            setters(name = with_nameservers, option_fn(vis = "")),
            with = |nameservers: &[Hostname]| -> Result<_> {
                validate_nameservers(nameservers)?;
                Ok(nameservers.to_vec())
            }
        )]
        nameservers: Option<Vec<Hostname>>,
        /// The authorisation code some TLDs require for a trade.
        ///
        /// ```
        /// use inwx_client::{ActionKind, AuthCode, DomainName, Handle, Irreversible, TradeRequest};
        ///
        /// let trade = TradeRequest::builder(Irreversible::acknowledge(
        ///         ActionKind::Trade,
        ///         &DomainName::parse("a.de")?,
        ///     ))
        ///     .with_registrant(Handle::new(1)?)
        ///     .auth_code(AuthCode::new("code-1")?)
        ///     .build()?;
        /// assert_eq!(trade.params()?["authCode"], "code-1");
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(setters(name = auth_code, option_fn(vis = "")))]
        auth_code: Option<AuthCode>,
        /// The whois provider.
        ///
        /// # Errors
        ///
        /// [`Error::Validation`] when the value is unusable.
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TradeRequest};
        ///
        /// let trade = TradeRequest::builder(Irreversible::acknowledge(
        ///         ActionKind::Trade,
        ///         &DomainName::parse("a.de")?,
        ///     ))
        ///     .with_registrant(Handle::new(1)?)
        ///     .with_whois_provider("Example")?
        ///     .build()?;
        /// assert_eq!(trade.params()?["whoisProvider"], "Example");
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(
            setters(name = with_whois_provider, option_fn(vis = "")),
            with = |provider: impl Into<String>| -> Result<_> {
                let provider = provider.into();
                validate_token("whoisProvider", &provider)?;
                Ok(provider.trim().to_owned())
            }
        )]
        whois_provider: Option<String>,
        /// The whois URL.
        ///
        /// # Errors
        ///
        /// [`Error::Validation`] when the value is unusable.
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TradeRequest};
        ///
        /// let trade = TradeRequest::builder(Irreversible::acknowledge(
        ///         ActionKind::Trade,
        ///         &DomainName::parse("a.de")?,
        ///     ))
        ///     .with_registrant(Handle::new(1)?)
        ///     .with_whois_url("https://whois.example.net")?
        ///     .build()?;
        /// assert_eq!(trade.params()?["whoisUrl"], "https://whois.example.net");
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(
            setters(name = with_whois_url, option_fn(vis = "")),
            with = |url: impl Into<String>| -> Result<_> {
                let url = url.into();
                validate_token("whoisUrl", &url)?;
                Ok(url.trim().to_owned())
            }
        )]
        whois_url: Option<String>,
        /// The date the trade is scheduled for (`scDate`).
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, Timestamp, TradeRequest};
        ///
        /// let trade = TradeRequest::builder(Irreversible::acknowledge(
        ///         ActionKind::Trade,
        ///         &DomainName::parse("a.de")?,
        ///     ))
        ///     .with_registrant(Handle::new(1)?)
        ///     .scheduled_at(Timestamp::parse("2026-12-01T00:00:00")?)
        ///     .build()?;
        /// assert_eq!(trade.params()?["scDate"], "2026-12-01T00:00:00");
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(setters(name = scheduled_at, option_fn(vis = "")))]
        sc_date: Option<Timestamp>,
        /// The TLD-specific extra data.
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, ExtData, Handle, Irreversible, TradeRequest};
        ///
        /// let mut extra = ExtData::new();
        /// extra.birth_city("Munich")?;
        /// let trade = TradeRequest::builder(Irreversible::acknowledge(
        ///         ActionKind::Trade,
        ///         &DomainName::parse("a.de")?,
        ///     ))
        ///     .with_registrant(Handle::new(1)?)
        ///     .with_ext_data(extra)
        ///     .build()?;
        /// assert_eq!(trade.params()?["extData"]["BIRTH-CITY"], "Munich");
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(setters(name = with_ext_data, option_fn(vis = "")))]
        ext_data: Option<ExtData>,
        /// Asks the API to answer before the registry does (`asynchron`).
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TradeRequest};
        ///
        /// let trade = TradeRequest::builder(Irreversible::acknowledge(
        ///         ActionKind::Trade,
        ///         &DomainName::parse("a.de")?,
        ///     ))
        ///     .with_registrant(Handle::new(1)?)
        ///     .asynchronous()
        ///     .build()?;
        /// assert_eq!(trade.params()?["asynchron"], true);
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(setters(name = asynchronous, option_fn(vis = "")), with = || true)]
        asynchron: Option<bool>,
        /// Runs the command in testing mode (`testing=true`).
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TradeRequest};
        ///
        /// let trade = TradeRequest::builder(Irreversible::acknowledge(
        ///         ActionKind::Trade,
        ///         &DomainName::parse("a.de")?,
        ///     ))
        ///     .with_registrant(Handle::new(1)?)
        ///     .dry_run()
        ///     .build()?;
        /// assert_eq!(trade.params()?["testing"], true);
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(setters(name = dry_run, option_fn(vis = "")), default, with = || true)]
        testing: bool,
    ) -> Result<Self> {
        let domain = match for_domain {
            Some(domain) => intent.into_domain_for(ActionKind::Trade, domain)?,
            None => intent.into_domain(ActionKind::Trade)?,
        };
        Ok(Self {
            domain,
            registrant,
            admin,
            tech,
            billing,
            nameservers,
            auth_code,
            whois_provider,
            whois_url,
            sc_date,
            ext_data,
            asynchron,
            testing,
        })
    }

    /// The domain whose owner changes.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TradeRequest};
    ///
    /// let trade = TradeRequest::builder(Irreversible::acknowledge(
    ///         ActionKind::Trade,
    ///         &DomainName::parse("a.de")?,
    ///     ))
    ///     .with_registrant(Handle::new(1)?)
    ///     .build()?;
    /// assert_eq!(trade.domain().as_str(), "a.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// The `domain.trade` parameters.
    ///
    /// # Errors
    ///
    /// Currently infallible: the registrant is a required member of the
    /// builder, so there is no missing-owner branch left to report. The
    /// signature keeps the [`Result`] so the call site stays uniform with the
    /// other ownership builders.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Handle, Irreversible, TradeRequest};
    ///
    /// let trade = TradeRequest::builder(Irreversible::acknowledge(
    ///         ActionKind::Trade,
    ///         &DomainName::parse("a.de")?,
    ///     ))
    ///     .with_registrant(Handle::new(991)?)
    ///     .build()?;
    /// assert_eq!(trade.params()?["registrant"], 991);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut params = base_params(&self.domain, self.testing);
        params.insert("registrant".to_owned(), json!(self.registrant));
        insert_handles(
            &mut params,
            &[
                ("admin", self.admin),
                ("tech", self.tech),
                ("billing", self.billing),
            ],
        );
        if let Some(nameservers) = &self.nameservers {
            params.insert("ns".to_owned(), json!(nameservers));
        }
        if let Some(code) = &self.auth_code {
            params.insert("authCode".to_owned(), json!(code));
        }
        if let Some(provider) = &self.whois_provider {
            params.insert("whoisProvider".to_owned(), json!(provider));
        }
        if let Some(url) = &self.whois_url {
            params.insert("whoisUrl".to_owned(), json!(url));
        }
        if let Some(at) = &self.sc_date {
            params.insert("scDate".to_owned(), json!(at));
        }
        if let Some(extra) = &self.ext_data {
            params.insert("extData".to_owned(), extra.params());
        }
        if let Some(asynchron) = self.asynchron {
            params.insert("asynchron".to_owned(), json!(asynchron));
        }
        Ok(Value::Object(params))
    }
}

/// A `domain.push` request: returns the domain to the registry, where it can be
/// picked up by another registrar.
///
/// ```
/// use inwx_client::{ActionKind, DomainName, Irreversible, PushRequest};
///
/// let push = PushRequest::builder(Irreversible::acknowledge(
///     ActionKind::Push,
///     &DomainName::parse("example.com")?,
/// ))
/// .with_target("other-registrar")?
/// .build()?;
///
/// assert_eq!(push.params()["target"], "other-registrar");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PushRequest {
    domain: DomainName,
    target: Option<String>,
    sc_date: Option<Timestamp>,
    testing: bool,
}

#[bon]
impl PushRequest {
    /// Starts a push for the domain named in `intent`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] unless `intent` acknowledges
    /// [`ActionKind::Push`]. The acknowledgement is checked by
    /// [`build`](PushRequestBuilder::build).
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, PushRequest};
    ///
    /// let wrong = Irreversible::acknowledge(ActionKind::Restore, &DomainName::parse("a.de")?);
    /// assert!(PushRequest::builder(wrong).build().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[builder]
    pub fn new(
        #[builder(start_fn)] intent: Irreversible,
        #[builder(setters(
            name = for_domain,
            option_fn(vis = ""),
            doc {
                /// Sets the domain this request is meant for and checks it
                /// against the acknowledgement.
                ///
                /// # Errors
                ///
                /// [`Error::Validation`] when it differs from `intent`.
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Irreversible, PushRequest};
                ///
                /// let intent = Irreversible::acknowledge(ActionKind::Push, &DomainName::parse("a.de")?);
                /// assert!(PushRequest::builder(intent.clone())
                ///     .for_domain(DomainName::parse("b.de")?)
                ///     .build()
                ///     .is_err());
                /// assert!(PushRequest::builder(intent)
                ///     .for_domain(DomainName::parse("a.de")?)
                ///     .build()
                ///     .is_ok());
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        for_domain: Option<DomainName>,
        /// Names the receiving registrar, where the TLD supports it (`target`).
        ///
        /// # Errors
        ///
        /// [`Error::Validation`] when the value is empty or longer than 64
        /// characters.
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, Irreversible, PushRequest};
        ///
        /// let push = PushRequest::builder(
        ///     Irreversible::acknowledge(ActionKind::Push, &DomainName::parse("a.de")?),
        /// )
        /// .with_target("other-registrar")?
        /// .build()?;
        /// assert_eq!(push.params()["target"], "other-registrar");
        /// assert!(PushRequest::builder(
        ///     Irreversible::acknowledge(ActionKind::Push, &DomainName::parse("a.de")?),
        /// )
        /// .with_target("")
        /// .is_err());
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(setters(name = with_target), with = |target: impl Into<String>| -> Result<_> {
            let target = target.into();
            let trimmed = target.trim();
            if trimmed.is_empty() || trimmed.chars().count() > 64 {
                return Err(Error::validation("target", "must be 1 to 64 characters"));
            }
            reject_control_chars("target", trimmed)?;
            Ok(trimmed.to_owned())
        })]
        target: Option<String>,
        /// Schedules the push for a later date (`scDate`).
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, Irreversible, PushRequest, Timestamp};
        ///
        /// let push = PushRequest::builder(
        ///     Irreversible::acknowledge(ActionKind::Push, &DomainName::parse("a.de")?),
        /// )
        /// .scheduled_at(Timestamp::parse("2026-12-01T00:00:00")?)
        /// .build()?;
        /// assert_eq!(push.params()["scDate"], "2026-12-01T00:00:00");
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(setters(name = scheduled_at))]
        sc_date: Option<Timestamp>,
        /// Runs the command in testing mode (`testing=true`).
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, Irreversible, PushRequest};
        ///
        /// let push = PushRequest::builder(
        ///     Irreversible::acknowledge(ActionKind::Push, &DomainName::parse("a.de")?),
        /// )
        /// .dry_run()
        /// .build()?;
        /// assert_eq!(push.params()["testing"], true);
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(default, setters(name = dry_run), with = || true)]
        testing: bool,
    ) -> Result<Self> {
        let domain = match for_domain {
            Some(domain) => intent.into_domain_for(ActionKind::Push, domain)?,
            None => intent.into_domain(ActionKind::Push)?,
        };
        Ok(Self {
            domain,
            target,
            sc_date,
            testing,
        })
    }

    /// The domain being pushed.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, PushRequest};
    ///
    /// let push = PushRequest::builder(
    ///     Irreversible::acknowledge(ActionKind::Push, &DomainName::parse("a.de")?),
    /// )
    /// .build()?;
    /// assert_eq!(push.domain().as_str(), "a.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// The `domain.push` parameters.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, PushRequest};
    ///
    /// let params = PushRequest::builder(
    ///     Irreversible::acknowledge(ActionKind::Push, &DomainName::parse("a.de")?),
    /// )
    /// .build()?
    /// .params();
    /// assert_eq!(params["domain"], "a.de");
    /// assert!(params.get("target").is_none());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut params = base_params(&self.domain, self.testing);
        if let Some(target) = &self.target {
            params.insert("target".to_owned(), json!(target));
        }
        if let Some(at) = &self.sc_date {
            params.insert("scDate".to_owned(), json!(at));
        }
        Value::Object(params)
    }
}

/// A `domain.restore` request: brings back an expired or deleted domain where
/// the TLD supports it, usually for a fee.
///
/// ```
/// use inwx_client::{ActionKind, DomainName, Irreversible, RenewalMode, RestoreRequest};
///
/// let restore = RestoreRequest::builder(Irreversible::acknowledge(
///     ActionKind::Restore,
///     &DomainName::parse("example.com")?,
/// ))
/// .with_renewal_mode(RenewalMode::AutoRenew)
/// .build()?;
///
/// assert_eq!(restore.params()["renewalMode"], "AUTORENEW");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct RestoreRequest {
    domain: DomainName,
    renewal_mode: Option<RenewalMode>,
    testing: bool,
}

#[bon]
impl RestoreRequest {
    /// Starts a restore for the domain named in `intent`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] unless `intent` acknowledges
    /// [`ActionKind::Restore`]. The acknowledgement is checked by
    /// [`build`](RestoreRequestBuilder::build).
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, RestoreRequest};
    ///
    /// let wrong = Irreversible::acknowledge(ActionKind::Push, &DomainName::parse("a.de")?);
    /// assert!(RestoreRequest::builder(wrong).build().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[builder]
    pub fn new(
        #[builder(start_fn)] intent: Irreversible,
        #[builder(setters(
            name = for_domain,
            option_fn(vis = ""),
            doc {
                /// Sets the domain this request is meant for and checks it
                /// against the acknowledgement.
                ///
                /// # Errors
                ///
                /// [`Error::Validation`] when it differs from `intent`.
                ///
                /// ```
                /// use inwx_client::{ActionKind, DomainName, Irreversible, RestoreRequest};
                ///
                /// let intent = Irreversible::acknowledge(ActionKind::Restore, &DomainName::parse("a.de")?);
                /// assert!(RestoreRequest::builder(intent.clone())
                ///     .for_domain(DomainName::parse("b.de")?)
                ///     .build()
                ///     .is_err());
                /// assert!(RestoreRequest::builder(intent)
                ///     .for_domain(DomainName::parse("a.de")?)
                ///     .build()
                ///     .is_ok());
                /// # Ok::<(), inwx_client::Error>(())
                /// ```
            }
        ))]
        for_domain: Option<DomainName>,
        /// What happens at expiry after the restore (`renewalMode`).
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, Irreversible, RenewalMode, RestoreRequest};
        ///
        /// let restore = RestoreRequest::builder(
        ///     Irreversible::acknowledge(ActionKind::Restore, &DomainName::parse("a.de")?),
        /// )
        /// .with_renewal_mode(RenewalMode::AutoDelete)
        /// .build()?;
        /// assert_eq!(restore.params()["renewalMode"], "AUTODELETE");
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(setters(name = with_renewal_mode))]
        renewal_mode: Option<RenewalMode>,
        /// Runs the command in testing mode (`testing=true`).
        ///
        /// ```
        /// use inwx_client::{ActionKind, DomainName, Irreversible, RestoreRequest};
        ///
        /// let restore = RestoreRequest::builder(
        ///     Irreversible::acknowledge(ActionKind::Restore, &DomainName::parse("a.de")?),
        /// )
        /// .dry_run()
        /// .build()?;
        /// assert_eq!(restore.params()["testing"], true);
        /// # Ok::<(), inwx_client::Error>(())
        /// ```
        #[builder(default, setters(name = dry_run), with = || true)]
        testing: bool,
    ) -> Result<Self> {
        let domain = match for_domain {
            Some(domain) => intent.into_domain_for(ActionKind::Restore, domain)?,
            None => intent.into_domain(ActionKind::Restore)?,
        };
        Ok(Self {
            domain,
            renewal_mode,
            testing,
        })
    }

    /// The domain being restored.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, RestoreRequest};
    ///
    /// let restore = RestoreRequest::builder(
    ///     Irreversible::acknowledge(ActionKind::Restore, &DomainName::parse("a.de")?),
    /// )
    /// .build()?;
    /// assert_eq!(restore.domain().as_str(), "a.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// The `domain.restore` parameters.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, RestoreRequest};
    ///
    /// let params = RestoreRequest::builder(
    ///     Irreversible::acknowledge(ActionKind::Restore, &DomainName::parse("a.de")?),
    /// )
    /// .build()?
    /// .params();
    /// assert_eq!(params["domain"], "a.de");
    /// assert!(params.get("renewalMode").is_none());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut params = base_params(&self.domain, self.testing);
        if let Some(mode) = &self.renewal_mode {
            params.insert("renewalMode".to_owned(), json!(mode));
        }
        Value::Object(params)
    }
}

/// A `domain.transfercancel` request: cancel a pending inbound transfer.
///
/// ```
/// use inwx_client::{ActionKind, DomainName, Irreversible, TransferCancelRequest};
///
/// let cancel = TransferCancelRequest::new(Irreversible::acknowledge(
///     ActionKind::TransferCancel,
///     &DomainName::parse("example.com")?,
/// ))?;
/// assert_eq!(cancel.params()["domain"], "example.com");
/// assert_eq!(cancel.params()["testing"], false);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TransferCancelRequest {
    domain: DomainName,
    testing: bool,
}

impl TransferCancelRequest {
    /// Starts a cancellation for the domain named in `intent`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] unless `intent` acknowledges
    /// [`ActionKind::TransferCancel`].
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferCancelRequest};
    ///
    /// let wrong = Irreversible::acknowledge(ActionKind::Trade, &DomainName::parse("a.de")?);
    /// assert!(TransferCancelRequest::new(wrong).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new(intent: Irreversible) -> Result<Self> {
        let domain = intent.into_domain(ActionKind::TransferCancel)?;
        Ok(Self {
            domain,
            testing: false,
        })
    }

    /// Starts a cancellation for `domain`, checking it against `intent`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] unless `intent` acknowledges
    /// [`ActionKind::TransferCancel`] for `domain`.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferCancelRequest};
    ///
    /// let intent = Irreversible::acknowledge(ActionKind::TransferCancel, &DomainName::parse("a.de")?);
    /// assert!(TransferCancelRequest::new_for_domain(intent.clone(), DomainName::parse("b.de")?).is_err());
    /// assert!(TransferCancelRequest::new_for_domain(intent, DomainName::parse("a.de")?).is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new_for_domain(intent: Irreversible, domain: DomainName) -> Result<Self> {
        let domain = intent.into_domain_for(ActionKind::TransferCancel, domain)?;
        Ok(Self {
            domain,
            testing: false,
        })
    }

    /// The domain whose inbound transfer is cancelled.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferCancelRequest};
    ///
    /// let cancel = TransferCancelRequest::new(
    ///     Irreversible::acknowledge(ActionKind::TransferCancel, &DomainName::parse("a.de")?),
    /// )?;
    /// assert_eq!(cancel.domain().as_str(), "a.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// Runs the command in testing mode (`testing=true`).
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferCancelRequest};
    ///
    /// let cancel = TransferCancelRequest::new(
    ///     Irreversible::acknowledge(ActionKind::TransferCancel, &DomainName::parse("a.de")?),
    /// )?
    /// .dry_run();
    /// assert_eq!(cancel.params()["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.testing = true;
        self
    }

    /// The `domain.transfercancel` parameters.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferCancelRequest};
    ///
    /// let params = TransferCancelRequest::new(
    ///     Irreversible::acknowledge(ActionKind::TransferCancel, &DomainName::parse("a.de")?),
    /// )?
    /// .params();
    /// assert_eq!(params["domain"], "a.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        Value::Object(base_params(&self.domain, self.testing))
    }
}

/// A `domain.transferOut` request: accept or deny a pending outbound transfer.
///
/// ```
/// use inwx_client::{ActionKind, DomainName, Irreversible, TransferAnswer, TransferOutRequest};
///
/// let answer = TransferOutRequest::new(
///     Irreversible::acknowledge(ActionKind::TransferOut, &DomainName::parse("example.com")?),
///     TransferAnswer::Nack,
/// )?;
/// assert_eq!(answer.params()["answer"], "NACK");
/// assert_eq!(answer.params()["testing"], false);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TransferOutRequest {
    domain: DomainName,
    answer: TransferAnswer,
    testing: bool,
}

impl TransferOutRequest {
    /// Answers the outbound transfer for the domain named in `intent`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] unless `intent` acknowledges
    /// [`ActionKind::TransferOut`].
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferAnswer, TransferOutRequest};
    ///
    /// let wrong = Irreversible::acknowledge(ActionKind::Push, &DomainName::parse("a.de")?);
    /// assert!(TransferOutRequest::new(wrong, TransferAnswer::Ack).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new(intent: Irreversible, answer: TransferAnswer) -> Result<Self> {
        let domain = intent.into_domain(ActionKind::TransferOut)?;
        Ok(Self {
            domain,
            answer,
            testing: false,
        })
    }

    /// Answers the outbound transfer for `domain`, checking it against `intent`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] unless `intent` acknowledges
    /// [`ActionKind::TransferOut`] for `domain`.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferAnswer, TransferOutRequest};
    ///
    /// let intent = Irreversible::acknowledge(ActionKind::TransferOut, &DomainName::parse("a.de")?);
    /// assert!(TransferOutRequest::new_for_domain(
    ///     intent.clone(), DomainName::parse("b.de")?, TransferAnswer::Ack,
    /// ).is_err());
    /// assert!(TransferOutRequest::new_for_domain(
    ///     intent, DomainName::parse("a.de")?, TransferAnswer::Ack,
    /// ).is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new_for_domain(
        intent: Irreversible,
        domain: DomainName,
        answer: TransferAnswer,
    ) -> Result<Self> {
        let domain = intent.into_domain_for(ActionKind::TransferOut, domain)?;
        Ok(Self {
            domain,
            answer,
            testing: false,
        })
    }

    /// The domain whose outbound transfer is answered.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferAnswer, TransferOutRequest};
    ///
    /// let answer = TransferOutRequest::new(
    ///     Irreversible::acknowledge(ActionKind::TransferOut, &DomainName::parse("a.de")?),
    ///     TransferAnswer::Nack,
    /// )?;
    /// assert_eq!(answer.domain().as_str(), "a.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// The answer this request will send.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferAnswer, TransferOutRequest};
    ///
    /// let answer = TransferOutRequest::new(
    ///     Irreversible::acknowledge(ActionKind::TransferOut, &DomainName::parse("a.de")?),
    ///     TransferAnswer::Ack,
    /// )?;
    /// assert_eq!(answer.answer(), TransferAnswer::Ack);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn answer(&self) -> TransferAnswer {
        self.answer
    }

    /// Runs the command in testing mode (`testing=true`).
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferAnswer, TransferOutRequest};
    ///
    /// let answer = TransferOutRequest::new(
    ///     Irreversible::acknowledge(ActionKind::TransferOut, &DomainName::parse("a.de")?),
    ///     TransferAnswer::Nack,
    /// )?
    /// .dry_run();
    /// assert_eq!(answer.params()["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.testing = true;
        self
    }

    /// The `domain.transferOut` parameters.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, TransferAnswer, TransferOutRequest};
    ///
    /// let params = TransferOutRequest::new(
    ///     Irreversible::acknowledge(ActionKind::TransferOut, &DomainName::parse("a.de")?),
    ///     TransferAnswer::Nack,
    /// )?
    /// .params();
    /// assert_eq!(params["domain"], "a.de");
    /// assert_eq!(params["answer"], "NACK");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut params = base_params(&self.domain, self.testing);
        params.insert("answer".to_owned(), json!(self.answer));
        Value::Object(params)
    }
}

/// The domain plus `testing`, the two parameters every command here shares.
fn base_params(domain: &DomainName, testing: bool) -> Map<String, Value> {
    let mut params = Map::new();
    params.insert("domain".to_owned(), json!(domain));
    params.insert("testing".to_owned(), json!(testing));
    params
}

/// Inserts the contact handles that were set.
fn insert_handles(params: &mut Map<String, Value>, handles: &[(&str, Option<Handle>)]) {
    for (field, handle) in handles {
        if let Some(handle) = handle {
            params.insert((*field).to_owned(), json!(handle));
        }
    }
}

/// Rejects an empty or duplicate nameserver list.
fn validate_nameservers(nameservers: &[Hostname]) -> Result<()> {
    if nameservers.is_empty() {
        return Err(Error::validation("ns", "must list at least one nameserver"));
    }
    for (index, nameserver) in nameservers.iter().enumerate() {
        if nameservers
            .iter()
            .take(index)
            .any(|earlier| earlier == nameserver)
        {
            return Err(Error::validation(
                "ns",
                format!("{nameserver} is listed twice"),
            ));
        }
    }
    Ok(())
}

/// Rejects a price that is not a finite positive amount.
fn validate_price(price: f64) -> Result<()> {
    if !price.is_finite() || price <= 0.0 {
        return Err(Error::validation(
            "agreedPrice",
            format!("must be a finite positive amount, got {price}"),
        ));
    }
    Ok(())
}

impl<T: Transport> InwxClient<T> {
    /// Transfers a domain in from another registrar (`domain.transfer`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{
    ///     ActionKind, AuthCode, DomainName, InwxClient, Irreversible, ReqwestTransport,
    ///     TransferRequest,
    /// };
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let request = TransferRequest::builder(Irreversible::acknowledge(
    ///     ActionKind::Transfer,
    ///     &DomainName::parse("example.com")?,
    /// ))
    /// .auth_code(AuthCode::new("aB3-xY9_42")?)
    /// .call()?;
    /// let outcome = client.transfer_domain(&request).await?;
    /// println!("charged {:?} {}", outcome.price, outcome.currency.unwrap_or_default());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`TransferRequest::params`], plus the usual
    /// transport and API errors. A transfer that is already pending (`2300`) is
    /// [`Error::TransferPending`], carrying the domain; the transfer was already
    /// ordered, so a second `domain.transfer` would order it again. Poll
    /// `domain.info` for the outcome.
    pub async fn transfer_domain(&self, request: &TransferRequest) -> Result<OwnershipResult> {
        match self.call("domain.transfer", request.params()?).await {
            Ok(data) => serde_json::from_value(data).map_err(Error::from),
            Err(Error::Api {
                code: 2300,
                message,
                ..
            }) => Err(Error::transfer_pending(request.domain().clone(), message)),
            Err(error) => Err(error),
        }
    }

    /// Changes the owner of a domain (`domain.trade`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{
    ///     ActionKind, DomainName, Handle, InwxClient, Irreversible, ReqwestTransport, TradeRequest,
    /// };
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let trade = TradeRequest::builder(Irreversible::acknowledge(
    ///         ActionKind::Trade,
    ///         &DomainName::parse("example.com")?,
    ///     ))
    ///     .with_registrant(Handle::new(1201)?)
    ///     .build()?;
    /// client.trade_domain(&trade).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`TradeRequest::params`], plus the usual
    /// transport and API errors.
    pub async fn trade_domain(&self, request: &TradeRequest) -> Result<OwnershipResult> {
        let data = self.call("domain.trade", request.params()?).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Returns a domain to the registry (`domain.push`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{ActionKind, DomainName, InwxClient, Irreversible, PushRequest, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let push = PushRequest::builder(Irreversible::acknowledge(
    ///     ActionKind::Push,
    ///     &DomainName::parse("example.com")?,
    /// ))
    /// .build()?;
    /// client.push_domain(&push).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors — `2306` when the TLD does not
    /// support a push.
    pub async fn push_domain(&self, request: &PushRequest) -> Result<()> {
        self.call("domain.push", request.params()).await?;
        Ok(())
    }

    /// Restores an expired or deleted domain (`domain.restore`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{
    ///     ActionKind, DomainName, InwxClient, Irreversible, ReqwestTransport, RestoreRequest,
    /// };
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let restore = RestoreRequest::builder(Irreversible::acknowledge(
    ///     ActionKind::Restore,
    ///     &DomainName::parse("example.com")?,
    /// ))
    /// .build()?;
    /// let restored = client.restore_domain(&restore).await?;
    /// println!("{:?}", restored.domain_ace);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors — `2304` when the domain is not in a
    /// restorable state.
    pub async fn restore_domain(&self, request: &RestoreRequest) -> Result<RestoreResult> {
        let data = self.call("domain.restore", request.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Cancels an inbound transfer (`domain.transfercancel`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{
    ///     ActionKind, DomainName, InwxClient, Irreversible, ReqwestTransport,
    ///     TransferCancelRequest,
    /// };
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let cancel = TransferCancelRequest::new(Irreversible::acknowledge(
    ///     ActionKind::TransferCancel,
    ///     &DomainName::parse("example.com")?,
    /// ))?;
    /// client.cancel_transfer(&cancel).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`TransferCancelRequest::new`], plus the usual
    /// transport and API errors — `2301` when nothing is pending.
    pub async fn cancel_transfer(&self, request: &TransferCancelRequest) -> Result<()> {
        self.call("domain.transfercancel", request.params()).await?;
        Ok(())
    }

    /// Accepts or denies an outbound transfer request (`domain.transferOut`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{
    ///     ActionKind, DomainName, InwxClient, Irreversible, ReqwestTransport, TransferAnswer,
    ///     TransferOutRequest,
    /// };
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let answer = TransferOutRequest::new(Irreversible::acknowledge(
    ///     ActionKind::TransferOut,
    ///     &DomainName::parse("example.com")?,
    /// ), TransferAnswer::Nack)?;
    /// client.answer_transfer_out(&answer).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`TransferOutRequest::new`], plus the usual
    /// transport and API errors — `2301` when no transfer is pending.
    pub async fn answer_transfer_out(&self, request: &TransferOutRequest) -> Result<()> {
        self.call("domain.transferOut", request.params()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(name: &str) -> DomainName {
        DomainName::parse(name).unwrap()
    }

    #[test]
    fn an_acknowledgement_cannot_authorise_another_action() {
        let trade = Irreversible::acknowledge(ActionKind::Trade, &domain("a.de"));
        assert!(TransferRequest::new(trade).is_err());
    }

    #[test]
    fn an_acknowledgement_cannot_authorise_another_domain() {
        let intent = Irreversible::acknowledge(ActionKind::Transfer, &domain("a.de"));
        // The builder records the domain it will actually send and rejects a
        // mismatch instead of silently reusing the acknowledgement's domain.
        assert!(TransferRequest::builder(intent.clone())
            .for_domain(domain("b.de"))
            .call()
            .is_err());
        assert!(TransferRequest::new_for_domain(intent, domain("b.de")).is_err());

        // The same check is reachable directly and covers both halves.
        let intent = Irreversible::acknowledge(ActionKind::Transfer, &domain("a.de"));
        assert!(intent.verify(ActionKind::Transfer, &domain("a.de")).is_ok());
        assert!(intent
            .verify(ActionKind::Transfer, &domain("b.de"))
            .is_err());
        assert!(intent.verify(ActionKind::Trade, &domain("a.de")).is_err());
    }

    #[test]
    fn each_request_builder_consumes_only_its_own_acknowledgement() {
        let trade = Irreversible::acknowledge(ActionKind::Trade, &domain("a.de"));
        assert!(TransferCancelRequest::new(trade.clone()).is_err());
        assert!(TransferOutRequest::new(trade, TransferAnswer::Ack).is_err());

        let cancel = TransferCancelRequest::new(Irreversible::acknowledge(
            ActionKind::TransferCancel,
            &domain("a.de"),
        ));
        assert_eq!(cancel.unwrap().domain().as_str(), "a.de");

        let out = TransferOutRequest::new(
            Irreversible::acknowledge(ActionKind::TransferOut, &domain("a.de")),
            TransferAnswer::Ack,
        );
        assert_eq!(out.unwrap().domain().as_str(), "a.de");
    }

    #[test]
    fn every_action_names_a_documented_method() {
        for action in [
            ActionKind::Transfer,
            ActionKind::Trade,
            ActionKind::Push,
            ActionKind::Restore,
            ActionKind::TransferCancel,
            ActionKind::TransferOut,
            ActionKind::Refund,
        ] {
            assert!(action.as_str().contains('.'), "{action:?}");
            assert_eq!(action.to_string(), action.as_str());
        }
    }

    #[test]
    fn trade_requires_a_registrant() {
        // `registrant` is a required builder member, so this cannot be built
        // without it; supplying it is the only path to `build()`.
        let trade = TradeRequest::builder(Irreversible::acknowledge(
            ActionKind::Trade,
            &domain("a.de"),
        ))
        .with_registrant(Handle::new(1201).unwrap())
        .build()
        .unwrap();
        assert_eq!(trade.params().unwrap()["registrant"], 1201);
    }

    #[test]
    fn restore_builder_keeps_the_wire_shape() {
        let restore = RestoreRequest::builder(Irreversible::acknowledge(
            ActionKind::Restore,
            &domain("a.de"),
        ))
        .with_renewal_mode(RenewalMode::AutoRenew)
        .dry_run()
        .build()
        .unwrap();
        assert_eq!(
            restore.params(),
            json!({
                "domain": "a.de",
                "renewalMode": "AUTORENEW",
                "testing": true,
            })
        );
    }

    #[test]
    fn restore_builder_requires_the_restore_acknowledgement() {
        assert!(RestoreRequest::builder(Irreversible::acknowledge(
            ActionKind::Push,
            &domain("a.de")
        ))
        .build()
        .is_err());
    }

    #[test]
    fn takeover_and_explicit_nameservers_conflict() {
        let request = TransferRequest::builder(Irreversible::acknowledge(
            ActionKind::Transfer,
            &domain("a.de"),
        ))
        .keeping_nameservers()
        .with_nameservers(&[Hostname::parse("ns1.example.net").unwrap()])
        .unwrap()
        .call()
        .unwrap();
        assert!(request.params().is_err());
    }

    #[test]
    fn ext_data_keys_are_checked() {
        let mut extra = ExtData::new();
        assert!(extra.set("BAD KEY", "x").is_err());
        assert!(extra.set("GOOD", "").is_err());
        assert!(extra.set("NO-DOMAIN-CHECK", "false").is_err());
        assert!(extra.set("NO-HOST-CHECK", "false").is_err());
        assert!(extra.set("BIRTH-DATE", "23.05.1990").is_err());
        assert!(extra.set("BIRTH-CITY", "x").is_err());
        assert!(extra.birth_date("2026-02-30").is_err());
        assert!(extra.birth_date("2026-02-28").is_ok());
        assert!(extra.birth_city("x".repeat(65).as_str()).is_err());
    }

    #[test]
    fn prices_must_be_positive_and_finite() {
        assert!(validate_price(0.0).is_err());
        assert!(validate_price(-1.0).is_err());
        assert!(validate_price(f64::NAN).is_err());
        assert!(validate_price(0.01).is_ok());
    }

    #[test]
    fn dnssec_free_defaults_do_not_leak_into_requests() {
        let params =
            PushRequest::builder(Irreversible::acknowledge(ActionKind::Push, &domain("a.de")))
                .build()
                .unwrap()
                .params();
        assert_eq!(params.as_object().unwrap().len(), 2);
    }
}
