//! DynDNS accounts (`dyndns.*`): the dynamic-DNS hostnames INWX serves.
//!
//! The account type here is not a domain handle: a DynDNS account has its own
//! username (5–42 characters per the `username` datatype), a password and a
//! list of hostnames whose `A`/`AAAA` records it may update.
//!
//! ```
//! use inwx_client::{DynDnsAccount, DynDnsAccountRef, Hostname};
//!
//! let request = DynDnsAccount::create(
//!     "tenant-42",
//!     "s3cret-pass",
//!     &[Hostname::parse("home.example.net")?],
//! )?;
//! assert_eq!(request.params()["username"], "tenant-42");
//! assert_eq!(request.params()["hostname"][0], "home.example.net");
//!
//! let target = DynDnsAccountRef::by_username("tenant-42")?;
//! assert_eq!(target.params()["username"], "tenant-42");
//! # Ok::<(), inwx_client::Error>(())
//! ```
//!
//! # Unverified
//!
//! `dyndns.updateRecord` is documented with only `ipAddress` and `ipAddressV6`
//! (Table 2.159) — no account or hostname selector. How the account is chosen
//! is not documented in the public API chapter, so [`InwxClient::dyndns_update_record`]
//! sends exactly the documented parameters and is marked *unverified* in
//! `docs/contracts.md`. Use [`InwxClient::create_record`](crate::InwxClient::create_record)
//! with [`RecordSpec`](crate::RecordSpec) for a path that is fully documented.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::record::RecordId;
use crate::secret::Password;
use crate::transport::Transport;
use crate::types::{de, validate_username, Hostname};

/// How a `dyndns.*` call names the account it is about.
///
/// The API accepts either an account id or a username; this type makes "both"
/// and "neither" unrepresentable instead of letting the server guess.
///
/// ```
/// use inwx_client::DynDnsAccountRef;
///
/// let by_id = DynDnsAccountRef::by_id(71)?;
/// assert_eq!(by_id.params()["accountId"], 71);
///
/// let by_name = DynDnsAccountRef::by_username("tenant-42")?;
/// assert_eq!(by_name.params()["username"], "tenant-42");
/// assert!(DynDnsAccountRef::by_username("ab").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynDnsAccountRef {
    /// Look the account up by id.
    Id(i64),
    /// Look the account up by username.
    Username(String),
}

impl DynDnsAccountRef {
    /// Refers to an account by id.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::DynDnsAccountRef;
    /// assert!(DynDnsAccountRef::by_id(1).is_ok());
    /// assert!(DynDnsAccountRef::by_id(0).is_err());
    /// ```
    pub fn by_id(account_id: i64) -> Result<Self> {
        if account_id <= 0 {
            return Err(Error::validation(
                "accountId",
                format!("must be a positive account id, got {account_id}"),
            ));
        }
        Ok(Self::Id(account_id))
    }

    /// Refers to an account by username.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the username is outside the documented 5–42
    /// characters.
    ///
    /// ```
    /// use inwx_client::DynDnsAccountRef;
    /// assert!(DynDnsAccountRef::by_username("tenant-42").is_ok());
    /// assert!(DynDnsAccountRef::by_username("a b c").is_err());
    /// ```
    pub fn by_username(username: &str) -> Result<Self> {
        validate_username("username", username)?;
        Ok(Self::Username(username.trim().to_owned()))
    }

    /// The parameters that select the account.
    ///
    /// ```
    /// use inwx_client::DynDnsAccountRef;
    /// assert_eq!(DynDnsAccountRef::by_id(71)?.params()["accountId"], 71);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        match self {
            Self::Id(id) => json!({ "accountId": id }),
            Self::Username(username) => json!({ "username": username }),
        }
    }
}

/// A DynDNS account as returned by `dyndns.info` and `dyndns.list`.
///
/// ```
/// use inwx_client::DynDnsAccountInfo;
///
/// let account: DynDnsAccountInfo = serde_json::from_str(
///     r#"{"accountId":71,"created":"2026-01-01T10:00:00","username":"tenant-42",
///         "records":[{"id":"88","name":"home","type":"A","content":"203.0.113.7"}]}"#,
/// )?;
/// assert_eq!(account.account_id, Some(71));
/// assert_eq!(account.records.len(), 1);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DynDnsAccountInfo {
    /// Account id.
    #[serde(default, rename = "accountId", deserialize_with = "de::opt_i64")]
    pub account_id: Option<i64>,
    /// Creation time.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub created: Option<String>,
    /// The account's username.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub username: Option<String>,
    /// The records the account may update.
    #[serde(default)]
    pub records: Vec<DynDnsRecord>,
}

/// One record a DynDNS account may update.
///
/// ```
/// use inwx_client::{DynDnsRecord, RecordType};
///
/// let record: DynDnsRecord = serde_json::from_str(
///     r#"{"id":"88","name":"home","type":"A","content":"203.0.113.7","ttl":60}"#,
/// )?;
/// assert_eq!(record.record_type, Some(RecordType::A));
/// assert_eq!(record.id.as_ref().map(inwx_client::RecordId::as_str), Some("88"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DynDnsRecord {
    /// Record id.
    #[serde(default, deserialize_with = "de::opt_record_id")]
    pub id: Option<RecordId>,
    /// Relative record name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// Record type.
    #[serde(default, rename = "type", deserialize_with = "de::opt_record_type")]
    pub record_type: Option<crate::record::RecordType>,
    /// Record content.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub content: Option<String>,
    /// TTL.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub ttl: Option<i64>,
}

/// The availability answer of `dyndns.check`.
///
/// ```
/// use inwx_client::DynDnsCheck;
///
/// let check: DynDnsCheck = serde_json::from_str(r#"{"username":"tenant-42","available":true}"#)?;
/// assert!(check.is_available());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DynDnsCheck {
    /// The username that was checked.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub username: Option<String>,
    /// Whether the username or hostname is still free.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub available: Option<bool>,
}

impl DynDnsCheck {
    /// Whether the checked name is available.
    ///
    /// ```
    /// use inwx_client::DynDnsCheck;
    ///
    /// let taken: DynDnsCheck = serde_json::from_str(r#"{"available":"0"}"#)?;
    /// assert!(!taken.is_available());
    ///
    /// let unknown: DynDnsCheck = serde_json::from_str(r#"{}"#)?;
    /// assert!(!unknown.is_available());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.available == Some(true)
    }
}

/// A `dyndns.create` request.
///
/// The password is stored without `Clone`, zeroed when the request is dropped,
/// and compared in constant time.
///
/// ```
/// use inwx_client::{DynDnsAccount, Hostname};
///
/// let host = Hostname::parse("home.example.net")?;
/// let request = DynDnsAccount::create(
///     "tenant-42",
///     "s3cret-pass",
///     &[host.clone()],
/// )?;
/// assert_eq!(request.params()["hostname"][0], "home.example.net");
/// assert_eq!(
///     request,
///     DynDnsAccount::create("tenant-42", "s3cret-pass", &[host])?,
/// );
/// # Ok::<(), inwx_client::Error>(())
/// ```
///
/// Cloning is intentionally unavailable:
///
/// ```compile_fail
/// # fn main() -> Result<(), inwx_client::Error> {
/// use inwx_client::{DynDnsAccount, Hostname};
///
/// let request = DynDnsAccount::create(
///     "tenant-42",
///     "s3cret-pass",
///     &[Hostname::parse("home.example.net")?],
/// )?;
/// let duplicate = request.clone();
/// # Ok(())
/// # }
/// ```
pub struct DynDnsAccount {
    username: String,
    password: Password,
    hostnames: Vec<Hostname>,
    testing: bool,
}

impl DynDnsAccount {
    /// A new DynDNS account with its hostnames.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the username is outside 5–42 characters, the
    /// password is empty, longer than 64 characters or contains a control
    /// character, or the hostname list is empty or has a duplicate.
    ///
    /// ```
    /// use inwx_client::{DynDnsAccount, Hostname};
    ///
    /// let host = Hostname::parse("home.example.net")?;
    /// assert!(DynDnsAccount::create("tenant-42", "pass", &[]).is_err());
    /// assert!(
    ///     DynDnsAccount::create("tenant-42", "pass", &[host.clone(), host]).is_err()
    /// );
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn create(
        username: &str,
        password: impl Into<String>,
        hostnames: &[Hostname],
    ) -> Result<Self> {
        validate_username("dyndns.username", username)?;
        let password = password.into();
        if password.is_empty() || password.chars().count() > 64 {
            return Err(Error::validation(
                "dyndns.password",
                "must be 1 to 64 characters",
            ));
        }
        if password.chars().any(char::is_control) {
            return Err(Error::validation(
                "dyndns.password",
                "must not contain control characters",
            ));
        }
        if hostnames.is_empty() {
            return Err(Error::validation(
                "dyndns.hostname",
                "must list at least one hostname",
            ));
        }
        for (index, hostname) in hostnames.iter().enumerate() {
            if hostnames[..index].contains(hostname) {
                return Err(Error::validation(
                    "dyndns.hostname",
                    format!("{hostname} is listed twice"),
                ));
            }
        }
        Ok(Self {
            username: username.trim().to_owned(),
            password: Password::new(password),
            hostnames: hostnames.to_vec(),
            testing: false,
        })
    }

    /// Runs the command in testing mode (`testing=true`).
    ///
    /// ```
    /// use inwx_client::{DynDnsAccount, Hostname};
    ///
    /// let request = DynDnsAccount::create(
    ///     "tenant-42",
    ///     "pass",
    ///     &[Hostname::parse("home.example.net")?],
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

    /// The `dyndns.create` parameters.
    ///
    /// ```
    /// use inwx_client::{DynDnsAccount, Hostname};
    ///
    /// let params = DynDnsAccount::create(
    ///     "tenant-42",
    ///     "pass",
    ///     &[Hostname::parse("home.example.net")?],
    /// )?
    /// .params();
    /// assert_eq!(params["username"], "tenant-42");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// The password is part of the parameters because the API needs it there;
    /// `Debug` on this type redacts it, so a logged request does not leak it.
    #[must_use]
    pub fn params(&self) -> Value {
        json!({
            "username": self.username,
            "password": self.password.expose(),
            "hostname": self.hostnames.iter().map(Hostname::as_str).collect::<Vec<_>>(),
            "testing": self.testing,
        })
    }
}

/// Compares every field. The password comparison is constant-time and always
/// runs, regardless of whether the other fields match.
impl PartialEq for DynDnsAccount {
    fn eq(&self, other: &Self) -> bool {
        let passwords_match = self.password == other.password;
        self.username == other.username
            && passwords_match
            && self.hostnames == other.hostnames
            && self.testing == other.testing
    }
}

impl Eq for DynDnsAccount {}

/// `Debug` redacts the password, the same rule [`crate::Credentials`] follows.
impl fmt::Debug for DynDnsAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DynDnsAccount")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("hostnames", &self.hostnames)
            .field("testing", &self.testing)
            .finish()
    }
}

/// The answer to `dyndns.create`.
///
/// ```
/// use inwx_client::DynDnsCreated;
///
/// let created: DynDnsCreated = serde_json::from_str(r#"{"accountId":71,"recordId":88}"#)?;
/// assert_eq!(created.account_id, Some(71));
/// assert_eq!(created.record_id, Some(88));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DynDnsCreated {
    /// The new account's id.
    #[serde(default, rename = "accountId", deserialize_with = "de::opt_i64")]
    pub account_id: Option<i64>,
    /// The id of the record that was created.
    #[serde(default, rename = "recordId", deserialize_with = "de::opt_i64")]
    pub record_id: Option<i64>,
}

/// The answer to `dyndns.updateRecord`.
///
/// ```
/// use inwx_client::DynDnsUpdate;
///
/// let updated: DynDnsUpdate = serde_json::from_str(
///     r#"{"ipv4_updated":1,"ipv6_updated":0}"#,
/// )?;
/// assert_eq!(updated.ipv4_updated, Some(1));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DynDnsUpdate {
    /// Number of IPv4 records updated.
    #[serde(default, rename = "ipv4_updated", deserialize_with = "de::opt_i64")]
    pub ipv4_updated: Option<i64>,
    /// Number of IPv6 records updated.
    #[serde(default, rename = "ipv6_updated", deserialize_with = "de::opt_i64")]
    pub ipv6_updated: Option<i64>,
}

/// One log entry of a DynDNS account (`dyndns.log`).
///
/// ```
/// use inwx_client::DynDnsLogEntry;
///
/// let entry: DynDnsLogEntry = serde_json::from_str(
///     r#"{"ip":"203.0.113.7","date":"2026-10-26T08:00:00"}"#,
/// )?;
/// assert_eq!(entry.ip.as_deref(), Some("203.0.113.7"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DynDnsLogEntry {
    /// The address that was seen.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub ip: Option<String>,
    /// When the update happened.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub date: Option<String>,
    /// Any other field the log line carries.
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, Value>,
}

/// The answer to `dyndns.log`.
///
/// ```
/// use inwx_client::DynDnsLog;
///
/// let log: DynDnsLog = serde_json::from_str(
///     r#"{"count":1,"logs":[{"ip":"203.0.113.7","date":"2026-10-26T08:00:00"}]}"#,
/// )?;
/// assert_eq!(log.count, Some(1));
/// assert_eq!(log.entries.len(), 1);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DynDnsLog {
    /// Number of log lines.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The log lines.
    #[serde(default, rename = "logs")]
    pub entries: Vec<DynDnsLogEntry>,
}

impl<T: Transport> InwxClient<T> {
    /// Changes a DynDNS account's password (`dyndns.changepassword`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.change_dyndns_password("tenant-42", "new-pass").await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable username or password, plus the
    /// usual transport and API errors.
    pub async fn change_dyndns_password(
        &self,
        username: &str,
        password: impl Into<String>,
    ) -> Result<()> {
        validate_username("dyndns.username", username)?;
        let password = password.into();
        if password.is_empty() || password.chars().count() > 64 {
            return Err(Error::validation(
                "dyndns.password",
                "must be 1 to 64 characters",
            ));
        }
        self.call(
            "dyndns.changepassword",
            json!({ "username": username.trim(), "password": password }),
        )
        .await?;
        Ok(())
    }

    /// Checks whether a DynDNS username or hostname is available
    /// (`dyndns.check`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let check = client.check_dyndns(Some("tenant-42"), None).await?;
    /// println!("available: {}", check.is_available());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when neither a username nor a hostname is given,
    /// plus the usual transport and API errors.
    pub async fn check_dyndns(
        &self,
        username: Option<&str>,
        hostnames: Option<&[Hostname]>,
    ) -> Result<DynDnsCheck> {
        let mut params = serde_json::Map::new();
        if let Some(username) = username {
            validate_username("dyndns.username", username)?;
            params.insert("username".to_owned(), json!(username.trim()));
        }
        if let Some(hostnames) = hostnames {
            if hostnames.is_empty() {
                return Err(Error::validation(
                    "dyndns.hostname",
                    "must not be empty when given; omit the list instead",
                ));
            }
            params.insert(
                "hostname".to_owned(),
                json!(hostnames.iter().map(Hostname::as_str).collect::<Vec<_>>()),
            );
        }
        if params.is_empty() {
            return Err(Error::validation(
                "dyndns.check",
                "needs a username or a hostname list",
            ));
        }
        let data = self.call("dyndns.check", Value::Object(params)).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Creates a DynDNS account (`dyndns.create`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DynDnsAccount, Hostname, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let request = DynDnsAccount::create(
    ///     "tenant-42",
    ///     std::env::var("DYNDNS_PASSWORD")?,
    ///     &[Hostname::parse("home.example.net")?],
    /// )?;
    /// let created = client.create_dyndns(&request).await?;
    /// println!("{:?}", created.account_id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors — `2302` when the username is taken.
    pub async fn create_dyndns(&self, request: &DynDnsAccount) -> Result<DynDnsCreated> {
        let data = self.call("dyndns.create", request.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Deletes a DynDNS account (`dyndns.delete`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DynDnsAccountRef, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client
    ///     .delete_dyndns(&DynDnsAccountRef::by_id(71)?)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors — `2303` when the account does not
    /// exist.
    pub async fn delete_dyndns(&self, account: &DynDnsAccountRef) -> Result<()> {
        self.call("dyndns.delete", account.params()).await?;
        Ok(())
    }

    /// Reads one DynDNS account (`dyndns.info`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DynDnsAccountRef, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let account = client
    ///     .dyndns_info(&DynDnsAccountRef::by_id(71)?)
    ///     .await?;
    /// println!("{:?}", account.records.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors — `2303` when the account does not
    /// exist.
    pub async fn dyndns_info(&self, account: &DynDnsAccountRef) -> Result<DynDnsAccountInfo> {
        let data = self.call("dyndns.info", account.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Lists DynDNS accounts, optionally filtered (`dyndns.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DynDnsAccountRef, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for account in client.list_dyndns(None).await? {
    ///     println!("{:?}", account.username);
    /// }
    /// let one = client
    ///     .list_dyndns(Some(&DynDnsAccountRef::by_username("tenant-42")?))
    ///     .await?;
    /// assert!(one.len() <= 1);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn list_dyndns(
        &self,
        filter: Option<&DynDnsAccountRef>,
    ) -> Result<Vec<DynDnsAccountInfo>> {
        let params = filter.map_or_else(|| json!({}), DynDnsAccountRef::params);
        let data = self.call("dyndns.list", params).await?;
        // The answer is either a bare array or a single object.
        let entries = match data {
            Value::Array(entries) => entries,
            Value::Object(_) => vec![data],
            _ => Vec::new(),
        };
        Ok(entries
            .into_iter()
            .filter_map(|entry| serde_json::from_value(entry).ok())
            .collect())
    }

    /// Reads a DynDNS account's recent log (`dyndns.log`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for entry in client.dyndns_log(71).await?.entries {
    ///     println!("{:?}", entry.ip);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive account id, plus the usual
    /// transport and API errors.
    pub async fn dyndns_log(&self, account_id: i64) -> Result<DynDnsLog> {
        if account_id <= 0 {
            return Err(Error::validation(
                "accountId",
                format!("must be a positive account id, got {account_id}"),
            ));
        }
        let data = self
            .call("dyndns.log", json!({ "accountId": account_id }))
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Updates the addresses of a DynDNS account (`dyndns.updateRecord`).
    ///
    /// At least one of the two addresses is required: the call selects the
    /// records to change by address family, so a request with neither changes
    /// nothing and would be a silent no-op.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::InwxClient;
    /// use inwx_client::ReqwestTransport;
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let updated = client
    ///     .dyndns_update_record(Some("203.0.113.7".parse()?), None)
    ///     .await?;
    /// println!("{:?}", updated.ipv4_updated);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// See the module documentation: how the account is selected is not
    /// documented, so this call is marked *unverified*.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when both addresses are `None` (or an IPv4 address
    /// is passed as `ipv6`), plus the usual transport and API errors.
    pub async fn dyndns_update_record(
        &self,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) -> Result<DynDnsUpdate> {
        if ipv4.is_none() && ipv6.is_none() {
            return Err(Error::validation(
                "dyndns.updateRecord",
                "needs at least one address",
            ));
        }
        let mut params = serde_json::Map::new();
        if let Some(ip) = ipv4 {
            params.insert("ipAddress".to_owned(), json!(ip.to_string()));
        }
        if let Some(ip) = ipv6 {
            params.insert("ipAddressV6".to_owned(), json!(ip.to_string()));
        }
        let data = self
            .call("dyndns.updateRecord", Value::Object(params))
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str) -> Hostname {
        Hostname::parse(name).unwrap()
    }

    #[test]
    fn usernames_follow_the_documented_length() {
        assert!(DynDnsAccountRef::by_username("abcd").is_err()); // 4
        assert!(DynDnsAccountRef::by_username("abcde").is_ok()); // 5
        assert!(DynDnsAccountRef::by_username(&"a".repeat(42)).is_ok());
        assert!(DynDnsAccountRef::by_username(&"a".repeat(43)).is_err());
    }

    #[test]
    fn accounts_need_a_hostname_and_a_password() {
        assert!(DynDnsAccount::create("tenant-42", "", &[host("a.example.net")]).is_err());
        assert!(DynDnsAccount::create("tenant-42", "pw", &[]).is_err());
        assert!(DynDnsAccount::create(
            "tenant-42",
            "pw",
            &[host("a.example.net"), host("a.example.net")]
        )
        .is_err());
    }

    #[test]
    fn debug_redacts_the_password() {
        let account =
            DynDnsAccount::create("tenant-42", "hunter2", &[host("a.example.net")]).unwrap();
        let rendered = format!("{account:?}");
        assert!(rendered.contains("tenant-42"));
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn accounts_compare_their_values() {
        let account =
            DynDnsAccount::create("tenant-42", "hunter2", &[host("a.example.net")]).unwrap();
        assert_eq!(
            account,
            DynDnsAccount::create("tenant-42", "hunter2", &[host("a.example.net")]).unwrap()
        );
        assert_ne!(
            account,
            DynDnsAccount::create("tenant-42", "hunter3", &[host("a.example.net")]).unwrap()
        );
    }

    #[test]
    fn account_refs_carry_exactly_one_selector() {
        let by_id = DynDnsAccountRef::by_id(71).unwrap().params();
        assert_eq!(by_id.as_object().unwrap().len(), 1);
        let by_name = DynDnsAccountRef::by_username("tenant-42").unwrap().params();
        assert_eq!(by_name.as_object().unwrap().len(), 1);
    }

    #[test]
    fn parse_ip_rejects_garbage() {
        assert!(crate::parse_ip("203.0.113.7").unwrap().is_ipv4());
        assert!(crate::parse_ip("2001:db8::1").unwrap().is_ipv6());
        assert!(crate::parse_ip("").is_err());
    }
}
