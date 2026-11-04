//! The `account.*` object: session probe, account data, password changes,
//! unlocking, sub-accounts and roles.
//!
//! The account object is the one namespace that describes the caller as well as
//! the accounts a reseller manages. Reads are classified in [`crate::is_read_only_method`]
//! and may be retried after an uncertain failure; every mutation here changes
//! access, credentials or account state and is therefore never replayed.
//!
//! ```
//! use inwx_client::{AccountRoleId, AccountUpdate};
//!
//! let update = AccountUpdate::new()?
//!     .with_city("Leipzig")?
//!     .with_language("de")?;
//! assert_eq!(update.params()?["city"], "Leipzig");
//! assert_eq!(AccountRoleId::Dns.id(), 20004);
//! # Ok::<(), inwx_client::Error>(())
//! ```

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Map, Value};
use std::fmt;
use std::str::FromStr;

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{
    de, list_rows, validate_country_code, validate_email_field, validate_id, validate_text,
    validate_token, validate_username, Password,
};

const MAX_TEXT64: usize = 64;
const MAX_TEXT255: usize = 255;
const MAX_TEXT10: usize = 10;
const MAX_TEXT100: usize = 100;
const MAX_LANGUAGE_LEN: usize = 10;
const MAX_TAN_LEN: usize = 10;

/// A role id in `account.getroles`, `account.addrole` and
/// `account.removerole`.
///
/// The API documents numeric role ids and may add more; an id this crate does
/// not know is carried as [`AccountRoleId::Other`] on responses. Requests accept
/// any positive id, so a role introduced by INWX after this crate was built does
/// not require a new release.
///
/// ```
/// use inwx_client::AccountRoleId;
///
/// assert_eq!(AccountRoleId::from_id(20000), AccountRoleId::Standard);
/// assert_eq!(AccountRoleId::from_id(20999), AccountRoleId::Other(20999));
/// assert_eq!(AccountRoleId::Accounting.to_string(), "20001");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountRoleId {
    /// Standard/full access (`20000`).
    Standard,
    /// Accounting (`20001`).
    Accounting,
    /// Domains (`20002`).
    Domain,
    /// Hosting (`20003`).
    Hosting,
    /// DNS (`20004`).
    Dns,
    /// Authcodes (`20005`).
    Authcodes,
    /// A role id this crate does not know, carried verbatim.
    Other(i64),
}

impl AccountRoleId {
    /// Converts an id into a known role or [`AccountRoleId::Other`].
    ///
    /// ```
    /// use inwx_client::AccountRoleId;
    ///
    /// assert_eq!(AccountRoleId::from_id(20005), AccountRoleId::Authcodes);
    /// assert_eq!(AccountRoleId::from_id(20006), AccountRoleId::Other(20006));
    /// ```
    #[must_use]
    pub fn from_id(id: i64) -> Self {
        match id {
            20_000 => Self::Standard,
            20_001 => Self::Accounting,
            20_002 => Self::Domain,
            20_003 => Self::Hosting,
            20_004 => Self::Dns,
            20_005 => Self::Authcodes,
            other => Self::Other(other),
        }
    }

    /// Builds a request role id, refusing non-positive values.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `id` is not positive.
    ///
    /// ```
    /// use inwx_client::AccountRoleId;
    ///
    /// assert!(AccountRoleId::new(20004).is_ok());
    /// assert!(AccountRoleId::new(0).is_err());
    /// ```
    pub fn new(id: i64) -> Result<Self> {
        Ok(Self::from_id(validate_id("account.roleId", id)?))
    }

    /// The numeric wire id.
    ///
    /// ```
    /// use inwx_client::AccountRoleId;
    /// assert_eq!(AccountRoleId::Standard.id(), 20000);
    /// ```
    #[must_use]
    pub fn id(self) -> i64 {
        match self {
            Self::Standard => 20_000,
            Self::Accounting => 20_001,
            Self::Domain => 20_002,
            Self::Hosting => 20_003,
            Self::Dns => 20_004,
            Self::Authcodes => 20_005,
            Self::Other(id) => id,
        }
    }

    /// The human-readable name for known roles.
    ///
    /// ```
    /// use inwx_client::AccountRoleId;
    /// assert_eq!(AccountRoleId::Dns.name(), Some("DNS"));
    /// assert_eq!(AccountRoleId::Other(20999).name(), None);
    /// ```
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        match self {
            Self::Standard => Some("Standard"),
            Self::Accounting => Some("Accounting"),
            Self::Domain => Some("Domain"),
            Self::Hosting => Some("Hosting"),
            Self::Dns => Some("DNS"),
            Self::Authcodes => Some("Authcodes"),
            Self::Other(_) => None,
        }
    }
}

impl fmt::Display for AccountRoleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.id().to_string())
    }
}

impl FromStr for AccountRoleId {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let id = input
            .trim()
            .parse::<i64>()
            .map_err(|_| Error::validation("account.roleId", "must be a numeric role id"))?;
        Self::new(id)
    }
}

impl Serialize for AccountRoleId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_i64(self.id())
    }
}

impl<'de> Deserialize<'de> for AccountRoleId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let id = match value {
            Value::Number(number) => number.as_i64(),
            Value::String(text) => text.trim().parse().ok(),
            _ => None,
        }
        .ok_or_else(|| D::Error::custom("account.roleId must be a number or numeric string"))?;
        Self::new(id).map_err(D::Error::custom)
    }
}

/// A legacy string role used by `account.getroles` before the numeric role id
/// was confirmed against the published tables.
///
/// The live API identifies roles by id. This type stays for source compatibility
/// with earlier releases; new code should use [`AccountRoleId`].
///
/// ```
/// use inwx_client::AccountRole;
///
/// assert_eq!(AccountRole::parse("admin")?, AccountRole::Admin);
/// assert_eq!(AccountRole::parse("TRUSTEE")?.as_str(), "TRUSTEE");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AccountRole {
    /// The account owner itself.
    Owner,
    /// Full control over the account.
    Admin,
    /// Technical contact.
    Tech,
    /// Billing contact.
    Billing,
    /// Explicitly no role.
    None,
    /// A role this crate does not know; carried verbatim, upper-cased.
    Other(String),
}

impl AccountRole {
    /// Parses a role, upper-casing it; unknown values become
    /// [`AccountRole::Other`].
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the input is empty.
    ///
    /// ```
    /// use inwx_client::AccountRole;
    ///
    /// assert_eq!(AccountRole::parse(" admin ")?, AccountRole::Admin);
    /// assert_eq!(AccountRole::parse("trustee")?, AccountRole::Other("TRUSTEE".into()));
    /// assert!(AccountRole::parse("  ").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn parse(input: &str) -> Result<Self> {
        let upper = input.trim().to_ascii_uppercase();
        if upper.is_empty() {
            return Err(Error::validation("account.role", "must not be empty"));
        }
        Ok(match upper.as_str() {
            "OWNER" => Self::Owner,
            "ADMIN" => Self::Admin,
            "TECH" => Self::Tech,
            "BILLING" => Self::Billing,
            "NONE" => Self::None,
            _ => Self::Other(upper),
        })
    }

    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::AccountRole;
    /// assert_eq!(AccountRole::Admin.as_str(), "ADMIN");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Owner => "OWNER",
            Self::Admin => "ADMIN",
            Self::Tech => "TECH",
            Self::Billing => "BILLING",
            Self::None => "NONE",
            Self::Other(raw) => raw,
        }
    }
}

impl fmt::Display for AccountRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for AccountRole {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl Serialize for AccountRole {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AccountRole {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// One role returned by `account.getroles`.
///
/// The documented response is an array whose rows can be either role ids or
/// objects carrying `roleId` / `id`. Every field is optional and scalars are
/// accepted as numbers or strings, so a newer spelling degrades to `None`
/// instead of failing the whole list.
///
/// ```
/// use inwx_client::{AccountRoleEntry, AccountRoleId};
///
/// let entry: AccountRoleEntry = serde_json::from_str(r#"{"roleId":"20004","extra":true}"#)?;
/// assert_eq!(entry.role_id, Some(AccountRoleId::Dns));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct AccountRoleEntry {
    /// Account id the role belongs to, when the row reports it.
    #[serde(
        default,
        rename = "accountId",
        alias = "account_id",
        deserialize_with = "de::opt_i64"
    )]
    pub account_id: Option<i64>,
    /// Numeric role id.
    #[serde(
        default,
        rename = "roleId",
        alias = "role_id",
        deserialize_with = "opt_role_id"
    )]
    pub role_id: Option<AccountRoleId>,
    /// Legacy string role, accepted permissively for older fixtures.
    #[serde(default, deserialize_with = "opt_account_role")]
    pub role: Option<AccountRole>,
}

/// Parses a numeric role id leniently: absent or empty means `None`.
fn opt_role_id<'de, D>(deserializer: D) -> std::result::Result<Option<AccountRoleId>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    Ok(match value {
        Value::Number(number) => number.as_i64().and_then(|id| AccountRoleId::new(id).ok()),
        Value::String(text) if !text.trim().is_empty() => text.trim().parse().ok(),
        _ => None,
    })
}

/// Parses a legacy role leniently: absent or empty means `None`, unknown is
/// carried.
fn opt_account_role<'de, D>(deserializer: D) -> std::result::Result<Option<AccountRole>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = de::opt_string(deserializer)?;
    match raw {
        Some(raw) if !raw.trim().is_empty() => Ok(AccountRole::parse(&raw).ok()),
        _ => Ok(None),
    }
}

/// The answer to `account.check`.
///
/// The method answers with the currently authenticated username when the API
/// reports one; every field is optional and unknown keys are ignored.
///
/// ```
/// use inwx_client::AccountCheck;
///
/// let check: AccountCheck = serde_json::from_str(r#"{"user":"florian","extra":1}"#)?;
/// assert_eq!(check.user.as_deref(), Some("florian"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct AccountCheck {
    /// Username of the active session.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub user: Option<String>,
}

/// One sub-account from `account.list`.
///
/// ```
/// use inwx_client::SubAccount;
///
/// let account: SubAccount = serde_json::from_str(
///     r#"{"id":"7","username":"sub","cc":"DE","tfaEnabled":1,"extra":true}"#,
/// )?;
/// assert_eq!(account.id, Some(7));
/// assert_eq!(account.two_factor_enabled, Some(true));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct SubAccount {
    /// Account id.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Login name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub username: Option<String>,
    /// First name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub firstname: Option<String>,
    /// Last name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub lastname: Option<String>,
    /// Organisation.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub org: Option<String>,
    /// Street.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub street: Option<String>,
    /// Postal code.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub pc: Option<String>,
    /// City.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub city: Option<String>,
    /// Country code.
    #[serde(
        default,
        rename = "cc",
        alias = "countryCode",
        deserialize_with = "de::opt_string"
    )]
    pub country_code: Option<String>,
    /// Phone number.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub voice: Option<String>,
    /// Fax number.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub fax: Option<String>,
    /// Email address.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub email: Option<String>,
    /// Whether two-factor authentication is enabled.
    #[serde(
        default,
        rename = "tfaEnabled",
        alias = "tfa_enabled",
        deserialize_with = "de::opt_bool"
    )]
    pub two_factor_enabled: Option<bool>,
}

/// The answer to `account.list`: the reseller account id and its sub-accounts.
///
/// ```
/// use inwx_client::SubAccountList;
///
/// let list: SubAccountList = serde_json::from_str(
///     r#"{"adminId":"1","accounts":[{"id":2,"username":"sub"}],"extra":true}"#,
/// )?;
/// assert_eq!(list.admin_id, Some(1));
/// assert_eq!(list.accounts[0].id, Some(2));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct SubAccountList {
    /// Reseller/admin account id.
    #[serde(
        default,
        rename = "adminId",
        alias = "admin_id",
        deserialize_with = "de::opt_i64"
    )]
    pub admin_id: Option<i64>,
    /// Sub-accounts under the reseller.
    #[serde(default, deserialize_with = "rows")]
    pub accounts: Vec<SubAccount>,
}

/// Permissively decodes a list that may be an array or a single object.
fn rows<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = Value::deserialize(deserializer)?;
    Ok(match value {
        Value::Array(entries) => entries
            .into_iter()
            .filter_map(|entry| serde_json::from_value(entry).ok())
            .collect(),
        Value::Object(_) => {
            serde_json::from_value(value).map_or_else(|_| Vec::new(), |row| vec![row])
        }
        _ => Vec::new(),
    })
}

/// A request for `account.create`.
///
/// The fields the API requires are constructor parameters; optional fields are
/// set with builder methods. Every field is validated before the request is
/// built, so an invalid value becomes [`Error::Validation`] instead of an API
/// error after the sub-account was created.
///
/// ```
/// use inwx_client::SubAccountCreate;
///
/// let request = SubAccountCreate::new(
///     "sub-account",
///     "Dr.",
///     "Ada",
///     "Lovelace",
///     "Main Street 1",
///     "12345",
///     "London",
///     "GB",
///     "ada@example.com",
/// )?;
/// assert_eq!(request.params()?["username"], "sub-account");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubAccountCreate {
    username: String,
    title: String,
    firstname: String,
    lastname: String,
    street: String,
    pc: String,
    city: String,
    cc: String,
    email: String,
    org: Option<String>,
    voice: Option<String>,
    fax: Option<String>,
    www: Option<String>,
    language: Option<String>,
    required_2fa: Option<i64>,
}

impl SubAccountCreate {
    /// Builds a create request with every documented required field.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when a field is empty, too long or not in the
    /// documented shape.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        username: impl Into<String>,
        title: impl Into<String>,
        firstname: impl Into<String>,
        lastname: impl Into<String>,
        street: impl Into<String>,
        pc: impl Into<String>,
        city: impl Into<String>,
        cc: impl Into<String>,
        email: impl Into<String>,
    ) -> Result<Self> {
        let username = checked_username("account.username", &username.into())?;
        let title = checked_text("account.title", &title.into(), MAX_TEXT64)?;
        let firstname = checked_text("account.firstname", &firstname.into(), MAX_TEXT64)?;
        let lastname = checked_text("account.lastname", &lastname.into(), MAX_TEXT64)?;
        let street = checked_text("account.street", &street.into(), MAX_TEXT255)?;
        let pc = checked_text("account.pc", &pc.into(), MAX_TEXT10)?;
        let city = checked_text("account.city", &city.into(), MAX_TEXT64)?;
        let cc = validate_country_code("account.cc", &cc.into())?;
        let email = validate_email_field("account.email", &email.into())?;
        Ok(Self {
            username,
            title,
            firstname,
            lastname,
            street,
            pc,
            city,
            cc,
            email,
            org: None,
            voice: None,
            fax: None,
            www: None,
            language: None,
            required_2fa: None,
        })
    }

    /// Sets the organisation (`org`, `token0255`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_org(mut self, org: impl Into<String>) -> Result<Self> {
        self.org = Some(checked_token("account.org", &org.into())?);
        Ok(self)
    }

    /// Sets the phone number (`voice`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_voice(mut self, voice: impl Into<String>) -> Result<Self> {
        self.voice = Some(checked_text("account.voice", &voice.into(), MAX_TEXT64)?);
        Ok(self)
    }

    /// Sets the fax number (`fax`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_fax(mut self, fax: impl Into<String>) -> Result<Self> {
        self.fax = Some(checked_text("account.fax", &fax.into(), MAX_TEXT64)?);
        Ok(self)
    }

    /// Sets the website (`www`, `token0255`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_www(mut self, www: impl Into<String>) -> Result<Self> {
        self.www = Some(checked_token("account.www", &www.into())?);
        Ok(self)
    }

    /// Sets the interface language (`language`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_language(mut self, language: impl Into<String>) -> Result<Self> {
        self.language = Some(checked_text(
            "account.language",
            &language.into(),
            MAX_LANGUAGE_LEN,
        )?);
        Ok(self)
    }

    /// Sets the `required2fa` flag.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not a non-negative API `int`.
    pub fn with_required_2fa(mut self, required: i64) -> Result<Self> {
        self.required_2fa = Some(checked_non_negative("account.required2fa", required)?);
        Ok(self)
    }

    /// The `account.create` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the already validated fields cannot be
    /// represented as JSON.
    pub fn params(&self) -> Result<Value> {
        let mut params = Map::new();
        params.insert("username".to_owned(), json!(self.username));
        params.insert("title".to_owned(), json!(self.title));
        params.insert("firstname".to_owned(), json!(self.firstname));
        params.insert("lastname".to_owned(), json!(self.lastname));
        params.insert("street".to_owned(), json!(self.street));
        params.insert("pc".to_owned(), json!(self.pc));
        params.insert("city".to_owned(), json!(self.city));
        params.insert("cc".to_owned(), json!(self.cc));
        params.insert("email".to_owned(), json!(self.email));
        for (key, value) in [
            ("org", &self.org),
            ("voice", &self.voice),
            ("fax", &self.fax),
            ("www", &self.www),
            ("language", &self.language),
        ] {
            if let Some(value) = value {
                params.insert(key.to_owned(), json!(value));
            }
        }
        if let Some(required) = self.required_2fa {
            params.insert("required2fa".to_owned(), json!(required));
        }
        Ok(Value::Object(params))
    }
}

/// The answer to `account.create`.
///
/// ```
/// use inwx_client::SubAccountCreated;
///
/// let created: SubAccountCreated = serde_json::from_str(r#"{"id":"4711"}"#)?;
/// assert_eq!(created.id, Some(4711));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct SubAccountCreated {
    /// Id of the created account.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
}

/// The answer to `account.delete`.
///
/// ```
/// use inwx_client::SubAccountsDeleted;
///
/// let deleted: SubAccountsDeleted = serde_json::from_str(r#"{"countDeleted":"2"}"#)?;
/// assert_eq!(deleted.count_deleted, Some(2));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct SubAccountsDeleted {
    /// Count of successfully deleted accounts.
    #[serde(
        default,
        rename = "countDeleted",
        alias = "count_deleted",
        deserialize_with = "de::opt_i64"
    )]
    pub count_deleted: Option<i64>,
}

/// A request for `account.update`.
///
/// All fields are optional on the wire. The builder accepts only changed fields
/// and [`AccountUpdate::params`] refuses an empty update, so an accidental call
/// cannot send a no-op mutation.
///
/// ```
/// use inwx_client::AccountUpdate;
///
/// let update = AccountUpdate::new()?.with_firstname("Ada")?.with_language("en")?;
/// assert_eq!(update.params()?["firstname"], "Ada");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AccountUpdate {
    username: Option<String>,
    title: Option<String>,
    firstname: Option<String>,
    lastname: Option<String>,
    org: Option<String>,
    street: Option<String>,
    pc: Option<String>,
    city: Option<String>,
    cc: Option<String>,
    voice: Option<String>,
    fax: Option<String>,
    www: Option<String>,
    email: Option<String>,
    email_automated: Option<String>,
    email_billing: Option<String>,
    renewal_report_email: Option<String>,
    service_pin: Option<String>,
    summary_invoice: Option<bool>,
    mail_list_id: Vec<i64>,
    language: Option<String>,
    notification_email: Option<bool>,
    notification_queue: Option<bool>,
    renewal_report: Option<bool>,
    low_balance: Option<f64>,
    bank_acc_holder: Option<String>,
    bank_code: Option<String>,
    bank_name: Option<String>,
    bank_acc_holder_no: Option<String>,
    vat_no: Option<String>,
    whois_provider: Option<String>,
    whois_url: Option<String>,
    default_registrant: Option<i64>,
    default_admin: Option<i64>,
    default_tech: Option<i64>,
    invoice_routing: Option<String>,
    order_reference: Option<String>,
    default_billing: Option<i64>,
    invoice_xml: Option<bool>,
    invoice_pdf: Option<bool>,
    default_nsset: Option<i64>,
    default_web: Option<String>,
    default_mail: Option<String>,
    default_import_ns: Option<bool>,
    default_renewal_mode: Option<String>,
    suppliment_invoice_text: Option<String>,
    password: Option<Password>,
    rows_per_page: Option<i64>,
    is_reseller: Option<i64>,
    testing: bool,
    nif: Option<String>,
    id_card: Option<String>,
    disable_premium: Option<bool>,
    premium_agreed_price_required: Option<bool>,
    enable_advertising: Option<bool>,
    wdrp_email: Option<String>,
    wdrp_email_name: Option<String>,
    errp_email: Option<String>,
    errp_email_name: Option<String>,
    foa_email: Option<String>,
    foa_email_name: Option<String>,
}

impl AccountUpdate {
    /// An empty update.
    ///
    /// # Errors
    ///
    /// This constructor cannot fail today; the fallible signature leaves room
    /// for future validation without changing call sites.
    pub fn new() -> Result<Self> {
        Ok(Self::default())
    }

    /// Sets the login name (`username`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the username is not in the documented shape.
    pub fn with_username(mut self, username: impl Into<String>) -> Result<Self> {
        self.username = Some(checked_username("account.username", &username.into())?);
        Ok(self)
    }

    /// Sets the salutation title (`title`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_title(mut self, title: impl Into<String>) -> Result<Self> {
        self.title = Some(checked_text("account.title", &title.into(), MAX_TEXT64)?);
        Ok(self)
    }

    /// Sets the first name (`firstname`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_firstname(mut self, firstname: impl Into<String>) -> Result<Self> {
        self.firstname = Some(checked_text(
            "account.firstname",
            &firstname.into(),
            MAX_TEXT64,
        )?);
        Ok(self)
    }

    /// Sets the last name (`lastname`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_lastname(mut self, lastname: impl Into<String>) -> Result<Self> {
        self.lastname = Some(checked_text(
            "account.lastname",
            &lastname.into(),
            MAX_TEXT64,
        )?);
        Ok(self)
    }

    /// Sets the organisation (`org`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_org(mut self, org: impl Into<String>) -> Result<Self> {
        self.org = Some(checked_token("account.org", &org.into())?);
        Ok(self)
    }

    /// Sets the street (`street`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_street(mut self, street: impl Into<String>) -> Result<Self> {
        self.street = Some(checked_text("account.street", &street.into(), MAX_TEXT255)?);
        Ok(self)
    }

    /// Sets the postal code (`pc`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_pc(mut self, pc: impl Into<String>) -> Result<Self> {
        self.pc = Some(checked_text("account.pc", &pc.into(), MAX_TEXT10)?);
        Ok(self)
    }

    /// Sets the city (`city`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_city(mut self, city: impl Into<String>) -> Result<Self> {
        self.city = Some(checked_text("account.city", &city.into(), MAX_TEXT64)?);
        Ok(self)
    }

    /// Sets the country code (`cc`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not an ISO 3166-1 alpha-2 code.
    pub fn with_country_code(mut self, cc: impl Into<String>) -> Result<Self> {
        self.cc = Some(validate_country_code("account.cc", &cc.into())?);
        Ok(self)
    }

    /// Sets the phone number (`voice`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_voice(mut self, voice: impl Into<String>) -> Result<Self> {
        self.voice = Some(checked_text("account.voice", &voice.into(), MAX_TEXT64)?);
        Ok(self)
    }

    /// Sets the fax number (`fax`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_fax(mut self, fax: impl Into<String>) -> Result<Self> {
        self.fax = Some(checked_text("account.fax", &fax.into(), MAX_TEXT64)?);
        Ok(self)
    }

    /// Sets the website (`www`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_www(mut self, www: impl Into<String>) -> Result<Self> {
        self.www = Some(checked_token("account.www", &www.into())?);
        Ok(self)
    }

    /// Sets the email address (`email`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not an email address.
    pub fn with_email(mut self, email: impl Into<String>) -> Result<Self> {
        self.email = Some(validate_email_field("account.email", &email.into())?);
        Ok(self)
    }

    /// Sets the automated email address (`emailAutomated`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not an email address.
    pub fn with_email_automated(mut self, email: impl Into<String>) -> Result<Self> {
        self.email_automated = Some(validate_email_field(
            "account.emailAutomated",
            &email.into(),
        )?);
        Ok(self)
    }

    /// Sets the billing email address (`emailBilling`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not an email address.
    pub fn with_email_billing(mut self, email: impl Into<String>) -> Result<Self> {
        self.email_billing = Some(validate_email_field("account.emailBilling", &email.into())?);
        Ok(self)
    }

    /// Sets the renewal report email address (`renewalReportEmail`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not an email address.
    pub fn with_renewal_report_email(mut self, email: impl Into<String>) -> Result<Self> {
        self.renewal_report_email = Some(validate_email_field(
            "account.renewalReportEmail",
            &email.into(),
        )?);
        Ok(self)
    }

    /// Sets the service PIN (`servicePin`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_service_pin(mut self, service_pin: impl Into<String>) -> Result<Self> {
        self.service_pin = Some(checked_text(
            "account.servicePin",
            &service_pin.into(),
            MAX_TEXT64,
        )?);
        Ok(self)
    }

    /// Sets the `summaryInvoice` flag.
    #[must_use]
    pub fn with_summary_invoice(mut self, summary_invoice: bool) -> Self {
        self.summary_invoice = Some(summary_invoice);
        self
    }

    /// Sets the subscribed mail-list ids (`mailListId`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty list or a non-positive id.
    pub fn with_mail_list_ids(mut self, ids: &[i64]) -> Result<Self> {
        self.mail_list_id = checked_ids("account.mailListId", ids)?;
        Ok(self)
    }

    /// Sets the interface language (`language`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_language(mut self, language: impl Into<String>) -> Result<Self> {
        self.language = Some(checked_text(
            "account.language",
            &language.into(),
            MAX_LANGUAGE_LEN,
        )?);
        Ok(self)
    }

    /// Sets the `notificationEmail` flag.
    #[must_use]
    pub fn with_notification_email(mut self, value: bool) -> Self {
        self.notification_email = Some(value);
        self
    }

    /// Sets the `notificationQueue` flag.
    #[must_use]
    pub fn with_notification_queue(mut self, value: bool) -> Self {
        self.notification_queue = Some(value);
        self
    }

    /// Sets the `renewalReport` flag.
    #[must_use]
    pub fn with_renewal_report(mut self, value: bool) -> Self {
        self.renewal_report = Some(value);
        self
    }

    /// Sets the low-balance notification value (`lowBalance`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is NaN or infinite.
    pub fn with_low_balance(mut self, value: f64) -> Result<Self> {
        if !value.is_finite() {
            return Err(Error::validation(
                "account.lowBalance",
                "must be a finite number",
            ));
        }
        self.low_balance = Some(value);
        Ok(self)
    }

    /// Sets the bank account holder (`bankAccHolder`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_bank_account_holder(mut self, value: impl Into<String>) -> Result<Self> {
        self.bank_acc_holder = Some(checked_token("account.bankAccHolder", &value.into())?);
        Ok(self)
    }

    /// Sets the bank code (`bankCode`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_bank_code(mut self, value: impl Into<String>) -> Result<Self> {
        self.bank_code = Some(checked_text("account.bankCode", &value.into(), MAX_TEXT64)?);
        Ok(self)
    }

    /// Sets the bank name (`bankName`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_bank_name(mut self, value: impl Into<String>) -> Result<Self> {
        self.bank_name = Some(checked_text("account.bankName", &value.into(), MAX_TEXT64)?);
        Ok(self)
    }

    /// Sets the bank account number (`bankAccHolderNo`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_bank_account_number(mut self, value: impl Into<String>) -> Result<Self> {
        self.bank_acc_holder_no = Some(checked_text(
            "account.bankAccHolderNo",
            &value.into(),
            MAX_TEXT64,
        )?);
        Ok(self)
    }

    /// Sets the VAT number (`vatNo`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_vat_no(mut self, value: impl Into<String>) -> Result<Self> {
        self.vat_no = Some(checked_text("account.vatNo", &value.into(), MAX_TEXT64)?);
        Ok(self)
    }

    /// Sets the default WHOIS provider (`whoisProvider`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_whois_provider(mut self, value: impl Into<String>) -> Result<Self> {
        self.whois_provider = Some(checked_token("account.whoisProvider", &value.into())?);
        Ok(self)
    }

    /// Sets the default WHOIS URL (`whoisUrl`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_whois_url(mut self, value: impl Into<String>) -> Result<Self> {
        self.whois_url = Some(checked_token("account.whoisUrl", &value.into())?);
        Ok(self)
    }

    /// Sets the default registrant handle (`defaultRegistrant`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not a positive handle id.
    pub fn with_default_registrant(mut self, value: i64) -> Result<Self> {
        self.default_registrant = Some(validate_id("account.defaultRegistrant", value)?);
        Ok(self)
    }

    /// Sets the default admin handle (`defaultAdmin`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not a positive handle id.
    pub fn with_default_admin(mut self, value: i64) -> Result<Self> {
        self.default_admin = Some(validate_id("account.defaultAdmin", value)?);
        Ok(self)
    }

    /// Sets the default tech handle (`defaultTech`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not a positive handle id.
    pub fn with_default_tech(mut self, value: i64) -> Result<Self> {
        self.default_tech = Some(validate_id("account.defaultTech", value)?);
        Ok(self)
    }

    /// Sets the invoice routing id (`invoiceRouting`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_invoice_routing(mut self, value: impl Into<String>) -> Result<Self> {
        self.invoice_routing = Some(checked_text(
            "account.invoiceRouting",
            &value.into(),
            MAX_TEXT100,
        )?);
        Ok(self)
    }

    /// Sets the order reference (`orderReference`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_order_reference(mut self, value: impl Into<String>) -> Result<Self> {
        self.order_reference = Some(checked_text(
            "account.orderReference",
            &value.into(),
            MAX_TEXT100,
        )?);
        Ok(self)
    }

    /// Sets the default billing handle (`defaultBilling`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not a positive handle id.
    pub fn with_default_billing(mut self, value: i64) -> Result<Self> {
        self.default_billing = Some(validate_id("account.defaultBilling", value)?);
        Ok(self)
    }

    /// Sets the `invoiceXml` flag.
    #[must_use]
    pub fn with_invoice_xml(mut self, value: bool) -> Self {
        self.invoice_xml = Some(value);
        self
    }

    /// Sets the `invoicePdf` flag.
    #[must_use]
    pub fn with_invoice_pdf(mut self, value: bool) -> Self {
        self.invoice_pdf = Some(value);
        self
    }

    /// Sets the default nameserver set (`defaultNsset`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not a positive id.
    pub fn with_default_nsset(mut self, value: i64) -> Result<Self> {
        self.default_nsset = Some(validate_id("account.defaultNsset", value)?);
        Ok(self)
    }

    /// Sets the default web nameserver entry (`defaultWeb`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_default_web(mut self, value: impl Into<String>) -> Result<Self> {
        self.default_web = Some(checked_token("account.defaultWeb", &value.into())?);
        Ok(self)
    }

    /// Sets the default mail nameserver entry (`defaultMail`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_default_mail(mut self, value: impl Into<String>) -> Result<Self> {
        self.default_mail = Some(checked_token("account.defaultMail", &value.into())?);
        Ok(self)
    }

    /// Sets the `defaultImportNS` flag.
    #[must_use]
    pub fn with_default_import_ns(mut self, value: bool) -> Self {
        self.default_import_ns = Some(value);
        self
    }

    /// Sets the default renewal mode (`defaultRenewalMode`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_default_renewal_mode(mut self, value: impl Into<String>) -> Result<Self> {
        self.default_renewal_mode =
            Some(checked_token("account.defaultRenewalMode", &value.into())?);
        Ok(self)
    }

    /// Sets the supplement invoice text (`supplimentinvoicetext`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_supplement_invoice_text(mut self, value: impl Into<String>) -> Result<Self> {
        self.suppliment_invoice_text = Some(checked_text(
            "account.supplimentinvoicetext",
            &value.into(),
            MAX_TEXT100,
        )?);
        Ok(self)
    }

    /// Sets the account password (`password`).
    ///
    /// The value is stored as a redacting, zeroizing [`Password`].
    #[must_use]
    pub fn with_password(mut self, password: Password) -> Self {
        self.password = Some(password);
        self
    }

    /// Sets the default rows per page (`rowsPerPage`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not a positive API `int`.
    pub fn with_rows_per_page(mut self, rows: i64) -> Result<Self> {
        self.rows_per_page = Some(validate_id("account.rowsPerPage", rows)?);
        Ok(self)
    }

    /// Sets the reseller flag (`isReseller`, documented as a tri-state boolean).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not a non-negative API `int`.
    pub fn with_is_reseller(mut self, value: i64) -> Result<Self> {
        self.is_reseller = Some(checked_non_negative("account.isReseller", value)?);
        Ok(self)
    }

    /// Marks the call as a dry run (`testing`).
    #[must_use]
    pub fn with_testing(mut self, testing: bool) -> Self {
        self.testing = testing;
        self
    }

    /// Sets the NIF (`nif`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_nif(mut self, value: impl Into<String>) -> Result<Self> {
        self.nif = Some(checked_text("account.nif", &value.into(), MAX_TEXT10)?);
        Ok(self)
    }

    /// Sets the ID card number (`idCard`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_id_card(mut self, value: impl Into<String>) -> Result<Self> {
        self.id_card = Some(checked_text("account.idCard", &value.into(), MAX_TEXT64)?);
        Ok(self)
    }

    /// Sets the `disablePremium` flag.
    #[must_use]
    pub fn with_disable_premium(mut self, value: bool) -> Self {
        self.disable_premium = Some(value);
        self
    }

    /// Sets the `isPremiumAgreedPriceRequired` flag.
    #[must_use]
    pub fn with_premium_agreed_price_required(mut self, value: bool) -> Self {
        self.premium_agreed_price_required = Some(value);
        self
    }

    /// Sets the `enableAdvertising` flag.
    #[must_use]
    pub fn with_enable_advertising(mut self, value: bool) -> Self {
        self.enable_advertising = Some(value);
        self
    }

    /// Sets the WDRP email (`wdrpEmail`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not an email address.
    pub fn with_wdrp_email(mut self, value: impl Into<String>) -> Result<Self> {
        self.wdrp_email = Some(validate_email_field("account.wdrpEmail", &value.into())?);
        Ok(self)
    }

    /// Sets the WDRP sender name (`wdrpEmailName`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_wdrp_email_name(mut self, value: impl Into<String>) -> Result<Self> {
        self.wdrp_email_name = Some(checked_token("account.wdrpEmailName", &value.into())?);
        Ok(self)
    }

    /// Sets the ERRP email (`errpEmail`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not an email address.
    pub fn with_errp_email(mut self, value: impl Into<String>) -> Result<Self> {
        self.errp_email = Some(validate_email_field("account.errpEmail", &value.into())?);
        Ok(self)
    }

    /// Sets the ERRP sender name (`errpEmailName`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_errp_email_name(mut self, value: impl Into<String>) -> Result<Self> {
        self.errp_email_name = Some(checked_token("account.errpEmailName", &value.into())?);
        Ok(self)
    }

    /// Sets the FOA email (`foaEmail`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not an email address.
    pub fn with_foa_email(mut self, value: impl Into<String>) -> Result<Self> {
        self.foa_email = Some(validate_email_field("account.foaEmail", &value.into())?);
        Ok(self)
    }

    /// Sets the FOA sender name (`foaEmailName`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_foa_email_name(mut self, value: impl Into<String>) -> Result<Self> {
        self.foa_email_name = Some(checked_token("account.foaEmailName", &value.into())?);
        Ok(self)
    }

    /// The `account.update` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the update changes no field.
    pub fn params(&self) -> Result<Value> {
        if self.is_empty() {
            return Err(Error::validation(
                "account.update",
                "sets no field; add at least one change",
            ));
        }
        let mut params = Map::new();
        for (key, value) in [
            ("username", &self.username),
            ("title", &self.title),
            ("firstname", &self.firstname),
            ("lastname", &self.lastname),
            ("org", &self.org),
            ("street", &self.street),
            ("pc", &self.pc),
            ("city", &self.city),
            ("cc", &self.cc),
            ("voice", &self.voice),
            ("fax", &self.fax),
            ("www", &self.www),
            ("email", &self.email),
            ("emailAutomated", &self.email_automated),
            ("emailBilling", &self.email_billing),
            ("renewalReportEmail", &self.renewal_report_email),
            ("servicePin", &self.service_pin),
            ("language", &self.language),
            ("bankAccHolder", &self.bank_acc_holder),
            ("bankCode", &self.bank_code),
            ("bankName", &self.bank_name),
            ("bankAccHolderNo", &self.bank_acc_holder_no),
            ("vatNo", &self.vat_no),
            ("whoisProvider", &self.whois_provider),
            ("whoisUrl", &self.whois_url),
            ("invoiceRouting", &self.invoice_routing),
            ("orderReference", &self.order_reference),
            ("defaultWeb", &self.default_web),
            ("defaultMail", &self.default_mail),
            ("defaultRenewalMode", &self.default_renewal_mode),
            ("supplimentinvoicetext", &self.suppliment_invoice_text),
            ("nif", &self.nif),
            ("idCard", &self.id_card),
            ("wdrpEmail", &self.wdrp_email),
            ("wdrpEmailName", &self.wdrp_email_name),
            ("errpEmail", &self.errp_email),
            ("errpEmailName", &self.errp_email_name),
            ("foaEmail", &self.foa_email),
            ("foaEmailName", &self.foa_email_name),
        ] {
            if let Some(value) = value {
                params.insert(key.to_owned(), json!(value));
            }
        }
        for (key, value) in [
            ("summaryInvoice", self.summary_invoice),
            ("notificationEmail", self.notification_email),
            ("notificationQueue", self.notification_queue),
            ("renewalReport", self.renewal_report),
            ("invoiceXml", self.invoice_xml),
            ("invoicePdf", self.invoice_pdf),
            ("defaultImportNS", self.default_import_ns),
            ("disablePremium", self.disable_premium),
            (
                "isPremiumAgreedPriceRequired",
                self.premium_agreed_price_required,
            ),
            ("enableAdvertising", self.enable_advertising),
        ] {
            if let Some(value) = value {
                params.insert(key.to_owned(), json!(value));
            }
        }
        for (key, value) in [
            ("defaultRegistrant", self.default_registrant),
            ("defaultAdmin", self.default_admin),
            ("defaultTech", self.default_tech),
            ("defaultBilling", self.default_billing),
            ("defaultNsset", self.default_nsset),
            ("rowsPerPage", self.rows_per_page),
            ("isReseller", self.is_reseller),
        ] {
            if let Some(value) = value {
                params.insert(key.to_owned(), json!(value));
            }
        }
        if let Some(low_balance) = self.low_balance {
            params.insert("lowBalance".to_owned(), json!(low_balance));
        }
        if !self.mail_list_id.is_empty() {
            params.insert("mailListId".to_owned(), json!(self.mail_list_id));
        }
        if let Some(password) = &self.password {
            params.insert("password".to_owned(), json!(password.as_str()));
        }
        if self.testing {
            params.insert("testing".to_owned(), json!(true));
        }
        Ok(Value::Object(params))
    }

    fn is_empty(&self) -> bool {
        self.username.is_none()
            && self.title.is_none()
            && self.firstname.is_none()
            && self.lastname.is_none()
            && self.org.is_none()
            && self.street.is_none()
            && self.pc.is_none()
            && self.city.is_none()
            && self.cc.is_none()
            && self.voice.is_none()
            && self.fax.is_none()
            && self.www.is_none()
            && self.email.is_none()
            && self.email_automated.is_none()
            && self.email_billing.is_none()
            && self.renewal_report_email.is_none()
            && self.service_pin.is_none()
            && self.summary_invoice.is_none()
            && self.mail_list_id.is_empty()
            && self.language.is_none()
            && self.notification_email.is_none()
            && self.notification_queue.is_none()
            && self.renewal_report.is_none()
            && self.low_balance.is_none()
            && self.bank_acc_holder.is_none()
            && self.bank_code.is_none()
            && self.bank_name.is_none()
            && self.bank_acc_holder_no.is_none()
            && self.vat_no.is_none()
            && self.whois_provider.is_none()
            && self.whois_url.is_none()
            && self.default_registrant.is_none()
            && self.default_admin.is_none()
            && self.default_tech.is_none()
            && self.invoice_routing.is_none()
            && self.order_reference.is_none()
            && self.default_billing.is_none()
            && self.invoice_xml.is_none()
            && self.invoice_pdf.is_none()
            && self.default_nsset.is_none()
            && self.default_web.is_none()
            && self.default_mail.is_none()
            && self.default_import_ns.is_none()
            && self.default_renewal_mode.is_none()
            && self.suppliment_invoice_text.is_none()
            && self.password.is_none()
            && self.rows_per_page.is_none()
            && self.is_reseller.is_none()
            && !self.testing
            && self.nif.is_none()
            && self.id_card.is_none()
            && self.disable_premium.is_none()
            && self.premium_agreed_price_required.is_none()
            && self.enable_advertising.is_none()
            && self.wdrp_email.is_none()
            && self.wdrp_email_name.is_none()
            && self.errp_email.is_none()
            && self.errp_email_name.is_none()
            && self.foa_email.is_none()
            && self.foa_email_name.is_none()
    }
}

/// A request for `account.changepassword`.
///
/// ```
/// use inwx_client::{AccountPasswordChange, Password};
///
/// let request = AccountPasswordChange::new(
///     "user",
///     Password::new("old")?,
///     Password::new("new")?,
/// )?;
/// assert_eq!(request.params()?["username"], "user");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct AccountPasswordChange {
    username: String,
    current_password: Password,
    new_password: Password,
    testing: bool,
}

impl AccountPasswordChange {
    /// Builds a password change request.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the username is not `text64`.
    pub fn new(
        username: impl Into<String>,
        current_password: Password,
        new_password: Password,
    ) -> Result<Self> {
        Ok(Self {
            username: checked_text("account.username", &username.into(), MAX_TEXT64)?,
            current_password,
            new_password,
            testing: false,
        })
    }

    /// Marks the call as a dry run (`testing`).
    #[must_use]
    pub fn with_testing(mut self, testing: bool) -> Self {
        self.testing = testing;
        self
    }

    /// The `account.changepassword` parameters.
    ///
    /// # Errors
    ///
    /// This method cannot fail after construction; the fallible signature keeps
    /// the request-builder shape consistent with the other account builders.
    pub fn params(&self) -> Result<Value> {
        let mut params = Map::new();
        params.insert("username".to_owned(), json!(self.username));
        params.insert(
            "currentpassword".to_owned(),
            json!(self.current_password.as_str()),
        );
        params.insert("password".to_owned(), json!(self.new_password.as_str()));
        if self.testing {
            params.insert("testing".to_owned(), json!(true));
        }
        Ok(Value::Object(params))
    }
}

impl fmt::Debug for AccountPasswordChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountPasswordChange")
            .field("username", &self.username)
            .field("current_password", &self.current_password)
            .field("new_password", &self.new_password)
            .field("testing", &self.testing)
            .finish()
    }
}

/// A request for `account.unlock`.
///
/// The documented parameter is an optional transaction number (`tan`); the
/// account to unlock is the one whose session is calling.
///
/// ```
/// use inwx_client::AccountUnlockRequest;
///
/// let request = AccountUnlockRequest::new()?.with_tan("123456")?;
/// assert_eq!(request.params()?["tan"], "123456");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountUnlockRequest {
    tan: Option<String>,
}

impl AccountUnlockRequest {
    /// Builds an empty unlock request.
    ///
    /// # Errors
    ///
    /// This constructor cannot fail today; the fallible signature keeps the
    /// builder shape consistent.
    pub fn new() -> Result<Self> {
        Ok(Self { tan: None })
    }

    /// Sets the transaction number (`tan`, `text10`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty or too long.
    pub fn with_tan(mut self, tan: impl Into<String>) -> Result<Self> {
        self.tan = Some(checked_text(
            "account.unlock.tan",
            &tan.into(),
            MAX_TAN_LEN,
        )?);
        Ok(self)
    }

    /// The `account.unlock` parameters.
    ///
    /// # Errors
    ///
    /// This method cannot fail after construction; the fallible signature keeps
    /// the builder shape consistent.
    pub fn params(&self) -> Result<Value> {
        let mut params = Map::new();
        if let Some(tan) = &self.tan {
            params.insert("tan".to_owned(), json!(tan));
        }
        Ok(Value::Object(params))
    }
}

/// Splits the legacy [`AccountRoleEntry`] answer shape from the documented
/// numeric role ids.
fn role_entries(data: &Value) -> Vec<AccountRoleEntry> {
    let rows = list_rows(data, "roles");
    rows.into_iter()
        .filter_map(|row| match row {
            Value::Object(mut fields) => {
                if !fields.contains_key("roleId") && !fields.contains_key("role_id") {
                    if let Some(id) = fields.get("id").cloned() {
                        fields.insert("roleId".to_owned(), id);
                    }
                }
                serde_json::from_value(Value::Object(fields)).ok()
            }
            scalar => {
                let mut fields = Map::new();
                fields.insert("roleId".to_owned(), scalar);
                serde_json::from_value(Value::Object(fields)).ok()
            }
        })
        .collect()
}

fn checked_username(field: &'static str, value: &str) -> Result<String> {
    validate_username(field, value)?;
    Ok(value.trim().to_owned())
}

fn checked_text(field: &'static str, value: &str, max: usize) -> Result<String> {
    validate_text(field, value, max)?;
    Ok(value.trim().to_owned())
}

fn checked_token(field: &'static str, value: &str) -> Result<String> {
    validate_token(field, value)?;
    Ok(value.trim().to_owned())
}

fn checked_non_negative(field: &'static str, value: i64) -> Result<i64> {
    if value < 0 {
        return Err(Error::validation(
            field,
            format!("must be a non-negative integer, got {value}"),
        ));
    }
    Ok(value)
}

fn checked_ids(field: &'static str, ids: &[i64]) -> Result<Vec<i64>> {
    if ids.is_empty() {
        return Err(Error::validation(field, "must list at least one id"));
    }
    let mut checked = Vec::with_capacity(ids.len());
    for id in ids {
        checked.push(validate_id(field, *id)?);
    }
    Ok(checked)
}

impl<T: Transport> InwxClient<T> {
    /// Checks whether the current session is still valid (`account.check`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let check = client.account_check().await?;
    /// println!("{:?}", check.user);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn account_check(&self) -> Result<AccountCheck> {
        let data = self.call("account.check", json!({})).await?;
        if data.is_null() {
            return Ok(AccountCheck::default());
        }
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Lists the current account's roles (`account.getroles`).
    ///
    /// Pass `Some(account_id)` to ask for the roles of one sub-account.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for role in client.account_roles(Some(4711)).await? {
    ///     println!("{:?}", role.role_id);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive account id, plus the usual
    /// transport and API errors.
    pub async fn account_roles(&self, account_id: Option<i64>) -> Result<Vec<AccountRoleEntry>> {
        let params = match account_id {
            Some(account_id) => {
                json!({ "accountId": validate_id("account.accountId", account_id)? })
            }
            None => json!({}),
        };
        let data = self.call("account.getroles", params).await?;
        Ok(role_entries(&data))
    }

    /// Grants a numeric role to an account (`account.addrole`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{AccountRoleId, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.add_role(4711, AccountRoleId::Dns).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive account or role id, plus the
    /// usual transport and API errors. An unconfirmed failure is
    /// [`crate::Error::Uncertain`] and is not replayed.
    pub async fn add_role(&self, account_id: i64, role_id: AccountRoleId) -> Result<()> {
        let account_id = validate_id("account.accountId", account_id)?;
        let role_id = AccountRoleId::new(role_id.id())?;
        self.call(
            "account.addrole",
            json!({ "accountId": account_id, "roleId": role_id.id() }),
        )
        .await?;
        Ok(())
    }

    /// Removes a numeric role from an account (`account.removerole`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{AccountRoleId, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.remove_role(4711, AccountRoleId::Accounting).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive account or role id, plus the
    /// usual transport and API errors. An unconfirmed failure is
    /// [`crate::Error::Uncertain`] and is not replayed.
    pub async fn remove_role(&self, account_id: i64, role_id: AccountRoleId) -> Result<()> {
        let account_id = validate_id("account.accountId", account_id)?;
        let role_id = AccountRoleId::new(role_id.id())?;
        self.call(
            "account.removerole",
            json!({ "accountId": account_id, "roleId": role_id.id() }),
        )
        .await?;
        Ok(())
    }

    /// Lists every sub-account of the reseller (`account.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let list = client.list_subaccounts().await?;
    /// println!("{:?}", list.admin_id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn list_subaccounts(&self) -> Result<SubAccountList> {
        let data = self.call("account.list", json!({})).await?;
        if data.is_null() {
            return Ok(SubAccountList::default());
        }
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Creates a sub-account (`account.create`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport, SubAccountCreate};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let request = SubAccountCreate::new(
    ///     "sub-account", "Dr.", "Ada", "Lovelace",
    ///     "Main Street 1", "12345", "London", "GB", "ada@example.com",
    /// )?;
    /// let created = client.create_subaccount(&request).await?;
    /// println!("{:?}", created.id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from the request builder, plus the usual transport
    /// and API errors. An unconfirmed failure is [`crate::Error::Uncertain`] and
    /// is not replayed.
    pub async fn create_subaccount(&self, request: &SubAccountCreate) -> Result<SubAccountCreated> {
        let data = self.call("account.create", request.params()?).await?;
        if data.is_null() {
            return Ok(SubAccountCreated::default());
        }
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Deletes one or more sub-accounts (`account.delete`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let deleted = client.delete_subaccounts(&[4711, 4712]).await?;
    /// println!("{:?}", deleted.count_deleted);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty list or a non-positive id, plus the
    /// usual transport and API errors. An unconfirmed failure is
    /// [`crate::Error::Uncertain`] and is not replayed.
    pub async fn delete_subaccounts(&self, ids: &[i64]) -> Result<SubAccountsDeleted> {
        let ids = checked_ids("account.ids", ids)?;
        let data = self.call("account.delete", json!({ "ids": ids })).await?;
        if data.is_null() {
            return Ok(SubAccountsDeleted::default());
        }
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Updates the current account data (`account.update`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{AccountUpdate, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let update = AccountUpdate::new()?.with_city("Leipzig")?;
    /// client.update_account(&update).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from the request builder, plus the usual transport
    /// and API errors. An unconfirmed failure is [`crate::Error::Uncertain`] and
    /// is not replayed.
    pub async fn update_account(&self, update: &AccountUpdate) -> Result<()> {
        self.call("account.update", update.params()?).await?;
        Ok(())
    }

    /// Changes the current account password (`account.changepassword`).
    ///
    /// Both secrets travel in the request body and are redacted from `Debug`.
    /// The locally cached session is dropped after a successful change, because
    /// it was established with the old password.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{AccountPasswordChange, InwxClient, Password, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let request = AccountPasswordChange::new(
    ///     "user",
    ///     Password::new(std::env::var("INWX_PASSWORD")?)?,
    ///     Password::new(std::env::var("INWX_NEW_PASSWORD")?)?,
    /// )?;
    /// client.change_account_password(&request).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from the request builder, plus the usual transport
    /// and API errors. An unconfirmed failure is [`crate::Error::Uncertain`] and
    /// is not replayed.
    pub async fn change_account_password(&self, request: &AccountPasswordChange) -> Result<()> {
        self.call("account.changepassword", request.params()?)
            .await?;
        self.clear_session();
        Ok(())
    }

    /// Unlocks the current account (`account.unlock`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{AccountUnlockRequest, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.unlock_account(&AccountUnlockRequest::new()?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from the request builder, plus the usual transport
    /// and API errors. An unconfirmed failure is [`crate::Error::Uncertain`] and
    /// is not replayed.
    pub async fn unlock_account(&self, request: &AccountUnlockRequest) -> Result<()> {
        self.call("account.unlock", request.params()?).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_request() -> SubAccountCreate {
        SubAccountCreate::new(
            "sub-account",
            "Dr.",
            "Ada",
            "Lovelace",
            "Main Street 1",
            "12345",
            "London",
            "GB",
            "ada@example.com",
        )
        .unwrap()
    }

    #[test]
    fn numeric_role_ids_round_trip_and_carry_unknown_values() {
        for (id, role) in [
            (20_000, AccountRoleId::Standard),
            (20_001, AccountRoleId::Accounting),
            (20_002, AccountRoleId::Domain),
            (20_003, AccountRoleId::Hosting),
            (20_004, AccountRoleId::Dns),
            (20_005, AccountRoleId::Authcodes),
            (20_999, AccountRoleId::Other(20_999)),
        ] {
            assert_eq!(AccountRoleId::from_id(id), role);
            assert_eq!(role.id(), id);
            assert_eq!(id.to_string().parse::<AccountRoleId>().unwrap(), role);
        }
        assert!(AccountRoleId::new(0).is_err());
    }

    #[test]
    fn role_rows_accept_ids_objects_and_numeric_strings() {
        let data = json!({"roles": [20000, {"roleId": "20004"}, {"id": 20005}, "bad"]});
        let rows = role_entries(&data);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].role_id, Some(AccountRoleId::Standard));
        assert_eq!(rows[1].role_id, Some(AccountRoleId::Dns));
        assert_eq!(rows[2].role_id, Some(AccountRoleId::Authcodes));
        assert!(rows[3].role_id.is_none());
    }

    #[test]
    fn account_check_accepts_scalars_and_ignores_unknown_fields() {
        let check: AccountCheck =
            serde_json::from_str(r#"{"user":42,"extra":{"nested":true}}"#).unwrap();
        assert_eq!(check.user.as_deref(), Some("42"));
        assert_eq!(AccountCheck::default().user, None);
    }

    #[test]
    fn subaccount_list_accepts_single_account_and_numeric_strings() {
        let list: SubAccountList = serde_json::from_str(
            r#"{"adminId":"1","accounts":{"id":"2","username":"sub","tfaEnabled":"1"}}"#,
        )
        .unwrap();
        assert_eq!(list.admin_id, Some(1));
        assert_eq!(list.accounts[0].id, Some(2));
        assert_eq!(list.accounts[0].two_factor_enabled, Some(true));
    }

    #[test]
    fn create_request_validates_required_fields_and_limits() {
        assert_eq!(
            create_request().params().unwrap()["username"],
            "sub-account"
        );
        assert!(SubAccountCreate::new(
            "ab",
            "Dr.",
            "Ada",
            "Lovelace",
            "Main Street 1",
            "12345",
            "London",
            "GB",
            "ada@example.com",
        )
        .is_err());
        assert!(SubAccountCreate::new(
            "sub-account",
            "Dr.",
            "Ada",
            "Lovelace",
            "Main Street 1",
            "12345678901",
            "London",
            "GB",
            "ada@example.com",
        )
        .is_err());
        assert_eq!(
            create_request()
                .with_org("x".repeat(255))
                .unwrap()
                .params()
                .unwrap()["org"],
            "x".repeat(255)
        );
        assert!(create_request().with_org("x".repeat(256)).is_err());
    }

    #[test]
    fn update_builder_sends_exact_camel_case_keys_and_refuses_empty_update() {
        assert!(AccountUpdate::new().unwrap().params().is_err());
        let params = AccountUpdate::new()
            .unwrap()
            .with_firstname("Ada")
            .unwrap()
            .with_default_registrant(4711)
            .unwrap()
            .with_low_balance(5.5)
            .unwrap()
            .with_testing(true)
            .params()
            .unwrap();
        assert_eq!(params["firstname"], "Ada");
        assert_eq!(params["defaultRegistrant"], 4711);
        assert_eq!(params["lowBalance"], 5.5);
        assert_eq!(params["testing"], true);
    }

    #[test]
    fn password_change_redacts_both_secrets_and_sends_documented_keys() {
        let request = AccountPasswordChange::new(
            "user",
            Password::new("old-secret").unwrap(),
            Password::new("new-secret").unwrap(),
        )
        .unwrap();
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("old-secret"));
        assert!(!rendered.contains("new-secret"));
        let params = request.params().unwrap();
        assert_eq!(params["username"], "user");
        assert_eq!(params["currentpassword"], "old-secret");
        assert_eq!(params["password"], "new-secret");
    }

    #[test]
    fn unlock_request_sends_only_tan_when_set() {
        assert_eq!(
            AccountUnlockRequest::new().unwrap().params().unwrap(),
            json!({})
        );
        assert_eq!(
            AccountUnlockRequest::new()
                .unwrap()
                .with_tan("123456")
                .unwrap()
                .params()
                .unwrap()["tan"],
            "123456"
        );
        assert!(AccountUnlockRequest::new()
            .unwrap()
            .with_tan("12345678901")
            .is_err());
    }
}
