//! Account roles (`account.getroles`, `account.addrole`, `account.removerole`).
//!
//! A reseller account grants roles to handles: the same handle can be the
//! technical contact of one customer and only the billing contact of another.
//! Reading them is free; granting and revoking one changes what another account
//! may do, so both are mutating and never replayed after an uncertain failure.
//!
//! ```
//! use inwx_client::AccountRole;
//!
//! let role = AccountRole::parse(" tech ")?;
//! assert_eq!(role, AccountRole::Tech);
//! assert_eq!(role.as_str(), "TECH");
//!
//! // A role this crate does not know survives the round trip.
//! assert_eq!(AccountRole::parse("TRUSTEE")?.as_str(), "TRUSTEE");
//! # Ok::<(), inwx_client::Error>(())
//! ```

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;
use std::fmt;
use std::str::FromStr;

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, list_rows, validate_id, validate_token};

/// A role INWX grants to a handle on an account.
///
/// Known values are parsed into a variant; anything else is kept verbatim in
/// [`AccountRole::Other`], so a role INWX adds later does not make this crate
/// fail to read the answer.
///
/// ```
/// use inwx_client::AccountRole;
///
/// assert_eq!(AccountRole::parse("admin").unwrap(), AccountRole::Admin);
/// assert_eq!(AccountRole::Other("TRUSTEE".into()).to_string(), "TRUSTEE");
/// assert!(AccountRole::parse("").is_err());
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
    /// ```
    /// use inwx_client::{AccountRole, Error};
    ///
    /// assert_eq!(AccountRole::parse(" Admin ").unwrap(), AccountRole::Admin);
    /// assert_eq!(
    ///     AccountRole::parse("trustee").unwrap(),
    ///     AccountRole::Other("TRUSTEE".into())
    /// );
    ///
    /// let err = AccountRole::parse("  ").unwrap_err();
    /// assert!(matches!(err, Error::Validation { field: "account.role", .. }));
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the input is empty.
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

/// One line of `account.getroles`: a handle and the role it holds.
///
/// Every field is optional and scalars are accepted as numbers or strings,
/// because INWX mixes the two between methods.
///
/// ```
/// use inwx_client::{AccountRole, AccountRoleEntry};
///
/// let entry: AccountRoleEntry = serde_json::from_str(
///     r#"{"handle":"4711","role":"billing","customer":"example","extra":true}"#,
/// )?;
/// assert_eq!(entry.handle, Some(4711));
/// assert_eq!(entry.role, Some(AccountRole::Billing));
/// assert_eq!(entry.customer.as_deref(), Some("example"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct AccountRoleEntry {
    /// Handle (customer id) the role belongs to.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub handle: Option<i64>,
    /// The granted role; unknown values are carried.
    #[serde(default, deserialize_with = "opt_account_role")]
    pub role: Option<AccountRole>,
    /// Handle or username of the account the role is granted to.
    #[serde(
        default,
        rename = "customer",
        alias = "username",
        deserialize_with = "de::opt_string"
    )]
    pub customer: Option<String>,
}

/// Parses a role leniently: absent or empty means `None`, unknown is carried.
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

impl<T: Transport> InwxClient<T> {
    /// Lists the roles of the account (`account.getroles`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for entry in client.account_roles().await? {
    ///     println!("{:?} {:?}", entry.handle, entry.role);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn account_roles(&self) -> Result<Vec<AccountRoleEntry>> {
        let data = self.call("account.getroles", json!({})).await?;
        let mut rows = list_rows(&data, "roles");
        if rows.is_empty() {
            // Depending on the API version the list arrives under `role`.
            rows = list_rows(&data, "role");
        }
        Ok(rows
            .into_iter()
            .filter_map(|row| serde_json::from_value(row).ok())
            .collect())
    }

    /// Grants a role to a handle (`account.addrole`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{AccountRole, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.add_role(4711, &AccountRole::Tech).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] for a handle that is not a positive id or an
    /// empty role, plus the usual transport and API errors. A failure after the
    /// request was written is [`crate::Error::Uncertain`] and is not replayed.
    pub async fn add_role(&self, handle: i64, role: &AccountRole) -> Result<()> {
        let handle = validate_id("account.handle", handle)?;
        validate_token("account.role", role.as_str())?;
        self.call(
            "account.addrole",
            json!({ "handle": handle, "role": role.as_str() }),
        )
        .await?;
        Ok(())
    }

    /// Revokes a role from a handle (`account.removerole`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{AccountRole, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.remove_role(4711, &AccountRole::Tech).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] for a handle that is not a positive id or an
    /// empty role, plus the usual transport and API errors. A failure after the
    /// request was written is [`crate::Error::Uncertain`] and is not replayed.
    pub async fn remove_role(&self, handle: i64, role: &AccountRole) -> Result<()> {
        let handle = validate_id("account.handle", handle)?;
        validate_token("account.role", role.as_str())?;
        self.call(
            "account.removerole",
            json!({ "handle": handle, "role": role.as_str() }),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_role_of_one_character_is_accepted_and_an_empty_one_is_not() {
        assert_eq!(
            AccountRole::parse("a").unwrap(),
            AccountRole::Other("A".to_owned())
        );
        assert!(AccountRole::parse("").is_err());
        // Only padding is still empty once trimmed.
        assert!(AccountRole::parse("   ").is_err());
    }

    #[test]
    fn a_role_of_255_characters_is_accepted_and_256_is_not() {
        let exact = "x".repeat(255);
        assert!(validate_token("account.role", &exact).is_ok());
        assert!(validate_token("account.role", &format!("{exact}x")).is_err());
    }

    #[test]
    fn a_handle_of_one_is_accepted_and_zero_is_not() {
        assert_eq!(validate_id("account.handle", 1).unwrap(), 1);
        assert!(validate_id("account.handle", 0).is_err());
        assert!(validate_id("account.handle", -1).is_err());
    }

    #[test]
    fn the_none_role_is_accepted_and_an_empty_one_is_not() {
        assert!(validate_token("account.role", AccountRole::None.as_str()).is_ok());
        assert_eq!(AccountRole::parse("none").unwrap(), AccountRole::None);
        assert!(AccountRole::parse("").is_err());
    }

    #[test]
    fn known_roles_round_trip_and_unknown_ones_are_carried() {
        for (input, expected) in [
            ("owner", AccountRole::Owner),
            (" admin ", AccountRole::Admin),
            ("Tech", AccountRole::Tech),
            ("BILLING", AccountRole::Billing),
            ("none", AccountRole::None),
            ("trustee", AccountRole::Other("TRUSTEE".to_owned())),
        ] {
            let parsed = AccountRole::parse(input).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(AccountRole::parse(parsed.as_str()).unwrap(), parsed);
            assert_eq!(parsed.to_string(), parsed.as_str());
        }
    }

    #[test]
    fn a_customer_arrives_as_customer_or_as_username() {
        let customer: AccountRoleEntry =
            serde_json::from_str(r#"{"handle":1,"role":"tech","customer":"a"}"#).unwrap();
        let username: AccountRoleEntry =
            serde_json::from_str(r#"{"handle":1,"role":"tech","username":"a"}"#).unwrap();
        assert_eq!(customer, username);
        assert_eq!(customer.customer.as_deref(), Some("a"));
    }

    #[test]
    fn an_unknown_or_absent_role_decodes_without_failing_the_row() {
        let unknown: AccountRoleEntry = serde_json::from_str(r#"{"role":"TRUSTEE"}"#).unwrap();
        assert_eq!(unknown.role, Some(AccountRole::Other("TRUSTEE".to_owned())));

        let empty: AccountRoleEntry = serde_json::from_str(r#"{"handle":"7","role":" "}"#).unwrap();
        assert_eq!(empty.role, None);
        assert_eq!(empty.handle, Some(7));

        let absent: AccountRoleEntry = serde_json::from_str(r"{}").unwrap();
        assert_eq!(absent, AccountRoleEntry::default());
    }
}
