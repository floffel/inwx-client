//! `AuthInfo2` (`authinfo2.*`): the registry-side authorisation info of a domain.
//!
//! Two methods: create the value for a domain, and ask what that costs before
//! creating it. The value itself is a secret — like the EPP
//! [`AuthCode`](crate::AuthCode) it prints `<redacted>` in `Debug` and
//! `Display`, so it cannot leak through a log line or an `unwrap` in a test.
//!
//! ```
//! use inwx_client::AuthInfo2;
//!
//! let value = AuthInfo2::new("aB3-xY9_42")?;
//! assert_eq!(value.as_str(), "aB3-xY9_42");
//! assert_eq!(format!("{value:?}"), "AuthInfo2(<redacted>)");
//! assert!(AuthInfo2::new("").is_err()); // fail closed on an empty secret
//! # Ok::<(), inwx_client::Error>(())
//! ```

use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, DomainName};

/// The `AuthInfo2` value of a domain.
///
/// A printable, whitespace-free token of at most 255 characters. An empty value
/// is refused: an empty secret is never a secret.
///
/// ```
/// use inwx_client::AuthInfo2;
///
/// let value = AuthInfo2::new("s3cr3t-value")?;
/// assert_eq!(value.as_str(), "s3cr3t-value");
/// assert_eq!(value.to_string(), "<redacted>");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AuthInfo2(String);

impl AuthInfo2 {
    /// Validates an `AuthInfo2` value.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty, longer than 255
    /// characters, not printable ASCII, or contains whitespace.
    ///
    /// ```
    /// use inwx_client::AuthInfo2;
    ///
    /// assert!(AuthInfo2::new("x".repeat(255)).is_ok());
    /// assert!(AuthInfo2::new("x".repeat(256)).is_err());
    /// assert!(AuthInfo2::new("two words").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let raw = value.into();
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(Error::validation("authInfo2", "must not be empty"));
        }
        if trimmed.chars().count() > 255 {
            return Err(Error::validation(
                "authInfo2",
                "must be at most 255 characters",
            ));
        }
        if !trimmed.is_ascii() {
            return Err(Error::validation("authInfo2", "must be printable ASCII"));
        }
        if trimmed.chars().any(char::is_whitespace) || trimmed.chars().any(char::is_control) {
            return Err(Error::validation(
                "authInfo2",
                "must not contain whitespace or control characters",
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// The value, for the caller who is allowed to see it.
    ///
    /// ```
    /// use inwx_client::AuthInfo2;
    /// assert_eq!(AuthInfo2::new("abc123")?.as_str(), "abc123");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AuthInfo2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthInfo2(<redacted>)")
    }
}

impl fmt::Display for AuthInfo2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl FromStr for AuthInfo2 {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::new(input)
    }
}

impl Serialize for AuthInfo2 {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AuthInfo2 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(D::Error::custom)
    }
}

/// An optional `AuthInfo2` that drops an unusable value instead of failing the
/// whole answer.
fn opt_auth_info2<'de, D>(deserializer: D) -> std::result::Result<Option<AuthInfo2>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(de::opt_string(deserializer)?.and_then(|raw| AuthInfo2::new(raw).ok()))
}

/// The answer of `authinfo2.create`.
///
/// ```
/// use inwx_client::AuthInfo2Record;
///
/// let record: AuthInfo2Record = serde_json::from_str(
///     r#"{"domainName":"example.com","authInfo2":"aB3-xY9_42","status":"ACTIVE"}"#,
/// )?;
/// assert_eq!(record.domain.as_deref(), Some("example.com"));
/// assert!(record.auth_info2.is_some());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct AuthInfo2Record {
    /// Id of the object the value belongs to, when the API reports one.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Domain the value belongs to.
    #[serde(
        default,
        rename = "domainName",
        alias = "domain",
        deserialize_with = "de::opt_string"
    )]
    pub domain: Option<String>,
    /// The value itself; `None` when the API sent nothing usable.
    #[serde(
        default,
        rename = "authInfo2",
        alias = "authinfo2",
        deserialize_with = "opt_auth_info2"
    )]
    pub auth_info2: Option<AuthInfo2>,
    /// State of the value, carried verbatim.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
}

/// The answer of `authinfo2.getprice`.
///
/// ```
/// use inwx_client::AuthInfo2PriceQuote;
///
/// let quote: AuthInfo2PriceQuote =
///     serde_json::from_str(r#"{"netPrice":"1.20","grossPrice":1.43,"currency":"EUR"}"#)?;
/// assert_eq!(quote.net_price, Some(1.20));
/// assert_eq!(quote.currency.as_deref(), Some("EUR"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct AuthInfo2PriceQuote {
    /// Price without VAT.
    #[serde(
        default,
        rename = "netPrice",
        alias = "net_price",
        deserialize_with = "de::opt_f64"
    )]
    pub net_price: Option<f64>,
    /// Price including VAT.
    #[serde(
        default,
        rename = "grossPrice",
        alias = "gross_price",
        deserialize_with = "de::opt_f64"
    )]
    pub gross_price: Option<f64>,
    /// Currency of both amounts.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// Applied VAT rate, when the API sends one.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub vat: Option<f64>,
    /// Explanation, when the API sends one.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub message: Option<String>,
}

impl<T: Transport> InwxClient<T> {
    /// Creates the `AuthInfo2` value for a domain (`authinfo2.create`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let record = client.create_auth_info2(&DomainName::parse("example.com")?).await?;
    /// // The value is secret: print it explicitly, never through `Debug`.
    /// println!("{}", record.auth_info2.is_some());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors; `2303` when the domain is not in this
    /// account.
    pub async fn create_auth_info2(&self, domain: &DomainName) -> Result<AuthInfo2Record> {
        let data = self
            .call("authinfo2.create", json!({ "domainName": domain.as_str() }))
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// What creating the `AuthInfo2` value would cost (`authinfo2.getprice`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let quote = client.auth_info2_price(&DomainName::parse("example.com")?).await?;
    /// println!("{:?} {:?}", quote.net_price, quote.currency);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn auth_info2_price(&self, domain: &DomainName) -> Result<AuthInfo2PriceQuote> {
        let data = self
            .call(
                "authinfo2.getprice",
                json!({ "domainName": domain.as_str() }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_of_255_characters_is_accepted_and_256_is_not() {
        assert!(AuthInfo2::new("x".repeat(255)).is_ok());
        assert!(AuthInfo2::new("x".repeat(256)).is_err());
        assert!(AuthInfo2::new("").is_err());
    }

    #[test]
    fn the_secret_never_reaches_debug_or_display() {
        let value = AuthInfo2::new("do-not-log-me").unwrap();
        assert_eq!(format!("{value:?}"), "AuthInfo2(<redacted>)");
        assert_eq!(value.to_string(), "<redacted>");
        assert!(!format!("{value:?}").contains("do-not-log-me"));
    }

    #[test]
    fn an_unusable_secret_is_dropped_not_fatal() {
        let record: AuthInfo2Record =
            serde_json::from_str(r#"{"authInfo2":"with space","domainName":"a.de"}"#).unwrap();
        assert!(record.auth_info2.is_none());
        assert_eq!(record.domain.as_deref(), Some("a.de"));

        let snake: AuthInfo2Record =
            serde_json::from_str(r#"{"authinfo2":"ok","domain":"a.de"}"#).unwrap();
        assert_eq!(
            snake.auth_info2.map(|value| value.as_str().to_owned()),
            Some("ok".to_owned())
        );
    }
}
