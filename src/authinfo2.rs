//! AuthInfo2 codes (`authinfo2.*`): create them and ask what they cost.
//!
//! An AuthInfo2 code is a second-factor transfer credential: the crate can
//! create one and quote the price for the same request. Both methods take the
//! same parameters, so one request type — [`AuthInfo2Order`] — drives both; a
//! quote and the order that follows it therefore cannot drift apart.
//!
//! The code itself is a secret. [`AuthInfo2Code`] prints `<redacted>` in `Debug`
//! and `Display`, and only hands the value out through
//! [`AuthInfo2Code::expose`], so a `println!("{authinfo2:?}")` cannot leak it.
//!
//! ```
//! use inwx_client::AuthInfo2Order;
//!
//! let order = AuthInfo2Order::new()?.with_quantity(10)?;
//! assert_eq!(order.params()?["quantity"], 10);
//! assert!(AuthInfo2Order::new().unwrap().params().is_err());
//! # Ok::<(), inwx_client::Error>(())
//! ```

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::params::{self, ExtraFields};
use crate::transport::Transport;
use crate::types::{de, validate_token, DomainName};

/// Keys owned by [`AuthInfo2Order`].
const ORDER_KEYS: &[&str] = &["domain", "quantity", "customer"];

/// Largest quantity the crate sends in one AuthInfo2 request.
///
/// A bulk request for more codes than this is almost certainly a mistake, and
/// refusing it locally keeps an accidental order from being booked.
pub const MAX_AUTHINFO2_QUANTITY: u32 = 100;

/// An AuthInfo2 code.
///
/// `Debug` and `Display` redact the value; use [`AuthInfo2Code::expose`] to read
/// it.
///
/// ```
/// use inwx_client::AuthInfo2Code;
///
/// let code = AuthInfo2Code::new("a1b2-c3d4")?;
/// assert_eq!(code.expose(), "a1b2-c3d4");
/// assert_eq!(format!("{code}"), "<redacted>");
/// assert!(!format!("{code:?}").contains("a1b2"));
/// assert!(AuthInfo2Code::new("").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct AuthInfo2Code(String);

impl AuthInfo2Code {
    /// Validates and stores a code.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty value, one longer than 255 characters
    /// or one containing control characters.
    ///
    /// ```
    /// use inwx_client::AuthInfo2Code;
    /// assert!(AuthInfo2Code::new("code").is_ok());
    /// assert!(AuthInfo2Code::new("with\nnewline").is_err());
    /// ```
    pub fn new(code: impl Into<String>) -> Result<Self> {
        let code = code.into();
        validate_token("authinfo2.code", &code)?;
        Ok(Self(code.trim().to_owned()))
    }

    /// The code itself.
    ///
    /// ```
    /// use inwx_client::AuthInfo2Code;
    /// assert_eq!(AuthInfo2Code::new("code")?.expose(), "code");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AuthInfo2Code {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthInfo2Code(<redacted>)")
    }
}

impl std::fmt::Display for AuthInfo2Code {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Optional [`AuthInfo2Code`] field: absent, `null` and `""` all mean "not
/// reported", a string or number is validated.
fn opt_code<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<AuthInfo2Code>, D::Error> {
    let raw = de::opt_string(deserializer)?;
    Ok(match raw {
        Some(raw) if !raw.trim().is_empty() => AuthInfo2Code::new(raw).ok(),
        _ => None,
    })
}

/// One created AuthInfo2 code (`authinfo2.create`).
///
/// ```
/// use inwx_client::AuthInfo2;
///
/// let answer: AuthInfo2 = serde_json::from_str(
///     r#"{"id":9,"authinfo2":"s3cr3t","domain":"example.com","state":"DONE"}"#,
/// )?;
/// assert_eq!(answer.id, Some(9));
/// assert_eq!(answer.state.as_deref(), Some("DONE"));
/// // the code is there, but never printed:
/// assert!(!format!("{answer:?}").contains("s3cr3t"));
/// assert_eq!(answer.code.as_ref().map(|code| code.expose()), Some("s3cr3t"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct AuthInfo2 {
    /// Id of the created object.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// The code, redacted in `Debug`.
    #[serde(
        default,
        rename = "authinfo2",
        alias = "authInfo2",
        alias = "auth_info2",
        deserialize_with = "opt_code"
    )]
    pub code: Option<AuthInfo2Code>,
    /// Domain the code belongs to, when one was given.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub domain: Option<String>,
    /// State of the request.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub state: Option<String>,
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

/// The quote behind the same request (`authinfo2.getprice`).
///
/// ```
/// use inwx_client::AuthInfo2Price;
///
/// let quote: AuthInfo2Price = serde_json::from_str(
///     r#"{"netPrice":"10.00","grossPrice":11.9,"currency":"EUR","quantity":10,"unit":"pieces"}"#,
/// )?;
/// assert_eq!(quote.net_price, Some(10.0));
/// assert_eq!(quote.unit.as_deref(), Some("pieces"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct AuthInfo2Price {
    /// Price without VAT.
    #[serde(default, rename = "netPrice", deserialize_with = "de::opt_f64")]
    pub net_price: Option<f64>,
    /// Price including VAT.
    #[serde(default, rename = "grossPrice", deserialize_with = "de::opt_f64")]
    pub gross_price: Option<f64>,
    /// Currency of both prices.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// Quantity the quote covers.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub quantity: Option<i64>,
    /// Unit the quantity is counted in.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub unit: Option<String>,
    /// Fields this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// A request that either creates AuthInfo2 codes or quotes them.
///
/// Nothing is required at the type level — which object the code is created for
/// depends on the product — but an empty request is refused, because the API
/// would only answer `2003 Required parameter missing`.
///
/// ```
/// use inwx_client::{AuthInfo2Order, DomainName};
///
/// let order = AuthInfo2Order::new()?
///     .with_domain(&DomainName::parse("example.com")?)
///     .with_quantity(1)?;
/// let params = order.params()?;
/// assert_eq!(params["domain"], "example.com");
/// assert_eq!(params["quantity"], 1);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AuthInfo2Order {
    domain: Option<String>,
    quantity: Option<u32>,
    customer: Option<i64>,
    fields: ExtraFields,
}

impl AuthInfo2Order {
    /// An empty request; add at least one parameter.
    ///
    /// # Errors
    ///
    /// Never today; the signature leaves room for the checks the API enforces on
    /// an empty request.
    ///
    /// ```
    /// use inwx_client::AuthInfo2Order;
    /// assert!(AuthInfo2Order::new().is_ok());
    /// ```
    pub fn new() -> Result<Self> {
        Ok(Self::default())
    }

    /// Sets the domain the code is created for.
    ///
    /// ```
    /// use inwx_client::{AuthInfo2Order, DomainName};
    /// let order = AuthInfo2Order::new()?.with_domain(&DomainName::parse("example.com")?);
    /// assert_eq!(order.params()?["domain"], "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_domain(mut self, domain: &DomainName) -> Self {
        self.domain = Some(domain.as_str().to_owned());
        self
    }

    /// Sets how many codes to request.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for `0` or for a quantity above
    /// [`MAX_AUTHINFO2_QUANTITY`].
    ///
    /// ```
    /// use inwx_client::AuthInfo2Order;
    /// assert!(AuthInfo2Order::new()?.with_quantity(1).is_ok());
    /// assert!(AuthInfo2Order::new()?.with_quantity(100).is_ok());
    /// assert!(AuthInfo2Order::new()?.with_quantity(101).is_err());
    /// assert!(AuthInfo2Order::new()?.with_quantity(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_quantity(mut self, quantity: u32) -> Result<Self> {
        if quantity == 0 || quantity > MAX_AUTHINFO2_QUANTITY {
            return Err(Error::validation(
                "quantity",
                format!("must be 1 to {MAX_AUTHINFO2_QUANTITY}, got {quantity}"),
            ));
        }
        self.quantity = Some(quantity);
        Ok(self)
    }

    /// Sets the customer the codes belong to.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::AuthInfo2Order;
    /// assert!(AuthInfo2Order::new()?.with_customer(4711).is_ok());
    /// assert!(AuthInfo2Order::new()?.with_customer(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer(mut self, customer: i64) -> Result<Self> {
        self.customer = Some(params::object_id("customerId", customer)?);
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
    /// use inwx_client::AuthInfo2Order;
    /// let order = AuthInfo2Order::new()?.with_field("product", "AUTHINFO2")?;
    /// assert_eq!(order.params()?["product"], "AUTHINFO2");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_field(mut self, key: &str, value: impl Into<Value>) -> Result<Self> {
        self.fields.set(key, value.into(), ORDER_KEYS)?;
        Ok(self)
    }

    /// The parameters for `authinfo2.create` and `authinfo2.getprice`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when nothing was set.
    ///
    /// ```
    /// use inwx_client::AuthInfo2Order;
    /// assert!(AuthInfo2Order::new()?.params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut map = Map::new();
        if let Some(domain) = &self.domain {
            map.insert("domain".to_owned(), json!(domain));
        }
        if let Some(quantity) = self.quantity {
            map.insert("quantity".to_owned(), json!(quantity));
        }
        if let Some(customer) = self.customer {
            map.insert("customer".to_owned(), json!(customer));
        }
        self.fields.write_into(&mut map);
        params::require_payload("authinfo2.params", map.len())?;
        Ok(Value::Object(map))
    }
}

impl<T: Transport> InwxClient<T> {
    /// Creates AuthInfo2 codes (`authinfo2.create`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{AuthInfo2Order, DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let order = AuthInfo2Order::new()?.with_domain(&DomainName::parse("example.com")?);
    /// let created = client.create_authinfo2(&order).await?;
    /// if let Some(code) = &created.code {
    ///     // deliberate: the code only leaves `expose`, never `Debug`.
    ///     println!("state {:?}", created.state);
    ///     let _ = code.expose();
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the request carries no parameter, plus the
    /// usual transport and API errors.
    pub async fn create_authinfo2(&self, order: &AuthInfo2Order) -> Result<AuthInfo2> {
        let data = self.call("authinfo2.create", order.params()?).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// What the same request would cost (`authinfo2.getprice`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{AuthInfo2Order, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let quote = client.authinfo2_price(&AuthInfo2Order::new()?.with_quantity(10)?).await?;
    /// println!("{:?} {:?}", quote.gross_price, quote.currency);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the request carries no parameter, plus the
    /// usual transport and API errors.
    pub async fn authinfo2_price(&self, order: &AuthInfo2Order) -> Result<AuthInfo2Price> {
        let data = self.call("authinfo2.getprice", order.params()?).await?;
        serde_json::from_value(data).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantity_pair_is_one_and_one_hundred() {
        assert!(AuthInfo2Order::new().unwrap().with_quantity(1).is_ok());
        assert!(AuthInfo2Order::new().unwrap().with_quantity(100).is_ok());
        assert!(AuthInfo2Order::new().unwrap().with_quantity(101).is_err());
        assert!(AuthInfo2Order::new().unwrap().with_quantity(0).is_err());
    }

    #[test]
    fn an_empty_request_never_reaches_the_wire() {
        assert!(AuthInfo2Order::new().unwrap().params().is_err());
    }

    #[test]
    fn code_never_leaks_through_debug_or_display() {
        let code = AuthInfo2Code::new(String::from("sup3rsecret")).unwrap();
        assert_eq!(format!("{code}"), "<redacted>");
        assert!(!format!("{code:?}").contains("sup3rsecret"));

        let answer: AuthInfo2 = serde_json::from_str(r#"{"authInfo2":"sup3rsecret"}"#).unwrap();
        assert_eq!(
            answer.code.as_ref().map(AuthInfo2Code::expose),
            Some("sup3rsecret")
        );
        assert!(!format!("{answer:?}").contains("sup3rsecret"));
    }

    #[test]
    fn code_rejects_empty_and_control_characters() {
        assert!(AuthInfo2Code::new("").is_err());
        assert!(AuthInfo2Code::new("  ").is_err());
        assert!(AuthInfo2Code::new("a\u{1}b").is_err());
        assert!(AuthInfo2Code::new("a".repeat(255)).is_ok());
        assert!(AuthInfo2Code::new("a".repeat(256)).is_err());
    }

    #[test]
    fn an_unusable_code_is_dropped_not_guessed() {
        // An empty string in the payload means "no code", not a code.
        let answer: AuthInfo2 = serde_json::from_str(r#"{"authinfo2":""}"#).unwrap();
        assert!(answer.code.is_none());
    }

    #[test]
    fn reserved_keys_are_refused() {
        let order = || AuthInfo2Order::new().unwrap().with_quantity(2).unwrap();
        assert!(order().with_field("quantity", 3).is_err());
        assert!(order().with_field("not a name", 3).is_err());
    }

    #[test]
    fn domain_is_serialised_as_text() {
        let domain = DomainName::parse("example.com").unwrap();
        assert_eq!(
            AuthInfo2Order::new()
                .unwrap()
                .with_domain(&domain)
                .params()
                .unwrap()["domain"],
            "example.com"
        );
    }
}
