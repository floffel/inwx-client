//! The `authinfo2.*` object: the `AuthInfo2` product for `.de` domains.
//!
//! A `.de` domain has no EPP transfer code; the registry moves it with an
//! `AuthInfo2` token instead, and moving one is a paid order. Two methods cover
//! that: `authinfo2.create` orders the product for a single domain, and
//! `authinfo2.getprice` asks what such an order costs.
//!
//! The answer of `create` is an order confirmation — a product name and the
//! amount that was charged — not the token itself, so nothing here is redacted:
//! what a secret would look like is covered by [`AuthCode`](crate::AuthCode).
//!
//! ```
//! use inwx_client::{AuthInfo2Order, DomainName};
//!
//! let order = AuthInfo2Order::new(DomainName::parse("example.de")?, true);
//! let params = order.params();
//! assert_eq!(params["domain"], "example.de");
//! assert_eq!(params["testing"], true); // a dry run: the order is not placed
//! # Ok::<(), inwx_client::Error>(())
//! ```
//!
//! Note the parameter name: this object sends `domain`, not the `domainName`
//! the rest of the API uses.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, DomainName};

/// A request for `authinfo2.create`: the domain plus the dry-run switch.
///
/// `testing` is a parameter of the constructor and not a default, because the
/// difference between the two calls is whether money is spent: `false` places a
/// billable order, `true` only asks what would happen.
///
/// ```
/// use inwx_client::{AuthInfo2Order, DomainName};
///
/// let domain = DomainName::parse("example.de")?;
/// let dry_run = AuthInfo2Order::new(domain.clone(), true);
/// assert_eq!(dry_run.params()["testing"], true);
///
/// let real = AuthInfo2Order::new(domain, false);
/// assert!(real.params().get("testing").is_none());
/// assert_eq!(real.domain().as_str(), "example.de");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthInfo2Order {
    domain: DomainName,
    testing: bool,
}

impl AuthInfo2Order {
    /// Builds the request for `domain`, with `testing` as the explicit opt-in
    /// to a dry run.
    ///
    /// The domain arrives as the validated [`DomainName`], so an empty name, a
    /// malformed one or one beyond
    /// [`MAX_DOMAIN_LEN`](crate::MAX_DOMAIN_LEN) is already a parse error
    /// by the time an order can exist. Upstream types `domain` as `text255`;
    /// a name has to be a syntactically valid domain here, which is stricter.
    ///
    /// ```
    /// use inwx_client::{AuthInfo2Order, DomainName};
    ///
    /// let order = AuthInfo2Order::new(DomainName::parse("example.de")?, false);
    /// assert!(!order.is_testing());
    /// assert_eq!(order.params()["domain"], "example.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn new(domain: DomainName, testing: bool) -> Self {
        Self { domain, testing }
    }

    /// The domain the order is for.
    ///
    /// ```
    /// use inwx_client::{AuthInfo2Order, DomainName};
    ///
    /// let order = AuthInfo2Order::new(DomainName::parse("example.de")?, false);
    /// assert_eq!(order.domain().as_str(), "example.de");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// Whether this is a dry run instead of a real order.
    ///
    /// ```
    /// use inwx_client::{AuthInfo2Order, DomainName};
    ///
    /// assert!(AuthInfo2Order::new(DomainName::parse("example.de")?, true).is_testing());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn is_testing(&self) -> bool {
        self.testing
    }

    /// The `authinfo2.create` parameters.
    ///
    /// `testing` is left out entirely unless it is set, so the wire format
    /// never states a default the API did not ask for.
    ///
    /// ```
    /// use inwx_client::{AuthInfo2Order, DomainName};
    ///
    /// let params = AuthInfo2Order::new(DomainName::parse("example.de")?, false).params();
    /// assert_eq!(params, serde_json::json!({ "domain": "example.de" }));
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut params = Map::new();
        params.insert("domain".to_owned(), json!(self.domain.as_str()));
        if self.testing {
            params.insert("testing".to_owned(), json!(true));
        }
        Value::Object(params)
    }
}

/// The answer of `authinfo2.create`: the confirmation of a placed order.
///
/// Every field is optional and unknown keys are ignored, so a change in what
/// INWX reports costs a `None` instead of a failed parse. Prices are the
/// documented `float`s and arrive as numbers or as numeric strings; both spell-
/// ings of each key (`net_price` and `netPrice`) are accepted.
///
/// ```
/// use inwx_client::AuthInfo2OrderResult;
///
/// let result: AuthInfo2OrderResult = serde_json::from_str(
///     r#"{"product":"DE-AuthInfo2","net_price":"1.20","price":1.43,
///         "currency":"EUR","message":"order placed","vat":19.0}"#,
/// )?;
/// assert_eq!(result.product.as_deref(), Some("DE-AuthInfo2"));
/// assert_eq!(result.net_price, Some(1.20));
/// assert_eq!(result.price, Some(1.43));
/// assert_eq!(result.currency.as_deref(), Some("EUR"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct AuthInfo2OrderResult {
    /// The `AuthInfo2` product that was ordered.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub product: Option<String>,
    /// Price without VAT.
    #[serde(default, alias = "netPrice", deserialize_with = "de::opt_f64")]
    pub net_price: Option<f64>,
    /// Price including VAT.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub price: Option<f64>,
    /// Currency of both amounts, kept as the string the API sent.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// What the API has to say about the order.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub message: Option<String>,
}

/// The answer of `authinfo2.getprice`: what an `AuthInfo2` order costs.
///
/// ```
/// use inwx_client::AuthInfo2PriceQuote;
///
/// let quote: AuthInfo2PriceQuote = serde_json::from_str(
///     r#"{"product":"DE-AuthInfo2","netPrice":1.2,"price":"1.43","currency":"EUR"}"#,
/// )?;
/// assert_eq!(quote.net_price, Some(1.2));
/// assert_eq!(quote.price, Some(1.43));
/// assert_eq!(quote.currency.as_deref(), Some("EUR"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct AuthInfo2PriceQuote {
    /// The product the quote is for.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub product: Option<String>,
    /// Price without VAT.
    #[serde(default, alias = "netPrice", deserialize_with = "de::opt_f64")]
    pub net_price: Option<f64>,
    /// Price including VAT.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub price: Option<f64>,
    /// Currency of both amounts, kept as the string the API sent.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
}

impl<T: Transport> InwxClient<T> {
    /// Orders the `AuthInfo2` product for a domain (`authinfo2.create`).
    ///
    /// Pass `testing: true` on the [`AuthInfo2Order`] to ask instead of order.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{AuthInfo2Order, DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let order = AuthInfo2Order::new(DomainName::parse("example.de")?, false);
    /// let result = client.create_auth_info2(&order).await?;
    /// println!("{:?} {:?} {:?}", result.product, result.price, result.currency);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// This is a billable, non-idempotent order, so it is never replayed: on a
    /// 429, a 5xx or a timeout after the request was written the call answers
    /// [`Error::Uncertain`] after a single attempt. Check the current state
    /// (`domain.info`) before ordering again — a retry could buy the product
    /// twice.
    ///
    /// # Errors
    ///
    /// [`Error::NotAuthenticated`] without a session, [`Error::Api`] when the
    /// domain is not in this account (`2303`) or the product is unavailable,
    /// [`Error::Transport`]/[`Error::Http`] for a transport or HTTP failure,
    /// [`Error::Json`] for an unreadable body, and [`Error::Uncertain`] when the
    /// request was written but the answer never arrived — that outcome is never
    /// replayed, because the order may already have been placed.
    pub async fn create_auth_info2(&self, order: &AuthInfo2Order) -> Result<AuthInfo2OrderResult> {
        let data = self.call("authinfo2.create", order.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// What an `AuthInfo2` order would cost (`authinfo2.getprice`).
    ///
    /// The method takes no parameters upstream, so this sends an empty object.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let quote = client.auth_info2_price().await?;
    /// println!("{:?} {:?} {:?}", quote.product, quote.price, quote.currency);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::NotAuthenticated`], [`Error::Api`], [`Error::Transport`],
    /// [`Error::Uncertain`], [`Error::Json`] or [`Error::Http`]. Being
    /// read-only, the call is replayed on a transient failure.
    pub async fn auth_info2_price(&self) -> Result<AuthInfo2PriceQuote> {
        let data = self.call("authinfo2.getprice", json!({})).await?;
        serde_json::from_value(data).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{MAX_DOMAIN_LEN, MAX_LABEL_LEN};

    /// A name of exactly `length` characters built from valid labels.
    fn domain_of_len(length: usize) -> String {
        let head = format!(
            "{}.{}.{}.",
            "a".repeat(MAX_LABEL_LEN),
            "b".repeat(MAX_LABEL_LEN),
            "c".repeat(MAX_LABEL_LEN)
        );
        format!("{head}{}", "d".repeat(length - head.len()))
    }

    #[test]
    fn a_domain_of_253_characters_is_accepted_and_254_is_not() {
        // Just inside the limit, just outside it, and the degenerate case.
        let at_limit = domain_of_len(MAX_DOMAIN_LEN);
        assert_eq!(at_limit.chars().count(), MAX_DOMAIN_LEN);
        let order = AuthInfo2Order::new(DomainName::parse(&at_limit).unwrap(), true);
        assert_eq!(
            order.params()["domain"].as_str().map(str::len),
            Some(MAX_DOMAIN_LEN)
        );

        let over_limit = format!("{at_limit}d");
        assert_eq!(over_limit.chars().count(), MAX_DOMAIN_LEN + 1);
        assert!(DomainName::parse(&over_limit).is_err());

        assert!(DomainName::parse("").is_err());
        assert!(DomainName::parse("   ").is_err());
    }

    #[test]
    fn testing_is_only_sent_when_it_is_set() {
        let domain = DomainName::parse("example.de").unwrap();
        let dry = AuthInfo2Order::new(domain.clone(), true);
        assert_eq!(dry.params()["testing"], json!(true));
        assert!(dry.is_testing());

        let real = AuthInfo2Order::new(domain.clone(), false);
        assert!(real.params().get("testing").is_none());
        assert!(!real.is_testing());
        assert_eq!(real.domain(), &domain);

        // Two orders of the same shape are equal; a flipped switch is not.
        assert_eq!(real, AuthInfo2Order::new(domain.clone(), false));
        assert_ne!(real, dry);
        let _ = format!("{real:?}");
        let _ = real.clone();
    }

    #[test]
    fn both_spellings_decode_and_unknown_fields_are_ignored() {
        let snake: AuthInfo2OrderResult = serde_json::from_str(
            r#"{"product":"P","net_price":1.5,"price":2.0,"currency":"EUR","message":"m","extra":{"a":1}}"#,
        )
        .unwrap();
        assert_eq!(snake.net_price, Some(1.5));
        assert_eq!(snake.message.as_deref(), Some("m"));

        let camel: AuthInfo2OrderResult =
            serde_json::from_str(r#"{"netPrice":"1.5","price":"2.0"}"#).unwrap();
        assert_eq!(camel.net_price, Some(1.5));
        assert_eq!(camel.price, Some(2.0));
    }

    #[test]
    fn an_unusable_price_degrades_to_none_instead_of_failing() {
        let wrong_type: AuthInfo2PriceQuote =
            serde_json::from_str(r#"{"net_price":true,"price":[1,2],"currency":"EUR"}"#).unwrap();
        assert_eq!(wrong_type.net_price, None);
        assert_eq!(wrong_type.price, None);
        assert_eq!(wrong_type.currency.as_deref(), Some("EUR"));

        let missing: AuthInfo2PriceQuote = serde_json::from_str(r"{}").unwrap();
        assert_eq!(missing, AuthInfo2PriceQuote::default());

        let null: AuthInfo2OrderResult =
            serde_json::from_str(r#"{"product":null,"net_price":null}"#).unwrap();
        assert_eq!(null.product, None);
        assert_eq!(null.net_price, None);
    }
}
