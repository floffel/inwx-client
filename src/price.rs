//! Prices: `domain.getPrices`, `domain.getalldomainprices`,
//! `domain.getdomainprice`, `domain.getextradatarules`, `domain.getPromos` and
//! `domain.priceChanges`.
//!
//! Prices are `float` on the wire and are kept as `f64` here: they are quotes to
//! display and compare, not amounts to sum. For anything that charges money, use
//! the amount the API returns from the actual `create`/`renew` call.
//!
//! Everything here decodes permissively: unknown fields are ignored, a price
//! that is neither a number nor a numeric string becomes `None` instead of
//! failing the whole answer, an answer of one object is read as one row, and
//! `snake_case` is accepted where the API writes `camelCase`. Order types that this
//! crate does not know stay on the struct as raw text, next to the typed view of
//! them.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, parse_rows, validate_text, DomainName, Period, PriceType};

/// One TLD's price list, from `domain.getPrices` or
/// `domain.getalldomainprices`.
///
/// ```
/// use inwx_client::TldPrice;
///
/// let price: TldPrice = serde_json::from_str(
///     r#"{"tld":"de","currency":"EUR","createPrice":8.9,"transferPrice":8.9,
///         "renewalPrice":8.9,"updatePrice":0,"tradePrice":0,
///         "createPeriod":1,"transferPeriod":1,"renewalPeriod":1,"vat":19.0}"#,
/// )?;
/// assert_eq!(price.tld, "de");
/// assert_eq!(price.create, Some(8.9));
/// assert_eq!(price.renewal_period, Some(1));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct TldPrice {
    /// Top level domain, without the dot.
    #[serde(default, alias = "domain")]
    pub tld: String,
    /// Currency of every amount in this entry.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// Registration price per year.
    #[serde(
        default,
        rename = "createPrice",
        alias = "create_price",
        alias = "regPrice",
        alias = "reg_price",
        alias = "create",
        deserialize_with = "de::opt_f64"
    )]
    pub create: Option<f64>,
    /// Transfer price per year.
    #[serde(
        default,
        rename = "transferPrice",
        alias = "transfer_price",
        alias = "transfer",
        deserialize_with = "de::opt_f64"
    )]
    pub transfer: Option<f64>,
    /// Renewal price per year.
    #[serde(
        default,
        rename = "renewalPrice",
        alias = "renewal_price",
        alias = "renewal",
        deserialize_with = "de::opt_f64"
    )]
    pub renewal: Option<f64>,
    /// Update price.
    #[serde(
        default,
        rename = "updatePrice",
        alias = "update_price",
        alias = "update",
        deserialize_with = "de::opt_f64"
    )]
    pub update: Option<f64>,
    /// Owner change price.
    #[serde(
        default,
        rename = "tradePrice",
        alias = "trade_price",
        alias = "trade",
        deserialize_with = "de::opt_f64"
    )]
    pub trade: Option<f64>,
    /// Trustee service price per year.
    #[serde(
        default,
        rename = "trusteePrice",
        alias = "trustee_price",
        alias = "trustee",
        deserialize_with = "de::opt_f64"
    )]
    pub trustee: Option<f64>,
    /// Minimum registration period in years.
    #[serde(
        default,
        rename = "createPeriod",
        alias = "create_period",
        deserialize_with = "de::opt_i64"
    )]
    pub create_period: Option<i64>,
    /// Minimum transfer period in years.
    #[serde(
        default,
        rename = "transferPeriod",
        alias = "transfer_period",
        deserialize_with = "de::opt_i64"
    )]
    pub transfer_period: Option<i64>,
    /// Minimum renewal period in years.
    #[serde(
        default,
        rename = "renewalPeriod",
        alias = "renewal_period",
        deserialize_with = "de::opt_i64"
    )]
    pub renewal_period: Option<i64>,
    /// Applied VAT rate, when `vat` was requested.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub vat: Option<f64>,
    /// Monthly registration price.
    #[serde(
        default,
        rename = "monthlyCreatePrice",
        alias = "monthly_create_price",
        deserialize_with = "de::opt_f64"
    )]
    pub monthly_create: Option<f64>,
    /// Monthly renewal price.
    #[serde(
        default,
        rename = "monthlyRenewalPrice",
        alias = "monthly_renewal_price",
        deserialize_with = "de::opt_f64"
    )]
    pub monthly_renewal: Option<f64>,
    /// Monthly trustee price.
    #[serde(
        default,
        rename = "monthlyTrusteePrice",
        alias = "monthly_trustee_price",
        deserialize_with = "de::opt_f64"
    )]
    pub monthly_trustee: Option<f64>,
    /// Restore price.
    #[serde(
        default,
        rename = "restorePrice",
        alias = "restore_price",
        deserialize_with = "de::opt_f64"
    )]
    pub restore: Option<f64>,
    /// Whether the quoted price is a premium price.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub premium: Option<bool>,
    /// Whether the quoted price is a promo price.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub promo: Option<bool>,
    /// Promo price.
    #[serde(
        default,
        rename = "promoPrice",
        alias = "promo_price",
        deserialize_with = "de::opt_f64"
    )]
    pub promo_price: Option<f64>,
    /// Promo action type, as it arrived.
    #[serde(
        default,
        rename = "promoType",
        alias = "promo_type",
        deserialize_with = "de::opt_string"
    )]
    pub promo_type: Option<String>,
    /// Period the quoted price applies to.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub period: Option<String>,
}

/// The price table, as returned by `domain.getPrices` and by
/// `domain.getalldomainprices`.
///
/// ```
/// use inwx_client::PriceList;
///
/// let list: PriceList = serde_json::from_str(
///     r#"{"price":[{"tld":"de","currency":"EUR","createPrice":8.9},{"tld":"com","createPrice":12.5}]}"#,
/// )?;
/// assert_eq!(list.len(), 2);
/// assert_eq!(list.find("com").unwrap().create, Some(12.5));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct PriceList {
    /// Total number of TLDs in the answer.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// One entry per TLD.
    #[serde(default, rename = "price", alias = "prices", alias = "domain")]
    pub prices: Vec<TldPrice>,
}

impl PriceList {
    /// Number of TLD entries.
    ///
    /// ```
    /// use inwx_client::PriceList;
    /// assert_eq!(PriceList::default().len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.prices.len()
    }

    /// Whether the list is empty.
    ///
    /// ```
    /// use inwx_client::PriceList;
    /// assert_eq!(PriceList::default().len(), 0);
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prices.is_empty()
    }

    /// Whether the answer is only part of the table, comparing the number of
    /// entries to `count`, when the API reports one.
    ///
    /// ```
    /// use inwx_client::PriceList;
    ///
    /// let partial: PriceList = serde_json::from_str(r#"{"count":2,"price":[{"tld":"de"}]}"#)?;
    /// assert!(partial.has_more());
    /// let whole: PriceList = serde_json::from_str(r#"{"count":1,"price":[{"tld":"de"}]}"#)?;
    /// assert!(!whole.has_more());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.count
            .is_some_and(|count| i64::try_from(self.prices.len()).unwrap_or(i64::MAX) < count)
    }

    /// The entry for a TLD, case-insensitively and tolerating a leading dot.
    ///
    /// ```
    /// use inwx_client::PriceList;
    ///
    /// let list: PriceList = serde_json::from_str(r#"{"price":[{"tld":"de","createPrice":8.9}]}"#)?;
    /// assert!(list.find(".DE").is_some());
    /// assert!(list.find("com").is_none());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn find(&self, tld: &str) -> Option<&TldPrice> {
        let wanted = tld.trim().trim_start_matches('.').to_ascii_lowercase();
        self.prices
            .iter()
            .find(|price| price.tld.eq_ignore_ascii_case(&wanted))
    }
}

/// A price for one domain and one action (`domain.getdomainprice`).
///
/// ```
/// use inwx_client::{DomainPriceQuote, PriceType};
///
/// let quote: DomainPriceQuote = serde_json::from_str(
///     r#"{"domain":"example.com","type":"renewal","price":12.5,"currency":"EUR","premium":0}"#,
/// )?;
/// assert_eq!(quote.price, Some(12.5));
/// assert_eq!(quote.price_type.as_deref(), Some("renewal"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct DomainPriceQuote {
    /// The domain the quote is for.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub domain: Option<String>,
    /// Action the quote applies to.
    #[serde(default, rename = "type", deserialize_with = "de::opt_string")]
    pub price_type: Option<String>,
    /// Billing period, when the API reports one.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub period: Option<String>,
    /// The amount.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub price: Option<f64>,
    /// Currency of `price`.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// Whether a promo price applies.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub promo: Option<bool>,
    /// Whether the domain is a premium domain.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub premium: Option<bool>,
}

/// The TLD list as the API wants it: trimmed, without the leading dot,
/// lower-cased, blanks dropped. An empty list means "everything" and is then
/// left out of the request.
fn normalise_tlds(tlds: &[&str]) -> Vec<String> {
    tlds.iter()
        .map(|tld| tld.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|tld| !tld.is_empty())
        .collect()
}

/// One TLD as a normalized string: trimmed, without a leading dot, lower-cased.
fn normalise_tld_value(tld: &str) -> String {
    tld.trim().trim_start_matches('.').to_ascii_lowercase()
}

/// One optional TLD filter. Unlike the list, an empty filter is refused: the
/// caller asked to narrow the answer and then named nothing, which is a typo
/// rather than a request for the whole table.
fn normalise_tld(tld: Option<&str>) -> Result<Option<String>> {
    let Some(tld) = tld else {
        return Ok(None);
    };
    let tld = tld.trim().trim_start_matches('.').to_ascii_lowercase();
    if tld.is_empty() {
        return Err(Error::validation("tld", "must not be empty"));
    }
    Ok(Some(tld))
}

/// A `textNN` request field that is optional: absent is fine, present has to be
/// non-empty and within the documented length.
fn normalise_optional_text<'a>(
    field: &'static str,
    value: Option<&'a str>,
    max: usize,
) -> Result<Option<&'a str>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    validate_text(field, trimmed, max)?;
    Ok(Some(trimmed))
}

/// Extra-data rules are documented as `array_text255`: an array of strings, one
/// string, or nothing.
fn parse_rule_rows(data: &Value) -> Vec<ExtraDataRule> {
    for key in ["rules", "extradata", "extradataRules"] {
        match data.get(key) {
            Some(Value::Array(rows)) => {
                return rows
                    .iter()
                    .filter_map(|row| row.as_str().map(ExtraDataRule::from))
                    .collect();
            }
            Some(Value::String(rule)) => return vec![ExtraDataRule::from(rule.clone())],
            _ => {}
        }
    }
    Vec::new()
}

/// The rows under a key, marking every row when it belongs to the past array.
fn parse_price_changes(data: &Value, key: &str, is_past: bool) -> Vec<PriceChange> {
    parse_rows::<PriceChange>(data, key)
        .into_iter()
        .map(|mut change| {
            change.is_past = is_past;
            change
        })
        .collect()
}

/// One extra-data rule returned by `domain.getextradatarules`.
///
/// INWX documents the answer as a list of `text255` rule strings, not as a
/// structured rule object. The text is kept verbatim and also split into the
/// `name`/`value` pair that the rule syntax uses when it has one.
///
/// ```
/// use inwx_client::ExtraDataRule;
///
/// let rule = ExtraDataRule::from("X_FN_INDUSTRY=retail");
/// assert_eq!(rule.as_str(), "X_FN_INDUSTRY=retail");
/// assert_eq!(rule.name(), Some("X_FN_INDUSTRY"));
/// assert_eq!(rule.value(), Some("retail"));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtraDataRule(String);

impl ExtraDataRule {
    /// The rule text exactly as the API returned it.
    ///
    /// ```
    /// use inwx_client::ExtraDataRule;
    ///
    /// let rule = ExtraDataRule::from("X_FN_VAT");
    /// assert_eq!(rule.as_str(), "X_FN_VAT");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The part before the first `=`, when the rule carries one.
    ///
    /// ```
    /// use inwx_client::ExtraDataRule;
    ///
    /// assert_eq!(ExtraDataRule::from("X_FN_VAT=DE123").name(), Some("X_FN_VAT"));
    /// assert_eq!(ExtraDataRule::from("REQUIRED").name(), None);
    /// ```
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.0.trim().split_once('=').map(|(name, _)| name.trim())
    }

    /// The part after the first `=`, when the rule carries one.
    ///
    /// ```
    /// use inwx_client::ExtraDataRule;
    ///
    /// assert_eq!(ExtraDataRule::from("X_FN_VAT=DE123").value(), Some("DE123"));
    /// assert_eq!(ExtraDataRule::from("REQUIRED").value(), None);
    /// ```
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.0.trim().split_once('=').map(|(_, value)| value.trim())
    }

    /// Whether the rule text is empty after trimming.
    ///
    /// ```
    /// use inwx_client::ExtraDataRule;
    ///
    /// assert!(ExtraDataRule::from("  ").is_empty());
    /// assert!(!ExtraDataRule::from("X_FN_VAT").is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl From<&str> for ExtraDataRule {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for ExtraDataRule {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for ExtraDataRule {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ExtraDataRule {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(Self(raw))
    }
}

/// A promo price (`domain.getPromos`).
///
/// ```
/// use inwx_client::PromoCode;
///
/// let promo: PromoCode = serde_json::from_str(
///     r#"{"tld":"de","netPrice":"1.00","currency":"EUR",
///         "endTime":"2026-03-31T23:59:59"}"#,
/// )?;
/// assert_eq!(promo.tld.as_deref(), Some("de"));
/// assert_eq!(promo.price, Some(1.0));
/// assert_eq!(promo.currency.as_deref(), Some("EUR"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct PromoCode {
    /// The TLD the promo applies to.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub tld: Option<String>,
    /// The promo code, when the API maps a code to the price.
    #[serde(default, rename = "code", deserialize_with = "de::opt_string")]
    pub code: Option<String>,
    /// Net promotional price.
    #[serde(
        default,
        rename = "netPrice",
        alias = "net_price",
        alias = "price",
        deserialize_with = "de::opt_f64"
    )]
    pub price: Option<f64>,
    /// Currency of the net price.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// End time of the promo, as text.
    #[serde(
        default,
        rename = "endTime",
        alias = "end_time",
        alias = "validUntil",
        alias = "valid_until",
        deserialize_with = "de::opt_string"
    )]
    pub end_time: Option<String>,
    /// Order type the promo applies to, as it arrived.
    #[serde(
        default,
        rename = "promoType",
        alias = "promo_type",
        alias = "orderType",
        alias = "order_type",
        alias = "order",
        deserialize_with = "de::opt_string"
    )]
    pub order_type: Option<String>,
    /// Billing period the promo applies to, when reported.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub period: Option<String>,
}

impl PromoCode {
    /// The promo TLD without a leading dot, lower-cased.
    ///
    /// ```
    /// use inwx_client::PromoCode;
    ///
    /// let promo: PromoCode = serde_json::from_str(r#"{"tld":".DE"}"#)?;
    /// assert_eq!(promo.normalised_tld().as_deref(), Some("de"));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn normalised_tld(&self) -> Option<String> {
        self.tld.as_deref().map(normalise_tld_value)
    }

    /// [`Self::order_type`] as a [`PriceType`], or `None` when absent or not
    /// one of the documented order types.
    ///
    /// ```
    /// use inwx_client::{PriceType, PromoCode};
    ///
    /// let promo: PromoCode = serde_json::from_str(r#"{"promoType":"REG"}"#)?;
    /// assert_eq!(promo.price_type(), Some(PriceType::Reg));
    /// let unknown: PromoCode = serde_json::from_str(r#"{"promoType":"gift"}"#)?;
    /// assert_eq!(unknown.price_type(), None);
    /// assert_eq!(unknown.order_type.as_deref(), Some("gift"));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn price_type(&self) -> Option<PriceType> {
        self.order_type.as_deref().and_then(|raw| raw.parse().ok())
    }
}

/// A scheduled price change (`domain.priceChanges`).
///
/// A quote from `domain.getPrices` goes stale on the day in
/// [`Self::change_date`]; this is what tells a caller that it will.
///
/// ```
/// use inwx_client::PriceChange;
///
/// let change: PriceChange = serde_json::from_str(
///     r#"{"tld":"com","affectsCustomer":true,"createPrice":"13.90",
///         "renewalPrice":12.5,"currency":"EUR","changeDate":"2026-01-01"}"#,
/// )?;
/// assert_eq!(change.create, Some(13.9));
/// assert_eq!(change.renewal, Some(12.5));
/// assert_eq!(change.change_date.as_deref(), Some("2026-01-01"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct PriceChange {
    /// TLD whose price changes.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub tld: Option<String>,
    /// Whether the customer has active domains for the TLD.
    #[serde(
        default,
        rename = "affectsCustomer",
        alias = "affects_customer",
        deserialize_with = "de::opt_bool"
    )]
    pub affects_customer: Option<bool>,
    /// Currency of every amount in this change.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// Date the new prices take effect.
    #[serde(
        default,
        rename = "changeDate",
        alias = "change_date",
        alias = "effective",
        alias = "date",
        alias = "startDate",
        alias = "start_date",
        deserialize_with = "de::opt_string"
    )]
    pub change_date: Option<String>,
    /// Registration price per year.
    #[serde(
        default,
        rename = "createPrice",
        alias = "create_price",
        alias = "regPrice",
        alias = "reg_price",
        deserialize_with = "de::opt_f64"
    )]
    pub create: Option<f64>,
    /// Registration price per month.
    #[serde(
        default,
        rename = "monthlyCreatePrice",
        alias = "monthly_create_price",
        deserialize_with = "de::opt_f64"
    )]
    pub monthly_create: Option<f64>,
    /// Transfer price per year.
    #[serde(
        default,
        rename = "transferPrice",
        alias = "transfer_price",
        deserialize_with = "de::opt_f64"
    )]
    pub transfer: Option<f64>,
    /// Renewal price per year.
    #[serde(
        default,
        rename = "renewalPrice",
        alias = "renewal_price",
        deserialize_with = "de::opt_f64"
    )]
    pub renewal: Option<f64>,
    /// Renewal price per month.
    #[serde(
        default,
        rename = "monthlyRenewalPrice",
        alias = "monthly_renewal_price",
        deserialize_with = "de::opt_f64"
    )]
    pub monthly_renewal: Option<f64>,
    /// Update price.
    #[serde(
        default,
        rename = "updatePrice",
        alias = "update_price",
        deserialize_with = "de::opt_f64"
    )]
    pub update: Option<f64>,
    /// Trade price.
    #[serde(
        default,
        rename = "tradePrice",
        alias = "trade_price",
        deserialize_with = "de::opt_f64"
    )]
    pub trade: Option<f64>,
    /// Trustee service price per year.
    #[serde(
        default,
        rename = "trusteePrice",
        alias = "trustee_price",
        deserialize_with = "de::opt_f64"
    )]
    pub trustee: Option<f64>,
    /// Trustee service price per month.
    #[serde(
        default,
        rename = "monthlyTrusteePrice",
        alias = "monthly_trustee_price",
        deserialize_with = "de::opt_f64"
    )]
    pub monthly_trustee: Option<f64>,
    /// Restore price.
    #[serde(
        default,
        rename = "restorePrice",
        alias = "restore_price",
        deserialize_with = "de::opt_f64"
    )]
    pub restore: Option<f64>,
    /// Whether this row came from the documented `pastChanges` list.
    #[serde(skip)]
    pub is_past: bool,
}

impl<T: Transport> InwxClient<T> {
    /// Lists the TLD price table (`domain.getPrices`).
    ///
    /// Passing no TLDs returns the account's full table, which is large; pass
    /// the TLDs you care about.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let prices = client.tld_prices(&["de", "com"]).await?;
    /// println!("{:?}", prices.find("de").and_then(|price| price.renewal));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn tld_prices(&self, tlds: &[&str]) -> Result<PriceList> {
        let tlds = normalise_tlds(tlds);
        let params = if tlds.is_empty() {
            json!({})
        } else {
            json!({ "tld": tlds })
        };
        let data = self.call("domain.getPrices", params).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// The current prices for one or more domains
    /// (`domain.getalldomainprices`).
    ///
    /// INWX documents `page` and `pagelimit` on `domain.getPrices`; this method
    /// takes a domain list and an optional period instead.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// use inwx_client::Period;
    /// let prices = client
    ///     .all_domain_prices(&["example.de", "example.com"], Some(Period::years(1)?))
    ///     .await?;
    /// println!("{} entries", prices.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when no non-blank domain is given, plus the usual
    /// transport and API errors.
    pub async fn all_domain_prices(
        &self,
        domains: &[&str],
        period: Option<Period>,
    ) -> Result<PriceList> {
        let domains: Vec<&str> = domains
            .iter()
            .map(|domain| domain.trim())
            .filter(|domain| !domain.is_empty())
            .collect();
        if domains.is_empty() {
            return Err(Error::validation("domain", "must not be empty"));
        }
        let mut params = Map::new();
        params.insert("domain".to_owned(), json!(domains));
        if let Some(period) = period {
            params.insert("period".to_owned(), json!(period));
        }
        let data = self
            .call("domain.getalldomainprices", Value::Object(params))
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Quotes a price for one domain and action (`domain.getdomainprice`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, PriceType, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let quote = client
    ///     .domain_price(&DomainName::parse("example.com")?, PriceType::Renewal, None)
    ///     .await?;
    /// println!("{:?}", quote.price);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn domain_price(
        &self,
        domain: &DomainName,
        price_type: PriceType,
        period: Option<Period>,
    ) -> Result<DomainPriceQuote> {
        let mut params = Map::new();
        params.insert("domain".to_owned(), json!([domain.as_str()]));
        params.insert("pricetype".to_owned(), json!(price_type.as_str()));
        if let Some(period) = period {
            params.insert("period".to_owned(), json!(period));
        }
        let data = self
            .call("domain.getdomainprice", Value::Object(params))
            .await?;
        // The documented shape is `resData.domain[0]`; older responses put the
        // quote directly in `resData`, and `domain` may then be the name itself.
        let entry = match data.get("domain") {
            Some(Value::Array(entries)) => entries.first().cloned(),
            Some(object @ Value::Object(_)) => Some(object.clone()),
            _ => Some(data.clone()),
        };
        let entry = entry.ok_or(Error::MissingField {
            method: "domain.getdomainprice",
            field: "resData.domain[0]",
        })?;
        serde_json::from_value(entry).map_err(Error::from)
    }

    /// The extra data an order for a TLD has to carry
    /// (`domain.getextradatarules`).
    ///
    /// These are the registry-specific rules (`domain.create` sends the extra
    /// data besides the contact handles); pass the TLD you are about to order.
    /// `tld: None` asks for every rule the account has.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let rules = client.extra_data_rules(Some(".de")).await?;
    /// for rule in &rules {
    ///     println!("{rule}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `tld` is `Some` but blank, plus the usual
    /// transport and API errors.
    pub async fn extra_data_rules(&self, tld: Option<&str>) -> Result<Vec<ExtraDataRule>> {
        let mut params = Map::new();
        if let Some(tld) = normalise_tld(tld)? {
            params.insert("tld".to_owned(), json!(tld));
        }
        let data = self
            .call("domain.getextradatarules", Value::Object(params))
            .await?;
        Ok(parse_rule_rows(&data))
    }

    /// The promo prices for one or more TLDs (`domain.getPromos`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// use inwx_client::{Period, PriceType};
    /// for promo in client
    ///     .promo_prices(&["de"], Some(PriceType::Reg), Some(Period::years(1)?), None)
    ///     .await?
    /// {
    ///     println!(
    ///         "{:?}: {:?} {}",
    ///         promo.tld,
    ///         promo.price,
    ///         promo.currency.clone().unwrap_or_default()
    ///     );
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when a TLD or voucher is present but blank, plus
    /// the usual transport and API errors.
    pub async fn promo_prices(
        &self,
        tlds: &[&str],
        promo_type: Option<PriceType>,
        period: Option<Period>,
        voucher: Option<&str>,
    ) -> Result<Vec<PromoCode>> {
        let mut params = Map::new();
        let tlds = normalise_tlds(tlds);
        if !tlds.is_empty() {
            params.insert("tlds".to_owned(), json!(tlds));
        }
        if let Some(promo_type) = promo_type {
            params.insert(
                "promoType".to_owned(),
                json!(promo_type.as_str().to_ascii_uppercase()),
            );
        }
        if let Some(period) = period {
            let (length, unit) = period.parts();
            params.insert("period".to_owned(), json!(length));
            params.insert("periodUnit".to_owned(), json!(unit));
        }
        if let Some(voucher) = normalise_optional_text("voucher", voucher, 64)? {
            params.insert("voucher".to_owned(), json!(voucher));
        }
        let data = self.call("domain.getPromos", Value::Object(params)).await?;
        Ok(parse_rows::<PromoCode>(&data, "promos"))
    }

    /// The price changes that are already scheduled
    /// (`domain.priceChanges`).
    ///
    /// A quote from [`InwxClient::tld_prices`] is only trustworthy until the
    /// `change_date` of a change for the same TLD.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for change in client.price_changes().await? {
    ///     println!("{:?} changes on {:?}", change.tld, change.change_date);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn price_changes(&self) -> Result<Vec<PriceChange>> {
        let data = self
            .call("domain.priceChanges", Value::Object(Map::new()))
            .await?;
        let mut changes = parse_price_changes(&data, "futureChanges", false);
        changes.extend(parse_price_changes(&data, "pastChanges", true));
        Ok(changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_is_case_insensitive_and_dot_tolerant() {
        let list: PriceList = serde_json::from_str(
            r#"{"count":1,"price":[{"tld":"DE","currency":"EUR","renewalPrice":"8.90"}]}"#,
        )
        .unwrap();
        assert_eq!(list.find("de").unwrap().renewal, Some(8.9));
        assert_eq!(list.len(), 1);
        assert!(!list.is_empty());
    }

    #[test]
    fn missing_amounts_stay_none() {
        let price: TldPrice = serde_json::from_str(r#"{"tld":"com"}"#).unwrap();
        assert!(price.create.is_none());
        assert!(price.currency.is_none());
    }

    #[test]
    fn a_named_tld_filter_passes_and_a_blank_one_does_not() {
        assert_eq!(normalise_tld(Some(" DE ")).unwrap().as_deref(), Some("de"));
        assert_eq!(
            normalise_tld(Some("  .DE ")).unwrap().as_deref(),
            Some("de")
        );
        assert_eq!(normalise_tld(None).unwrap(), None);
        for blank in ["", " ", "."] {
            assert!(
                normalise_tld(Some(blank)).is_err(),
                "{blank:?} must be refused"
            );
        }
    }

    #[test]
    fn a_tld_list_drops_the_blanks_it_is_handed() {
        assert_eq!(normalise_tlds(&[".DE", " com ", "", "."]), ["de", "com"]);
        assert_eq!(normalise_tlds(&[]), Vec::<String>::new());
    }

    #[test]
    fn has_more_is_about_the_entry_after_the_last_one() {
        let whole: PriceList =
            serde_json::from_str(r#"{"count":1,"price":[{"tld":"de"}]}"#).unwrap();
        assert!(!whole.has_more());
        let partial: PriceList =
            serde_json::from_str(r#"{"count":2,"price":[{"tld":"de"}]}"#).unwrap();
        assert!(partial.has_more());
        assert!(!PriceList::default().has_more());
    }

    #[test]
    fn camel_case_and_snake_case_amounts_are_the_same_row() {
        let camel: TldPrice =
            serde_json::from_str(r#"{"tld":"de","createPrice":8.9,"createPeriod":1}"#).unwrap();
        let snake: TldPrice =
            serde_json::from_str(r#"{"tld":"de","create_price":8.9,"create_period":1}"#).unwrap();
        let bare: TldPrice = serde_json::from_str(r#"{"tld":"de","create":8.9}"#).unwrap();
        assert_eq!(camel, snake);
        assert_eq!(camel.create, bare.create);
        assert_eq!(camel.create_period, Some(1));
    }

    #[test]
    fn a_price_that_is_neither_number_nor_numeric_string_is_none() {
        let good: TldPrice = serde_json::from_str(r#"{"createPrice":"8.90"}"#).unwrap();
        assert_eq!(good.create, Some(8.9));
        let bad: TldPrice = serde_json::from_str(r#"{"tld":"de","createPrice":"eight"}"#).unwrap();
        assert_eq!(bad.create, None);
        assert_eq!(bad.tld, "de");
        let wrong_type: PriceChange =
            serde_json::from_str(r#"{"createPrice":[1,2],"renewalPrice":{"a":1}}"#).unwrap();
        assert_eq!(wrong_type.create, None);
        assert_eq!(wrong_type.renewal, None);
    }

    #[test]
    fn unknown_fields_are_ignored_by_every_price_row() {
        let extra = r#","registryInternal":{"uuid":"x","flag":true}"#;
        assert!(serde_json::from_str::<TldPrice>(&format!(r#"{{"tld":"de"{extra}}}"#)).is_ok());
        assert!(serde_json::from_str::<ExtraDataRule>(r#""X_A=1""#).is_ok());
        assert!(serde_json::from_str::<PromoCode>(&format!(r#"{{"code":"X"{extra}}}"#)).is_ok());
        assert!(serde_json::from_str::<PriceChange>(&format!(r#"{{"tld":"de"{extra}}}"#)).is_ok());
    }

    #[test]
    fn unknown_text_fields_are_carried_not_rejected() {
        let rule: ExtraDataRule = serde_json::from_str(r#""X_UNKNOWN=value""#).unwrap();
        assert_eq!(rule.name(), Some("X_UNKNOWN"));
        assert_eq!(rule.value(), Some("value"));
        let change: PriceChange =
            serde_json::from_str(r#"{"affectsCustomer":"yes","changeDate":"2026-01-01"}"#).unwrap();
        assert_eq!(change.affects_customer, Some(true));
        assert_eq!(change.change_date.as_deref(), Some("2026-01-01"));
        let promo: PromoCode = serde_json::from_str(r#"{"tld":".DE","netPrice":"1.00"}"#).unwrap();
        assert_eq!(promo.normalised_tld().as_deref(), Some("de"));
        assert_eq!(promo.price, Some(1.0));
    }

    #[test]
    fn a_single_rule_string_counts_as_one_row() {
        let single = json!({"rules": "X_A=1"});
        let rows = parse_rule_rows(&single);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name(), Some("X_A"));
        assert_eq!(rows[0].value(), Some("1"));
    }

    #[test]
    fn an_empty_answer_is_no_rows_under_every_spelling() {
        let empty = json!({"promos": []});
        let rows: Vec<PromoCode> = parse_rows(&empty, "promos");
        assert_eq!(rows, Vec::<PromoCode>::new());
        let absent = json!({"somethingElse": 1});
        let rows: Vec<PriceChange> = parse_rows(&absent, "futureChanges");
        assert_eq!(rows, Vec::<PriceChange>::new());
    }

    #[test]
    fn a_price_change_carries_all_documented_amounts() {
        let change: PriceChange = serde_json::from_str(
            r#"{"createPrice":"13.90","monthlyCreatePrice":"1.16","transferPrice":12.5,
                "renewalPrice":"12.00","monthlyRenewalPrice":1.0,"updatePrice":0,
                "tradePrice":1,"trusteePrice":2,"monthlyTrusteePrice":"0.17",
                "restorePrice":100}"#,
        )
        .unwrap();
        assert_eq!(change.create, Some(13.9));
        assert_eq!(change.monthly_create, Some(1.16));
        assert_eq!(change.transfer, Some(12.5));
        assert_eq!(change.renewal, Some(12.0));
        assert_eq!(change.monthly_renewal, Some(1.0));
        assert_eq!(change.update, Some(0.0));
        assert_eq!(change.trade, Some(1.0));
        assert_eq!(change.trustee, Some(2.0));
        assert_eq!(change.monthly_trustee, Some(0.17));
        assert_eq!(change.restore, Some(100.0));
    }

    #[test]
    fn extra_data_rules_keep_their_raw_text() {
        let text = ExtraDataRule::from(" X_FN_VAT=DE123 ");
        assert_eq!(text.as_str(), " X_FN_VAT=DE123 ");
        assert_eq!(text.name(), Some("X_FN_VAT"));
        assert_eq!(text.value(), Some("DE123"));
        assert!(ExtraDataRule::from("  ").is_empty());
    }
}
