//! Prices: `domain.getPrices`, `domain.getalldomainprices`,
//! `domain.getdomainprice`, `domain.getextradatarules`, `domain.getpromos` and
//! `domain.pricechanges`.
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
use serde_json::{json, Value};
use std::cmp::Ordering;

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, parse_rows, validate_page_limit, DomainName, Period, PriceType};

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
    #[serde(default)]
    pub tld: String,
    /// Currency of every amount in this entry.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// Registration price per year.
    #[serde(
        default,
        rename = "createPrice",
        alias = "create_price",
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
    /// entries to `count`. Only `domain.getalldomainprices` pages, so only that
    /// answer carries a `count` that can make this true.
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

/// The typed view of an order-type field: `None` for a value this crate does
/// not know — which is why the raw text stays on the struct next to it.
fn typed_order(raw: Option<&str>) -> Option<PriceType> {
    raw.and_then(|raw| raw.parse().ok())
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

/// Rows of a list answer whose key the documentation does not settle: the first
/// candidate that carries rows wins, and an empty answer is empty under every
/// spelling.
fn parse_any_rows<T: serde::de::DeserializeOwned>(data: &Value, keys: &[&str]) -> Vec<T> {
    keys.iter()
        .find_map(|key| {
            let rows = parse_rows::<T>(data, key);
            if rows.is_empty() {
                None
            } else {
                Some(rows)
            }
        })
        .unwrap_or_default()
}

/// Extra data an order for a TLD has to carry
/// (`domain.getextradatarules`).
///
/// These are the registry-specific fields — a membership number, a VAT ID, a
/// trade register entry — that `domain.create` and `domain.update` must send
/// besides the contact handles. [`ExtraDataRule::required`] says which of them
/// the order is refused without.
///
/// ```
/// use inwx_client::{ExtraDataRule, PriceType};
///
/// let rule: ExtraDataRule = serde_json::from_str(
///     r#"{"tld":"de","key":"X_FN_INDUSTRY","label":"Industry","type":"select",
///         "required":1,"orderType":"reg","values":["retail","craft"],"pattern":"^.{2,}$"}"#,
/// )?;
/// assert_eq!(rule.key.as_deref(), Some("X_FN_INDUSTRY"));
/// assert_eq!(rule.required, Some(true));
/// assert_eq!(rule.field_type.as_deref(), Some("select"));
/// assert_eq!(rule.price_type(), Some(PriceType::Reg));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct ExtraDataRule {
    /// TLD the rule belongs to.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub tld: Option<String>,
    /// Field handle, exactly as `domain.create` must send it.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub key: Option<String>,
    /// Label to show the customer.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub label: Option<String>,
    /// Longer description of what the field is for.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub description: Option<String>,
    /// Whether the order fails without this field.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub required: Option<bool>,
    /// Control type: `text`, `select`, `checkbox`, …
    #[serde(
        default,
        rename = "type",
        alias = "fieldType",
        alias = "field_type",
        deserialize_with = "de::opt_string"
    )]
    pub field_type: Option<String>,
    /// Fixed values, for a `select` rule.
    #[serde(default, deserialize_with = "de::vec_string")]
    pub values: Vec<String>,
    /// Pre-filled value, when the registry ships one.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub default: Option<String>,
    /// Regular expression the value has to match.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub pattern: Option<String>,
    /// Order the rule applies to, as it arrived; `reg`, `renewal`, … or a
    /// spelling this crate does not know.
    #[serde(
        default,
        rename = "orderType",
        alias = "order_type",
        alias = "order",
        alias = "pricetype",
        deserialize_with = "de::opt_string"
    )]
    pub order_type: Option<String>,
    /// Billing period the rule is quoted for, in years.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub period: Option<i64>,
}

impl ExtraDataRule {
    /// [`Self::order_type`] as a [`PriceType`], or `None` for a value this
    /// crate does not know — the raw text stays in `order_type` either way.
    ///
    /// ```
    /// use inwx_client::{ExtraDataRule, PriceType};
    ///
    /// let known: ExtraDataRule = serde_json::from_str(r#"{"orderType":"TRANSFER"}"#)?;
    /// assert_eq!(known.price_type(), Some(PriceType::Transfer));
    /// let unknown: ExtraDataRule = serde_json::from_str(r#"{"orderType":"refund"}"#)?;
    /// assert_eq!(unknown.price_type(), None);
    /// assert_eq!(unknown.order_type.as_deref(), Some("refund"));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn price_type(&self) -> Option<PriceType> {
        typed_order(self.order_type.as_deref())
    }

    /// Whether the rule is one of the free-text kind, which is the common case
    /// and the one that needs a `pattern` check before submitting.
    ///
    /// ```
    /// use inwx_client::ExtraDataRule;
    ///
    /// let text: ExtraDataRule = serde_json::from_str(r#"{"type":"text"}"#)?;
    /// assert!(text.is_text());
    /// let select: ExtraDataRule = serde_json::from_str(r#"{"type":"select"}"#)?;
    /// assert!(!select.is_text());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_text(&self) -> bool {
        self.field_type
            .as_deref()
            .is_some_and(|kind| kind.eq_ignore_ascii_case("text"))
    }
}

/// A promo or voucher code (`domain.getpromos`).
///
/// ```
/// use inwx_client::PromoCode;
///
/// let promo: PromoCode = serde_json::from_str(
///     r#"{"code":"SPRING26","description":".de for one euro","price":"1.00",
///         "currency":"EUR","tld":["de","eu"],"validFrom":"2026-01-01",
///         "validUntil":"2026-03-31","period":1}"#,
/// )?;
/// assert_eq!(promo.code.as_deref(), Some("SPRING26"));
/// assert_eq!(promo.price, Some(1.0));
/// assert_eq!(promo.tlds.len(), 2);
/// assert_eq!(promo.valid_until.as_deref(), Some("2026-03-31"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct PromoCode {
    /// The code, as it is passed to an order.
    #[serde(
        default,
        rename = "promoCode",
        alias = "promo_code",
        alias = "code",
        deserialize_with = "de::opt_string"
    )]
    pub code: Option<String>,
    /// What the promo is worth, in words.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub description: Option<String>,
    /// Fixed price the code sets, when it sets one.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub price: Option<f64>,
    /// Discount share, when the code is a percentage instead.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub discount: Option<f64>,
    /// Currency of `price`.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// TLDs the code can be spent on.
    #[serde(
        default,
        rename = "tld",
        alias = "tlds",
        deserialize_with = "de::vec_string"
    )]
    pub tlds: Vec<String>,
    /// First day it is valid, as text.
    #[serde(
        default,
        rename = "validFrom",
        alias = "valid_from",
        deserialize_with = "de::opt_string"
    )]
    pub valid_from: Option<String>,
    /// Last day it is valid, as text.
    #[serde(
        default,
        rename = "validUntil",
        alias = "valid_until",
        deserialize_with = "de::opt_string"
    )]
    pub valid_until: Option<String>,
    /// Order the code applies to, as it arrived.
    #[serde(
        default,
        rename = "orderType",
        alias = "order_type",
        alias = "order",
        alias = "pricetype",
        deserialize_with = "de::opt_string"
    )]
    pub order_type: Option<String>,
    /// Number of years the code covers.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub period: Option<i64>,
}

impl PromoCode {
    /// [`Self::order_type`] as a [`PriceType`], or `None` for a value this
    /// crate does not know.
    ///
    /// ```
    /// use inwx_client::{PriceType, PromoCode};
    ///
    /// let promo: PromoCode = serde_json::from_str(r#"{"orderType":"renewal"}"#)?;
    /// assert_eq!(promo.price_type(), Some(PriceType::Renewal));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn price_type(&self) -> Option<PriceType> {
        typed_order(self.order_type.as_deref())
    }
}

/// A scheduled price change (`domain.pricechanges`).
///
/// A quote from `domain.getPrices` goes stale on the day in
/// [`Self::effective`]; this is what tells a caller that it will.
///
/// ```
/// use inwx_client::{PriceChange, PriceType};
///
/// let change: PriceChange = serde_json::from_str(
///     r#"{"tld":"com","type":"renewal","period":1,"price":"13.90","oldPrice":12.5,
///         "currency":"EUR","startDate":"2026-01-01"}"#,
/// )?;
/// assert_eq!(change.price, Some(13.9));
/// assert_eq!(change.old_price, Some(12.5));
/// assert_eq!(change.effective.as_deref(), Some("2026-01-01"));
/// assert_eq!(change.price_type(), Some(PriceType::Renewal));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct PriceChange {
    /// TLD whose price changes.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub tld: Option<String>,
    /// Order the change applies to, as it arrived.
    #[serde(
        default,
        rename = "type",
        alias = "action",
        alias = "orderType",
        alias = "order_type",
        alias = "pricetype",
        deserialize_with = "de::opt_string"
    )]
    pub action: Option<String>,
    /// Billing period in years.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub period: Option<i64>,
    /// The new amount.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub price: Option<f64>,
    /// The amount before the change.
    #[serde(
        default,
        rename = "oldPrice",
        alias = "old_price",
        deserialize_with = "de::opt_f64"
    )]
    pub old_price: Option<f64>,
    /// Currency of both amounts.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// First day the new price is billed, as text.
    #[serde(
        default,
        rename = "effective",
        alias = "date",
        alias = "startDate",
        alias = "start_date",
        deserialize_with = "de::opt_string"
    )]
    pub effective: Option<String>,
}

impl PriceChange {
    /// [`Self::action`] as a [`PriceType`], or `None` for a value this crate
    /// does not know.
    ///
    /// ```
    /// use inwx_client::{PriceChange, PriceType};
    ///
    /// let known: PriceChange = serde_json::from_str(r#"{"type":"trade"}"#)?;
    /// assert_eq!(known.price_type(), Some(PriceType::Trade));
    /// let unknown: PriceChange = serde_json::from_str(r#"{"type":"restoreFee"}"#)?;
    /// assert_eq!(unknown.price_type(), None);
    /// assert_eq!(unknown.action.as_deref(), Some("restoreFee"));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn price_type(&self) -> Option<PriceType> {
        typed_order(self.action.as_deref())
    }

    /// Direction of the change, from the two amounts. `None` when either
    /// amount is missing, when they are the same, or when one of them is not a
    /// number at all.
    ///
    /// ```
    /// use inwx_client::PriceChange;
    ///
    /// let up: PriceChange = serde_json::from_str(r#"{"price":13.9,"oldPrice":12.5}"#)?;
    /// assert_eq!(up.is_increase(), Some(true));
    /// let down: PriceChange = serde_json::from_str(r#"{"price":"11.00","oldPrice":12.5}"#)?;
    /// assert_eq!(down.is_increase(), Some(false));
    /// let unclear: PriceChange = serde_json::from_str(r#"{"price":13.9}"#)?;
    /// assert_eq!(unclear.is_increase(), None);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_increase(&self) -> Option<bool> {
        let (Some(price), Some(old)) = (self.price, self.old_price) else {
            return None;
        };
        match price.partial_cmp(&old) {
            Some(Ordering::Greater) => Some(true),
            Some(Ordering::Less) => Some(false),
            Some(Ordering::Equal) | None => None,
        }
    }
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

    /// The whole TLD price table in one call (`domain.getalldomainprices`).
    ///
    /// Unlike [`InwxClient::tld_prices`] this is paged: `count` in the answer is
    /// the size of the entire table, so [`PriceList::has_more`] says whether
    /// another page has to be asked for. Passing no TLDs asks for every TLD the
    /// account can order.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let mut page = 1;
    /// loop {
    ///     let prices = client.all_domain_prices(&[".de", ".com"], page, 250).await?;
    ///     println!("{} entries on this page", prices.len());
    ///     if !prices.has_more() {
    ///         break;
    ///     }
    ///     page += 1;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the page size is zero, plus the usual transport
    /// and API errors.
    pub async fn all_domain_prices(
        &self,
        tlds: &[&str],
        page: u32,
        limit: u32,
    ) -> Result<PriceList> {
        let limit = validate_page_limit(limit)?;
        let mut params = json!({ "page": page.max(1), "pagelimit": limit });
        let tlds = normalise_tlds(tlds);
        if !tlds.is_empty() {
            params["tld"] = json!(tlds);
        }
        let data = self.call("domain.getalldomainprices", params).await?;
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
        let mut params = json!({
            "domain": [domain.as_str()],
            "pricetype": price_type.as_str(),
        });
        if let Some(period) = period {
            params["period"] = json!(period);
        }
        let data = self.call("domain.getdomainprice", params).await?;
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
    /// These are the registry-specific fields (`domain.create` sends them
    /// besides the contact handles); pass the TLD you are about to order.
    /// `tld: None` asks for every rule the account has, `order` narrows the
    /// answer to one order type.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, PriceType, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let rules = client
    ///         .extra_data_rules(Some(".de"), Some(PriceType::Reg))
    ///         .await?;
    /// for rule in rules.iter().filter(|rule| rule.required == Some(true)) {
    ///     println!("{} ({:?})", rule.key.clone().unwrap_or_default(), rule.pattern);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `tld` is `Some` but blank, plus the usual
    /// transport and API errors.
    pub async fn extra_data_rules(
        &self,
        tld: Option<&str>,
        order: Option<PriceType>,
    ) -> Result<Vec<ExtraDataRule>> {
        let mut params = json!({});
        if let Some(tld) = normalise_tld(tld)? {
            params["tld"] = json!(tld);
        }
        if let Some(order) = order {
            params["pricetype"] = json!(order.as_str());
        }
        let data = self.call("domain.getextradatarules", params).await?;
        Ok(parse_any_rows(
            &data,
            &["extradata", "extradataRules", "rules"],
        ))
    }

    /// The promo and voucher codes the account can spend (`domain.getpromos`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for promo in client.promo_codes(Some("de"), 1, 50).await? {
    ///     println!(
    ///         "{}: {:?} {}",
    ///         promo.code.clone().unwrap_or_default(),
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
    /// [`Error::Validation`] when the page size is zero or `tld` is `Some` but
    /// blank, plus the usual transport and API errors.
    pub async fn promo_codes(
        &self,
        tld: Option<&str>,
        page: u32,
        limit: u32,
    ) -> Result<Vec<PromoCode>> {
        let limit = validate_page_limit(limit)?;
        let mut params = json!({ "page": page.max(1), "pagelimit": limit });
        if let Some(tld) = normalise_tld(tld)? {
            params["tld"] = json!(tld);
        }
        let data = self.call("domain.getpromos", params).await?;
        Ok(parse_any_rows(&data, &["promo", "promos"]))
    }

    /// The price changes that are already scheduled
    /// (`domain.pricechanges`).
    ///
    /// A quote from [`InwxClient::tld_prices`] is only trustworthy until the
    /// `effective` date of a change for the same TLD and order.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for change in client.price_changes(Some("com"), 1, 50).await? {
    ///     if change.is_increase() == Some(true) {
    ///         println!("{:?} rises on {:?}", change.tld, change.effective);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the page size is zero or `tld` is `Some` but
    /// blank, plus the usual transport and API errors.
    pub async fn price_changes(
        &self,
        tld: Option<&str>,
        page: u32,
        limit: u32,
    ) -> Result<Vec<PriceChange>> {
        let limit = validate_page_limit(limit)?;
        let mut params = json!({ "page": page.max(1), "pagelimit": limit });
        if let Some(tld) = normalise_tld(tld)? {
            params["tld"] = json!(tld);
        }
        let data = self.call("domain.pricechanges", params).await?;
        Ok(parse_any_rows(&data, &["pricechange", "pricechanges"]))
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
    fn a_page_size_of_one_is_the_last_valid_one() {
        assert_eq!(validate_page_limit(1).unwrap(), 1);
        assert_eq!(validate_page_limit(u32::MAX).unwrap(), u32::MAX);
        assert!(validate_page_limit(0).is_err());
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
            serde_json::from_str(r#"{"price":[1,2],"oldPrice":{"a":1}}"#).unwrap();
        assert_eq!(wrong_type.price, None);
        assert_eq!(wrong_type.old_price, None);
    }

    #[test]
    fn unknown_fields_are_ignored_by_every_price_row() {
        let extra = r#","registryInternal":{"uuid":"x","flag":true}"#;
        assert!(serde_json::from_str::<TldPrice>(&format!(r#"{{"tld":"de"{extra}}}"#)).is_ok());
        assert!(
            serde_json::from_str::<ExtraDataRule>(&format!(r#"{{"key":"X_A"{extra}}}"#)).is_ok()
        );
        assert!(serde_json::from_str::<PromoCode>(&format!(r#"{{"code":"X"{extra}}}"#)).is_ok());
        assert!(serde_json::from_str::<PriceChange>(&format!(r#"{{"tld":"de"{extra}}}"#)).is_ok());
    }

    #[test]
    fn an_unknown_order_type_is_carried_not_rejected() {
        let rule: ExtraDataRule = serde_json::from_str(r#"{"orderType":"refund"}"#).unwrap();
        assert_eq!(rule.order_type.as_deref(), Some("refund"));
        assert_eq!(rule.price_type(), None);
        let change: PriceChange = serde_json::from_str(r#"{"action":"RESTORE"}"#).unwrap();
        assert_eq!(change.price_type(), Some(PriceType::Restore));
        let promo: PromoCode = serde_json::from_str(r#"{"order":"renewal"}"#).unwrap();
        assert_eq!(promo.price_type(), Some(PriceType::Renewal));
    }

    #[test]
    fn a_single_object_answer_counts_as_one_row() {
        let single = json!({"extradata": {"key": "X_A", "required": "1"}});
        let rows: Vec<ExtraDataRule> = parse_any_rows(&single, &["extradata", "rules"]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].required, Some(true));
    }

    #[test]
    fn an_empty_answer_is_no_rows_under_every_spelling() {
        let empty = json!({"promo": [], "promos": []});
        let rows: Vec<PromoCode> = parse_any_rows(&empty, &["promo", "promos"]);
        assert_eq!(rows, Vec::<PromoCode>::new());
        let absent = json!({"somethingElse": 1});
        let rows: Vec<PriceChange> = parse_any_rows(&absent, &["pricechange", "pricechanges"]);
        assert_eq!(rows, Vec::<PriceChange>::new());
    }

    #[test]
    fn a_scheduled_change_compares_its_two_amounts() {
        let up: PriceChange = serde_json::from_str(r#"{"price":"13.90","oldPrice":12.5}"#).unwrap();
        assert_eq!(up.is_increase(), Some(true));
        let flat: PriceChange =
            serde_json::from_str(r#"{"price":12.5,"oldPrice":"12.50"}"#).unwrap();
        assert_eq!(flat.is_increase(), None);
        assert_eq!(PriceChange::default().is_increase(), None);
    }

    #[test]
    fn a_text_rule_is_only_text_when_the_api_says_so() {
        let text: ExtraDataRule = serde_json::from_str(r#"{"fieldType":"TEXT"}"#).unwrap();
        assert!(text.is_text());
        let select: ExtraDataRule =
            serde_json::from_str(r#"{"type":"select","values":"retail"}"#).unwrap();
        assert!(!select.is_text());
        assert_eq!(select.values, ["retail"]);
    }
}
