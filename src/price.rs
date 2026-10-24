//! Prices (`domain.getPrices`, `domain.getalldomainprices`,
//! `domain.getdomainprice`).
//!
//! Prices are `float` on the wire and are kept as `f64` here: they are quotes to
//! display and compare, not amounts to sum. For anything that charges money, use
//! the amount the API returns from the actual `create`/`renew` call.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, DomainName, Period, PriceType};

/// One TLD's price list, from `domain.getPrices`.
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
    #[serde(default, rename = "createPrice", deserialize_with = "de::opt_f64")]
    pub create: Option<f64>,
    /// Transfer price per year.
    #[serde(default, rename = "transferPrice", deserialize_with = "de::opt_f64")]
    pub transfer: Option<f64>,
    /// Renewal price per year.
    #[serde(default, rename = "renewalPrice", deserialize_with = "de::opt_f64")]
    pub renewal: Option<f64>,
    /// Update price.
    #[serde(default, rename = "updatePrice", deserialize_with = "de::opt_f64")]
    pub update: Option<f64>,
    /// Owner change price.
    #[serde(default, rename = "tradePrice", deserialize_with = "de::opt_f64")]
    pub trade: Option<f64>,
    /// Trustee service price per year.
    #[serde(default, rename = "trusteePrice", deserialize_with = "de::opt_f64")]
    pub trustee: Option<f64>,
    /// Minimum registration period in years.
    #[serde(default, rename = "createPeriod", deserialize_with = "de::opt_i64")]
    pub create_period: Option<i64>,
    /// Minimum transfer period in years.
    #[serde(default, rename = "transferPeriod", deserialize_with = "de::opt_i64")]
    pub transfer_period: Option<i64>,
    /// Minimum renewal period in years.
    #[serde(default, rename = "renewalPeriod", deserialize_with = "de::opt_i64")]
    pub renewal_period: Option<i64>,
    /// Applied VAT rate, when `vat` was requested.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub vat: Option<f64>,
}

/// The answer to `domain.getPrices`.
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
    #[serde(default, rename = "price")]
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
        let tlds = tlds
            .iter()
            .map(|tld| tld.trim().trim_start_matches('.').to_ascii_lowercase())
            .filter(|tld| !tld.is_empty())
            .collect::<Vec<_>>();
        let params = if tlds.is_empty() {
            json!({})
        } else {
            json!({ "tld": tlds })
        };
        let data = self.call("domain.getPrices", params).await?;
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
}
