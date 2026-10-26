//! DynDNS subscriptions (`dyndnssubscription.*`): the plans that bundle DynDNS
//! accounts.
//!
//! Four methods, all small: order a plan, cancel one, list the account's
//! subscriptions and list the purchasable plans. Ordering and cancelling spend
//! money, so both take an identifier and neither guesses: the plan id for an
//! order, the subscription id for a cancellation.
//!
//! ```
//! use inwx_client::DynDnsSubscription;
//!
//! let plan: DynDnsSubscription = serde_json::from_str(
//!     r#"{"id":4,"name":"DynDNS 5","accountsAmount":5,"price":9.9,"currency":"EUR"}"#,
//! )?;
//! assert_eq!(plan.accounts_amount, Some(5));
//! assert_eq!(plan.name.as_deref(), Some("DynDNS 5"));
//! # Ok::<(), serde_json::Error>(())
//! ```

use serde::Deserialize;
use serde_json::{json, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::de;

/// A DynDNS subscription or plan (`dyndnssubscription.list`, `listProducts`).
///
/// ```
/// use inwx_client::DynDnsSubscription;
///
/// let subscription: DynDnsSubscription = serde_json::from_str(
///     r#"{"id":7,"name":"DynDNS 5","accountsAmount":5,"price":9.9,"currency":"EUR",
///         "createdAt":"2026-01-01T10:00:00","paidUntil":"2027-01-01T00:00:00"}"#,
/// )?;
/// assert_eq!(subscription.id, Some(7));
/// assert_eq!(subscription.paid_until.as_deref(), Some("2027-01-01T00:00:00"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct DynDnsSubscription {
    /// Subscription (or plan) id.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Name of the subscription.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// Number of DynDNS accounts the plan includes.
    #[serde(default, rename = "accountsAmount", deserialize_with = "de::opt_i64")]
    pub accounts_amount: Option<i64>,
    /// Price for one year, without VAT.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub price: Option<f64>,
    /// Currency of `price`.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// Creation date.
    #[serde(default, rename = "createdAt", deserialize_with = "de::opt_string")]
    pub created_at: Option<String>,
    /// Date of the last payment.
    #[serde(default, rename = "lastPaymentAt", deserialize_with = "de::opt_string")]
    pub last_payment_at: Option<String>,
    /// Expiry date.
    #[serde(default, rename = "paidUntil", deserialize_with = "de::opt_string")]
    pub paid_until: Option<String>,
}

/// Rejects a non-positive id.
fn validate_id(field: &'static str, id: i64) -> Result<i64> {
    if id <= 0 {
        return Err(Error::validation(
            field,
            format!("must be a positive id, got {id}"),
        ));
    }
    Ok(id)
}

impl<T: Transport> InwxClient<T> {
    /// Orders a DynDNS subscription (`dyndnssubscription.create`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.create_dyndns_subscription(4).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive plan id, plus the usual transport
    /// and API errors — `2104` on a billing failure.
    pub async fn create_dyndns_subscription(&self, plan_id: i64) -> Result<()> {
        let plan_id = validate_id("dyndnssubscription.id", plan_id)?;
        self.call("dyndnssubscription.create", json!({ "id": plan_id }))
            .await?;
        Ok(())
    }

    /// Cancels a DynDNS subscription (`dyndnssubscription.cancel`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.cancel_dyndns_subscription(7).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive subscription id, plus the usual
    /// transport and API errors.
    pub async fn cancel_dyndns_subscription(&self, subscription_id: i64) -> Result<()> {
        let subscription_id = validate_id("dyndnssubscription.id", subscription_id)?;
        self.call(
            "dyndnssubscription.cancel",
            json!({ "id": subscription_id }),
        )
        .await?;
        Ok(())
    }

    /// Lists the account's active subscriptions (`dyndnssubscription.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for subscription in client.list_dyndns_subscriptions(1, 20).await? {
    ///     println!("{:?} {:?}", subscription.id, subscription.paid_until);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the page limit is zero, plus the usual
    /// transport and API errors.
    pub async fn list_dyndns_subscriptions(
        &self,
        page: u32,
        limit: u32,
    ) -> Result<Vec<DynDnsSubscription>> {
        self.dyndns_subscriptions("dyndnssubscription.list", page, limit)
            .await
    }

    /// Lists the purchasable DynDNS plans (`dyndnssubscription.listProducts`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for plan in client.list_dyndns_subscription_products(1, 20).await? {
    ///     println!("{:?} {:?}", plan.id, plan.price);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::validation`] when the page limit is zero, plus the usual
    /// transport and API errors.
    pub async fn list_dyndns_subscription_products(
        &self,
        page: u32,
        limit: u32,
    ) -> Result<Vec<DynDnsSubscription>> {
        self.dyndns_subscriptions("dyndnssubscription.listProducts", page, limit)
            .await
    }

    /// Both listing methods share the same paging and `subscription[]` answer.
    async fn dyndns_subscriptions(
        &self,
        method: &str,
        page: u32,
        limit: u32,
    ) -> Result<Vec<DynDnsSubscription>> {
        if limit == 0 {
            return Err(Error::validation("pagelimit", "must be at least 1"));
        }
        let data = self
            .call(method, json!({ "page": page.max(1), "pagelimit": limit }))
            .await?;
        let entries = match data.get("subscription") {
            Some(Value::Array(entries)) => entries.clone(),
            Some(single @ Value::Object(_)) => vec![single.clone()],
            _ => Vec::new(),
        };
        Ok(entries
            .into_iter()
            .filter_map(|entry| serde_json::from_value(entry).ok())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_subscription_tolerates_missing_fields() {
        let subscription: DynDnsSubscription = serde_json::from_str(r#"{"id":"7"}"#).unwrap();
        assert_eq!(subscription.id, Some(7));
        assert!(subscription.price.is_none());
        assert_eq!(subscription, subscription.clone());
    }

    #[test]
    fn ids_must_be_positive() {
        assert!(validate_id("id", 1).is_ok());
        assert!(validate_id("id", 0).is_err());
        assert!(validate_id("id", -2).is_err());
    }
}
