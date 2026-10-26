//! Hosting packages (`hosting.*`): ordering, listing, suspending and the
//! billing period.
//!
//! The package list carries more fields than any caller needs, and the API marks
//! almost all of them optional — they are modelled as `Option` rather than
//! defaulted, so "not reported" and "zero" stay distinguishable.
//!
//! ```
//! use inwx_client::HostingPeriod;
//!
//! assert_eq!(HostingPeriod::try_from(12u32)?.months(), 12);
//! assert!(HostingPeriod::try_from(9u32).is_err());
//! # Ok::<(), inwx_client::Error>(())
//! ```

use std::str::FromStr;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::de;

/// A billing period a hosting package can be moved to (`period`).
///
/// The documentation allows 1, 3, 6, 12, 18 and 24 months, "but not less than
/// the default for the product" — the lower bound is a product property the API
/// enforces, so only the set membership is checked here.
///
/// ```
/// use inwx_client::HostingPeriod;
///
/// assert_eq!(HostingPeriod::Months1.as_str(), "1");
/// assert_eq!("24".parse::<HostingPeriod>()?, HostingPeriod::Months24);
/// assert!("9".parse::<HostingPeriod>().is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostingPeriod {
    /// One month.
    Months1,
    /// Three months.
    Months3,
    /// Six months.
    Months6,
    /// Twelve months.
    Months12,
    /// Eighteen months.
    Months18,
    /// Twenty-four months.
    Months24,
}

impl HostingPeriod {
    /// The number of months.
    ///
    /// ```
    /// use inwx_client::HostingPeriod;
    /// assert_eq!(HostingPeriod::Months18.months(), 18);
    /// ```
    #[must_use]
    pub fn months(self) -> u32 {
        match self {
            Self::Months1 => 1,
            Self::Months3 => 3,
            Self::Months6 => 6,
            Self::Months12 => 12,
            Self::Months18 => 18,
            Self::Months24 => 24,
        }
    }

    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::HostingPeriod;
    /// assert_eq!(HostingPeriod::Months3.as_str(), "3");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Months1 => "1",
            Self::Months3 => "3",
            Self::Months6 => "6",
            Self::Months12 => "12",
            Self::Months18 => "18",
            Self::Months24 => "24",
        }
    }
}

impl TryFrom<u32> for HostingPeriod {
    type Error = Error;

    /// # Errors
    ///
    /// [`Error::Validation`] for a month count outside `{1, 3, 6, 12, 18, 24}`.
    ///
    /// ```
    /// use inwx_client::HostingPeriod;
    /// assert!(HostingPeriod::try_from(6u32).is_ok());
    /// assert!(HostingPeriod::try_from(2u32).is_err());
    /// ```
    fn try_from(months: u32) -> Result<Self> {
        Ok(match months {
            1 => Self::Months1,
            3 => Self::Months3,
            6 => Self::Months6,
            12 => Self::Months12,
            18 => Self::Months18,
            24 => Self::Months24,
            other => {
                return Err(Error::validation(
                    "hosting.period",
                    format!("{other} is not a billable period (1, 3, 6, 12, 18, 24 months)"),
                ));
            }
        })
    }
}

impl FromStr for HostingPeriod {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let months: u32 = input.trim().parse().map_err(|_| {
            Error::validation(
                "hosting.period",
                format!("{input:?} is not a number of months"),
            )
        })?;
        Self::try_from(months)
    }
}

impl std::fmt::Display for HostingPeriod {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl serde::Serialize for HostingPeriod {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// One hosting package, from `hosting.list` or `hosting.getPrices`.
///
/// ```
/// use inwx_client::HostingPackage;
///
/// let package: HostingPackage = serde_json::from_str(
///     r#"{"id":5,"product":"Hosting M","suspended":0,"product_id":17}"#,
/// )?;
/// assert_eq!(package.id, Some(5));
/// assert_eq!(package.is_suspended(), Some(false));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct HostingPackage {
    /// Package id, used by every other call.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Product name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub product: Option<String>,
    /// Cancellation date, when one is booked.
    #[serde(
        default,
        rename = "cancellationDate",
        deserialize_with = "de::opt_string"
    )]
    pub cancellation_date: Option<String>,
    /// Next cancellation date.
    #[serde(
        default,
        rename = "nextCancellationDate",
        deserialize_with = "de::opt_string"
    )]
    pub next_cancellation_date: Option<String>,
    /// Product id.
    #[serde(default, rename = "product_id", deserialize_with = "de::opt_i64")]
    pub product_id: Option<i64>,
    /// Product type.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub producttype: Option<String>,
    /// Server number.
    #[serde(default, rename = "serverNo", deserialize_with = "de::opt_i64")]
    pub server_no: Option<i64>,
    /// Server account number.
    #[serde(default, rename = "serverAccount", deserialize_with = "de::opt_i64")]
    pub server_account: Option<i64>,
    /// Server IP.
    #[serde(default, rename = "serverIP", deserialize_with = "de::opt_string")]
    pub server_ip: Option<String>,
    /// Server mail address.
    #[serde(default, rename = "serverMail", deserialize_with = "de::opt_string")]
    pub server_mail: Option<String>,
    /// Whether the package is suspended.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub suspended: Option<bool>,
    /// Webmail host.
    #[serde(default, rename = "webMail", deserialize_with = "de::opt_string")]
    pub web_mail: Option<String>,
    /// FTP host.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub ftp: Option<String>,
    /// SMTP host.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub smtp: Option<String>,
    /// Inbound SMTP hosts.
    #[serde(default, rename = "smtpIn0", deserialize_with = "de::opt_string")]
    pub smtp_in0: Option<String>,
    /// Second inbound SMTP host.
    #[serde(default, rename = "smtpIn1", deserialize_with = "de::opt_string")]
    pub smtp_in1: Option<String>,
    /// External IP of the package.
    #[serde(default, rename = "externIp", deserialize_with = "de::opt_string")]
    pub extern_ip: Option<String>,
    /// Port on the external IP.
    #[serde(default, rename = "externIpPort", deserialize_with = "de::opt_string")]
    pub extern_ip_port: Option<String>,
    /// IPv6 address.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub ipv6: Option<String>,
    /// Refund amount on cancellation.
    #[serde(
        default,
        rename = "cancellationRefund",
        deserialize_with = "de::opt_f64"
    )]
    pub cancellation_refund: Option<f64>,
    /// Current billing period in months.
    #[serde(default, rename = "executionPeriod", deserialize_with = "de::opt_i64")]
    pub execution_period: Option<i64>,
}

impl HostingPackage {
    /// Whether the API reports the package as suspended.
    ///
    /// ```
    /// use inwx_client::HostingPackage;
    ///
    /// let package: HostingPackage = serde_json::from_str(r#"{"id":1,"suspended":true}"#)?;
    /// assert_eq!(package.is_suspended(), Some(true));
    ///
    /// let unknown: HostingPackage = serde_json::from_str(r#"{"id":1}"#)?;
    /// assert_eq!(unknown.is_suspended(), None);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_suspended(&self) -> Option<bool> {
        self.suspended
    }
}

/// The suspension state of one package (`hosting.issuspended`).
///
/// ```
/// use inwx_client::HostingSuspension;
///
/// let state: HostingSuspension = serde_json::from_str(
///     r#"{"isSuspended":false,"paidUntil":"2027-01-01"}"#,
/// )?;
/// assert_eq!(state.suspended, Some(false));
/// assert_eq!(state.paid_until.as_deref(), Some("2027-01-01"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct HostingSuspension {
    /// Whether the package is suspended.
    #[serde(default, rename = "isSuspended", deserialize_with = "de::opt_bool")]
    pub suspended: Option<bool>,
    /// Cancellation time, when one is booked.
    #[serde(default, rename = "endDate", deserialize_with = "de::opt_string")]
    pub end_date: Option<String>,
    /// Paid-until date.
    #[serde(default, rename = "paidUntil", deserialize_with = "de::opt_string")]
    pub paid_until: Option<String>,
}

/// The prices charged when a suspended package is unsuspended
/// (`hosting.unsuspend`).
///
/// ```
/// use inwx_client::HostingReinstatement;
///
/// let answer: HostingReinstatement = serde_json::from_str(
///     r#"{"netPrice":5.0,"grossPrice":5.95,"currency":"EUR","quantity":1,"unit":"months"}"#,
/// )?;
/// assert_eq!(answer.gross_price, Some(5.95));
/// assert_eq!(answer.unit.as_deref(), Some("months"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct HostingReinstatement {
    /// Net price.
    #[serde(default, rename = "netPrice", deserialize_with = "de::opt_f64")]
    pub net_price: Option<f64>,
    /// Gross price.
    #[serde(default, rename = "grossPrice", deserialize_with = "de::opt_f64")]
    pub gross_price: Option<f64>,
    /// Currency of the prices.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// Quantity charged.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub quantity: Option<i64>,
    /// Unit of the quantity (`months` or `years`).
    #[serde(default, deserialize_with = "de::opt_string")]
    pub unit: Option<String>,
    /// System message.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub message: Option<String>,
}

/// An order for a hosting package (`hosting.create`).
///
/// The documentation lists `hostingId` and `productId` as alternatives and marks
/// both optional; ordering nothing is a guaranteed `2003`, so this type requires
/// exactly one of them.
///
/// ```
/// use inwx_client::HostingOrder;
///
/// let order = HostingOrder::product(17)?.dry_run();
/// assert_eq!(order.params()["productId"], "17");
/// assert_eq!(order.params()["testing"], true);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostingOrder {
    hosting_id: Option<i64>,
    product_id: Option<i64>,
    testing: bool,
}

impl HostingOrder {
    /// Orders an existing hosting id (an upgrade).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::HostingOrder;
    /// assert!(HostingOrder::existing(5).is_ok());
    /// assert!(HostingOrder::existing(0).is_err());
    /// ```
    pub fn existing(hosting_id: i64) -> Result<Self> {
        validate_id("hostingId", hosting_id)?;
        Ok(Self {
            hosting_id: Some(hosting_id),
            product_id: None,
            testing: false,
        })
    }

    /// Orders a new package by product id.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::HostingOrder;
    /// assert!(HostingOrder::product(17).is_ok());
    /// assert!(HostingOrder::product(-2).is_err());
    /// ```
    pub fn product(product_id: i64) -> Result<Self> {
        validate_id("productId", product_id)?;
        Ok(Self {
            hosting_id: None,
            product_id: Some(product_id),
            testing: false,
        })
    }

    /// Runs the order in testing mode (`testing=true`).
    ///
    /// ```
    /// use inwx_client::HostingOrder;
    /// assert_eq!(HostingOrder::product(17)?.dry_run().params()["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.testing = true;
        self
    }

    /// The `hosting.create` parameters.
    ///
    /// ```
    /// use inwx_client::HostingOrder;
    /// assert_eq!(HostingOrder::existing(5)?.params()["hostingId"], "5");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut params = serde_json::Map::new();
        if let Some(id) = self.hosting_id {
            params.insert("hostingId".to_owned(), json!(id.to_string()));
        }
        if let Some(id) = self.product_id {
            params.insert("productId".to_owned(), json!(id.to_string()));
        }
        params.insert("testing".to_owned(), json!(self.testing));
        Value::Object(params)
    }
}

/// Rejects a non-positive id.
fn validate_id(field: &'static str, id: i64) -> Result<()> {
    if id <= 0 {
        return Err(Error::validation(
            field,
            format!("must be a positive id, got {id}"),
        ));
    }
    Ok(())
}

impl<T: Transport> InwxClient<T> {
    /// Orders a hosting package (`hosting.create`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{HostingOrder, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.create_hosting(&HostingOrder::product(17)?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors — `2104` on a billing failure.
    pub async fn create_hosting(&self, order: &HostingOrder) -> Result<()> {
        self.call("hosting.create", order.params()).await?;
        Ok(())
    }

    /// Lists the account's hosting packages (`hosting.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for package in client.list_hosting().await? {
    ///     println!("{:?} {:?}", package.id, package.product);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn list_hosting(&self) -> Result<Vec<HostingPackage>> {
        let data = self.call("hosting.list", json!({})).await?;
        let entries = match data.get("hosting") {
            Some(Value::Array(entries)) => entries.clone(),
            _ => Vec::new(),
        };
        Ok(entries
            .into_iter()
            .filter_map(|entry| serde_json::from_value(entry).ok())
            .collect())
    }

    /// Lists hosting products with their prices (`hosting.getPrices`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for product in client.hosting_prices().await? {
    ///     println!("{:?} {:?}", product.id, product.product);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn hosting_prices(&self) -> Result<Vec<HostingPackage>> {
        let data = self.call("hosting.getPrices", json!({})).await?;
        let entries = match data.get("hosting") {
            Some(Value::Array(entries)) => entries.clone(),
            _ => Vec::new(),
        };
        Ok(entries
            .into_iter()
            .filter_map(|entry| serde_json::from_value(entry).ok())
            .collect())
    }

    /// Checks whether a package is suspended (`hosting.issuspended`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let state = client.hosting_suspended(5).await?;
    /// println!("{:?}", state.suspended);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn hosting_suspended(&self, hosting_id: i64) -> Result<HostingSuspension> {
        validate_id("hostingId", hosting_id)?;
        let data = self
            .call("hosting.issuspended", json!({ "hostingId": hosting_id }))
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Returns the control-panel URL of a package (`hosting.controlPanel`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// println!("{}", client.hosting_control_panel(5).await?);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, [`Error::MissingField`] when
    /// the answer carries no `url`, plus the usual transport and API errors.
    pub async fn hosting_control_panel(&self, hosting_id: i64) -> Result<String> {
        validate_id("hostingId", hosting_id)?;
        let data = self
            .call("hosting.controlPanel", json!({ "id": hosting_id }))
            .await?;
        data.get("url")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or(Error::MissingField {
                method: "hosting.controlPanel",
                field: "resData.url",
            })
    }

    /// Cancels a package (`hosting.cancel`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.cancel_hosting(5).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn cancel_hosting(&self, hosting_id: i64) -> Result<()> {
        validate_id("hostingId", hosting_id)?;
        self.call(
            "hosting.cancel",
            json!({ "hostingId": hosting_id.to_string() }),
        )
        .await?;
        Ok(())
    }

    /// Withdraws a cancellation (`hosting.reinstate`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.reinstate_hosting(5).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn reinstate_hosting(&self, hosting_id: i64) -> Result<()> {
        validate_id("hostingId", hosting_id)?;
        self.call(
            "hosting.reinstate",
            json!({ "hostingId": hosting_id.to_string() }),
        )
        .await?;
        Ok(())
    }

    /// Unsuspends a suspended package (`hosting.unsuspend`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let charged = client.unsuspend_hosting(5).await?;
    /// println!("{:?} {:?}", charged.gross_price, charged.currency);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn unsuspend_hosting(&self, hosting_id: i64) -> Result<HostingReinstatement> {
        validate_id("hostingId", hosting_id)?;
        let data = self
            .call("hosting.unsuspend", json!({ "hostingId": hosting_id }))
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Changes the billing period (`hosting.updatePeriod`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{HostingPeriod, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client
    ///     .update_hosting_period(5, HostingPeriod::Months12)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn update_hosting_period(
        &self,
        hosting_id: i64,
        period: HostingPeriod,
    ) -> Result<()> {
        validate_id("hostingId", hosting_id)?;
        self.call(
            "hosting.updatePeriod",
            json!({ "hostingId": hosting_id, "period": period.months() }),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_documented_periods_exist() {
        for months in [1, 3, 6, 12, 18, 24] {
            assert_eq!(HostingPeriod::try_from(months).unwrap().months(), months);
        }
        for months in [0, 2, 5, 25] {
            assert!(HostingPeriod::try_from(months).is_err());
        }
    }

    #[test]
    fn orders_carry_exactly_one_id() {
        let params = HostingOrder::product(17).unwrap().params();
        assert!(params.get("hostingId").is_none());
        assert_eq!(params["productId"], "17");

        let params = HostingOrder::existing(5).unwrap().params();
        assert_eq!(params["hostingId"], "5");
        assert!(params.get("productId").is_none());
    }

    #[test]
    fn suspension_parses_permissively() {
        let state: HostingSuspension = serde_json::from_str(r#"{"isSuspended":"1"}"#).unwrap();
        assert_eq!(state.suspended, Some(true));
        assert!(state.end_date.is_none());
    }

    #[test]
    fn package_fields_stay_optional() {
        let package: HostingPackage = serde_json::from_str(r#"{"id":"5"}"#).unwrap();
        assert_eq!(package.id, Some(5));
        assert!(package.product.is_none());
        assert_eq!(package.is_suspended(), None);
    }
}
