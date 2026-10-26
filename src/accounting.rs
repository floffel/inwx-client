//! Accounting (`accounting.*`): balance, invoices, statements and refunds.
//!
//! Everything that returns a document returns it base64-encoded in a `pdf` (or
//! `raw`) field, so [`Document::pdf_bytes`] decodes it with the `base64` crate
//! instead of leaving every caller to re-implement that.
//!
//! ```
//! use inwx_client::Document;
//!
//! let document: Document = Document::parse(r#"{"pdf":"JVBERi0xLjQK"}"#)?;
//! assert_eq!(&document.pdf_bytes()?[..5], b"%PDF-");
//! assert!(document.is_pdf());
//! # Ok::<(), inwx_client::Error>(())
//! ```
//!
//! # Money is irreversible
//!
//! [`InwxClient::refund`] moves money out of the account balance. It takes an
//! [`Irreversible`] acknowledgement naming [`ActionKind::Refund`], so a refund
//! cannot be constructed by accident — the same guard the ownership commands
//! use.

use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transfer::{ActionKind, Irreversible};
use crate::transport::Transport;
use crate::types::{de, validate_text, validate_token, DocumentFormat, Timestamp};

/// A document returned by the API (`pdf` base64 or `raw` text).
///
/// ```
/// use inwx_client::Document;
///
/// let document: Document = Document::parse(r#"{"raw":"statement"}"#)?;
/// assert!(!document.is_pdf());
/// assert_eq!(document.raw.as_deref(), Some("statement"));
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Document {
    /// Base64-encoded PDF.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub pdf: Option<String>,
    /// Raw text, when the request asked for a text format.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub raw: Option<String>,
}

impl Document {
    /// Parses a `resData` document payload.
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the payload is not an object with the expected
    /// fields.
    ///
    /// ```
    /// use inwx_client::Document;
    ///
    /// assert!(Document::parse(r#"{"pdf":"JVBERi0="}"#).is_ok());
    /// assert!(Document::parse("[]").is_err());
    /// ```
    pub fn parse(body: &str) -> Result<Self> {
        // A struct deserialises from a JSON *array* positionally, which would
        // turn `[]` into "no document" instead of an error.
        let value: Value = serde_json::from_str(body).map_err(Error::from)?;
        if !value.is_object() {
            return Err(Error::validation("document", "expected a JSON object"));
        }
        serde_json::from_value(value).map_err(Error::from)
    }

    /// Whether the payload is a PDF.
    ///
    /// ```
    /// use inwx_client::Document;
    /// assert!(Document::parse(r#"{"pdf":"JVBERi0="}"#)?.is_pdf());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn is_pdf(&self) -> bool {
        self.pdf.is_some()
    }

    /// The decoded PDF bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the document carries no `pdf` field, and
    /// [`Error::Validation`] when the value is not valid base64 (a truncated
    /// transfer would otherwise be saved as a corrupt file).
    ///
    /// ```
    /// use inwx_client::Document;
    ///
    /// let document: Document = Document::parse(r#"{"pdf":"JVBERi0xLjQK"}"#)?;
    /// assert_eq!(document.pdf_bytes()?.len(), 9);
    ///
    /// let broken: Document = Document::parse(r#"{"pdf":"!!!"}"#)?;
    /// assert!(broken.pdf_bytes().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn pdf_bytes(&self) -> Result<Vec<u8>> {
        let encoded = self.pdf.as_deref().ok_or_else(|| {
            Error::validation("document.pdf", "the answer carries no pdf document")
        })?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|error| {
                Error::validation("document.pdf", format!("is not valid base64: {error}"))
            })
    }
}

/// The account balance (`accounting.accountBalance`).
///
/// ```
/// use inwx_client::AccountBalance;
///
/// let balance: AccountBalance = serde_json::from_str(
///     r#"{"total":250.0,"available":190.5,"locked":59.5,"creditLimit":0}"#,
/// )?;
/// assert_eq!(balance.available, Some(190.5));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct AccountBalance {
    /// Accumulated received payments.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub total: Option<f64>,
    /// Deposit available for transactions.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub available: Option<f64>,
    /// Deposit locked by transactions in progress.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub locked: Option<f64>,
    /// The account's credit limit.
    #[serde(default, rename = "creditLimit", deserialize_with = "de::opt_f64")]
    pub credit_limit: Option<f64>,
}

/// One credit log entry (`accounting.creditLogById`).
///
/// ```
/// use inwx_client::CreditLog;
///
/// let log: CreditLog = serde_json::from_str(
///     r#"{"id":7,"amount":100.0,"creditTime":"2026-10-01T10:00:00",
///         "creditType":"PAYPAL","currency":"EUR","last4":"4242"}"#,
/// )?;
/// assert_eq!(log.amount, Some(100.0));
/// assert_eq!(log.last4.as_deref(), Some("4242"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct CreditLog {
    /// Log id.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Amount credited.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub amount: Option<f64>,
    /// When the credit arrived.
    #[serde(default, rename = "creditTime", deserialize_with = "de::opt_string")]
    pub credit_time: Option<String>,
    /// Customer id.
    #[serde(default, rename = "customerId", deserialize_with = "de::opt_i64")]
    pub customer_id: Option<i64>,
    /// Payment method.
    #[serde(default, rename = "creditType", deserialize_with = "de::opt_string")]
    pub credit_type: Option<String>,
    /// Payment provider transaction id.
    #[serde(default, rename = "transactionId", deserialize_with = "de::opt_string")]
    pub transaction_id: Option<String>,
    /// Refund id, when this entry is a refund.
    #[serde(default, rename = "refundId", deserialize_with = "de::opt_i64")]
    pub refund_id: Option<i64>,
    /// Free-form transaction details.
    #[serde(
        default,
        rename = "transactionDetails",
        deserialize_with = "de::opt_string"
    )]
    pub transaction_details: Option<String>,
    /// Currency.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub currency: Option<String>,
    /// Last four digits of the card, for card payments.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub last4: Option<String>,
}

/// One invoice from `accounting.listInvoices`.
///
/// ```
/// use inwx_client::Invoice;
///
/// let invoice: Invoice = serde_json::from_str(
///     r#"{"invoiceId":"2026-0042","date":"2026-10-01","afterTax":119.0,
///         "preTax":100.0,"type":"INVOICE"}"#,
/// )?;
/// assert_eq!(invoice.invoice_id.as_deref(), Some("2026-0042"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Invoice {
    /// Invoice id, as a string.
    #[serde(default, rename = "invoiceId", deserialize_with = "de::opt_string")]
    pub invoice_id: Option<String>,
    /// Invoice date.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub date: Option<String>,
    /// Amount including tax.
    #[serde(default, rename = "afterTax", deserialize_with = "de::opt_f64")]
    pub after_tax: Option<f64>,
    /// Amount excluding tax.
    #[serde(default, rename = "preTax", deserialize_with = "de::opt_f64")]
    pub pre_tax: Option<f64>,
    /// Kind of invoice.
    #[serde(default, rename = "type", deserialize_with = "de::opt_string")]
    pub kind: Option<String>,
}

/// One locked-funds entry (`accounting.lockedFunds`).
///
/// ```
/// use inwx_client::LockedFund;
///
/// let fund: LockedFund = serde_json::from_str(
///     r#"{"date":"2026-10-01T10:00:00","domain":"example.com","amount":12.5,"status":"LOCKED"}"#,
/// )?;
/// assert_eq!(fund.amount, Some(12.5));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct LockedFund {
    /// When the amount was locked.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub date: Option<String>,
    /// Domain the lock belongs to.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub domain: Option<String>,
    /// Locked amount.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub amount: Option<f64>,
    /// Domain status at lock time.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
}

/// One certificate-related fund lock (`sslFunds` in `accounting.lockedFunds`).
///
/// ```
/// use inwx_client::SslFund;
///
/// let fund: SslFund = serde_json::from_str(
///     r#"{"certificateId":9,"commonName":"example.com","netto":33.53,"vat":6.37,
///         "productId":17,"productName":"DomainValidation","status":"LOCKED"}"#,
/// )?;
/// assert_eq!(fund.certificate_id, Some(9));
/// assert!((fund.gross() - 39.9).abs() < 1e-9);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct SslFund {
    /// Certificate id.
    #[serde(default, rename = "certificateId", deserialize_with = "de::opt_i64")]
    pub certificate_id: Option<i64>,
    /// When the amount was locked.
    #[serde(default, rename = "creationDate", deserialize_with = "de::opt_string")]
    pub creation_date: Option<String>,
    /// Common name, when already known.
    #[serde(default, rename = "commonName", deserialize_with = "de::opt_string")]
    pub common_name: Option<String>,
    /// Net amount.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub netto: Option<f64>,
    /// VAT amount.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub vat: Option<f64>,
    /// Product id.
    #[serde(default, rename = "productId", deserialize_with = "de::opt_i64")]
    pub product_id: Option<i64>,
    /// Product name.
    #[serde(default, rename = "productName", deserialize_with = "de::opt_string")]
    pub product_name: Option<String>,
    /// Lock status.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
}

impl SslFund {
    /// Net plus VAT, or `0.0` when either is missing.
    ///
    /// ```
    /// use inwx_client::SslFund;
    ///
    /// let unknown: SslFund = serde_json::from_str(r#"{"netto":10.0}"#)?;
    /// assert!(unknown.gross() < f64::EPSILON);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn gross(&self) -> f64 {
        match (self.netto, self.vat) {
            (Some(net), Some(vat)) => net + vat,
            _ => 0.0,
        }
    }
}

/// The answer to `accounting.lockedFunds`.
///
/// ```
/// use inwx_client::LockedFunds;
///
/// let funds: LockedFunds = serde_json::from_str(
///     r#"{"funds":[{"domain":"example.com","amount":12.5}],
///         "sslFunds":[{"certificateId":9,"netto":10.0,"vat":1.9}]}"#,
/// )?;
/// assert_eq!(funds.funds.len(), 1);
/// assert_eq!(funds.ssl_funds.len(), 1);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct LockedFunds {
    /// Domain-related locks.
    #[serde(default)]
    pub funds: Vec<LockedFund>,
    /// Certificate-related locks.
    #[serde(default, rename = "sslFunds")]
    pub ssl_funds: Vec<SslFund>,
    /// Optional PDF of the statement.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub pdf: Option<String>,
}

/// One transaction log line (`accounting.log`).
///
/// ```
/// use inwx_client::Transaction;
///
/// let entry: Transaction = serde_json::from_str(
///     r#"{"date":"2026-10-01T10:00:00","amount":-8.9,"type":"RENEW",
///         "details":"example.com","refundable":true}"#,
/// )?;
/// assert_eq!(entry.amount, Some(-8.9));
/// assert!(entry.is_refundable());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Transaction {
    /// When the entry was written.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub date: Option<String>,
    /// Amount; negative for charges.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub amount: Option<f64>,
    /// Kind of action.
    #[serde(default, rename = "type", deserialize_with = "de::opt_string")]
    pub kind: Option<String>,
    /// Free-form details.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub details: Option<String>,
    /// Whether the payment can be refunded.
    #[serde(default, deserialize_with = "de::opt_bool")]
    pub refundable: Option<bool>,
}

impl Transaction {
    /// Whether the entry is refundable.
    ///
    /// ```
    /// use inwx_client::Transaction;
    ///
    /// let unknown: Transaction = serde_json::from_str(r#"{"amount":1.0}"#)?;
    /// assert!(!unknown.is_refundable());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_refundable(&self) -> bool {
        self.refundable == Some(true)
    }
}

/// One page of `accounting.log`.
///
/// ```
/// use inwx_client::TransactionLog;
///
/// let log: TransactionLog = serde_json::from_str(
///     r#"{"count":1,"sum":-8.9,"log":[{"amount":-8.9,"type":"RENEW"}]}"#,
/// )?;
/// assert_eq!(log.sum, Some(-8.9));
/// assert_eq!(log.entries.len(), 1);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct TransactionLog {
    /// Total number of entries.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// Sum of the amounts on this page.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub sum: Option<f64>,
    /// The entries.
    #[serde(default, rename = "log")]
    pub entries: Vec<Transaction>,
}

/// A query for `accounting.getstatement`.
///
/// ```
/// use inwx_client::{StatementQuery, Timestamp};
///
/// let query = StatementQuery::new(
///     Timestamp::parse("2026-01-01T00:00:00")?,
///     Timestamp::parse("2026-12-31T23:59:59")?,
/// )?;
/// assert_eq!(query.params()["format"], "PDF");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementQuery {
    from: Timestamp,
    to: Timestamp,
    format: DocumentFormat,
    page: u32,
    limit: u32,
}

impl StatementQuery {
    /// A statement for a date range, as PDF.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `to` is not after `from` — the API answers an
    /// empty document for a reversed range, which looks like a bug on our side.
    ///
    /// ```
    /// use inwx_client::{StatementQuery, Timestamp};
    ///
    /// let from = Timestamp::parse("2026-12-31T00:00:00")?;
    /// let to = Timestamp::parse("2026-01-01T00:00:00")?;
    /// assert!(StatementQuery::new(from, to).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new(from: Timestamp, to: Timestamp) -> Result<Self> {
        if to <= from {
            return Err(Error::validation("dateTo", "must be after dateFrom"));
        }
        Ok(Self {
            from,
            to,
            format: DocumentFormat::Pdf,
            page: 1,
            limit: 20,
        })
    }

    /// Sets the document format.
    ///
    /// ```
    /// use inwx_client::{DocumentFormat, StatementQuery, Timestamp};
    ///
    /// let query = StatementQuery::new(
    ///     Timestamp::parse("2026-01-01T00:00:00")?,
    ///     Timestamp::parse("2026-02-01T00:00:00")?,
    /// )?
    /// .with_format(DocumentFormat::Csv);
    /// assert_eq!(query.params()["format"], "CSV");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_format(mut self, format: DocumentFormat) -> Self {
        self.format = format;
        self
    }

    /// Sets paging.
    ///
    /// ```
    /// use inwx_client::{StatementQuery, Timestamp};
    ///
    /// let query = StatementQuery::new(
    ///     Timestamp::parse("2026-01-01T00:00:00")?,
    ///     Timestamp::parse("2026-02-01T00:00:00")?,
    /// )?
    /// .with_page(2, 50);
    /// assert_eq!(query.params()["page"], 2);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_page(mut self, page: u32, limit: u32) -> Self {
        self.page = page.max(1);
        self.limit = limit;
        self
    }

    /// The `accounting.getstatement` parameters.
    ///
    /// ```
    /// use inwx_client::{StatementQuery, Timestamp};
    ///
    /// let params = StatementQuery::new(
    ///     Timestamp::parse("2026-01-01T00:00:00")?,
    ///     Timestamp::parse("2026-02-01T00:00:00")?,
    /// )?
    /// .params();
    /// assert_eq!(params["dateFrom"], "2026-01-01T00:00:00");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        json!({
            "dateFrom": self.from,
            "dateTo": self.to,
            "format": self.format,
            "page": self.page,
            "pagelimit": self.limit,
        })
    }
}

/// A query for `accounting.log`.
///
/// ```
/// use inwx_client::TransactionLogQuery;
///
/// let query = TransactionLogQuery::new()
///     .with_prices(0.0, 100.0)?
///     .with_page(1, 25);
/// assert_eq!(query.params()["priceMax"], 100.0);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionLogQuery {
    from: Option<Timestamp>,
    to: Option<Timestamp>,
    price_min: Option<f64>,
    price_max: Option<f64>,
    page: u32,
    limit: u32,
}

impl Default for TransactionLogQuery {
    fn default() -> Self {
        Self {
            from: None,
            to: None,
            price_min: None,
            price_max: None,
            page: 1,
            limit: 20,
        }
    }
}

impl TransactionLogQuery {
    /// An empty query (the API's default range).
    ///
    /// ```
    /// use inwx_client::TransactionLogQuery;
    /// assert_eq!(TransactionLogQuery::new().params()["pagelimit"], 20);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restricts the range.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `to` is not after `from`.
    ///
    /// ```
    /// use inwx_client::{Timestamp, TransactionLogQuery};
    ///
    /// let query = TransactionLogQuery::new().with_range(
    ///     Timestamp::parse("2026-01-01T00:00:00")?,
    ///     Timestamp::parse("2026-02-01T00:00:00")?,
    /// )?;
    /// assert!(query.params().get("dateFrom").is_some());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_range(mut self, from: Timestamp, to: Timestamp) -> Result<Self> {
        if to <= from {
            return Err(Error::validation("dateTo", "must be after dateFrom"));
        }
        self.from = Some(from);
        self.to = Some(to);
        Ok(self)
    }

    /// Restricts the amount range.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when either bound is not a finite non-negative
    /// amount, or `max` is below `min`.
    ///
    /// ```
    /// use inwx_client::TransactionLogQuery;
    ///
    /// assert!(TransactionLogQuery::new().with_prices(0.0, 10.0).is_ok());
    /// assert!(TransactionLogQuery::new().with_prices(10.0, 1.0).is_err());
    /// assert!(TransactionLogQuery::new().with_prices(-1.0, 10.0).is_err());
    /// ```
    pub fn with_prices(mut self, min: f64, max: f64) -> Result<Self> {
        if !min.is_finite() || !max.is_finite() || min < 0.0 || max < min {
            return Err(Error::validation(
                "priceMin",
                format!("needs finite amounts with 0 <= min <= max, got {min}..{max}"),
            ));
        }
        self.price_min = Some(min);
        self.price_max = Some(max);
        Ok(self)
    }

    /// Sets paging.
    ///
    /// ```
    /// use inwx_client::TransactionLogQuery;
    /// assert_eq!(TransactionLogQuery::new().with_page(3, 5).params()["page"], 3);
    /// ```
    #[must_use]
    pub fn with_page(mut self, page: u32, limit: u32) -> Self {
        self.page = page.max(1);
        self.limit = limit;
        self
    }

    /// The `accounting.log` parameters.
    ///
    /// ```
    /// use inwx_client::TransactionLogQuery;
    /// let params = TransactionLogQuery::new().params();
    /// assert_eq!(params["page"], 1);
    /// assert!(params.get("dateFrom").is_none());
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut params = Map::new();
        if let Some(from) = &self.from {
            params.insert("dateFrom".to_owned(), json!(from));
        }
        if let Some(to) = &self.to {
            params.insert("dateTo".to_owned(), json!(to));
        }
        if let Some(min) = self.price_min {
            params.insert("priceMin".to_owned(), json!(min));
        }
        if let Some(max) = self.price_max {
            params.insert("priceMax".to_owned(), json!(max));
        }
        params.insert("page".to_owned(), json!(self.page));
        params.insert("pagelimit".to_owned(), json!(self.limit));
        Value::Object(params)
    }
}

/// A refund request (`accounting.refund`).
///
/// ```
/// use inwx_client::{ActionKind, Irreversible, RefundRequest};
///
/// let refund = RefundRequest::new(
///     Irreversible::acknowledge(ActionKind::Refund, &inwx_client::DomainName::parse("example.com")?),
///     7,
///     25.0,
/// )?;
/// assert_eq!(refund.params()["amount"], 25.0);
/// # Ok::<(), inwx_client::Error>(())
/// ```
///
/// The acknowledgement names a domain because [`Irreversible`] is shared with
/// the ownership commands; for a refund the domain is carried for the audit
/// trail, and the amount is what matters.
#[derive(Debug, Clone, PartialEq)]
pub struct RefundRequest {
    intent: Irreversible,
    credit_log_id: i64,
    amount: f64,
}

impl RefundRequest {
    /// A refund of `amount` from credit log `credit_log_id`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the intent does not name
    /// [`ActionKind::Refund`], the log id is not positive, or the amount is not
    /// a finite positive value.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, RefundRequest};
    ///
    /// let wrong = Irreversible::acknowledge(ActionKind::Trade, &DomainName::parse("a.de")?);
    /// assert!(RefundRequest::new(wrong, 7, 10.0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn new(intent: Irreversible, credit_log_id: i64, amount: f64) -> Result<Self> {
        if intent.action() != ActionKind::Refund {
            return Err(Error::validation(
                "intent",
                format!(
                    "this acknowledgement names {} but the request performs accounting.refund",
                    intent.action()
                ),
            ));
        }
        if credit_log_id <= 0 {
            return Err(Error::validation(
                "creditlogid",
                format!("must be a positive credit log id, got {credit_log_id}"),
            ));
        }
        if !amount.is_finite() || amount <= 0.0 {
            return Err(Error::validation(
                "amount",
                format!("must be a finite positive amount, got {amount}"),
            ));
        }
        Ok(Self {
            intent,
            credit_log_id,
            amount,
        })
    }

    /// The `accounting.refund` parameters.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, RefundRequest};
    ///
    /// let refund = RefundRequest::new(
    ///     Irreversible::acknowledge(ActionKind::Refund, &DomainName::parse("a.de")?),
    ///     7,
    ///     10.0,
    /// )?;
    /// assert_eq!(refund.params()["creditlogid"], 7);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        json!({ "creditlogid": self.credit_log_id, "amount": self.amount })
    }

    /// The acknowledgement this request carries, for logging.
    ///
    /// ```
    /// use inwx_client::{ActionKind, DomainName, Irreversible, RefundRequest};
    ///
    /// let refund = RefundRequest::new(
    ///     Irreversible::acknowledge(ActionKind::Refund, &DomainName::parse("a.de")?),
    ///     7,
    ///     10.0,
    /// )?;
    /// assert_eq!(refund.intent().action(), ActionKind::Refund);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn intent(&self) -> &Irreversible {
        &self.intent
    }
}

/// A postal delivery request (`accounting.sendbypost`).
///
/// ```
/// use inwx_client::PostalDelivery;
///
/// let delivery = PostalDelivery::new("2026-0042", true)?;
/// assert_eq!(delivery.params()["acceptCosts"], true);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostalDelivery {
    invoice_id: String,
    accept_costs: bool,
    send_twice: bool,
    testing: bool,
}

impl PostalDelivery {
    /// A delivery request for one invoice.
    ///
    /// The API requires `acceptCosts`; passing it explicitly here is the point
    /// of the type — a postal invoice costs money and cannot be ordered by
    /// forgetting a flag.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the invoice id is empty or unusable.
    ///
    /// ```
    /// use inwx_client::PostalDelivery;
    ///
    /// assert!(PostalDelivery::new("2026-0042", true).is_ok());
    /// assert!(PostalDelivery::new("", true).is_err());
    /// ```
    pub fn new(invoice_id: &str, accept_costs: bool) -> Result<Self> {
        validate_token("invoiceId", invoice_id)?;
        Ok(Self {
            invoice_id: invoice_id.trim().to_owned(),
            accept_costs,
            send_twice: false,
            testing: false,
        })
    }

    /// Allows a duplicate delivery request for the same invoice.
    ///
    /// ```
    /// use inwx_client::PostalDelivery;
    ///
    /// let delivery = PostalDelivery::new("2026-0042", true)?.allowing_duplicates();
    /// assert_eq!(delivery.params()["sendTwice"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn allowing_duplicates(mut self) -> Self {
        self.send_twice = true;
        self
    }

    /// Runs the command in testing mode (`testing=true`).
    ///
    /// ```
    /// use inwx_client::PostalDelivery;
    ///
    /// let delivery = PostalDelivery::new("2026-0042", true)?.dry_run();
    /// assert_eq!(delivery.params()["testing"], true);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.testing = true;
        self
    }

    /// The `accounting.sendbypost` parameters.
    ///
    /// ```
    /// use inwx_client::PostalDelivery;
    ///
    /// let params = PostalDelivery::new("2026-0042", true)?.params();
    /// assert_eq!(params["invoiceId"], "2026-0042");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        json!({
            "invoiceId": self.invoice_id,
            "acceptCosts": self.accept_costs,
            "sendTwice": self.send_twice,
            "testing": self.testing,
        })
    }
}

impl<T: Transport> InwxClient<T> {
    /// Reads the account balance (`accounting.accountBalance`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let balance = client.account_balance().await?;
    /// println!("{:?} available", balance.available);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn account_balance(&self) -> Result<AccountBalance> {
        let data = self.call("accounting.accountBalance", json!({})).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Reads one credit log entry (`accounting.creditLogById`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let log = client.credit_log(7).await?;
    /// println!("{:?}", log.amount);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn credit_log(&self, credit_log_id: i64) -> Result<CreditLog> {
        if credit_log_id <= 0 {
            return Err(Error::validation(
                "creditLogId",
                format!("must be a positive credit log id, got {credit_log_id}"),
            ));
        }
        let data = self
            .call(
                "accounting.creditLogById",
                json!({ "creditLogId": credit_log_id }),
            )
            .await?;
        // The API nests the entry under `log`.
        let entry = data.get("log").cloned().unwrap_or(data);
        serde_json::from_value(entry).map_err(Error::from)
    }

    /// Downloads one invoice as PDF (`accounting.getInvoice`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let pdf = client.invoice_document("2026-0042").await?;
    /// std::fs::write("invoice.pdf", pdf.pdf_bytes()?)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable invoice id, plus the usual
    /// transport and API errors.
    pub async fn invoice_document(&self, invoice_id: &str) -> Result<Document> {
        validate_token("invoiceId", invoice_id)?;
        let data = self
            .call(
                "accounting.getInvoice",
                json!({ "invoiceId": invoice_id.trim() }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Downloads the preview invoice of a month
    /// (`accounting.getPreviewInvoice`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let pdf = client.preview_invoice(2026, 10).await?;
    /// assert!(pdf.is_pdf());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the month is outside 1–12 or the year outside
    /// 2000–2100, plus the usual transport and API errors.
    pub async fn preview_invoice(&self, year: u16, month: u8) -> Result<Document> {
        if !(2000..=2100).contains(&year) {
            return Err(Error::validation(
                "year",
                format!("must be 2000 to 2100, got {year}"),
            ));
        }
        if !(1..=12).contains(&month) {
            return Err(Error::validation(
                "month",
                format!("must be 1 to 12, got {month}"),
            ));
        }
        let data = self
            .call(
                "accounting.getPreviewInvoice",
                json!({ "year": year, "month": month }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Downloads the receipt of a payment (`accounting.getReceipt`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let pdf = client
    ///     .receipt(7, "100.00", "Deposit", "2026-10-01")
    ///     .await?;
    /// assert!(pdf.is_pdf());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id or an empty text field, plus
    /// the usual transport and API errors.
    pub async fn receipt(
        &self,
        payment_id: i64,
        amount: &str,
        details: &str,
        date: &str,
    ) -> Result<Document> {
        if payment_id <= 0 {
            return Err(Error::validation(
                "id",
                format!("must be a positive payment id, got {payment_id}"),
            ));
        }
        for (field, value) in [("amount", amount), ("details", details), ("date", date)] {
            validate_text(field, value, 64)?;
        }
        let payload = self
            .call(
                "accounting.getReceipt",
                json!({
                    "id": payment_id,
                    "amount": amount.trim(),
                    "details": details.trim(),
                    "date": date.trim(),
                }),
            )
            .await?;
        serde_json::from_value(payload).map_err(Error::from)
    }

    /// Downloads a statement of transactions (`accounting.getstatement`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport, StatementQuery, Timestamp};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let query = StatementQuery::new(
    ///     Timestamp::parse("2026-01-01T00:00:00")?,
    ///     Timestamp::parse("2026-12-31T23:59:59")?,
    /// )?;
    /// let pdf = client.statement(&query).await?;
    /// assert!(pdf.is_pdf());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn statement(&self, query: &StatementQuery) -> Result<Document> {
        let data = self.call("accounting.getstatement", query.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Lists all invoices (`accounting.listInvoices`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for invoice in client.list_invoices().await? {
    ///     println!("{:?}", invoice.invoice_id);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn list_invoices(&self) -> Result<Vec<Invoice>> {
        let data = self.call("accounting.listInvoices", json!({})).await?;
        let entries = match data.get("invoice") {
            Some(Value::Array(entries)) => entries.clone(),
            _ => Vec::new(),
        };
        Ok(entries
            .into_iter()
            .filter_map(|entry| serde_json::from_value(entry).ok())
            .collect())
    }

    /// Reads the locked-funds log (`accounting.lockedFunds`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let funds = client.locked_funds(None, None, 1, 20).await?;
    /// println!("{} locks", funds.funds.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when a range is reversed or the page limit is zero,
    /// plus the usual transport and API errors.
    pub async fn locked_funds(
        &self,
        from: Option<Timestamp>,
        to: Option<Timestamp>,
        page: u32,
        limit: u32,
    ) -> Result<LockedFunds> {
        if let (Some(from), Some(to)) = (&from, &to) {
            if to <= from {
                return Err(Error::validation("dateTo", "must be after dateFrom"));
            }
        }
        if limit == 0 {
            return Err(Error::validation("pagelimit", "must be at least 1"));
        }
        let mut params = Map::new();
        if let Some(from) = &from {
            params.insert("dateFrom".to_owned(), json!(from));
        }
        if let Some(to) = &to {
            params.insert("dateTo".to_owned(), json!(to));
        }
        params.insert("page".to_owned(), json!(page.max(1)));
        params.insert("pagelimit".to_owned(), json!(limit));
        let data = self
            .call("accounting.lockedFunds", Value::Object(params))
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Reads the transaction log (`accounting.log`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport, TransactionLogQuery};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let log = client.account_log(&TransactionLogQuery::new()).await?;
    /// println!("{:?} entries", log.count);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn account_log(&self, query: &TransactionLogQuery) -> Result<TransactionLog> {
        let data = self.call("accounting.log", query.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Refunds credit to the original payment method (`accounting.refund`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{
    ///     ActionKind, DomainName, InwxClient, Irreversible, RefundRequest, ReqwestTransport,
    /// };
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let refund = RefundRequest::new(
    ///     Irreversible::acknowledge(ActionKind::Refund, &DomainName::parse("example.com")?),
    ///     7,
    ///     25.0,
    /// )?;
    /// client.refund(&refund).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn refund(&self, refund: &RefundRequest) -> Result<()> {
        self.call("accounting.refund", refund.params()).await?;
        Ok(())
    }

    /// Requests postal delivery of an invoice (`accounting.sendbypost`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, PostalDelivery, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client
    ///     .send_invoice_by_post(&PostalDelivery::new("2026-0042", true)?)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn send_invoice_by_post(&self, delivery: &PostalDelivery) -> Result<()> {
        self.call("accounting.sendbypost", delivery.params())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(value: &str) -> Timestamp {
        Timestamp::parse(value).unwrap()
    }

    #[test]
    fn documents_decode_only_valid_base64() {
        let good: Document = serde_json::from_str(r#"{"pdf":"JVBERi0="}"#).unwrap();
        assert_eq!(good.pdf_bytes().unwrap(), b"%PDF-");

        let bad: Document = serde_json::from_str(r#"{"pdf":"***"}"#).unwrap();
        assert!(bad.pdf_bytes().is_err());

        let none: Document = serde_json::from_str(r#"{"raw":"x"}"#).unwrap();
        assert!(none.pdf_bytes().is_err());
    }

    #[test]
    fn reversed_ranges_are_rejected() {
        assert!(StatementQuery::new(ts("2026-02-01T00:00:00"), ts("2026-01-01T00:00:00")).is_err());
        assert!(TransactionLogQuery::new()
            .with_range(ts("2026-02-01T00:00:00"), ts("2026-01-01T00:00:00"))
            .is_err());
    }

    #[test]
    fn price_ranges_must_be_ordered_and_non_negative() {
        assert!(TransactionLogQuery::new().with_prices(0.0, 0.0).is_ok());
        assert!(TransactionLogQuery::new().with_prices(5.0, 1.0).is_err());
        assert!(TransactionLogQuery::new()
            .with_prices(f64::NAN, 1.0)
            .is_err());
    }

    #[test]
    fn refunds_need_the_refund_acknowledgement() {
        let domain = crate::DomainName::parse("a.de").unwrap();
        let wrong = Irreversible::acknowledge(ActionKind::Transfer, &domain);
        assert!(RefundRequest::new(wrong, 7, 10.0).is_err());

        let right = Irreversible::acknowledge(ActionKind::Refund, &domain);
        assert!(RefundRequest::new(right.clone(), 0, 10.0).is_err());
        assert!(RefundRequest::new(right.clone(), 7, 0.0).is_err());
        assert!(RefundRequest::new(right, 7, 10.0).is_ok());
    }

    #[test]
    fn postal_delivery_requires_an_invoice() {
        assert!(PostalDelivery::new("", true).is_err());
        let delivery = PostalDelivery::new("2026-0042", true).unwrap();
        assert_eq!(delivery.params()["acceptCosts"], true);
    }

    #[test]
    fn ssl_fund_gross_needs_both_amounts() {
        let fund: SslFund = serde_json::from_str(r#"{"netto":10.0,"vat":1.9}"#).unwrap();
        assert!((fund.gross() - 11.9).abs() < 1e-9);
    }
}
