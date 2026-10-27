//! PDFs (`pdf.document`, `pdf.get`): documents INWX renders for a reseller or
//! one of its customers.
//!
//! Two methods. `pdf.document` renders a document and answers with the PDF plus
//! — depending on the product — a hash under which INWX keeps it; `pdf.get`
//! fetches a rendered PDF again by that hash. Both bodies are base64 on the
//! wire, which [`PdfDocument::bytes`] hides.
//!
//! The object is described in the API documentation chapter 2 §2.19.
//!
//! ```
//! use inwx_client::{PdfHash, PdfRender};
//!
//! let render = PdfRender::new()?.with_document_type("INVOICE")?.with_customer(4711)?;
//! assert_eq!(render.params()?["type"], "INVOICE");
//! assert_eq!(PdfHash::new("8f2a")?.as_str(), "8f2a");
//! # Ok::<(), inwx_client::Error>(())
//! ```

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::{InwxClient, Language};
use crate::error::{Error, Result};
use crate::params::{self, ExtraFields};
use crate::transport::Transport;
use crate::types::{de, validate_token};

/// Keys owned by [`PdfRender`].
const RENDER_KEYS: &[&str] = &["type", "customer", "language"];

/// A request for a rendered document (`pdf.document`).
///
/// Nothing is required at the type level — which document is renderable depends
/// on the product — but an empty request is refused, because the API would only
/// answer `2003 Required parameter missing`.
///
/// ```
/// use inwx_client::{Language, PdfRender};
///
/// let render = PdfRender::new()?
///     .with_document_type("CONTRACT")?
///     .with_customer(4711)?
///     .with_language(Language::De);
/// let params = render.params()?;
/// assert_eq!(params["type"], "CONTRACT");
/// assert_eq!(params["language"], "de");
/// assert!(PdfRender::new().unwrap().params().is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PdfRender {
    document_type: Option<String>,
    customer: Option<i64>,
    language: Option<Language>,
    fields: ExtraFields,
}

impl PdfRender {
    /// An empty request; add at least one parameter.
    ///
    /// # Errors
    ///
    /// Never today; the signature leaves room for the checks the API enforces on
    /// an empty request.
    ///
    /// ```
    /// use inwx_client::PdfRender;
    /// assert!(PdfRender::new().is_ok());
    /// ```
    pub fn new() -> Result<Self> {
        Ok(Self::default())
    }

    /// Sets which document to render.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::PdfRender;
    /// assert_eq!(
    ///     PdfRender::new()?.with_document_type("INVOICE")?.params()?["type"],
    ///     "INVOICE"
    /// );
    /// assert!(PdfRender::new()?.with_document_type("").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_document_type(mut self, document_type: &str) -> Result<Self> {
        validate_token("pdf.type", document_type)?;
        self.document_type = Some(document_type.trim().to_owned());
        Ok(self)
    }

    /// Renders the document for one customer.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::PdfRender;
    /// assert!(PdfRender::new()?.with_customer(4711).is_ok());
    /// assert!(PdfRender::new()?.with_customer(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer(mut self, customer: i64) -> Result<Self> {
        self.customer = Some(params::object_id("customerId", customer)?);
        Ok(self)
    }

    /// Sets the language of the rendered document.
    ///
    /// ```
    /// use inwx_client::{Language, PdfRender};
    /// assert_eq!(
    ///     PdfRender::new()?.with_language(Language::En).params()?["language"],
    ///     "en"
    /// );
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_language(mut self, language: Language) -> Self {
        self.language = Some(language);
        self
    }

    /// Adds a parameter this crate does not model.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `key` is not a parameter name, or when a typed
    /// setter already owns it.
    ///
    /// ```
    /// use inwx_client::PdfRender;
    /// let render = PdfRender::new()?.with_document_type("INVOICE")?.with_field("year", 2026)?;
    /// assert_eq!(render.params()?["year"], 2026);
    /// assert!(PdfRender::new()?.with_document_type("X")?.with_field("type", "Y").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_field(mut self, key: &str, value: impl Into<Value>) -> Result<Self> {
        self.fields.set(key, value.into(), RENDER_KEYS)?;
        Ok(self)
    }

    /// The `pdf.document` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when nothing was set.
    ///
    /// ```
    /// use inwx_client::PdfRender;
    /// assert!(PdfRender::new()?.params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut map = Map::new();
        if let Some(document_type) = &self.document_type {
            map.insert("type".to_owned(), json!(document_type));
        }
        if let Some(customer) = self.customer {
            map.insert("customer".to_owned(), json!(customer));
        }
        if let Some(language) = self.language {
            map.insert("language".to_owned(), json!(language.as_str()));
        }
        self.fields.write_into(&mut map);
        params::require_payload("pdf.document.params", map.len())?;
        Ok(Value::Object(map))
    }
}

/// The hash under which INWX keeps a rendered PDF (`pdf.get`).
///
/// A hash goes into a URL-ish parameter, so control characters are refused and
/// the length is bounded before anything is built.
///
/// ```
/// use inwx_client::PdfHash;
///
/// let hash = PdfHash::new(String::from("8f2a41c0"))?;
/// assert_eq!(hash.as_str(), "8f2a41c0");
/// assert!(PdfHash::new("with\nnewline").is_err());
/// assert!(PdfHash::new("").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PdfHash(String);

impl PdfHash {
    /// Validates and stores a hash.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty value, one longer than 255 characters
    /// or one containing control characters.
    ///
    /// ```
    /// use inwx_client::PdfHash;
    /// assert!(PdfHash::new("8f2a").is_ok());
    /// assert!(PdfHash::new("a".repeat(255)).is_ok());
    /// assert!(PdfHash::new("a".repeat(256)).is_err());
    /// ```
    pub fn new(hash: impl Into<String>) -> Result<Self> {
        let hash = hash.into();
        validate_token("pdf.hash", &hash)?;
        Ok(Self(hash.trim().to_owned()))
    }

    /// The hash as it goes on the wire.
    ///
    /// ```
    /// use inwx_client::PdfHash;
    /// assert_eq!(PdfHash::new("8f2a")?.as_str(), "8f2a");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PdfHash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::str::FromStr for PdfHash {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::new(input)
    }
}

/// A rendered PDF (`pdf.document`, `pdf.get`).
///
/// ```
/// use inwx_client::PdfDocument;
///
/// let document: PdfDocument =
///     serde_json::from_str(r#"{"data":"JVBERi0=","hash":"8f2a","filename":"invoice.pdf"}"#)?;
/// assert_eq!(document.hash.as_deref(), Some("8f2a"));
/// assert_eq!(document.bytes()?, b"%PDF-");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct PdfDocument {
    /// Base64-encoded PDF.
    #[serde(default, alias = "pdf", deserialize_with = "de::opt_string")]
    pub data: Option<String>,
    /// Hash the document was stored under, when INWX stores it.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub hash: Option<String>,
    /// File name the API suggests.
    #[serde(
        default,
        rename = "filename",
        alias = "file_name",
        alias = "name",
        deserialize_with = "de::opt_string"
    )]
    pub filename: Option<String>,
    /// Fields this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

impl PdfDocument {
    /// The decoded PDF bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the answer carries no body, when it is not
    /// valid base64, or when it exceeds the crate's 8 MiB ceiling.
    ///
    /// ```
    /// use inwx_client::PdfDocument;
    ///
    /// let document: PdfDocument = serde_json::from_str(r#"{"pdf":"aGk="}"#)?;
    /// assert_eq!(document.bytes()?, b"hi");
    ///
    /// let empty: PdfDocument = serde_json::from_str(r#"{"hash":"8f2a"}"#)?;
    /// assert!(empty.bytes().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let encoded = self
            .data
            .as_deref()
            .ok_or_else(|| Error::validation("pdf.data", "the answer carries no pdf body"))?;
        params::decode_document(encoded)
    }

    /// The stored hash, validated for a later `pdf.get`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the answer carries no hash, or one that is not
    /// a usable token.
    ///
    /// ```
    /// use inwx_client::PdfDocument;
    ///
    /// let document: PdfDocument = serde_json::from_str(r#"{"hash":"8f2a"}"#)?;
    /// assert_eq!(document.required_hash()?.as_str(), "8f2a");
    ///
    /// let anonymous: PdfDocument = serde_json::from_str(r#"{"data":"aGk="}"#)?;
    /// assert!(anonymous.required_hash().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn required_hash(&self) -> Result<PdfHash> {
        let hash = self
            .hash
            .as_deref()
            .ok_or_else(|| Error::validation("pdf.hash", "the answer carries no hash"))?;
        PdfHash::new(hash)
    }
}

impl<T: Transport> InwxClient<T> {
    /// Renders a document (`pdf.document`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, PdfRender, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let render = PdfRender::new()?.with_document_type("INVOICE")?.with_customer(4711)?;
    /// let document = client.render_pdf(&render).await?;
    /// std::fs::write("invoice.pdf", document.bytes()?)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the request carries no parameter, plus the
    /// usual transport and API errors.
    pub async fn render_pdf(&self, render: &PdfRender) -> Result<PdfDocument> {
        let data = self.call("pdf.document", render.params()?).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Fetches a rendered PDF again by its hash (`pdf.get`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, PdfHash, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let document = client.fetch_pdf(&PdfHash::new(String::from("8f2a41c0"))?).await?;
    /// println!("{:?}", document.filename);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors; [`PdfHash`] has already checked the
    /// hash.
    pub async fn fetch_pdf(&self, hash: &PdfHash) -> Result<PdfDocument> {
        let data = self
            .call("pdf.get", json!({ "hash": hash.as_str() }))
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_request_never_reaches_the_wire() {
        assert!(PdfRender::new().unwrap().params().is_err());
    }

    #[test]
    fn ids_stop_at_zero() {
        assert!(PdfRender::new().unwrap().with_customer(1).is_ok());
        assert!(PdfRender::new().unwrap().with_customer(0).is_err());
    }

    #[test]
    fn document_types_stop_at_255_characters() {
        assert!(PdfRender::new()
            .unwrap()
            .with_document_type(&"I".repeat(255))
            .is_ok());
        assert!(PdfRender::new()
            .unwrap()
            .with_document_type(&"I".repeat(256))
            .is_err());
    }

    #[test]
    fn hashes_stop_at_255_characters() {
        assert!(PdfHash::new("a".repeat(255)).is_ok());
        assert!(PdfHash::new("a".repeat(256)).is_err());
        assert!(PdfHash::new("with\nnewline").is_err());
        assert!(PdfHash::new("  ").is_err());
    }

    #[test]
    fn a_hash_round_trips_through_the_parser() {
        let hash: PdfHash = "8f2a".parse().unwrap();
        assert_eq!(hash.to_string(), "8f2a");
        assert!("".parse::<PdfHash>().is_err());
    }

    #[test]
    fn reserved_keys_cannot_be_overridden_by_hand() {
        let render = PdfRender::new()
            .unwrap()
            .with_document_type("INVOICE")
            .unwrap();
        assert!(render.clone().with_field("type", "X").is_err());
        assert!(render.with_field("year", 2026).is_ok());
    }

    #[test]
    fn a_missing_body_or_hash_is_reported() {
        let document: PdfDocument = serde_json::from_str(r#"{"hash":"8f2a"}"#).unwrap();
        assert!(document.bytes().is_err());
        assert_eq!(document.required_hash().unwrap().as_str(), "8f2a");

        let body_only: PdfDocument = serde_json::from_str(r#"{"data":"aGk="}"#).unwrap();
        assert!(body_only.required_hash().is_err());
        assert_eq!(body_only.bytes().unwrap(), b"hi");

        let under_pdf_key: PdfDocument = serde_json::from_str(r#"{"pdf":"aGk="}"#).unwrap();
        assert_eq!(under_pdf_key.bytes().unwrap(), b"hi");
    }
}
