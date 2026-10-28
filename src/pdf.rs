//! Generated PDFs (`pdf.document`, `pdf.get`): documents the API renders on
//! demand — invoices, statements, contracts.
//!
//! `pdf.document` asks INWX to render a document and answers with a handle;
//! `pdf.get` fetches the bytes for that handle. Both are read-only, so neither
//! needs an acknowledgement — but the body is base64, and the crate decodes it
//! rather than handing back a string the caller has to parse again.
//!
//! ```
//! use inwx_client::{DocumentFormat, PdfRender};
//!
//! let render = PdfRender::new("invoice", 4711)?.with_format(DocumentFormat::Pdf)?;
//! let params = render.params()?;
//! assert_eq!(params["type"], "INVOICE");
//! assert_eq!(params["format"], "PDF");
//! # Ok::<(), inwx_client::Error>(())
//! ```

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::document::MAX_DOCUMENT_BYTES;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{
    de, decode_base64, validate_id, validate_upper_token, DocumentFormat, Timestamp,
};

/// Longest document type token this crate accepts.
const MAX_TYPE_LEN: usize = 64;

/// The `pdf.document` request: which document class, and which object.
///
/// ```
/// use inwx_client::{DocumentFormat, PdfRender};
///
/// let render = PdfRender::new("statement", 4711)?
///     .with_customer_number(123456)?
///     .with_format(DocumentFormat::Pdf)?;
/// let params = render.params()?;
/// assert_eq!(params["type"], "STATEMENT");
/// assert_eq!(params["id"], 4711);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfRender {
    document_type: String,
    object_id: i64,
    customer_number: Option<i64>,
    format: Option<DocumentFormat>,
    from: Option<Timestamp>,
    to: Option<Timestamp>,
    testing: bool,
}

impl PdfRender {
    /// Renders the document `object_id` of class `document_type`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or oddly shaped class token, or a
    /// non-positive object id.
    ///
    /// ```
    /// use inwx_client::PdfRender;
    ///
    /// assert!(PdfRender::new("invoice", 1).is_ok());
    /// assert!(PdfRender::new("", 1).is_err());
    /// assert!(PdfRender::new("invoice", 0).is_err());
    /// ```
    pub fn new(document_type: impl Into<String>, object_id: i64) -> Result<Self> {
        Ok(Self {
            document_type: validate_upper_token("pdf.type", &document_type.into(), MAX_TYPE_LEN)?,
            object_id: validate_id("pdf.id", object_id)?,
            customer_number: None,
            format: None,
            from: None,
            to: None,
            testing: false,
        })
    }

    /// Sets the customer whose document is rendered.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive customer number.
    ///
    /// ```
    /// use inwx_client::PdfRender;
    ///
    /// let render = PdfRender::new("invoice", 1)?.with_customer_number(123456)?;
    /// assert_eq!(render.params()?["customerNumber"], 123456);
    /// assert!(PdfRender::new("invoice", 1)?.with_customer_number(-2).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer_number(mut self, customer_number: i64) -> Result<Self> {
        self.customer_number = Some(validate_id("customer.number", customer_number)?);
        Ok(self)
    }

    /// Sets the output format.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the format is not documented for PDF
    /// rendering — [`DocumentFormat::Csv`] belongs to the zone exports.
    ///
    /// ```
    /// use inwx_client::{DocumentFormat, PdfRender};
    ///
    /// let render = PdfRender::new("invoice", 1)?.with_format(DocumentFormat::Raw)?;
    /// assert_eq!(render.params()?["format"], "RAW");
    /// assert!(PdfRender::new("invoice", 1)?.with_format(DocumentFormat::Csv).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_format(mut self, format: DocumentFormat) -> Result<Self> {
        if format == DocumentFormat::Csv {
            return Err(Error::validation(
                "pdf.format",
                "CSV is a zone export format, not a document format (RAW, PDF)",
            ));
        }
        self.format = Some(format);
        Ok(self)
    }

    /// Restricts the document to a period (`dateFrom`).
    ///
    /// ```
    /// use inwx_client::{PdfRender, Timestamp};
    ///
    /// let render = PdfRender::new("statement", 1)?
    ///     .with_from(Timestamp::parse("2026-01-01T00:00:00")?);
    /// assert_eq!(render.params()?["dateFrom"], "2026-01-01T00:00:00");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_from(mut self, from: Timestamp) -> Self {
        self.from = Some(from);
        self
    }

    /// Restricts the document to a period (`dateTo`).
    ///
    /// ```
    /// use inwx_client::{PdfRender, Timestamp};
    ///
    /// let render = PdfRender::new("statement", 1)?
    ///     .with_to(Timestamp::parse("2026-12-31T23:59:59")?);
    /// assert_eq!(render.params()?["dateTo"], "2026-12-31T23:59:59");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_to(mut self, to: Timestamp) -> Self {
        self.to = Some(to);
        self
    }

    /// Marks the call as a dry run (`testing`).
    ///
    /// ```
    /// use inwx_client::PdfRender;
    ///
    /// let render = PdfRender::new("invoice", 1)?.with_testing(true);
    /// assert!(render.params()?.get("testing").is_some());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_testing(mut self, testing: bool) -> Self {
        self.testing = testing;
        self
    }

    /// The `pdf.document` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `dateFrom` is after `dateTo`.
    ///
    /// ```
    /// use inwx_client::{PdfRender, Timestamp};
    ///
    /// let render = PdfRender::new("invoice", 1)?
    ///     .with_from(Timestamp::parse("2026-02-01T00:00:00")?)
    ///     .with_to(Timestamp::parse("2026-01-01T00:00:00")?);
    /// assert!(render.params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        if let (Some(from), Some(to)) = (&self.from, &self.to) {
            if from > to {
                return Err(Error::validation(
                    "pdf.dateFrom",
                    "must not be after dateTo",
                ));
            }
        }
        let mut params = Map::new();
        params.insert("type".to_owned(), json!(self.document_type));
        params.insert("id".to_owned(), json!(self.object_id));
        if let Some(customer_number) = self.customer_number {
            params.insert("customerNumber".to_owned(), json!(customer_number));
        }
        if let Some(format) = self.format {
            params.insert("format".to_owned(), json!(format.as_str()));
        }
        if let Some(from) = &self.from {
            params.insert("dateFrom".to_owned(), json!(from.as_str()));
        }
        if let Some(to) = &self.to {
            params.insert("dateTo".to_owned(), json!(to.as_str()));
        }
        if self.testing {
            params.insert("testing".to_owned(), json!(true));
        }
        Ok(Value::Object(params))
    }
}

/// The handle `pdf.document` answers with.
///
/// ```
/// use inwx_client::PdfHandle;
///
/// let handle: PdfHandle =
///     serde_json::from_str(r#"{"pdfId":"99","filename":"invoice-4711.pdf","status":"READY"}"#)?;
/// assert_eq!(handle.id, Some(99));
/// assert_eq!(handle.filename.as_deref(), Some("invoice-4711.pdf"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct PdfHandle {
    /// Handle for `pdf.get`.
    #[serde(
        default,
        rename = "pdfId",
        alias = "id",
        deserialize_with = "de::opt_i64"
    )]
    pub id: Option<i64>,
    /// File name the document will arrive under.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub filename: Option<String>,
    /// Rendering state, carried verbatim.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
}

/// The rendered document (`pdf.get`).
///
/// ```
/// use inwx_client::PdfFile;
///
/// let file: PdfFile = serde_json::from_str(
///     r#"{"filename":"invoice.pdf","content":"JVBERi0xLjc=","mimeType":"application/pdf"}"#,
/// )?;
/// assert_eq!(&file.bytes()?[..5], b"%PDF-");
/// assert_eq!(file.mime_type.as_deref(), Some("application/pdf"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct PdfFile {
    /// File name, when the API sends one.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub filename: Option<String>,
    /// Base64-encoded body.
    #[serde(
        default,
        rename = "content",
        alias = "pdf",
        deserialize_with = "de::opt_string"
    )]
    pub content: Option<String>,
    /// MIME type, when the API reports one.
    #[serde(
        default,
        rename = "mimeType",
        alias = "mime_type",
        deserialize_with = "de::opt_string"
    )]
    pub mime_type: Option<String>,
    /// Raw text, when the request asked for `RAW`.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub raw: Option<String>,
}

impl PdfFile {
    /// Decodes the body, refusing anything larger than
    /// [`MAX_DOCUMENT_BYTES`] or not base64.
    ///
    /// ```
    /// use inwx_client::PdfFile;
    ///
    /// let file: PdfFile = serde_json::from_str(r#"{"content":"aGk="}"#)?;
    /// assert_eq!(file.bytes()?, b"hi");
    ///
    /// let empty = PdfFile::default();
    /// assert!(empty.bytes().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when there is no body, it is too large, or it is
    /// not base64.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let encoded = self.content.as_deref().ok_or_else(|| {
            Error::validation("pdf.content", "the answer carries no document body")
        })?;
        check_pdf_size(encoded.len())?;
        decode_base64("pdf.content", encoded)
    }
}

/// Largest base64 body this crate is willing to decode.
///
/// Base64 grows its input by four thirds, so the limit on the decoded document
/// becomes a limit on the string length — checked before `base64` allocates the
/// decoded copy.
const MAX_ENCODED_LEN: usize = MAX_DOCUMENT_BYTES.div_ceil(3) * 4;

/// Refuses an oversized body before decoding it.
fn check_pdf_size(encoded_len: usize) -> Result<()> {
    if encoded_len > MAX_ENCODED_LEN {
        return Err(Error::validation(
            "pdf.content",
            format!(
                "is {encoded_len} encoded bytes, above the {MAX_ENCODED_LEN} byte limit \
                 ({MAX_DOCUMENT_BYTES} decoded bytes)"
            ),
        ));
    }
    Ok(())
}

impl<T: Transport> InwxClient<T> {
    /// Asks INWX to render a document (`pdf.document`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, PdfRender, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let handle = client.render_pdf(&PdfRender::new("invoice", 4711)?).await?;
    /// println!("{:?} {:?}", handle.id, handle.filename);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable class token, id or date range, plus
    /// the usual transport and API errors.
    pub async fn render_pdf(&self, render: &PdfRender) -> Result<PdfHandle> {
        let params = render.params()?;
        let data = self.call("pdf.document", params).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Fetches a rendered document (`pdf.get`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let file = client.fetch_pdf(99).await?;
    /// std::fs::write("invoice.pdf", file.bytes()?)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive handle or an undecodable body,
    /// plus the usual transport and API errors.
    pub async fn fetch_pdf(&self, pdf_id: i64) -> Result<PdfFile> {
        validate_id("pdf.id", pdf_id)?;
        let data = self.call("pdf.get", json!({ "pdfId": pdf_id })).await?;
        serde_json::from_value(data).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_type_token_of_64_characters_is_accepted_and_65_is_not() {
        let ok = "T".repeat(64);
        assert!(PdfRender::new(&ok, 1).is_ok());
        assert!(PdfRender::new(format!("T{ok}"), 1).is_err());
    }

    #[test]
    fn ids_must_be_positive() {
        assert!(PdfRender::new("invoice", 1).is_ok());
        assert!(PdfRender::new("invoice", 0).is_err());
        assert!(PdfRender::new("invoice", -1).is_err());
    }

    #[test]
    fn a_period_only_makes_sense_forward() {
        let from = Timestamp::parse("2026-02-01T00:00:00").unwrap();
        let to = Timestamp::parse("2026-01-01T00:00:00").unwrap();
        assert!(PdfRender::new("statement", 1)
            .unwrap()
            .with_from(from.clone())
            .with_to(to.clone())
            .params()
            .is_err());
        assert!(PdfRender::new("statement", 1)
            .unwrap()
            .with_from(to)
            .with_to(from)
            .params()
            .is_ok());
    }

    #[test]
    fn csv_is_not_a_document_format() {
        assert!(PdfRender::new("invoice", 1)
            .unwrap()
            .with_format(DocumentFormat::Csv)
            .is_err());
        assert!(PdfRender::new("invoice", 1)
            .unwrap()
            .with_format(DocumentFormat::Pdf)
            .is_ok());
    }

    #[test]
    fn bodies_are_decoded_or_refused() {
        let file: PdfFile = serde_json::from_str(r#"{"pdf": "aGk="}"#).unwrap();
        assert_eq!(file.bytes().unwrap(), b"hi");

        let huge = PdfFile {
            content: Some("A".repeat(MAX_ENCODED_LEN + 1)),
            ..PdfFile::default()
        };
        assert!(huge.bytes().is_err());
    }

    #[test]
    fn the_last_accepted_body_is_one_byte_bigger_than_the_first_rejected() {
        assert!(check_pdf_size(MAX_ENCODED_LEN).is_ok());
        assert!(check_pdf_size(MAX_ENCODED_LEN + 1).is_err());
        assert!(check_pdf_size(0).is_ok());
    }
}
