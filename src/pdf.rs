//! Generated PDFs (`pdf.document`, `pdf.get`): documents the API renders on
//! demand — invoices, statements, contracts.
//!
//! `pdf.document` asks INWX to render a document and answers with a handle;
//! `pdf.get` fetches the bytes for that handle once it is [`PdfStatus::Ready`].
//! Both are read-only, so neither needs an acknowledgement — but the body is
//! base64, and the crate decodes it rather than handing back a string the caller
//! has to parse again.
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

use std::fmt;
use std::io::Read as _;

use base64::read::DecoderReader;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::document::MAX_DOCUMENT_BYTES;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, validate_id, validate_upper_token, DocumentFormat, Timestamp};

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
    /// rendering. [`DocumentFormat::Raw`] and [`DocumentFormat::Csv`] belong
    /// to text exports, not PDF rendering.
    ///
    /// ```
    /// use inwx_client::{DocumentFormat, PdfRender};
    ///
    /// let render = PdfRender::new("invoice", 1)?.with_format(DocumentFormat::Pdf)?;
    /// assert_eq!(render.params()?["format"], "PDF");
    /// assert!(PdfRender::new("invoice", 1)?.with_format(DocumentFormat::Raw).is_err());
    /// assert!(PdfRender::new("invoice", 1)?.with_format(DocumentFormat::Csv).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_format(mut self, format: DocumentFormat) -> Result<Self> {
        if format != DocumentFormat::Pdf {
            return Err(Error::validation(
                "pdf.format",
                "only PDF is a document format; RAW and CSV are text export formats",
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
    /// Rendering state, carried verbatim for forward compatibility. Prefer
    /// [`PdfHandle::status`] and [`PdfHandle::ready_id`] when the state must be
    /// interpreted.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
}

/// Rendering state of a [`PdfHandle`].
///
/// ```
/// use inwx_client::PdfStatus;
///
/// assert_eq!(PdfStatus::parse("ready")?, PdfStatus::Ready);
/// assert_eq!(PdfStatus::parse("error")?, PdfStatus::Failed);
/// assert_eq!(
///     PdfStatus::parse("SOMETHING_NEW")?,
///     PdfStatus::Other("SOMETHING_NEW".into())
/// );
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PdfStatus {
    /// The document is rendered and ready for [`InwxClient::fetch_pdf`].
    Ready,
    /// The render is still in progress; wait before fetching.
    Pending,
    /// The render failed and no usable document should be fetched.
    Failed,
    /// A status this crate does not know; carried verbatim, upper-cased.
    Other(String),
}

impl PdfStatus {
    /// Parses a PDF render status, upper-casing it.
    ///
    /// `ERROR` is treated as the same failure state as `FAILED`, and an unknown
    /// value is carried as [`PdfStatus::Other`].
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the input is empty.
    ///
    /// ```
    /// use inwx_client::PdfStatus;
    ///
    /// assert_eq!(PdfStatus::parse("pending")?, PdfStatus::Pending);
    /// assert_eq!(PdfStatus::parse("FAILED")?, PdfStatus::Failed);
    /// assert!(PdfStatus::parse("   ").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn parse(input: &str) -> Result<Self> {
        let upper = input.trim().to_ascii_uppercase();
        if upper.is_empty() {
            return Err(Error::validation("pdf.status", "must not be empty"));
        }
        Ok(match upper.as_str() {
            "READY" => Self::Ready,
            "PENDING" => Self::Pending,
            "FAILED" | "ERROR" => Self::Failed,
            _ => Self::Other(upper),
        })
    }

    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::PdfStatus;
    ///
    /// assert_eq!(PdfStatus::Ready.as_str(), "READY");
    /// assert_eq!(PdfStatus::Other("NEW".into()).as_str(), "NEW");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ready => "READY",
            Self::Pending => "PENDING",
            Self::Failed => "FAILED",
            Self::Other(raw) => raw,
        }
    }
}

impl fmt::Display for PdfStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for PdfStatus {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl PdfHandle {
    /// The typed rendering status of the handle.
    ///
    /// The raw [`status`](Self::status) field is kept verbatim; this method
    /// interprets the states this crate knows while leaving future states in
    /// [`PdfStatus::Other`].
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedAnswer`] when the answer carried no render status, or
    /// [`Error::Validation`] when the status was blank.
    ///
    /// ```
    /// use inwx_client::{PdfHandle, PdfStatus};
    ///
    /// let handle: PdfHandle = serde_json::from_str(r#"{"status":"READY"}"#)?;
    /// assert_eq!(handle.status()?, PdfStatus::Ready);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn status(&self) -> Result<PdfStatus> {
        let raw = self.status.as_deref().ok_or_else(|| {
            Error::unexpected_answer(
                "pdf.document",
                "status",
                "the answer carries no render status; wait until the handle is READY",
            )
        })?;
        PdfStatus::parse(raw)
    }

    /// The `pdfId` to pass to [`InwxClient::fetch_pdf`], but only when the
    /// render has reached [`PdfStatus::Ready`].
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedAnswer`] when the handle has no positive numeric id,
    /// no status, or a status other than `READY`; [`Error::Validation`] when
    /// the raw status is blank. A pending render must be checked again before
    /// fetching, and a failed render has no usable document.
    ///
    /// ```
    /// use inwx_client::{Error, PdfHandle, PdfStatus};
    ///
    /// let ready: PdfHandle =
    ///     serde_json::from_str(r#"{"pdfId":"99","status":"READY"}"#)?;
    /// assert_eq!(ready.ready_id()?, 99);
    ///
    /// let pending: PdfHandle =
    ///     serde_json::from_str(r#"{"pdfId":"99","status":"PENDING"}"#)?;
    /// assert!(matches!(
    ///     pending.ready_id(),
    ///     Err(Error::UnexpectedAnswer { field: "status", .. })
    /// ));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn ready_id(&self) -> Result<i64> {
        let id = self.id.filter(|id| *id > 0).ok_or_else(|| {
            Error::unexpected_answer(
                "pdf.document",
                "pdfId",
                "the answer carries no usable pdfId; the render may still exist, so inspect it before rendering again",
            )
        })?;
        match self.status()? {
            PdfStatus::Ready => Ok(id),
            PdfStatus::Pending => Err(Error::unexpected_answer(
                "pdf.document",
                "status",
                "the render is still pending; wait until READY before calling fetch_pdf",
            )),
            PdfStatus::Failed => Err(Error::unexpected_answer(
                "pdf.document",
                "status",
                "the render failed; do not call fetch_pdf for this handle",
            )),
            PdfStatus::Other(raw) => Err(Error::unexpected_answer(
                "pdf.document",
                "status",
                format!("status {raw:?} is not READY; fetch only after a READY status"),
            )),
        }
    }
}

/// The rendered document (`pdf.get`).
///
/// The body is deliberately not printed: `Debug` shows the file name, the MIME
/// type and the encoded length of `content`, never the base64 text itself. That
/// text carries a customer's invoice, contract or account statement, and a
/// derived `Debug` used to dump megabytes of it into every log line.
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
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
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
}

/// `Debug` without the body: a document is often a person's invoice or account
/// statement, so only the encoded length of `content` is printed.
impl fmt::Debug for PdfFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PdfFile")
            .field("filename", &self.filename)
            .field(
                "content",
                &format_args!(
                    "{} encoded bytes",
                    self.content.as_deref().map_or(0, str::len)
                ),
            )
            .field("mime_type", &self.mime_type)
            .finish()
    }
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
        decode_pdf_base64(encoded)
    }
}

/// Largest base64 body this crate is willing to decode before the decoded
/// length is checked.
///
/// Base64 grows its input by four thirds, so the limit on the decoded document
/// becomes a limit on the string length — checked before `base64` allocates the
/// decoded copy. The decoded length is still the authoritative check: this
/// encoded length alone cannot distinguish `MAX_DOCUMENT_BYTES`,
/// `MAX_DOCUMENT_BYTES + 1` and `MAX_DOCUMENT_BYTES + 2`, which all encode to
/// the same number of base64 characters.
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

/// Decodes a PDF body, refusing more than [`MAX_DOCUMENT_BYTES`] once decoded.
fn decode_pdf_base64(encoded: &str) -> Result<Vec<u8>> {
    check_pdf_size(encoded.len())?;
    let encoded = encoded.trim();
    let decoder = DecoderReader::new(
        encoded.as_bytes(),
        &base64::engine::general_purpose::STANDARD,
    );
    let limit = u64::try_from(MAX_DOCUMENT_BYTES.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    decoder
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            Error::validation("pdf.content", format!("is not valid base64: {error}"))
        })?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::validation(
            "pdf.content",
            format!(
                "exceeds the {MAX_DOCUMENT_BYTES} byte decoded document limit ({} bytes read)",
                bytes.len(),
            ),
        ));
    }
    Ok(bytes)
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
    /// println!("{:?} {:?} {:?}", handle.id, handle.filename, handle.status);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable class token, id or date range, plus
    /// the usual transport and API errors. A success whose answer carries no
    /// positive numeric `pdfId` is [`Error::UnexpectedAnswer`], because the
    /// render may exist but cannot be fetched; inspect the render state before
    /// asking for another one.
    pub async fn render_pdf(&self, render: &PdfRender) -> Result<PdfHandle> {
        let params = render.params()?;
        let data = self.call("pdf.document", params).await?;
        let handle: PdfHandle = serde_json::from_value(data).map_err(Error::from)?;
        if handle.id.is_none_or(|id| id <= 0) {
            return Err(Error::unexpected_answer(
                "pdf.document",
                "pdfId",
                "the answer carries no usable pdfId, so the rendered document cannot be fetched; inspect the render state before rendering again",
            ));
        }
        Ok(handle)
    }

    /// Fetches a rendered document (`pdf.get`).
    ///
    /// The caller must wait until the handle reaches [`PdfStatus::Ready`] and
    /// pass [`PdfHandle::ready_id`]; this method only performs the fetch.
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
    /// [`Error::Validation`] for a non-positive handle or a payload that does
    /// not fit the model, plus the usual transport and API errors.
    pub async fn fetch_pdf(&self, pdf_id: i64) -> Result<PdfFile> {
        validate_id("pdf.id", pdf_id)?;
        let data = self.call("pdf.get", json!({ "pdfId": pdf_id })).await?;
        serde_json::from_value(data).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::encode_base64;

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
    fn only_pdf_is_a_document_format() {
        assert!(PdfRender::new("invoice", 1)
            .unwrap()
            .with_format(DocumentFormat::Csv)
            .is_err());
        assert!(PdfRender::new("invoice", 1)
            .unwrap()
            .with_format(DocumentFormat::Raw)
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
    fn the_encoded_length_guard_accepts_the_padded_maximum() {
        assert!(check_pdf_size(MAX_ENCODED_LEN).is_ok());
        assert!(check_pdf_size(MAX_ENCODED_LEN + 1).is_err());
        assert!(check_pdf_size(0).is_ok());
    }

    #[test]
    fn decoded_documents_are_limited_at_the_documented_boundary() {
        for (len, accepted) in [
            (MAX_DOCUMENT_BYTES, true),
            (MAX_DOCUMENT_BYTES + 1, false),
            (MAX_DOCUMENT_BYTES + 2, false),
        ] {
            let body = vec![b'x'; len];
            let file = PdfFile {
                content: Some(encode_base64(&body)),
                ..PdfFile::default()
            };
            let decoded = file.bytes();
            assert_eq!(decoded.is_ok(), accepted, "{len} decoded bytes");
            if let Ok(bytes) = decoded {
                assert_eq!(bytes.len(), len);
            }
        }
    }

    #[test]
    fn debug_never_prints_the_document_body() {
        let body = "JVBERi0xLjQK";
        let file = PdfFile {
            filename: Some("invoice.pdf".to_owned()),
            content: Some(body.to_owned()),
            mime_type: Some("application/pdf".to_owned()),
        };
        let debug = format!("{file:?}");
        assert!(!debug.contains(body));
        assert!(!debug.contains("JVBERi0x"));
        assert!(debug.contains("invoice.pdf"));
        assert!(debug.contains("application/pdf"));
        assert!(debug.contains(&format!("{} encoded bytes", body.len())));
    }

    #[test]
    fn debug_of_an_empty_body_reports_zero_encoded_bytes() {
        assert!(format!("{:?}", PdfFile::default()).contains("0 encoded bytes"));
    }

    #[test]
    fn pdf_statuses_parse_known_values_and_carry_unknown_ones() {
        for (raw, expected) in [
            ("ready", PdfStatus::Ready),
            ("READY", PdfStatus::Ready),
            (" pending ", PdfStatus::Pending),
            ("FAILED", PdfStatus::Failed),
            ("error", PdfStatus::Failed),
            ("NEW_STATE", PdfStatus::Other("NEW_STATE".into())),
        ] {
            assert_eq!(PdfStatus::parse(raw).unwrap(), expected);
        }
        assert!(PdfStatus::parse("   ").is_err());
    }

    #[test]
    fn a_ready_handle_has_a_fetchable_id() {
        let ready: PdfHandle = serde_json::from_str(r#"{"pdfId":"99","status":"READY"}"#).unwrap();
        assert_eq!(ready.status().unwrap(), PdfStatus::Ready);
        assert_eq!(ready.ready_id().unwrap(), 99);

        let one: PdfHandle = serde_json::from_str(r#"{"pdfId":"1","status":"ready"}"#).unwrap();
        assert_eq!(one.ready_id().unwrap(), 1);

        let zero: PdfHandle = serde_json::from_str(r#"{"pdfId":"0","status":"READY"}"#).unwrap();
        assert!(matches!(
            zero.ready_id(),
            Err(Error::UnexpectedAnswer { field: "pdfId", .. })
        ));
    }

    #[test]
    fn a_handle_is_not_fetchable_until_ready() {
        for (raw, message) in [
            ("PENDING", "still pending"),
            ("FAILED", "render failed"),
            ("ERROR", "render failed"),
            ("FUTURE", "not READY"),
        ] {
            let handle: PdfHandle =
                serde_json::from_str(&format!(r#"{{"pdfId":99,"status":"{raw}"}}"#)).unwrap();
            let error = handle.ready_id().unwrap_err();
            assert!(matches!(
                error,
                Error::UnexpectedAnswer {
                    field: "status",
                    ..
                }
            ));
            assert!(error.to_string().contains(message), "{raw}: {error}");
        }

        let missing = PdfHandle::default();
        assert!(matches!(
            missing.status(),
            Err(Error::UnexpectedAnswer {
                field: "status",
                ..
            })
        ));
        assert!(matches!(
            missing.ready_id(),
            Err(Error::UnexpectedAnswer { field: "pdfId", .. })
        ));
    }
}
