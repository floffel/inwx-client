//! Reseller documents (`document.*`): files a reseller stores at INWX —
//! proofs, mandates, attachments for an application.
//!
//! Four methods: upload a file, list what is stored, download one and delete
//! one. Uploads are the risky direction, so the crate checks the file name
//! (never a path), refuses an empty body and validates the size *before* it
//! base64-encodes anything.
//!
//! ```
//! use inwx_client::DocumentUpload;
//!
//! let upload = DocumentUpload::new("mandate.pdf", b"%PDF-1.7 mandate")?
//!     .with_document_type("mandate")?
//!     .with_customer_number(123456)?;
//!
//! let params = upload.params();
//! assert_eq!(params["filename"], "mandate.pdf");
//! assert_eq!(params["type"], "MANDATE");
//! # Ok::<(), inwx_client::Error>(())
//! ```

use std::fmt;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{
    de, decode_base64, encode_base64, parse_rows, validate_filename, validate_id,
    validate_page_limit, validate_text, validate_upper_token, DomainName,
};

/// Largest document body this crate accepts, before encoding.
///
/// The check runs on the bytes the caller already has, so an accidental
/// multi-gigabyte upload fails locally instead of being base64-encoded into a
/// 32 MiB JSON string first.
///
/// ```
/// use inwx_client::{DocumentUpload, MAX_DOCUMENT_BYTES};
///
/// assert_eq!(MAX_DOCUMENT_BYTES, 16 * 1024 * 1024);
/// assert!(DocumentUpload::new("a.pdf", &vec![0u8; MAX_DOCUMENT_BYTES]).is_ok());
/// assert!(DocumentUpload::new("a.pdf", &vec![0u8; MAX_DOCUMENT_BYTES + 1]).is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

/// Longest type token this crate accepts for a document.
const MAX_TYPE_LEN: usize = 64;
/// Longest comment this crate sends with a document.
const MAX_COMMENT_LEN: usize = 4096;

/// One stored document, as listed by `document.list`.
///
/// ```
/// use inwx_client::DocumentEntry;
///
/// let entry: DocumentEntry = serde_json::from_str(
///     r#"{"id":81,"filename":"mandate.pdf","type":"MANDATE","size":10240,"read":0}"#,
/// )?;
/// assert_eq!(entry.id, Some(81));
/// assert_eq!(entry.size, Some(10_240));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DocumentEntry {
    /// Document id, used by `download` and `delete`.
    #[serde(
        default,
        rename = "documentId",
        alias = "id",
        deserialize_with = "de::opt_i64"
    )]
    pub id: Option<i64>,
    /// Stored file name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub filename: Option<String>,
    /// Document class, carried verbatim.
    #[serde(default, rename = "type", deserialize_with = "de::opt_string")]
    pub document_type: Option<String>,
    /// MIME type, when the API reports one.
    #[serde(
        default,
        rename = "mimeType",
        alias = "mime_type",
        deserialize_with = "de::opt_string"
    )]
    pub mime_type: Option<String>,
    /// Size in bytes.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub size: Option<i64>,
    /// Owning customer.
    #[serde(
        default,
        rename = "customerNumber",
        alias = "customer_number",
        deserialize_with = "de::opt_i64"
    )]
    pub customer_number: Option<i64>,
    /// Domain the document belongs to, when it names one.
    #[serde(
        default,
        rename = "domainName",
        alias = "domain",
        deserialize_with = "de::opt_string"
    )]
    pub domain: Option<String>,
    /// Upload date, as text.
    #[serde(
        default,
        rename = "createdAt",
        alias = "created_at",
        deserialize_with = "de::opt_string"
    )]
    pub created_at: Option<String>,
    /// State of the document, carried verbatim.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub status: Option<String>,
    /// Whether the document has been read.
    #[serde(default, rename = "read", deserialize_with = "de::opt_bool")]
    pub read: Option<bool>,
}

/// The `document.upload` request: a file name, a body and optional metadata.
///
/// The body is deliberately absent from `Debug` — documents are mandates and
/// ID copies, and a struct printed in a log line must not carry them.
///
/// ```
/// use inwx_client::DocumentUpload;
///
/// let upload = DocumentUpload::new("id-copy.pdf", b"%PDF-1.7 copy")?;
/// assert_eq!(upload.params()["filename"], "id-copy.pdf");
/// let printed = format!("{upload:?}");
/// assert!(printed.contains("content: 13 bytes"), "{printed}");
/// assert!(!printed.contains("PDF"), "{printed}");
/// assert!(DocumentUpload::new("../etc/passwd", b"x").is_err());
/// assert!(DocumentUpload::new("a.pdf", b"").is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct DocumentUpload {
    filename: String,
    content: Vec<u8>,
    document_type: Option<String>,
    customer_number: Option<i64>,
    domain: Option<DomainName>,
    comment: Option<String>,
    testing: bool,
}

impl DocumentUpload {
    /// Uploads `content` under `filename`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the file name is empty, longer than 255
    /// characters, contains a path separator or control characters, or when the
    /// body is empty or larger than [`MAX_DOCUMENT_BYTES`].
    ///
    /// ```
    /// use inwx_client::{DocumentUpload, MAX_DOCUMENT_BYTES};
    ///
    /// assert!(DocumentUpload::new("note.txt", b"hello").is_ok());
    /// assert!(DocumentUpload::new("dir/note.txt", b"hello").is_err());
    /// assert!(DocumentUpload::new("note.txt", &vec![0u8; MAX_DOCUMENT_BYTES + 1]).is_err());
    /// ```
    pub fn new(filename: impl Into<String>, content: &[u8]) -> Result<Self> {
        let filename = validate_filename("document.filename", &filename.into())?;
        if content.is_empty() {
            return Err(Error::validation(
                "document.content",
                "must not be empty — upload nothing or upload a file",
            ));
        }
        if content.len() > MAX_DOCUMENT_BYTES {
            return Err(Error::validation(
                "document.content",
                format!(
                    "is {} bytes, and the limit is {MAX_DOCUMENT_BYTES}",
                    content.len()
                ),
            ));
        }
        Ok(Self {
            filename,
            content: content.to_vec(),
            document_type: None,
            customer_number: None,
            domain: None,
            comment: None,
            testing: false,
        })
    }

    /// Sets the document class (`type`, upper-cased).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or oddly shaped class token.
    ///
    /// ```
    /// use inwx_client::DocumentUpload;
    ///
    /// let upload = DocumentUpload::new("a.pdf", b"x")?.with_document_type(" mandate ")?;
    /// assert_eq!(upload.params()["type"], "MANDATE");
    /// assert!(DocumentUpload::new("a.pdf", b"x")?.with_document_type("a b").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_document_type(mut self, document_type: impl Into<String>) -> Result<Self> {
        self.document_type = Some(validate_upper_token(
            "document.type",
            &document_type.into(),
            MAX_TYPE_LEN,
        )?);
        Ok(self)
    }

    /// Sets the owning customer.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive customer number.
    ///
    /// ```
    /// use inwx_client::DocumentUpload;
    ///
    /// let upload = DocumentUpload::new("a.pdf", b"x")?.with_customer_number(123456)?;
    /// assert_eq!(upload.params()["customerNumber"], 123456);
    /// assert!(DocumentUpload::new("a.pdf", b"x")?.with_customer_number(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer_number(mut self, customer_number: i64) -> Result<Self> {
        self.customer_number = Some(validate_id("customer.number", customer_number)?);
        Ok(self)
    }

    /// Sets the domain the document belongs to.
    ///
    /// ```
    /// use inwx_client::{DocumentUpload, DomainName};
    ///
    /// let upload = DocumentUpload::new("a.pdf", b"x")?
    ///     .with_domain(DomainName::parse("example.com")?);
    /// assert_eq!(upload.params()["domainName"], "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_domain(mut self, domain: DomainName) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Sets a comment for the people reviewing the document.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the comment is empty or too long.
    ///
    /// ```
    /// use inwx_client::DocumentUpload;
    ///
    /// let upload = DocumentUpload::new("a.pdf", b"x")?.with_comment("signed 2026-03-01")?;
    /// assert_eq!(upload.params()["comment"], "signed 2026-03-01");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_comment(mut self, comment: impl Into<String>) -> Result<Self> {
        let comment = comment.into();
        validate_text("document.comment", &comment, MAX_COMMENT_LEN)?;
        self.comment = Some(comment);
        Ok(self)
    }

    /// Marks the call as a dry run (`testing`).
    ///
    /// ```
    /// use inwx_client::DocumentUpload;
    ///
    /// let upload = DocumentUpload::new("a.pdf", b"x").unwrap().with_testing(true);
    /// assert_eq!(upload.params()["testing"], true);
    /// ```
    #[must_use]
    pub fn with_testing(mut self, testing: bool) -> Self {
        self.testing = testing;
        self
    }

    /// The `document.upload` parameters, with the body base64-encoded.
    ///
    /// ```
    /// use inwx_client::DocumentUpload;
    ///
    /// let params = DocumentUpload::new("a.txt", b"hi")?.params();
    /// assert_eq!(params["content"], "aGk=");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut params = Map::new();
        params.insert("filename".to_owned(), json!(self.filename));
        params.insert("content".to_owned(), json!(encode_base64(&self.content)));
        if let Some(document_type) = &self.document_type {
            params.insert("type".to_owned(), json!(document_type));
        }
        if let Some(customer_number) = self.customer_number {
            params.insert("customerNumber".to_owned(), json!(customer_number));
        }
        if let Some(domain) = &self.domain {
            params.insert("domainName".to_owned(), json!(domain.as_str()));
        }
        if let Some(comment) = &self.comment {
            params.insert("comment".to_owned(), json!(comment));
        }
        if self.testing {
            params.insert("testing".to_owned(), json!(true));
        }
        Value::Object(params)
    }
}

/// `Debug` without the body: a document is often a person's ID copy.
impl fmt::Debug for DocumentUpload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DocumentUpload")
            .field("filename", &self.filename)
            .field("content", &format_args!("{} bytes", self.content.len()))
            .field("document_type", &self.document_type)
            .field("customer_number", &self.customer_number)
            .field("domain", &self.domain)
            .field("comment", &self.comment)
            .field("testing", &self.testing)
            .finish()
    }
}

/// A downloaded document (`document.download`).
///
/// ```
/// use inwx_client::DownloadedDocument;
///
/// let document: DownloadedDocument = serde_json::from_str(
///     r#"{"filename":"mandate.pdf","content":"JVBERi0xLjc=","mimeType":"application/pdf"}"#,
/// )?;
/// assert_eq!(document.filename.as_deref(), Some("mandate.pdf"));
/// assert_eq!(&document.bytes()?[..5], b"%PDF-");
/// assert!(document.is_pdf());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DownloadedDocument {
    /// Document id, when the API echoes it.
    #[serde(
        default,
        rename = "documentId",
        alias = "id",
        deserialize_with = "de::opt_i64"
    )]
    pub id: Option<i64>,
    /// Stored file name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub filename: Option<String>,
    /// Base64-encoded body.
    #[serde(
        default,
        rename = "content",
        alias = "data",
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
    /// Size in bytes, when the API reports one.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub size: Option<i64>,
}

impl DownloadedDocument {
    /// Decodes the body.
    ///
    /// ```
    /// use inwx_client::DownloadedDocument;
    ///
    /// let good: DownloadedDocument = serde_json::from_str(r#"{"content":"aGk="}"#)?;
    /// assert_eq!(good.bytes()?, b"hi");
    ///
    /// let broken: DownloadedDocument = serde_json::from_str(r#"{"content":"!!!not base64!!!"}"#)?;
    /// assert!(broken.bytes().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when there is no body or it is not base64.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let encoded = self.content.as_deref().ok_or_else(|| {
            Error::validation("document.content", "the answer carries no document body")
        })?;
        decode_base64("document.content", encoded)
    }

    /// Whether the body looks like a PDF, by file name or magic bytes.
    ///
    /// ```
    /// use inwx_client::DownloadedDocument;
    ///
    /// let document: DownloadedDocument =
    ///     serde_json::from_str(r#"{"filename":"x.pdf","content":"JVBERi0xLjc="}"#)?;
    /// assert!(document.is_pdf());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn is_pdf(&self) -> bool {
        if self
            .filename
            .as_deref()
            .is_some_and(|name| name.to_ascii_lowercase().ends_with(".pdf"))
        {
            return true;
        }
        self.bytes().is_ok_and(|bytes| bytes.starts_with(b"%PDF-"))
    }
}

/// A search + paging for `document.list`.
///
/// ```
/// use inwx_client::DocumentQuery;
///
/// let query = DocumentQuery::new()
///     .with_document_type("mandate")?
///     .with_customer_number(123456)?
///     .with_page(1, 20)?;
/// let params = query.params()?;
/// assert_eq!(params["type"], "MANDATE");
/// assert_eq!(params["pagelimit"], 20);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DocumentQuery {
    document_type: Option<String>,
    customer_number: Option<i64>,
    domain: Option<DomainName>,
    filename: Option<String>,
    page: Option<u32>,
    limit: Option<u32>,
}

impl DocumentQuery {
    /// An unfiltered query.
    ///
    /// ```
    /// use inwx_client::DocumentQuery;
    /// assert!(DocumentQuery::new().params().unwrap().is_object());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by document class, upper-cased.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or oddly shaped class token.
    ///
    /// ```
    /// use inwx_client::DocumentQuery;
    ///
    /// assert_eq!(DocumentQuery::new().with_document_type("mandate")?.params()?["type"], "MANDATE");
    /// assert!(DocumentQuery::new().with_document_type("").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_document_type(mut self, document_type: impl Into<String>) -> Result<Self> {
        self.document_type = Some(validate_upper_token(
            "document.type",
            &document_type.into(),
            MAX_TYPE_LEN,
        )?);
        Ok(self)
    }

    /// Filters by owning customer.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive customer number.
    ///
    /// ```
    /// use inwx_client::DocumentQuery;
    /// assert!(DocumentQuery::new().with_customer_number(1).is_ok());
    /// assert!(DocumentQuery::new().with_customer_number(0).is_err());
    /// ```
    pub fn with_customer_number(mut self, customer_number: i64) -> Result<Self> {
        self.customer_number = Some(validate_id("customer.number", customer_number)?);
        Ok(self)
    }

    /// Filters by domain.
    ///
    /// ```
    /// use inwx_client::{DocumentQuery, DomainName};
    ///
    /// let query = DocumentQuery::new().with_domain(DomainName::parse("example.com")?);
    /// assert_eq!(query.params()?["domainName"], "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_domain(mut self, domain: DomainName) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Filters by file name.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name is empty or contains a path separator.
    ///
    /// ```
    /// use inwx_client::DocumentQuery;
    ///
    /// assert_eq!(DocumentQuery::new().with_filename("a.pdf")?.params()?["filename"], "a.pdf");
    /// assert!(DocumentQuery::new().with_filename("a/b.pdf").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_filename(mut self, filename: impl Into<String>) -> Result<Self> {
        self.filename = Some(validate_filename("document.filename", &filename.into())?);
        Ok(self)
    }

    /// Sets the page (1-based) and the page size.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the page size is zero.
    ///
    /// ```
    /// use inwx_client::DocumentQuery;
    ///
    /// assert_eq!(DocumentQuery::new().with_page(1, 1)?.params()?["pagelimit"], 1);
    /// assert!(DocumentQuery::new().with_page(1, 0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_page(mut self, page: u32, limit: u32) -> Result<Self> {
        self.limit = Some(validate_page_limit(limit)?);
        self.page = Some(page.max(1));
        Ok(self)
    }

    /// The `document.list` parameters.
    ///
    /// # Errors
    ///
    /// Never fails today: every value is validated when it is set, so the
    /// parameters are always sendable. The `Result` keeps the shape of the
    /// builders that can refuse a value.
    ///
    /// ```
    /// use inwx_client::DocumentQuery;
    /// assert!(DocumentQuery::new().params().unwrap().is_object());
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut params = Map::new();
        if let Some(document_type) = &self.document_type {
            params.insert("type".to_owned(), json!(document_type));
        }
        if let Some(customer_number) = self.customer_number {
            params.insert("customerNumber".to_owned(), json!(customer_number));
        }
        if let Some(domain) = &self.domain {
            params.insert("domainName".to_owned(), json!(domain.as_str()));
        }
        if let Some(filename) = &self.filename {
            params.insert("filename".to_owned(), json!(filename));
        }
        params.insert("page".to_owned(), json!(self.page.unwrap_or(1)));
        params.insert("pagelimit".to_owned(), json!(self.limit.unwrap_or(50)));
        Ok(Value::Object(params))
    }
}

impl<T: Transport> InwxClient<T> {
    /// Uploads a document (`document.upload`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DocumentUpload, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let upload = DocumentUpload::new("mandate.pdf", &std::fs::read("mandate.pdf")?)?
    ///     .with_document_type("mandate")?;
    /// let stored = client.upload_document(&upload).await?;
    /// println!("{:?}", stored.id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable file name or body, plus the usual
    /// transport and API errors.
    pub async fn upload_document(&self, upload: &DocumentUpload) -> Result<DocumentEntry> {
        let data = self.call("document.upload", upload.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Lists stored documents (`document.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DocumentQuery, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let query = DocumentQuery::new().with_page(1, 20)?;
    /// for document in client.list_documents(&query).await? {
    ///     println!("{:?} {:?}", document.id, document.filename);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the query carries a bad filter or page size,
    /// plus the usual transport and API errors.
    pub async fn list_documents(&self, query: &DocumentQuery) -> Result<Vec<DocumentEntry>> {
        let params = query.params()?;
        let data = self.call("document.list", params).await?;
        Ok(parse_rows(&data, "document"))
    }

    /// Downloads one document (`document.download`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let document = client.download_document(81).await?;
    /// let body = document.bytes()?;
    /// let name = document.filename.unwrap_or_else(|| "document.bin".to_owned());
    /// std::fs::write(name, body)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id or an undecodable body, plus
    /// the usual transport and API errors.
    pub async fn download_document(&self, document_id: i64) -> Result<DownloadedDocument> {
        validate_id("document.id", document_id)?;
        let data = self
            .call("document.download", json!({ "documentId": document_id }))
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Deletes one document (`document.delete`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.delete_document(81).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn delete_document(&self, document_id: i64) -> Result<()> {
        validate_id("document.id", document_id)?;
        self.call("document.delete", json!({ "documentId": document_id }))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_filename_of_255_characters_is_accepted_and_256_is_not() {
        let ok = "a".repeat(255);
        let too_long = format!("{ok}b");
        assert!(DocumentUpload::new(ok, b"x").is_ok());
        assert!(DocumentUpload::new(too_long, b"x").is_err());
    }

    #[test]
    fn the_last_accepted_size_is_one_byte_bigger_than_the_first_rejected() {
        assert!(DocumentUpload::new("a.bin", &vec![0u8; MAX_DOCUMENT_BYTES]).is_ok());
        assert!(DocumentUpload::new("a.bin", &vec![0u8; MAX_DOCUMENT_BYTES + 1]).is_err());
        assert!(DocumentUpload::new("a.bin", b"").is_err());
    }

    #[test]
    fn a_filename_is_never_a_path() {
        for bad in ["", " ", ".", "..", "dir/a.pdf", "dir\\a.pdf", "a\nb.pdf"] {
            assert!(DocumentUpload::new(bad, b"x").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ids_and_page_limits_are_checked_before_the_wire() {
        assert!(DocumentQuery::new().with_customer_number(0).is_err());
        assert!(DocumentQuery::new().with_page(1, 0).is_err());
        assert!(DocumentQuery::new().with_page(1, 1).is_ok());
    }

    #[test]
    fn the_body_never_reaches_debug() {
        let upload = DocumentUpload::new("id.pdf", b"secret-bytes").unwrap();
        let text = format!("{upload:?}");
        assert!(!text.contains("secret-bytes"), "{text}");
        assert!(text.contains("12 bytes"));
    }

    #[test]
    fn uploads_encode_the_body() {
        let params = DocumentUpload::new("a.txt", b"hi")
            .unwrap()
            .with_document_type("note")
            .unwrap()
            .params();
        assert_eq!(params["content"], "aGk=");
        assert_eq!(params["type"], "NOTE");
        assert!(params.get("testing").is_none());
    }

    #[test]
    fn documents_are_parsed_permissively() {
        let entry: DocumentEntry =
            serde_json::from_str(r#"{"documentId":"81","mimeType":"application/pdf"}"#).unwrap();
        assert_eq!(entry.id, Some(81));
        assert_eq!(entry.mime_type.as_deref(), Some("application/pdf"));

        let snake: DocumentEntry =
            serde_json::from_str(r#"{"id":81,"mime_type":"application/pdf"}"#).unwrap();
        assert_eq!(snake.mime_type, entry.mime_type);
    }
}
