//! Documents (`document.*`): files a reseller stores at INWX — contracts,
//! signed PDFs, attachments.
//!
//! Four methods: `list`, `upload`, `download`, `delete`. Documents travel
//! base64-encoded, which the crate hides: [`DocumentUpload::new`] takes bytes
//! and encodes them after checking the size, [`DocumentDownload::bytes`]
//! decodes them after checking the encoded length. Nothing allocates a payload
//! the API could not have asked for.
//!
//! The object is described in the API documentation chapter 2 §2.21.
//!
//! ```
//! use inwx_client::DocumentSummary;
//!
//! let document: DocumentSummary = serde_json::from_str(
//!     r#"{"id":88,"name":"contract.pdf","mimeType":"application/pdf","size":1234}"#,
//! )?;
//! assert_eq!(document.id, Some(88));
//! assert_eq!(document.mime_type.as_deref(), Some("application/pdf"));
//! # Ok::<(), serde_json::Error>(())
//! ```

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::params::{self, ExtraFields};
use crate::transport::Transport;
use crate::types::{de, validate_token};

/// Keys owned by [`DocumentUpload`].
const UPLOAD_KEYS: &[&str] = &["name", "type", "data", "customer"];
/// One entry of `document.list`, or the summary `document.upload` answers with.
///
/// ```
/// use inwx_client::DocumentSummary;
///
/// let camel: DocumentSummary =
///     serde_json::from_str(r#"{"id":"88","mimeType":"text/plain","createdAt":"2026-10-01"}"#)?;
/// let snake: DocumentSummary =
///     serde_json::from_str(r#"{"id":88,"mime_type":"text/plain","created_at":"2026-10-01"}"#)?;
/// assert_eq!(camel, snake);
/// assert_eq!(camel.mime_type.as_deref(), Some("text/plain"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DocumentSummary {
    /// Document id, used by `download` and `delete`.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// File name as stored.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// MIME type of the stored file.
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
    /// Customer the document belongs to.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub customer: Option<i64>,
    /// Creation timestamp.
    #[serde(
        default,
        rename = "createdAt",
        alias = "created_at",
        deserialize_with = "de::opt_string"
    )]
    pub created_at: Option<String>,
    /// Fields this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// One page of `document.list`.
///
/// ```
/// use inwx_client::DocumentListPage;
///
/// let page: DocumentListPage = serde_json::from_str(
///     r#"{"count":2,"document":[{"id":1},{"id":2}]}"#,
/// )?;
/// assert_eq!(page.count, Some(2));
/// assert_eq!(page.len(), 2);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct DocumentListPage {
    /// Total number of documents, not just this page.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The documents on this page.
    #[serde(default, rename = "document", alias = "documents")]
    pub documents: Vec<DocumentSummary>,
}

impl DocumentListPage {
    /// Number of documents on this page.
    ///
    /// ```
    /// use inwx_client::DocumentListPage;
    /// let page: DocumentListPage = serde_json::from_str(r#"{"document":[{"id":1}]}"#)?;
    /// assert_eq!(page.len(), 1);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    /// Whether this page carries no document at all.
    ///
    /// ```
    /// use inwx_client::DocumentListPage;
    /// assert!(DocumentListPage::default().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }
}

/// The filter behind `document.list`.
///
/// ```
/// use inwx_client::DocumentQuery;
///
/// let query = DocumentQuery::new().with_page(1, 25)?;
/// assert_eq!(query.params()["pagelimit"], 25);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DocumentQuery {
    customer: Option<i64>,
    document_type: Option<String>,
    name: Option<String>,
    page: Option<u32>,
    limit: Option<u32>,
}

impl DocumentQuery {
    /// All documents of the reseller account.
    ///
    /// ```
    /// use inwx_client::DocumentQuery;
    /// assert_eq!(DocumentQuery::new().params(), serde_json::json!({}));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by customer id.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::DocumentQuery;
    /// assert!(DocumentQuery::new().with_customer(4711).is_ok());
    /// assert!(DocumentQuery::new().with_customer(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer(mut self, customer: i64) -> Result<Self> {
        self.customer = Some(params::object_id("customerId", customer)?);
        Ok(self)
    }

    /// Filters by document type.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::DocumentQuery;
    /// assert_eq!(
    ///     DocumentQuery::new().with_type("CONTRACT")?.params()["type"],
    ///     "CONTRACT"
    /// );
    /// assert!(DocumentQuery::new().with_type("").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_type(mut self, document_type: &str) -> Result<Self> {
        validate_token("document.type", document_type)?;
        self.document_type = Some(document_type.trim().to_owned());
        Ok(self)
    }

    /// Filters by file name.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::DocumentQuery;
    /// assert!(DocumentQuery::new().with_name("contract.pdf").is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_name(mut self, name: &str) -> Result<Self> {
        validate_token("document.name", name)?;
        self.name = Some(name.trim().to_owned());
        Ok(self)
    }

    /// Sets the page (1-based) and the page size.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the limit is `0` or above the crate's own
    /// ceiling of 1000 entries per page.
    ///
    /// ```
    /// use inwx_client::DocumentQuery;
    /// assert!(DocumentQuery::new().with_page(1, 1).is_ok());
    /// assert!(DocumentQuery::new().with_page(1, 1_000).is_ok());
    /// assert!(DocumentQuery::new().with_page(1, 1_001).is_err());
    /// assert!(DocumentQuery::new().with_page(1, 0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_page(mut self, page: u32, limit: u32) -> Result<Self> {
        let (page, limit) = params::paging(page, limit)?;
        self.page = Some(page);
        self.limit = Some(limit);
        Ok(self)
    }

    /// The `document.list` parameters.
    ///
    /// ```
    /// use inwx_client::DocumentQuery;
    /// let params = DocumentQuery::new().with_page(3, 10).unwrap().params();
    /// assert_eq!(params["page"], 3);
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut map = Map::new();
        if let Some(customer) = self.customer {
            map.insert("customer".to_owned(), json!(customer));
        }
        if let Some(document_type) = &self.document_type {
            map.insert("type".to_owned(), json!(document_type));
        }
        if let Some(name) = &self.name {
            map.insert("name".to_owned(), json!(name));
        }
        if let Some(page) = self.page {
            map.insert("page".to_owned(), json!(page));
        }
        if let Some(limit) = self.limit {
            map.insert("pagelimit".to_owned(), json!(limit));
        }
        Value::Object(map)
    }
}

/// A file to store (`document.upload`).
///
/// The payload is encoded once, at construction, so an oversized or empty blob
/// fails where it is written instead of after the request was built.
///
/// ```
/// use inwx_client::DocumentUpload;
///
/// let upload = DocumentUpload::new("contract.pdf", b"%PDF-1.4 contract")?
///     .with_mime_type("application/pdf")?
///     .with_customer(4711)?;
/// let params = upload.params();
/// assert_eq!(params["name"], "contract.pdf");
/// assert_eq!(upload.byte_len(), 17);
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct DocumentUpload {
    name: String,
    mime_type: Option<String>,
    customer: Option<i64>,
    encoded: String,
    bytes: usize,
    fields: ExtraFields,
}

impl DocumentUpload {
    /// Takes the file name and the raw bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long name, for empty bytes or
    /// for a payload above the crate's 8 MiB ceiling.
    ///
    /// ```
    /// use inwx_client::DocumentUpload;
    /// assert!(DocumentUpload::new("a.txt", b"hello").is_ok());
    /// assert!(DocumentUpload::new("a.txt", b"").is_err());
    /// assert!(DocumentUpload::new("", b"hello").is_err());
    /// ```
    pub fn new(name: &str, bytes: &[u8]) -> Result<Self> {
        validate_token("document.name", name)?;
        Ok(Self {
            name: name.trim().to_owned(),
            mime_type: None,
            customer: None,
            encoded: params::encode_document(bytes)?,
            bytes: bytes.len(),
            fields: ExtraFields::default(),
        })
    }

    /// Takes a payload that is already base64-encoded.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long name, or for a payload
    /// that is not valid base64 within the crate's 8 MiB ceiling.
    ///
    /// ```
    /// use inwx_client::DocumentUpload;
    /// assert!(DocumentUpload::from_base64("a.txt", "aGVsbG8=").is_ok());
    /// assert!(DocumentUpload::from_base64("a.txt", "not base64!").is_err());
    /// ```
    pub fn from_base64(name: &str, encoded: &str) -> Result<Self> {
        validate_token("document.name", name)?;
        let decoded = params::decode_document(encoded)?;
        Ok(Self {
            name: name.trim().to_owned(),
            mime_type: None,
            customer: None,
            encoded: encoded.trim().to_owned(),
            bytes: decoded.len(),
            fields: ExtraFields::default(),
        })
    }

    /// The file name that will be sent.
    ///
    /// ```
    /// use inwx_client::DocumentUpload;
    /// assert_eq!(DocumentUpload::new("a.txt", b"x")?.name(), "a.txt");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Size of the decoded payload in bytes.
    ///
    /// ```
    /// use inwx_client::DocumentUpload;
    /// assert_eq!(DocumentUpload::new("a.txt", b"12345")?.byte_len(), 5);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.bytes
    }

    /// Sets the MIME type (`type`).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or over-long token.
    ///
    /// ```
    /// use inwx_client::DocumentUpload;
    /// let upload = DocumentUpload::new("a.txt", b"x")?.with_mime_type("text/plain")?;
    /// assert_eq!(upload.params()["type"], "text/plain");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_mime_type(mut self, mime_type: &str) -> Result<Self> {
        validate_token("document.type", mime_type)?;
        self.mime_type = Some(mime_type.trim().to_owned());
        Ok(self)
    }

    /// Stores the document for one customer.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::DocumentUpload;
    /// assert!(DocumentUpload::new("a.txt", b"x")?.with_customer(4711).is_ok());
    /// assert!(DocumentUpload::new("a.txt", b"x")?.with_customer(0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_customer(mut self, customer: i64) -> Result<Self> {
        self.customer = Some(params::object_id("customerId", customer)?);
        Ok(self)
    }

    /// Adds a parameter this crate does not model.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `key` is not a parameter name, or when a typed
    /// setter already owns it.
    ///
    /// ```
    /// use inwx_client::DocumentUpload;
    /// let upload = DocumentUpload::new("a.txt", b"x")?.with_field("category", "CONTRACT")?;
    /// assert_eq!(upload.params()["category"], "CONTRACT");
    /// assert!(DocumentUpload::new("a.txt", b"x")?.with_field("name", "y").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_field(mut self, key: &str, value: impl Into<Value>) -> Result<Self> {
        self.fields.set(key, value.into(), UPLOAD_KEYS)?;
        Ok(self)
    }

    /// The `document.upload` parameters.
    ///
    /// ```
    /// use inwx_client::DocumentUpload;
    /// let params = DocumentUpload::new("a.txt", b"hi")?.params();
    /// assert_eq!(params["data"], "aGk=");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut map = Map::new();
        map.insert("name".to_owned(), json!(self.name));
        if let Some(mime_type) = &self.mime_type {
            map.insert("type".to_owned(), json!(mime_type));
        }
        if let Some(customer) = self.customer {
            map.insert("customer".to_owned(), json!(customer));
        }
        map.insert("data".to_owned(), json!(self.encoded));
        self.fields.write_into(&mut map);
        Value::Object(map)
    }
}

/// The file `document.download` answered with.
///
/// ```
/// use inwx_client::DocumentDownload;
///
/// let download: DocumentDownload = serde_json::from_str(
///     r#"{"name":"contract.pdf","type":"application/pdf","data":"JVBERi0="}"#,
/// )?;
/// assert_eq!(download.name.as_deref(), Some("contract.pdf"));
/// assert_eq!(download.bytes()?, b"%PDF-");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct DocumentDownload {
    /// File name as stored.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// MIME type as stored.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub mime_type: Option<String>,
    /// Base64-encoded body.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub data: Option<String>,
    /// Fields this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

impl DocumentDownload {
    /// The decoded body.
    ///
    /// The encoded length is checked before decoding, so a corrupt or absurdly
    /// large payload is reported instead of allocated.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the answer carries no body, when it is not
    /// valid base64, or when it exceeds the crate's 8 MiB ceiling.
    ///
    /// ```
    /// use inwx_client::DocumentDownload;
    ///
    /// let download: DocumentDownload = serde_json::from_str(r#"{"data":"aGk="}"#)?;
    /// assert_eq!(download.bytes()?, b"hi");
    ///
    /// let empty: DocumentDownload = serde_json::from_str(r#"{"name":"x"}"#)?;
    /// assert!(empty.bytes().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let encoded = self.data.as_deref().ok_or_else(|| {
            Error::validation("document.data", "the answer carries no document body")
        })?;
        params::decode_document(encoded)
    }
}

impl<T: Transport> InwxClient<T> {
    /// Lists stored documents (`document.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DocumentQuery, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let page = client
    ///     .list_documents(&DocumentQuery::new().with_page(1, 20)?)
    ///     .await?;
    /// for document in &page.documents {
    ///     println!("{:?} {:?}", document.name, document.size);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors; the query itself validates its
    /// filters.
    pub async fn list_documents(&self, query: &DocumentQuery) -> Result<DocumentListPage> {
        let data = self.call("document.list", query.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Stores a document (`document.upload`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DocumentUpload, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let upload = DocumentUpload::new("contract.pdf", b"%PDF-1.4 signed")?
    ///     .with_mime_type("application/pdf")?;
    /// let stored = client.upload_document(&upload).await?;
    /// println!("{:?}", stored.id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable name or payload — checked when the
    /// [`DocumentUpload`] is built, before anything is sent — plus the usual
    /// transport and API errors.
    pub async fn upload_document(&self, upload: &DocumentUpload) -> Result<DocumentSummary> {
        let data = self.call("document.upload", upload.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Fetches one document (`document.download`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let download = client.download_document(88).await?;
    /// std::fs::write("contract.pdf", download.bytes()?)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn download_document(&self, document_id: i64) -> Result<DocumentDownload> {
        let id = params::object_id("documentId", document_id)?;
        let data = self
            .call("document.download", json!({ "documentId": id }))
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
    /// client.delete_document(88).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn delete_document(&self, document_id: i64) -> Result<()> {
        let id = params::object_id("documentId", document_id)?;
        self.call("document.delete", json!({ "documentId": id }))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_stop_at_eight_mebibytes() {
        let inside = vec![b'x'; params::MAX_DOCUMENT_BYTES];
        let outside = vec![b'x'; params::MAX_DOCUMENT_BYTES + 1];
        assert!(DocumentUpload::new("a.bin", &inside).is_ok());
        assert!(DocumentUpload::new("a.bin", &outside).is_err());
    }

    #[test]
    fn an_empty_payload_is_refused_before_the_wire() {
        let error = DocumentUpload::new("a.txt", b"").unwrap_err();
        assert!(error.is_validation());
    }

    #[test]
    fn names_stop_at_255_characters() {
        assert!(DocumentUpload::new(&"a".repeat(255), b"x").is_ok());
        assert!(DocumentUpload::new(&"a".repeat(256), b"x").is_err());
    }

    #[test]
    fn ids_stop_at_zero() {
        assert!(DocumentQuery::new().with_customer(1).is_ok());
        assert!(DocumentQuery::new().with_customer(0).is_err());
    }

    #[test]
    fn page_limit_pair_is_one_and_one_thousand() {
        assert!(DocumentQuery::new().with_page(1, 1).is_ok());
        assert!(DocumentQuery::new().with_page(1, 1_000).is_ok());
        assert!(DocumentQuery::new().with_page(1, 1_001).is_err());
        assert!(DocumentQuery::new().with_page(1, 0).is_err());
    }

    #[test]
    fn upload_encodes_once_and_keeps_the_byte_count() {
        let upload = DocumentUpload::new("a.txt", b"hi").unwrap();
        assert_eq!(upload.params()["data"], "aGk=");
        assert_eq!(upload.byte_len(), 2);

        let from_base64 = DocumentUpload::from_base64("a.txt", "aGk=").unwrap();
        assert_eq!(from_base64.byte_len(), 2);
        assert_eq!(from_base64.params(), upload.params());
    }

    #[test]
    fn reserved_keys_cannot_be_overridden_by_hand() {
        assert!(DocumentUpload::new("a.txt", b"x")
            .unwrap()
            .with_field("name", "y")
            .is_err());
        assert!(DocumentUpload::new("a.txt", b"x")
            .unwrap()
            .with_field("category", "Z")
            .is_ok());
    }

    #[test]
    fn download_reports_a_missing_body_instead_of_an_empty_file() {
        let download: DocumentDownload = serde_json::from_str(r#"{"name":"x"}"#).unwrap();
        assert!(download.bytes().is_err());

        let broken: DocumentDownload = serde_json::from_str(r#"{"data":"!!!"}"#).unwrap();
        assert!(broken.bytes().is_err());
    }

    #[test]
    fn list_accepts_singular_and_plural_keys() {
        let singular: DocumentListPage =
            serde_json::from_str(r#"{"document":[{"id":1}]}"#).unwrap();
        let plural: DocumentListPage = serde_json::from_str(r#"{"documents":[{"id":1}]}"#).unwrap();
        assert_eq!(singular, plural);
    }
}
