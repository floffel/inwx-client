//! Reseller documents (`document.*`): files a reseller stores at INWX —
//! proofs, mandates, attachments for an application.
//!
//! Four methods: upload a file, list what is stored, download one and delete
//! one. Uploads are the risky direction, so the crate checks the file name
//! (never a path), refuses an empty body and validates the size *before* it
//! base64-encodes anything. The read side is checked too: a download carries
//! the size it claims, and [`DownloadedDocument::bytes`] holds the decoded body
//! against it, so a body that was cut short in transit fails instead of being
//! written to disk as a whole document.
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

use serde::de::Error as _;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{
    decode_base64, encode_base64, field_map, parse_rows, pick_bool, pick_i64, pick_text,
    validate_filename, validate_id, validate_page_limit, validate_text, validate_upper_token,
    DomainName,
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
/// The API is mid-rename on several of these keys, so a row may carry the new
/// spelling, the old one, or both: `documentId`/`id`, `mimeType`/`mime_type`,
/// `customerNumber`/`customer_number`, `domainName`/`domain` and
/// `createdAt`/`created_at` are merged instead of rejected, and the first
/// spelling that carries a value wins.
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
///
/// ```
/// use inwx_client::DocumentEntry;
///
/// // Both spellings in one row: the answer is merged, not refused.
/// let entry: DocumentEntry = serde_json::from_str(
///     r#"{"documentId":81,"id":81,"mimeType":"application/pdf","mime_type":"application/pdf"}"#,
/// )?;
/// assert_eq!(entry.id, Some(81));
/// assert_eq!(entry.mime_type.as_deref(), Some("application/pdf"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DocumentEntry {
    /// Document id, used by `download` and `delete`.
    pub id: Option<i64>,
    /// Stored file name.
    pub filename: Option<String>,
    /// Document class, carried verbatim.
    pub document_type: Option<String>,
    /// MIME type, when the API reports one.
    pub mime_type: Option<String>,
    /// Size in bytes.
    pub size: Option<i64>,
    /// Owning customer.
    pub customer_number: Option<i64>,
    /// Domain the document belongs to, when it names one.
    pub domain: Option<String>,
    /// Upload date, as text.
    pub created_at: Option<String>,
    /// State of the document, carried verbatim.
    pub status: Option<String>,
    /// Whether the document has been read.
    pub read: Option<bool>,
}

/// Reads a row by key, so both spellings of a renamed field land in one place.
impl<'de> Deserialize<'de> for DocumentEntry {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let fields = field_map(deserializer)?;
        Ok(Self {
            id: pick_i64(&fields, &["documentId", "id"]),
            filename: pick_text(&fields, &["filename"]),
            document_type: pick_text(&fields, &["type"]),
            mime_type: pick_text(&fields, &["mimeType", "mime_type"]),
            size: pick_i64(&fields, &["size"]),
            customer_number: pick_i64(&fields, &["customerNumber", "customer_number"]),
            domain: pick_text(&fields, &["domainName", "domain"]),
            created_at: pick_text(&fields, &["createdAt", "created_at"]),
            status: pick_text(&fields, &["status"]),
            read: pick_bool(&fields, &["read"]),
        })
    }
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
    /// The API then checks the request and stores nothing, and
    /// [`upload_document`](crate::InwxClient::upload_document) answers
    /// [`DocumentUploadOutcome::DryRun`] instead of a stored document.
    ///
    /// ```
    /// use inwx_client::DocumentUpload;
    ///
    /// let upload = DocumentUpload::new("a.pdf", b"x").unwrap().with_testing(true);
    /// assert_eq!(upload.params()["testing"], true);
    /// assert!(upload.is_dry_run());
    /// ```
    #[must_use]
    pub fn with_testing(mut self, testing: bool) -> Self {
        self.testing = testing;
        self
    }

    /// Whether this upload is a dry run, so nothing will be stored.
    ///
    /// ```
    /// use inwx_client::DocumentUpload;
    ///
    /// let real = DocumentUpload::new("a.pdf", b"x")?;
    /// assert!(!real.is_dry_run());
    ///
    /// // Straight back to a real upload, should the check pass.
    /// let dry = real.clone().with_testing(true);
    /// assert!(dry.is_dry_run());
    /// assert!(!dry.with_testing(false).is_dry_run());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn is_dry_run(&self) -> bool {
        self.testing
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

/// What a `document.upload` did: stored a file, or stored nothing because the
/// request was a dry run.
///
/// The answer used to be a plain [`DocumentEntry`], whose `id` is an `Option` —
/// so "the API stored the file but the answer named no id" and "nothing was
/// stored at all" arrived as the same `Ok`. A caller that recorded the upload as
/// done then had a document it could never download or delete, and the obvious
/// recovery, uploading again, duplicates it. The two outcomes are separate
/// values now: a real upload either names its document or fails as
/// [`Error::Ambiguous`], and a dry run says so.
///
/// ```
/// use inwx_client::{DocumentUploadOutcome, Error};
///
/// let stored = DocumentUploadOutcome::stored(81);
/// assert_eq!(stored.id(), Some(81));
/// assert!(stored.is_stored());
/// assert!(!stored.is_dry_run());
///
/// let dry = DocumentUploadOutcome::dry_run();
/// assert_eq!(dry.id(), None);
/// assert!(dry.is_dry_run());
/// assert!(matches!(dry.stored_id(), Err(Error::MissingField { .. })));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DocumentUploadOutcome {
    /// The API stored the file and named it.
    Stored {
        /// Document id from the answer, and therefore a handle for
        /// [`download_document`](crate::InwxClient::download_document) and
        /// [`delete_document`](crate::InwxClient::delete_document).
        id: i64,
        /// The rest of the row the API answered with, `id` filled in from the
        /// same answer — useful to confirm the file name and size the service
        /// recorded. Boxed so the outcome stays as small as its id: the row is
        /// usually dropped once the caller has read the id.
        entry: Box<DocumentEntry>,
    },
    /// A dry run ([`DocumentUpload::with_testing`]): the API checked the
    /// request and stored nothing, so there is no id and nothing to list.
    DryRun,
}

impl DocumentUploadOutcome {
    /// Builds a `Stored` outcome for `id`.
    ///
    /// The row carries the id and nothing else; a real upload fills in the
    /// fields the API echoed back. [`upload_document`](crate::InwxClient::upload_document)
    /// only ever stores a positive id, because a non-positive one would be
    /// refused by `download_document` and `delete_document`.
    ///
    /// ```
    /// use inwx_client::DocumentUploadOutcome;
    ///
    /// let outcome = DocumentUploadOutcome::stored(81);
    /// assert_eq!(outcome.id(), Some(81));
    /// assert_eq!(outcome.stored_id()?, 81);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn stored(id: i64) -> Self {
        Self::Stored {
            id,
            entry: Box::new(DocumentEntry {
                id: Some(id),
                ..DocumentEntry::default()
            }),
        }
    }

    /// The `DryRun` outcome: nothing was stored.
    ///
    /// ```
    /// use inwx_client::DocumentUploadOutcome;
    ///
    /// assert!(DocumentUploadOutcome::dry_run().is_dry_run());
    /// ```
    #[must_use]
    pub fn dry_run() -> Self {
        Self::DryRun
    }

    /// The id of the stored document, or `None` for a dry run.
    ///
    /// ```
    /// use inwx_client::DocumentUploadOutcome;
    ///
    /// assert_eq!(DocumentUploadOutcome::stored(81).id(), Some(81));
    /// assert_eq!(DocumentUploadOutcome::dry_run().id(), None);
    /// ```
    #[must_use]
    pub fn id(&self) -> Option<i64> {
        match self {
            Self::Stored { id, .. } => Some(*id),
            Self::DryRun => None,
        }
    }

    /// The row the API answered with, or `None` for a dry run.
    ///
    /// ```
    /// use inwx_client::DocumentUploadOutcome;
    ///
    /// assert!(DocumentUploadOutcome::stored(81).entry().is_some());
    /// assert!(DocumentUploadOutcome::dry_run().entry().is_none());
    /// ```
    #[must_use]
    pub fn entry(&self) -> Option<&DocumentEntry> {
        match self {
            Self::Stored { entry, .. } => Some(entry),
            Self::DryRun => None,
        }
    }

    /// Takes the row out, or `None` for a dry run.
    ///
    /// ```
    /// use inwx_client::DocumentUploadOutcome;
    ///
    /// let name = DocumentUploadOutcome::stored(81)
    ///     .into_entry()
    ///     .and_then(|entry| entry.filename);
    /// assert_eq!(name, None);
    /// ```
    #[must_use]
    pub fn into_entry(self) -> Option<DocumentEntry> {
        match self {
            Self::Stored { entry, .. } => Some(*entry),
            Self::DryRun => None,
        }
    }

    /// Whether a file was stored.
    ///
    /// ```
    /// use inwx_client::DocumentUploadOutcome;
    ///
    /// assert!(DocumentUploadOutcome::stored(81).is_stored());
    /// assert!(!DocumentUploadOutcome::dry_run().is_stored());
    /// ```
    #[must_use]
    pub fn is_stored(&self) -> bool {
        self.id().is_some()
    }

    /// Whether the call was a dry run and stored nothing.
    ///
    /// ```
    /// use inwx_client::DocumentUploadOutcome;
    ///
    /// assert!(DocumentUploadOutcome::dry_run().is_dry_run());
    /// assert!(!DocumentUploadOutcome::stored(81).is_dry_run());
    /// ```
    #[must_use]
    pub fn is_dry_run(&self) -> bool {
        matches!(self, Self::DryRun)
    }

    /// The id, or a typed error when nothing was stored.
    ///
    /// # Errors
    ///
    /// [`Error::MissingField`] for a dry run: it stored nothing, so there is no
    /// document to name.
    ///
    /// ```
    /// use inwx_client::{DocumentUploadOutcome, Error};
    ///
    /// assert_eq!(DocumentUploadOutcome::stored(81).stored_id()?, 81);
    /// assert!(matches!(
    ///     DocumentUploadOutcome::dry_run().stored_id(),
    ///     Err(Error::MissingField { field: "documentId", .. })
    /// ));
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn stored_id(&self) -> Result<i64> {
        self.id().ok_or(Error::MissingField {
            method: "document.upload",
            field: "documentId",
        })
    }
}

/// A downloaded document (`document.download`).
///
/// Like [`DocumentEntry`], the answer is read by key: `documentId`/`id` and
/// `content`/`data` are merged when INWX sends both spellings, and the first
/// spelling that carries a value wins.
///
/// The answer also reports the stored size, and [`DownloadedDocument::bytes`]
/// holds the decoded body against it: a body cut short in transit can still
/// decode when the cut lands on a base64 boundary, and the declared size is the
/// only thing that tells the two apart. A negative `size` is refused when the
/// answer is parsed, because no decoded body can have one.
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
///
/// ```
/// use inwx_client::DownloadedDocument;
///
/// // The body arrives under both keys during the rename.
/// let document: DownloadedDocument =
///     serde_json::from_str(r#"{"content":"aGk=","data":"aGk="}"#)?;
/// assert_eq!(document.bytes()?, b"hi");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DownloadedDocument {
    /// Document id, when the API echoes it.
    pub id: Option<i64>,
    /// Stored file name.
    pub filename: Option<String>,
    /// Base64-encoded body.
    pub content: Option<String>,
    /// MIME type, when the API reports one.
    pub mime_type: Option<String>,
    /// Size in bytes, when the API reports one.
    ///
    /// The answer is a claim, not a measurement: [`bytes`](Self::bytes) compares
    /// it with the decoded body and fails as [`Error::SizeMismatch`] when the two
    /// disagree. Never negative — a parsed answer with a negative size is
    /// rejected, and a hand-built one is refused by `bytes` just the same.
    pub size: Option<i64>,
}

/// Reads a download by key, so both spellings of a renamed field land in one
/// place.
///
/// A negative `size` fails the answer instead of landing in the row: no decoded
/// body can have a negative length, so the number is a mangled claim rather than
/// a small one, and carrying it would only move the contradiction to
/// [`DownloadedDocument::bytes`].
impl<'de> Deserialize<'de> for DownloadedDocument {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let fields = field_map(deserializer)?;
        let size = match pick_i64(&fields, &["size"]) {
            Some(declared) if declared < 0 => {
                return Err(D::Error::custom(format!(
                    "document size must not be negative, got {declared}"
                )));
            }
            size => size,
        };
        Ok(Self {
            id: pick_i64(&fields, &["documentId", "id"]),
            filename: pick_text(&fields, &["filename"]),
            content: pick_text(&fields, &["content", "data"]),
            mime_type: pick_text(&fields, &["mimeType", "mime_type"]),
            size,
        })
    }
}

impl DownloadedDocument {
    /// Decodes the body and holds it against the size the answer declared.
    ///
    /// ```rust
    /// use inwx_client::{DownloadedDocument, Error};
    ///
    /// let good: DownloadedDocument = serde_json::from_str(r#"{"content":"aGk="}"#)?;
    /// assert_eq!(good.bytes()?, b"hi");
    ///
    /// let broken: DownloadedDocument = serde_json::from_str(r#"{"content":"!!!not base64!!!"}"#)?;
    /// assert!(broken.bytes().is_err());
    ///
    /// // A body cut on a base64 boundary still decodes to two bytes, and only
    /// // the declared size notices that it is short.
    /// let truncated: DownloadedDocument =
    ///     serde_json::from_str(r#"{"content":"aGk=","size":40}"#)?;
    /// assert!(matches!(
    ///     truncated.bytes(),
    ///     Err(Error::SizeMismatch { declared: 40, actual: 2, .. })
    /// ));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when there is no body or it is not base64,
    /// [`Error::SizeMismatch`] when the decoded body is not as long as the
    /// answer's `size` says, and [`Error::UnexpectedAnswer`] when the row carries
    /// a negative `size` — a parsed answer refuses one, so only a hand-built
    /// value can get that far.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let encoded = self.content.as_deref().ok_or_else(|| {
            Error::validation("document.content", "the answer carries no document body")
        })?;
        let bytes = decode_base64("document.content", encoded)?;
        // A size the answer never reported cannot contradict anything.
        let Some(declared) = self.size else {
            return Ok(bytes);
        };
        let declared = u64::try_from(declared).map_err(|_| {
            Error::unexpected_answer(
                "document.download",
                "size",
                format!("declares a negative size ({declared})"),
            )
        })?;
        let actual = bytes.len() as u64;
        if declared == actual {
            Ok(bytes)
        } else {
            Err(Error::size_mismatch("document.download", declared, actual))
        }
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
/// let params = query.params();
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
    /// assert!(DocumentQuery::new().params().is_object());
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
    /// assert_eq!(DocumentQuery::new().with_document_type("mandate")?.params()["type"], "MANDATE");
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
    /// assert_eq!(query.params()["domainName"], "example.com");
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
    /// assert_eq!(DocumentQuery::new().with_filename("a.pdf")?.params()["filename"], "a.pdf");
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
    /// [`Error::Validation`] when `page` is `0` (INWX pages start at `1`), or
    /// when the page size is zero.
    ///
    /// ```
    /// use inwx_client::DocumentQuery;
    ///
    /// assert_eq!(DocumentQuery::new().with_page(1, 1)?.params()["pagelimit"], 1);
    /// assert_eq!(DocumentQuery::new().with_page(2, 50)?.params()["page"], 2);
    /// assert!(DocumentQuery::new().with_page(0, 1).is_err());
    /// assert!(DocumentQuery::new().with_page(1, 0).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_page(mut self, page: u32, limit: u32) -> Result<Self> {
        if page == 0 {
            return Err(Error::validation(
                "page",
                "must be at least 1 (pages start at 1)",
            ));
        }
        self.limit = Some(validate_page_limit(limit)?);
        self.page = Some(page);
        Ok(self)
    }

    /// The `document.list` parameters.
    ///
    /// Unset filters are omitted; `page` defaults to `1` and `pagelimit` to
    /// `50`. Every value was checked by the setter that stored it, so building
    /// the map cannot fail.
    ///
    /// ```
    /// use inwx_client::DocumentQuery;
    ///
    /// let params = DocumentQuery::new().params();
    /// assert_eq!(params["page"], 1);
    /// assert_eq!(params["pagelimit"], 50);
    /// assert!(params.get("type").is_none());
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
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
        Value::Object(params)
    }
}

impl<T: Transport> InwxClient<T> {
    /// Uploads a document (`document.upload`).
    ///
    /// Answers [`DocumentUploadOutcome::Stored`] with the id and the row the API
    /// echoed back, or [`DocumentUploadOutcome::DryRun`] when the request was
    /// marked with [`DocumentUpload::with_testing`] and nothing was stored.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DocumentUpload, DocumentUploadOutcome, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let upload = DocumentUpload::new("mandate.pdf", &std::fs::read("mandate.pdf")?)?
    ///     .with_document_type("mandate")?;
    ///
    /// match client.upload_document(&upload).await? {
    ///     DocumentUploadOutcome::Stored { id, entry } => println!("stored as {id} ({entry:?})"),
    ///     _ => println!("nothing was stored"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable file name or body, plus the usual
    /// transport and API errors. An accepted upload whose answer names no usable
    /// id — missing, not a number, or zero — is [`Error::Ambiguous`]: the file
    /// may well be stored, so listing the documents beats uploading again, which
    /// would leave a duplicate behind.
    pub async fn upload_document(&self, upload: &DocumentUpload) -> Result<DocumentUploadOutcome> {
        let data = self.call("document.upload", upload.params()).await?;
        if upload.is_dry_run() {
            // Nothing was stored, so an id in the answer would name nothing:
            // reading one would invent a handle for a document that does not
            // exist. The outcome is certain either way.
            return Ok(DocumentUploadOutcome::dry_run());
        }
        let entry: DocumentEntry = serde_json::from_value(data).map_err(|source| {
            Error::ambiguous(
                "document.upload",
                "the answer could not be read, so the stored document has no id; \
                 list the documents before uploading again",
            )
            .with_source(source)
        })?;
        // `download_document` and `delete_document` refuse a non-positive id, so
        // one from the API is not a handle: report the upload as ambiguous
        // instead of handing out a value the crate itself would reject.
        let id = entry.id.filter(|id| *id > 0).ok_or_else(|| {
            Error::ambiguous(
                "document.upload",
                "the answer carries no usable documentId, so the stored document \
                 cannot be downloaded or deleted; list the documents before \
                 uploading again",
            )
        })?;
        Ok(DocumentUploadOutcome::Stored {
            id,
            entry: Box::new(DocumentEntry {
                id: Some(id),
                ..entry
            }),
        })
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
    /// The usual transport and API errors. The query itself cannot fail here:
    /// every filter and the page size were checked when they were set.
    pub async fn list_documents(&self, query: &DocumentQuery) -> Result<Vec<DocumentEntry>> {
        let params = query.params();
        let data = self.call("document.list", params).await?;
        Ok(parse_rows(&data, "document"))
    }

    /// Downloads one document (`document.download`).
    ///
    /// The answer is not a file yet: it carries the base64 body next to the size
    /// the service says it stored, and [`DownloadedDocument::bytes`] decodes the
    /// one and holds it against the other. Writing the bytes without that check
    /// is what turns a transfer cut short on a base64 boundary into a plausible
    /// but incomplete file.
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
    /// [`Error::Validation`] for a non-positive id, [`Error::Json`] for an answer
    /// that does not fit the model — including a negative `size`, which no body
    /// can have — plus the usual transport and API errors.
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
        assert!(DocumentQuery::new().with_page(0, 1).is_err());
        assert!(DocumentQuery::new().with_page(1, 1).is_ok());
        assert!(DocumentQuery::new().with_page(u32::MAX, 1).is_ok());
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
    fn a_stored_outcome_names_its_id_and_a_dry_run_names_nothing() {
        let stored = DocumentUploadOutcome::stored(81);
        assert_eq!(stored.id(), Some(81));
        assert_eq!(stored.stored_id().unwrap(), 81);
        assert!(stored.is_stored());
        assert!(!stored.is_dry_run());
        assert_eq!(stored.entry().and_then(|entry| entry.id), Some(81));
        assert_eq!(
            stored.clone().into_entry().and_then(|entry| entry.id),
            Some(81)
        );

        let dry = DocumentUploadOutcome::dry_run();
        assert_eq!(dry.id(), None);
        assert!(dry.is_dry_run());
        assert!(!dry.is_stored());
        assert!(dry.entry().is_none());
        assert!(dry.clone().into_entry().is_none());
        assert!(dry.stored_id().is_err());
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

    #[test]
    fn a_row_carrying_both_spellings_is_merged_not_rejected() {
        let both: DocumentEntry = serde_json::from_str(
            r#"{"documentId":81,"id":81,"mimeType":"application/pdf",
                "mime_type":"application/pdf","customerNumber":123456,
                "customer_number":123456,"domainName":"example.com","domain":"example.com",
                "createdAt":"2026-03-01","created_at":"2026-03-01"}"#,
        )
        .unwrap();
        assert_eq!(both.id, Some(81));
        assert_eq!(both.mime_type.as_deref(), Some("application/pdf"));
        assert_eq!(both.customer_number, Some(123_456));
        assert_eq!(both.domain.as_deref(), Some("example.com"));
        assert_eq!(both.created_at.as_deref(), Some("2026-03-01"));
    }

    #[test]
    fn the_first_spelling_that_carries_a_value_wins() {
        // Both spellings present: the one the API renamed to decides, so the
        // row cannot flip its id on the way through the merge.
        let both: DocumentEntry = serde_json::from_str(r#"{"documentId":81,"id":82}"#).unwrap();
        assert_eq!(both.id, Some(81));

        // Only the old spelling: the same value, one key later.
        let only_old: DocumentEntry = serde_json::from_str(r#"{"id":82}"#).unwrap();
        assert_eq!(only_old.id, Some(82));

        // A `null` leading spelling is not a value and hands over.
        let nulled: DocumentEntry = serde_json::from_str(r#"{"documentId":null,"id":81}"#).unwrap();
        assert_eq!(nulled.id, Some(81));

        // Neither spelling unusable: absent, where the leading key exists.
        let empty: DocumentEntry = serde_json::from_str(r#"{"documentId":null}"#).unwrap();
        assert_eq!(empty.id, None);
    }

    #[test]
    fn a_download_carrying_both_body_spellings_is_merged() {
        let both: DownloadedDocument = serde_json::from_str(
            r#"{"documentId":81,"id":81,"content":"aGk=","data":"aGk=","mimeType":"text/plain","mime_type":"text/plain"}"#,
        )
        .unwrap();
        assert_eq!(both.id, Some(81));
        assert_eq!(both.bytes().unwrap(), b"hi");
        assert_eq!(both.mime_type.as_deref(), Some("text/plain"));

        // The spellings disagreeing is a contradiction, not a second body: the
        // leading key wins and the body stays one document.
        let split: DownloadedDocument =
            serde_json::from_str(r#"{"content":"aGk=","data":"Ynll"}"#).unwrap();
        assert_eq!(split.bytes().unwrap(), b"hi");
    }

    #[test]
    fn a_row_with_both_spellings_survives_the_list_parse() {
        // Before the merge this row failed to deserialize and `parse_rows`
        // dropped it, so a paging caller silently lost a document.
        let data = json!({
            "document": [
                { "documentId": 1, "id": 1, "filename": "a.pdf" },
                { "id": 2, "filename": "b.pdf" }
            ]
        });
        let rows: Vec<DocumentEntry> = parse_rows(&data, "document");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].filename.as_deref(), Some("a.pdf"));
        assert_eq!(rows[1].id, Some(2));
    }

    #[test]
    fn a_row_that_is_not_an_object_is_still_an_error() {
        assert!(serde_json::from_str::<DocumentEntry>("[]").is_err());
        assert!(serde_json::from_str::<DownloadedDocument>("\"aGk=\"").is_err());
    }

    #[test]
    fn a_body_that_matches_its_declared_size_decodes_and_one_byte_off_is_refused() {
        // `hi` is two bytes: 2 is the last accepted claim, 1 and 3 the first
        // refused ones on either side.
        let exact: DownloadedDocument =
            serde_json::from_str(r#"{"content":"aGk=","size":2}"#).unwrap();
        assert_eq!(exact.bytes().unwrap(), b"hi");

        let short: DownloadedDocument =
            serde_json::from_str(r#"{"content":"aGk=","size":3}"#).unwrap();
        assert!(matches!(
            short.bytes(),
            Err(Error::SizeMismatch {
                declared: 3,
                actual: 2,
                ..
            })
        ));

        let long: DownloadedDocument =
            serde_json::from_str(r#"{"content":"aGk=","size":1}"#).unwrap();
        assert!(matches!(
            long.bytes(),
            Err(Error::SizeMismatch {
                declared: 1,
                actual: 2,
                ..
            })
        ));

        // No claim, nothing to contradict.
        let unchecked: DownloadedDocument = serde_json::from_str(r#"{"content":"aGk="}"#).unwrap();
        assert_eq!(unchecked.bytes().unwrap(), b"hi");
    }

    #[test]
    fn a_body_cut_on_a_base64_boundary_is_caught_by_the_declared_size() {
        // `hello` trimmed to `aGVs` still decodes — to three bytes instead of
        // five. Only the size the answer declared notices.
        let truncated: DownloadedDocument =
            serde_json::from_str(r#"{"filename":"a.txt","content":"aGVs","size":5}"#).unwrap();
        let error = truncated.bytes().unwrap_err();
        assert_eq!(
            error.to_string(),
            "`document.download` declared 5 bytes but the body carries 3"
        );
        assert!(!error.is_uncertain());
        assert!(!error.is_retryable());
        assert!(!error.is_validation());
    }

    #[test]
    fn a_negative_declared_size_fails_the_answer_and_zero_is_still_a_size() {
        // Zero is the boundary that is still a size: an empty body.
        let empty: DownloadedDocument = serde_json::from_str(r#"{"content":"","size":0}"#).unwrap();
        assert_eq!(empty.size, Some(0));
        assert_eq!(empty.bytes().unwrap(), Vec::<u8>::new());

        // One byte below zero is not, so the row never reaches a caller.
        for size in ["-1", "-5", "-9223372036854775808"] {
            let json = format!(r#"{{"content":"aGk=","size":{size}}}"#);
            let error = serde_json::from_str::<DownloadedDocument>(&json).unwrap_err();
            assert!(error.to_string().contains("must not be negative"), "{json}");
        }

        // The same row parses when the size is a usable claim.
        let fine: DownloadedDocument =
            serde_json::from_str(r#"{"content":"aGk=","size":2}"#).unwrap();
        assert_eq!(fine.size, Some(2));
    }

    #[test]
    fn a_hand_built_negative_size_is_refused_by_bytes() {
        // The field is public, so a caller can build the contradiction the
        // deserialiser refuses — `bytes` still will not decode it.
        let document = DownloadedDocument {
            content: Some("aGk=".to_owned()),
            size: Some(-5),
            ..DownloadedDocument::default()
        };
        assert!(matches!(
            document.bytes(),
            Err(Error::UnexpectedAnswer { field: "size", .. })
        ));
    }
}
