//! Typed client for the [INWX](https://www.inwx.com) `DomRobot` JSON-RPC API —
//! domains, zones and DNS records, ownership changes, certificates, hosting,
//! DNSSEC, tags, nameserver sets, DynDNS, accounting and the reseller/partner
//! objects (applications, customers, documents, hosts, messages, PDFs).
//!
//! INWX is a German registrar and DNS provider. Its API is a single JSON-RPC
//! endpoint (`https://api.domrobot.com/jsonrpc/`, or the free OTE sandbox at
//! `https://api.ote.domrobot.com/jsonrpc/`) where every command returns HTTP 200
//! and reports failure in the body: `{"code": 2303, "msg": "Object does not
//! exist"}`. This crate models that correctly — a non-`1000` code is an
//! [`Error::Api`], not a parse problem.
//!
//! # Quickstart
//!
//! Point the first run at the free OTE sandbox, not at a production account:
//! [`InwxClient::sandbox`] sends every command to [`SANDBOX_BASE_URL`]
//! (`https://api.ote.domrobot.com/jsonrpc/`), which exposes the same command
//! surface but owns no live zone and bills nothing. Production is the opt-in
//! swap [`InwxClient::new`] — the code below is identical there, and the same
//! `create_record` / `delete_record` pair then edits a real zone. The
//! production client itself lives at [`DEFAULT_BASE_URL`].
//!
//! ```no_run
//! # #[cfg(feature = "http")]
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use inwx_client::{DomainName, InwxClient, RecordSpec, ReqwestTransport, SANDBOX_BASE_URL};
//!
//! // Sandbox credentials (an OTE test account), never the production password.
//! let client = InwxClient::sandbox(ReqwestTransport::new())
//!     .with_credentials("username", std::env::var("INWX_SANDBOX_PASSWORD")?)?;
//! assert_eq!(client.base_url(), SANDBOX_BASE_URL);
//!
//! let domain = DomainName::parse("example.com")?;
//! let check = client.check_domain(&domain).await?;
//! println!("available: {}", check.is_available());
//!
//! // Sandbox data only: the record lands in the OTE zone, not in a live one.
//! let record = RecordSpec::a("www", "203.0.113.7")?.with_ttl(3600)?;
//! let id = client.create_record(&domain, &record).await?;
//!
//! // Destructive step, kept explicit: this removes the record created above.
//! client.delete_record(&id).await?;
//! # Ok(())
//! # }
//! ```
//!
//! The base URL is a property of the client, not of the transport, so one
//! [`ReqwestTransport`] serves both endpoints and a swap only changes which
//! zone the commands hit — see [Endpoints and the sandbox](#endpoints-and-the-sandbox).
//!
//! Nothing above runs in a test, because it needs a socket and credentials. The
//! same sequence without either is the block below: a scripted [`Transport`]
//! that answers each JSON-RPC method from a canned body. This example is compiled
//! and executed in every feature configuration (`cargo test --doc`, including
//! `--no-default-features`), so the login, the parsed answer and the mock path
//! are checked rather than only described:
//!
//! ```
//! use inwx_client::transport::{Request, Response, Transport};
//! use inwx_client::{DomainName, InwxClient, RecordSpec, Result};
//! use serde_json::{json, Value};
//!
//! /// Answers each JSON-RPC method from a canned envelope — no socket involved.
//! struct Scripted;
//!
//! impl Transport for Scripted {
//!     async fn execute(&self, request: Request<'_>) -> Result<Response> {
//!         let method = serde_json::from_slice::<Value>(&request.body)
//!             .ok()
//!             .and_then(|body| body.get("method")?.as_str().map(str::to_owned));
//!         let (headers, payload) = match method.as_deref() {
//!             // The login answer has to carry the session cookie; that header
//!             // is the only credential on every later call.
//!             Some("account.login") => (
//!                 vec![("Set-Cookie".to_owned(), "domrobot=token; Path=/".to_owned())],
//!                 json!({ "code": 1000, "msg": "Login successful" }),
//!             ),
//!             Some("domain.check") => (
//!                 Vec::new(),
//!                 json!({
//!                     "code": 1000,
//!                     "msg": "ok",
//!                     "resData": { "domain": [{ "domain": "example.com", "avail": 1, "status": "free" }] },
//!                 }),
//!             ),
//!             Some("nameserver.createRecord") => (
//!                 Vec::new(),
//!                 json!({ "code": 1000, "msg": "ok", "resData": { "id": "4711" } }),
//!             ),
//!             _ => (Vec::new(), json!({ "code": 1000, "msg": "ok" })),
//!         };
//!         Ok(Response::new(200, headers, payload.to_string().into_bytes()))
//!     }
//! }
//!
//! # fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
//! # tokio::runtime::Runtime::new()?.block_on(async {
//! // `Scripted` never opens a socket, so the default (production) base URL
//! // above is inert here — nothing is sent anywhere.
//! let client = InwxClient::new(Scripted).with_credentials("user", "secret")?;
//!
//! let domain = DomainName::parse("example.com")?;
//! let check = client.check_domain(&domain).await?;
//! assert!(check.is_available());
//!
//! let record = RecordSpec::a("www", "203.0.113.7")?;
//! let id = client.create_record(&domain, &record).await?;
//! assert_eq!(id.as_str(), "4711");
//! client.delete_record(&id).await?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # })?;
//! # Ok(())
//! # }
//! ```
//!
//! # What it covers
//!
//! | Area | Methods |
//! | --- | --- |
//! | Session | `account.login`, `account.logout`, `account.check`, `account.info`, `account.unlock`, `account.changepassword` |
//! | Account | `account.update` |
//! | Sub-accounts | `account.list`, `account.create`, `account.delete` |
//! | Domains | `domain.check`, `domain.create`, `domain.info`, `domain.list`, `domain.update`, `domain.renew`, `domain.delete`, `domain.whois`, `domain.setClientHold`, `domain.removeClientHold`, `domain.setAuthInfo`, `domain.setDomainTransferCode`, `domain.block`, `domain.unblock` |
//! | Ownership | `domain.transfer`, `domain.trade`, `domain.push`, `domain.restore`, `domain.transfercancel`, `domain.transferOut` |
//! | DNS records | `nameserver.info` (read), `nameserver.createRecord`, `nameserver.updateRecord`, `nameserver.deleteRecord` |
//! | Zones | `nameserver.create`, `nameserver.update`, `nameserver.delete`, `nameserver.list`, `nameserver.info`, `nameserver.check`, `nameserver.clone`, `nameserver.export`, `nameserver.exportlist`, `nameserver.exportrecords` |
//! | Certificates | `certificate.*` (13 methods) |
//! | Hosting | `hosting.*` (9 methods) |
//! | DNSSEC | `dnssec.*` (7 methods) |
//! | Tags | `tag.*` (5 methods) |
//! | Nameserver sets | `nameserverset.*` (5 methods) |
//! | DynDNS | `dyndns.*` (8 methods) |
//! | DynDNS subscriptions | `dyndnssubscription.create`, `dyndnssubscription.cancel`, `dyndnssubscription.list`, `dyndnssubscription.listProducts` |
//! | Accounting | `accounting.*` (11 methods) |
//! | Account roles | `account.getroles`, `account.addrole`, `account.removerole` |
//! | Contacts | `contact.create`, `contact.info`, `contact.list`, `contact.update`, `contact.delete` |
//! | Diagnostics | `domain.log`, `domain.stats`, `domain.getRules`, `domain.getTldGroups` |
//! | Prices | `domain.getPrices`, `domain.getdomainprice`, `domain.getalldomainprices`, `domain.getextradatarules`, `domain.getpromos`, `domain.pricechanges` |
//! | Applications | `application.check`, `create`, `delete`, `info`, `list`, `update` |
//! | Customers | `customer.info`, `update`, `delete`, `contactverificationsettingsinfo`, `contactverificationsettingsupdate`, `listdownloads`, `requestdataexport` |
//! | Hosts (glue records) | `host.check`, `create`, `delete`, `info`, `list`, `update` |
//! | Documents | `document.upload`, `list`, `download`, `delete` |
//! | Messages, news, handles, PDFs | `message.poll`, `ack`; `news.list`; `nichandle.list`; `pdf.document`, `pdf.get` |
//! | `AuthInfo2` | `authinfo2.create`, `authinfo2.getprice` |
//!
//! The list commands are walked by [`Pagination`] and the per-command listing types
//! ([`DomainListing`], [`ContactListing`], [`ZoneListing`], [`NicHandleListing`],
//! [`ApplicationListing`]);
//! they are client-side helpers, not additional API methods, so they are not part
//! of the table above.
//!
//! Every name in the table is a command the crate really sends; a count such as
//! `certificate.* (13 methods)` covers exactly the commands implemented in
//! `src/certificate.rs`, and `tests/coverage_table.rs` fails the build when the
//! two drift apart. Unknown methods stay reachable through [`InwxClient::call`];
//! what is not modelled yet is tracked as an issue, not hidden as
//! "out of scope".
//!
//! # Design
//!
//! * **Validate before you send.** [`DomainName`], [`Hostname`], [`RecordSpec`],
//!   [`RecordSet`], [`ZoneCreate`], [`ContactRequest`] and [`Period`] reject what
//!   the API would reject, so a typo costs a local error instead of a charged
//!   registration or a broken zone.
//!   The reseller builders keep that rule: a glue record outside its own domain,
//!   a file name that is a path, a 14th address or a document above
//!   [`MAX_DOCUMENT_BYTES`] is refused before anything is sent.
//! * **Say what cannot be undone.** Ownership changes and refunds take an
//!   [`Irreversible`] acknowledgement naming the action and the object, so a
//!   transfer cannot be built by copy-pasting a block and forgetting the domain.
//! * **Parse permissively.** Unknown fields are ignored, unknown enum values are
//!   carried ([`RecordType::Other`], [`RenewalMode::Other`],
//!   [`ContactType::Other`], [`AccountRole::Other`]), and scalars are accepted as
//!   numbers or strings —
//!   INWX is inconsistent between methods.
//! * **Walk the whole list.** [`InwxClient::list_all_domains`],
//!   [`InwxClient::list_all_contacts`], [`InwxClient::list_all_zones`],
//!   [`InwxClient::list_all_nichandles`] and
//!   [`InwxClient::list_all_applications`] return a [`Pages`] walk instead of
//!   one page: page size and bound are validated where they are set, the last
//!   page is cut at the bound, and [`Pages::bound_reached`] says whether the
//!   listing ended or the walk stopped early.
//! * **No socket needed.** The HTTP layer sits behind [`Transport`]; the
//!   quickstart above runs end to end against an inline scripted transport in
//!   every feature configuration, and the integration tests in `tests/` drive
//!   their own scripted transport (`tests/common`) for every command.
//! * **Cap what arrives.** [`read_capped_body`] bounds a response before it is
//!   buffered, so a huge answer or a header that lies about its size costs an
//!   error instead of memory.
//!
//! # Feature flags
//!
//! * `http` (default) — pulls in `reqwest` (rustls) and `tokio/time` and
//!   provides [`ReqwestTransport`]. Without it the crate is pure request
//!   building + response parsing: no TLS stack, no async runtime, no socket.
//!
//! # Endpoints and the sandbox
//!
//! * [`InwxClient::sandbox`] — [`SANDBOX_BASE_URL`],
//!   `https://api.ote.domrobot.com/jsonrpc/`. The free OTE sandbox: same
//!   commands, same answers, no live zone and no charge. This is where a
//!   mutating call belongs until the flow is understood.
//! * [`InwxClient::new`] — [`DEFAULT_BASE_URL`],
//!   `https://api.domrobot.com/jsonrpc/`. Every mutating command there is real:
//!   a registration costs money, a `delete_record` removes a record from a zone
//!   that is serving traffic.
//! * [`InwxClient::with_base_url`] — anything else (a proxy, a local test
//!   server).
//!
//! The endpoint travels inside each [`Request`](transport::Request), so one
//! transport serves all three; picking production is one constructor call, and
//! nothing in the client asks twice before writing.
//!
//! # Security
//!
//! * `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`.
//! * Panic-freedom is a lint, not a review habit: `clippy::unwrap_used`,
//!   `clippy::expect_used`, `clippy::panic`, `clippy::todo`,
//!   `clippy::unimplemented` and `clippy::indexing_slicing` are denied at the
//!   crate root, so a new `unwrap()` in library code fails `cargo clippy`
//!   instead of reaching a Lambda. Tests are the only exception — the allow is
//!   scoped to `cfg(test)` and cannot leak into the library build.
//! * Credentials and session cookies are redacted in `Debug` — [`Credentials`]
//!   prints `<redacted>` for the password, [`InwxClient`] prints only whether a
//!   session exists.
//! * [`Credentials`] cannot be cloned, zeroes the password when dropped, and
//!   compares passwords in constant time with `subtle`.
//! * The password is only ever sent in the `account.login` body, never in a URL
//!   or a header; afterwards the opaque session cookie is the only credential on
//!   the wire.
//! * Session cookies and credentials are rejected if they contain control
//!   characters, so a value cannot smuggle a second header.
//! * [`AuthCode`] (the EPP transfer code) prints `<redacted>` in `Debug` and
//!   `Display`, and its length is checked on the caller's string before the
//!   value is copied; the transfer controls (`domain.setAuthInfo`,
//!   `domain.setDomainTransferCode`) take it as a typed value, so a code cannot
//!   be sent unvalidated or leak through an error message. The DynDNS account
//!   type redacts its password.
//! * A certificate CSR is refused if it contains a private key: the field takes a
//!   signing request, and anything else would upload a secret to a third party.
//! * Retries are bounded (three attempts, exponential backoff) and only apply to
//!   failures that happened before the request was written, plus 429/5xx and
//!   `2300` (pending transfer) on a read-only method — a rejected command is
//!   never repeated. A 429/5xx is replayed only for a read-only method as well:
//!   for an order the status says nothing about whether it already went
//!   through, so that outcome is [`Error::Uncertain`] after a single attempt.
//!   `2300` follows the same gate and is returned as-is for a mutation, because
//!   the object was already reached and a second `domain.transfer` after the
//!   pending one settled is a second order. `account.login` is the one
//!   exception: it opens a session and nothing else, so a repeat replaces that
//!   session instead of duplicating a domain, an order or a charge, and a login
//!   is retried after a 429/5xx like any read.
//! * A transport failure after the request was written (a timeout, a reset
//!   mid-response) is [`Error::Uncertain`]: the command may have run. It is
//!   replayed only for a read-only method ([`is_read_only_method`]), never for a
//!   mutating one, so a registration cannot be submitted twice and a transfer
//!   code or a domain block cannot be applied twice. A login is the one write
//!   that is repeated here too, for the reason above.
//! * An answer that arrives but cannot be read as an envelope — a `200` carrying
//!   a gateway page, a blank or cut-off body — is [`Error::Undecodable`]: the
//!   exchange completed, so the command may have run, and the call reports that
//!   at once instead of replaying it. [`Error::Json`] stays the certain decode
//!   failure of a payload that arrived intact.
//! * [`Password`] (the new password of `account.changepassword`) redacts itself
//!   in `Debug` and `Display`, compares in constant time, is zeroized when it is
//!   dropped and has no `Deserialize`: a secret is an input and is never parsed
//!   back out of a response.
//! * A response body is capped at [`DEFAULT_MAX_RESPONSE_BYTES`], checked against
//!   `Content-Length` before the body is read and against a running total while
//!   it streams, so neither a misbehaving nor a compromised endpoint can make
//!   this process allocate without bound. Crossing the cap is
//!   [`Error::ResponseTooLarge`], which is
//!   terminal: the command behind it may already have run.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Panic-freedom is a gate, not a review habit: the restriction lints are absent
// from `clippy::all`/`clippy::pedantic`, so without these lines a new `unwrap()`
// on an API-controlled value would compile and ship.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing
)]
// Tests may unwrap: a panic in a test is a failure, and the alternative would
// bury every assertion in a `match`. The allow is scoped to `cfg(test)`, so it
// cannot leak into the library build.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing
    )
)]
// `record::RecordSpec` and friends read better than a flattened module.
#![allow(clippy::module_name_repetitions)]

pub mod account;
pub mod accounting;
pub mod application;
pub mod authinfo2;
pub mod certificate;
pub mod client;
pub mod contact;
pub mod customer;
pub mod diagnostics;
pub mod dnssec;
pub mod document;
pub mod domain;
pub mod dyndns;
pub mod dyndnssubscription;
pub mod error;
pub mod host;
pub mod hosting;
pub mod message;
pub mod nameserver;
pub mod nameserverset;
pub mod news;
pub mod nichandle;
pub mod pagination;
pub mod pdf;
pub mod price;
pub mod record;
pub mod rpc;
mod session;
pub mod tag;
pub mod transfer;
pub mod transport;
pub mod types;
pub mod zone;

pub use account::{
    AccountCheck, AccountPasswordChange, AccountRole, AccountRoleEntry, AccountRoleId,
    AccountUnlockRequest, AccountUpdate, SubAccount, SubAccountCreate, SubAccountCreated,
    SubAccountList, SubAccountsDeleted,
};
pub use accounting::{
    AccountBalance, CreditLog, Document, Invoice, LockedFund, LockedFunds, PostalDelivery,
    RefundRequest, SslFund, StatementQuery, Transaction, TransactionLog, TransactionLogQuery,
};
pub use application::{
    Application, ApplicationCheck, ApplicationCheckResult, ApplicationCreate, ApplicationListPage,
    ApplicationListing, ApplicationQuery, ApplicationType, ApplicationUpdate,
};
pub use authinfo2::{AuthInfo2Order, AuthInfo2OrderResult, AuthInfo2PriceQuote};
pub use certificate::{
    Certificate, CertificateId, CertificateLogEntry, CertificateMissingData, CertificateOrder,
    CertificateOrderResult, CertificateProduct, CertificateProductQuery, CertificateQuery,
    CertificateTerm, CertificateUpdate, CertificateValidationMethod, MAX_CSR_LEN,
};
pub use client::{
    is_read_only_method, AccountInfo, Credentials, InwxClient, Language, RetryPolicy,
    DEFAULT_ATTEMPTS, DEFAULT_BASE_DELAY, DEFAULT_BASE_URL, DEFAULT_MAX_DELAY, SANDBOX_BASE_URL,
};
pub use contact::{
    Contact, ContactListPage, ContactListing, ContactQuery, ContactRequest, ContactUpdate,
};
pub use customer::{
    ContactVerificationSettings, ContactVerificationSettingsUpdate, Customer, CustomerDownload,
    CustomerDownloadQuery, CustomerUpdate, DataExport,
};
pub use diagnostics::{
    DomainLog, DomainLogEntry, DomainLogQuery, DomainRule, DomainStat, DomainStats, TldGroup,
    TldGroupList, TldRules, MAX_PAGE_LIMIT,
};
pub use dnssec::{
    AddDnsKeyRequest, DnsKey, DnsKeyPair, DnssecAlgorithm, DnssecDigestType, DnssecDomainStatus,
    DnssecFlag, DnssecKey, DnssecKeyQuery, DnssecKeyStatus, DnssecState, DsRecord,
};
pub use document::{
    DocumentEntry, DocumentKind, DocumentQuery, DocumentUpload, DocumentUploadOutcome,
    DownloadedDocument, SavedName, MAX_DOCUMENT_BYTES,
};
pub use domain::{
    AuthInfoUpdate, ClientHoldResult, DomainCheck, DomainControlResult, DomainCreate, DomainInfo,
    DomainListPage, DomainListQuery, DomainListing, DomainRenew, DomainUpdate, Registration,
    RemoveClientHold, RenewalResult, SetClientHold, TransferCodeUpdate,
};
pub use dyndns::{
    DynDnsAccount, DynDnsAccountInfo, DynDnsAccountRef, DynDnsCheck, DynDnsCreated, DynDnsLog,
    DynDnsLogEntry, DynDnsRecord, DynDnsUpdate,
};
pub use dyndnssubscription::DynDnsSubscription;
pub use error::{
    retry_after_from_header, Error, ErrorSource, HttpBody, Result, MAX_HTTP_BODY_CHARS,
};
pub use host::{
    HostCheck, HostCheckResult, HostCreate, HostQuery, HostRecord, HostUpdate, MAX_HOST_ADDRESSES,
};
pub use hosting::{
    HostingOrder, HostingPackage, HostingPeriod, HostingReinstatement, HostingSuspension,
};
pub use message::{Message, MessageAck, PolledMessage};
pub use nameserver::{NameserverCheck, ZoneInfo, ZoneListPage, ZoneListing, ZoneSummary};
pub use nameserverset::{
    NameserverSet, NameserverSetCreate, NameserverSetType, NameserverSetUpdate,
};
pub use news::NewsItem;
pub use nichandle::{NicHandle, NicHandleListPage, NicHandleListing, NicHandleQuery};
pub use pagination::{
    Listing, Page, Pages, Pagination, DEFAULT_PAGE_SIZE, MAX_ITEMS, MAX_PAGES, MAX_PAGE_SIZE,
};
pub use pdf::{PdfFile, PdfHandle, PdfRender};
pub use price::{DomainPriceQuote, ExtraDataRule, PriceChange, PriceList, PromoCode, TldPrice};
pub use record::{
    DnsRecord, RecordId, RecordSet, RecordSpec, RecordType, RecordUpdate, DEFAULT_TTL, MAX_TTL,
};
pub use rpc::{Detail, RpcRequest, RpcResponse};
pub use tag::{Tag, TagUpdate, TagUsage, TaggedDomains};
pub use transfer::{
    ActionKind, ExtData, Irreversible, OwnershipResult, PushRequest, RestoreRequest, RestoreResult,
    TradeRequest, TransferAnswer, TransferRequest,
};
#[cfg(feature = "http")]
pub use transport::ReqwestTransport;
pub use transport::{
    read_capped_body, ChunkSource, Response, Transport, TransportStage, DEFAULT_MAX_RESPONSE_BYTES,
};
pub use types::{
    parse_ip, AuthCode, ContactType, DocumentFormat, DomainName, Email, Handle, Hostname, Password,
    Period, PriceType, RenewalMode, Timestamp, MAX_AUTH_CODE_LEN, MAX_DOMAIN_LEN, MAX_LABEL_LEN,
    MAX_PASSWORD_LEN,
};
pub use zone::{RecordExport, UrlRedirectType, ZoneCreate, ZoneExport, ZoneType, ZoneUpdate};
