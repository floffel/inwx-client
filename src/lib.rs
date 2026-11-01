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
//! ```no_run
//! # #[cfg(feature = "http")]
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use inwx_client::{DomainName, InwxClient, RecordSpec, ReqwestTransport};
//!
//! let client = InwxClient::new(ReqwestTransport::new())
//!     .with_credentials("username", std::env::var("INWX_PASSWORD")?)?;
//!
//! let domain = DomainName::parse("example.com")?;
//! let check = client.check_domain(&domain).await?;
//! println!("available: {}", check.is_available());
//!
//! let record = RecordSpec::a("www", "203.0.113.7")?.with_ttl(3600)?;
//! let id = client.create_record(&domain, &record).await?;
//! client.delete_record(&id).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # What it covers
//!
//! | Area | Methods |
//! | --- | --- |
//! | Session | `account.login`, `account.logout`, `account.check` (implicit), `account.info`, `account.unlock`, `account.changepassword` |
//! | Domains | `domain.check`, `domain.create`, `domain.info`, `domain.list`, `domain.update`, `domain.renew`, `domain.delete`, `domain.whois`, `domain.setClientHold`, `domain.removeClientHold` |
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
//! Every name in the table is a command the crate really sends; a count such as
//! `certificate.* (13 methods)` covers exactly the commands implemented in
//! `src/certificate.rs`, and `tests/coverage_table.rs` fails the build when the
//! two drift apart. `account.check` is implicit: the client treats it as a
//! session-free method but does not wrap it, so it goes through
//! [`InwxClient::call`]. Unknown methods stay reachable the same way; what is
//! not modelled yet is tracked as an issue, not hidden as "out of scope".
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
//! * **No socket needed.** The HTTP layer sits behind [`Transport`]; the test
//!   suite and the examples in these docs drive a scripted mock.
//!
//! # Feature flags
//!
//! * `http` (default) — pulls in `reqwest` (rustls) and `tokio/time` and
//!   provides [`ReqwestTransport`]. Without it the crate is pure request
//!   building + response parsing: no TLS stack, no async runtime, no socket.
//!
//! # Security
//!
//! * `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`.
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
//!   `Display`; the DynDNS account type redacts its password.
//! * A certificate CSR is refused if it contains a private key: the field takes a
//!   signing request, and anything else would upload a secret to a third party.
//! * Retries are bounded (three attempts, exponential backoff) and only apply to
//!   failures that happened before the request was written, 429/5xx and `2300`
//!   (pending transfer) — a rejected command is never repeated. A 429/5xx is
//!   replayed only for a read-only method as well: for an order the status says
//!   nothing about whether it already went through, so that outcome is
//!   [`Error::Uncertain`] after a single attempt.
//! * A transport failure after the request was written (a timeout, a reset
//!   mid-response) is [`Error::Uncertain`]: the command may have run. It is
//!   replayed only for a read-only method ([`is_read_only_method`]), never for a
//!   mutating one, so a registration cannot be submitted twice.
//! * [`Password`] (the new password of `account.changepassword`) redacts itself
//!   in `Debug` and `Display`, compares in constant time, is zeroized when it is
//!   dropped and has no `Deserialize`: a secret is an input and is never parsed
//!   back out of a response.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
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
pub mod pdf;
pub mod price;
pub mod record;
pub mod rpc;
pub mod tag;
pub mod transfer;
pub mod transport;
pub mod types;
pub mod zone;

pub use account::{AccountRole, AccountRoleEntry};
pub use accounting::{
    AccountBalance, CreditLog, Document, Invoice, LockedFund, LockedFunds, PostalDelivery,
    RefundRequest, SslFund, StatementQuery, Transaction, TransactionLog, TransactionLogQuery,
};
pub use application::{
    Application, ApplicationCheck, ApplicationCheckResult, ApplicationCreate, ApplicationQuery,
    ApplicationType, ApplicationUpdate,
};
pub use authinfo2::{AuthInfo2Order, AuthInfo2OrderResult, AuthInfo2PriceQuote};
pub use certificate::{
    Certificate, CertificateId, CertificateLogEntry, CertificateMissingData, CertificateOrder,
    CertificateOrderResult, CertificateProduct, CertificateProductQuery, CertificateQuery,
    CertificateTerm, CertificateUpdate, CertificateValidationMethod, MAX_CSR_LEN,
};
pub use client::{
    is_read_only_method, AccountInfo, AccountUnlock, Credentials, InwxClient, Language,
    RetryPolicy, UnlockAccount, DEFAULT_ATTEMPTS, DEFAULT_BASE_DELAY, DEFAULT_BASE_URL,
    DEFAULT_MAX_DELAY, MAX_SUBACCOUNT_USERNAME_LEN, SANDBOX_BASE_URL,
};
pub use contact::{Contact, ContactListPage, ContactQuery, ContactRequest, ContactUpdate};
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
    DocumentEntry, DocumentQuery, DocumentUpload, DownloadedDocument, MAX_DOCUMENT_BYTES,
};
pub use domain::{
    ClientHoldResult, DomainCheck, DomainCreate, DomainInfo, DomainListPage, DomainListQuery,
    DomainRenew, DomainUpdate, Registration, RemoveClientHold, RenewalResult, SetClientHold,
};
pub use dyndns::{
    DynDnsAccount, DynDnsAccountInfo, DynDnsAccountRef, DynDnsCheck, DynDnsCreated, DynDnsLog,
    DynDnsLogEntry, DynDnsRecord, DynDnsUpdate,
};
pub use dyndnssubscription::DynDnsSubscription;
pub use error::{Error, Result};
pub use host::{
    HostCheck, HostCheckResult, HostCreate, HostQuery, HostRecord, HostUpdate, MAX_HOST_ADDRESSES,
};
pub use hosting::{
    HostingOrder, HostingPackage, HostingPeriod, HostingReinstatement, HostingSuspension,
};
pub use message::{Message, MessageAck, PolledMessage};
pub use nameserver::{NameserverCheck, ZoneInfo, ZoneListPage, ZoneSummary};
pub use nameserverset::{
    NameserverSet, NameserverSetCreate, NameserverSetType, NameserverSetUpdate,
};
pub use news::NewsItem;
pub use nichandle::{NicHandle, NicHandleQuery};
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
pub use transport::{Response, Transport, TransportStage};
pub use types::{
    parse_ip, AuthCode, ContactType, DocumentFormat, DomainName, Email, Handle, Hostname, Password,
    Period, PriceType, RenewalMode, Timestamp, MAX_DOMAIN_LEN, MAX_LABEL_LEN, MAX_PASSWORD_LEN,
};
pub use zone::{RecordExport, UrlRedirectType, ZoneCreate, ZoneExport, ZoneType, ZoneUpdate};
