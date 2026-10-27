//! Typed client for the [INWX](https://www.inwx.com) `DomRobot` JSON-RPC API —
//! domains, zones and DNS records, ownership changes, certificates, hosting,
//! DNSSEC, tags, nameserver sets, DynDNS and accounting.
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
//! | Session | `account.login`, `account.logout`, `account.check`, `account.info` |
//! | Domains | `check`, `create`, `info`, `list`, `update`, `renew`, `delete`, `whois` |
//! | Ownership | `domain.transfer`, `domain.trade`, `domain.push`, `domain.restore`, `domain.transfercancel`, `domain.transferOut` |
//! | DNS records | `nameserver.info` (read), `createRecord`, `updateRecord`, `deleteRecord` |
//! | Zones | `nameserver.create`, `nameserver.update`, `nameserver.delete`, `nameserver.list`, `nameserver.info`, `nameserver.check`, `nameserver.clone`, `nameserver.export`, `nameserver.exportlist`, `nameserver.exportrecords` |
//! | Certificates | `certificate.*` (13 methods) |
//! | Hosting | `hosting.*` (9 methods) |
//! | DNSSEC | `dnssec.*` (7 methods) |
//! | Tags | `tag.*` (5 methods) |
//! | Nameserver sets | `nameserverset.*` (5 methods) |
//! | DynDNS | `dyndns.*` (8 methods) |
//! | Accounting | `accounting.*` (11 methods) |
//! | Contacts | `contact.create`, `info`, `list`, `update`, `delete` |
//! | Prices | `domain.getPrices`, `domain.getdomainprice` |
//! | Pagination | `Pagination` + `DomainPager`, `ContactPager`, `ZonePager` over `domain.list`, `contact.list`, `nameserver.list` |
//!
//! Unknown methods stay reachable through [`InwxClient::call`]; what is not
//! modelled yet is tracked as an issue, not hidden as "out of scope".
//!
//! # Design
//!
//! * **Validate before you send.** [`DomainName`], [`Hostname`], [`RecordSpec`],
//!   [`RecordSet`], [`ZoneCreate`], [`ContactRequest`] and [`Period`] reject what
//!   the API would reject, so a typo costs a local error instead of a charged
//!   registration or a broken zone.
//! * **Say what cannot be undone.** Ownership changes and refunds take an
//!   [`Irreversible`] acknowledgement naming the action and the object, so a
//!   transfer cannot be built by copy-pasting a block and forgetting the domain.
//! * **Parse permissively.** Unknown fields are ignored, unknown enum values are
//!   carried ([`RecordType::Other`], [`RenewalMode::Other`],
//!   [`ContactType::Other`]), and scalars are accepted as numbers or strings —
//!   INWX is inconsistent between methods.
//! * **Paginate within bounds.** [`Pagination`] carries a page size, an item cap and
//!   a request cap, all checked before the wire, and [`DomainPager`],
//!   [`ContactPager`] and [`ZonePager`] walk `page`/`pagelimit` until the provider
//!   runs out. Hitting the item cap truncates quietly; hitting the request cap is
//!   [`Error::Pagination`], so a partial list cannot look complete.
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
//!   transport failures, 429/5xx and `2300` (pending transfer) — a rejected
//!   command is never repeated.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// `record::RecordSpec` and friends read better than a flattened module.
#![allow(clippy::module_name_repetitions)]

pub mod accounting;
pub mod certificate;
pub mod client;
pub mod contact;
pub mod dnssec;
pub mod domain;
pub mod dyndns;
pub mod dyndnssubscription;
pub mod error;
pub mod hosting;
pub mod nameserver;
pub mod nameserverset;
pub mod pagination;
pub mod price;
pub mod record;
pub mod rpc;
pub mod tag;
pub mod transfer;
pub mod transport;
pub mod types;
pub mod zone;

pub use accounting::{
    AccountBalance, CreditLog, Document, Invoice, LockedFund, LockedFunds, PostalDelivery,
    RefundRequest, SslFund, StatementQuery, Transaction, TransactionLog, TransactionLogQuery,
};
pub use certificate::{
    Certificate, CertificateId, CertificateLogEntry, CertificateMissingData, CertificateOrder,
    CertificateOrderResult, CertificateProduct, CertificateProductQuery, CertificateQuery,
    CertificateTerm, CertificateUpdate, CertificateValidationMethod, MAX_CSR_LEN,
};
pub use client::{
    AccountInfo, Credentials, InwxClient, Language, RetryPolicy, DEFAULT_ATTEMPTS,
    DEFAULT_BASE_DELAY, DEFAULT_BASE_URL, DEFAULT_MAX_DELAY, SANDBOX_BASE_URL,
};
pub use contact::{
    Contact, ContactListPage, ContactPager, ContactQuery, ContactRequest, ContactUpdate,
};
pub use dnssec::{
    AddDnsKeyRequest, DnsKey, DnsKeyPair, DnssecAlgorithm, DnssecDigestType, DnssecDomainStatus,
    DnssecFlag, DnssecKey, DnssecKeyQuery, DnssecKeyStatus, DnssecState, DsRecord,
};
pub use domain::{
    DomainCheck, DomainCreate, DomainInfo, DomainListPage, DomainListQuery, DomainPager,
    DomainRenew, DomainUpdate, Registration, RenewalResult,
};
pub use dyndns::{
    DynDnsAccount, DynDnsAccountInfo, DynDnsAccountRef, DynDnsCheck, DynDnsCreated, DynDnsLog,
    DynDnsLogEntry, DynDnsRecord, DynDnsUpdate,
};
pub use dyndnssubscription::DynDnsSubscription;
pub use error::{Error, Result};
pub use hosting::{
    HostingOrder, HostingPackage, HostingPeriod, HostingReinstatement, HostingSuspension,
};
pub use nameserver::{NameserverCheck, ZoneInfo, ZoneListPage, ZonePager, ZoneSummary};
pub use nameserverset::{
    NameserverSet, NameserverSetCreate, NameserverSetType, NameserverSetUpdate,
};
pub use pagination::{
    Pagination, DEFAULT_MAX_ITEMS, DEFAULT_MAX_PAGES, DEFAULT_PAGE_SIZE, MAX_ITEMS, MAX_PAGES,
    MAX_PAGE_SIZE,
};
pub use price::{DomainPriceQuote, PriceList, TldPrice};
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
pub use transport::{Response, Transport};
pub use types::{
    parse_ip, AuthCode, ContactType, DocumentFormat, DomainName, Email, Handle, Hostname, Period,
    PriceType, RenewalMode, Timestamp, MAX_DOMAIN_LEN, MAX_LABEL_LEN,
};
pub use zone::{RecordExport, UrlRedirectType, ZoneCreate, ZoneExport, ZoneType, ZoneUpdate};
