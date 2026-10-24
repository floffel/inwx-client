//! Typed client for the [INWX](https://www.inwx.com) `DomRobot` JSON-RPC API —
//! domains, DNS records, contacts and prices.
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
//! | DNS records | `nameserver.info` (read), `createRecord`, `updateRecord`, `deleteRecord` |
//! | Zones | `nameserver.list`, `nameserver.info`, `nameserver.delete`, `nameserver.check` |
//! | Contacts | `contact.create`, `info`, `list`, `update`, `delete` |
//! | Prices | `domain.getPrices`, `domain.getdomainprice` |
//!
//! Everything else (accounting, certificates, hosting, `DynDNS`, DNSSEC, tags,
//! transfer/trade/restore, bulk export) is reachable through [`InwxClient::call`]
//! and is listed as deliberately out of scope in the README.
//!
//! # Design
//!
//! * **Validate before you send.** [`DomainName`], [`Hostname`], [`RecordSpec`],
//!   [`ContactRequest`] and [`Period`] reject what the API would reject, so a
//!   typo costs a local error instead of a charged registration.
//! * **Parse permissively.** Unknown fields are ignored, unknown enum values are
//!   carried ([`RecordType::Other`], [`RenewalMode::Other`],
//!   [`ContactType::Other`]), and scalars are accepted as numbers or strings —
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
//! * The password is only ever sent in the `account.login` body, never in a URL
//!   or a header; afterwards the opaque session cookie is the only credential on
//!   the wire.
//! * Session cookies and credentials are rejected if they contain control
//!   characters, so a value cannot smuggle a second header.
//! * Retries are bounded (three attempts, exponential backoff) and only apply to
//!   transport failures, 429/5xx and `2300` (pending transfer) — a rejected
//!   command is never repeated.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// `record::RecordSpec` and friends read better than a flattened module.
#![allow(clippy::module_name_repetitions)]

pub mod client;
pub mod contact;
pub mod domain;
pub mod error;
pub mod nameserver;
pub mod price;
pub mod record;
pub mod rpc;
pub mod transport;
pub mod types;

pub use client::{
    AccountInfo, Credentials, InwxClient, Language, RetryPolicy, DEFAULT_ATTEMPTS,
    DEFAULT_BASE_DELAY, DEFAULT_BASE_URL, DEFAULT_MAX_DELAY, SANDBOX_BASE_URL,
};
pub use contact::{Contact, ContactListPage, ContactQuery, ContactRequest, ContactUpdate};
pub use domain::{
    DomainCheck, DomainCreate, DomainInfo, DomainListPage, DomainListQuery, DomainRenew,
    DomainUpdate, Registration, RenewalResult,
};
pub use error::{Error, Result};
pub use nameserver::{NameserverCheck, ZoneInfo, ZoneListPage, ZoneSummary};
pub use price::{DomainPriceQuote, PriceList, TldPrice};
pub use record::{DnsRecord, RecordId, RecordSpec, RecordType, RecordUpdate, DEFAULT_TTL, MAX_TTL};
pub use rpc::{Detail, RpcRequest, RpcResponse};
#[cfg(feature = "http")]
pub use transport::ReqwestTransport;
pub use transport::{Response, Transport};
pub use types::{
    ContactType, DomainName, Hostname, Period, PriceType, RenewalMode, MAX_DOMAIN_LEN,
    MAX_LABEL_LEN,
};
