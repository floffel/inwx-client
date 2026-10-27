# inwx-client

Typed Rust client for the [INWX](https://www.inwx.com) DomRobot JSON-RPC API —
zones and DNS records, domain transfers and ownership changes, certificates,
hosting, DNSSEC, tags, nameserver sets, DynDNS, accounting, contacts and prices.

INWX is a German registrar and DNS provider. One endpoint
(`https://api.domrobot.com/jsonrpc/`, sandbox: `https://api.ote.domrobot.com/jsonrpc/`)
speaks a small JSON-RPC dialect where **transport success is not command
success**: every command answers HTTP 200 and reports failure in the body
(`{"code": 2303, "msg": "Object does not exist"}`). This crate models that
correctly — a non-success code is an `Error::Api`, not a parse problem.

```toml
[dependencies]
inwx-client = "0.2"
```

## Quickstart

```rust,no_run
use inwx_client::{DomainName, InwxClient, RecordSpec, ReqwestTransport};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let client = InwxClient::new(ReqwestTransport::new())
    .with_credentials("username", std::env::var("INWX_PASSWORD")?)?;

let domain = DomainName::parse("example.com")?;

// Availability (free to call).
let check = client.check_domain(&domain).await?;
println!("available: {}", check.is_available());

// DNS: create, list, update, delete.
let record = RecordSpec::a("www", "203.0.113.7")?.with_ttl(3600)?;
let id = client.create_record(&domain, &record).await?;

for existing in client.list_records(&domain).await? {
    println!("{} {} {}", existing.name_or_apex(), existing.record_type, existing.content);
}

client.delete_record(&id).await?;
# Ok(())
# }
```

The sandbox costs nothing and has the same API surface:

```rust,no_run
# use inwx_client::{InwxClient, ReqwestTransport};
# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let client = InwxClient::sandbox(ReqwestTransport::new())
    .with_credentials("user", "pass")?;
# Ok(())
# }
```

Nothing above needs a socket to compile or test: the HTTP layer sits behind the
`Transport` trait, and the whole test suite drives a scripted mock.

## What is covered

Every method below is implemented against the published INWX API documentation
(`account.inwx.com/en/help/apidoc`, chapters 1–4), and every shape is recorded in
[`docs/contracts.md`](docs/contracts.md) with the table it came from.

| Area | Methods / types | Notes |
| --- | --- | --- |
| Session | `account.login`, `account.logout`, `account.check` (implicit), `account.info` | cookie session, lazy login, one re-login on `2200`/`2201`/`2202` |
| Domains | `domain.check`, `domain.create`, `domain.info`, `domain.list`, `domain.update`, `domain.renew`, `domain.delete`, `domain.whois` | auth code (`authCode`) via `domain.info wide=1`; renewal mode and transfer lock via `domain.update` |
| Ownership | `domain.transfer`, `domain.trade`, `domain.push`, `domain.restore`, `domain.transfercancel`, `domain.transferOut` | typed builders behind an `Irreversible` acknowledgement that names the action and the domain; auth codes redacted in `Debug` |
| Zones | `nameserver.create`, `nameserver.update`, `nameserver.delete`, `nameserver.clone`, `nameserver.list`, `nameserver.info`, `nameserver.check`, `nameserver.export`, `nameserver.exportlist`, `nameserver.exportrecords` | `ZoneCreate`/`ZoneUpdate` builders; an update sends only what changed and can never touch a record |
| DNS records | `nameserver.info` (read), `nameserver.createRecord`, `nameserver.updateRecord`, `nameserver.deleteRecord` | typed payloads per record type, multi-id updates, `RecordSet` for the set-level rules (apex CNAME, CNAME siblings, duplicates) |
| Certificates | `certificate.create`, `cancel`, `getProduct`, `info`, `list`, `listProducts`, `listRemainingNeededData`, `log`, `reissue`, `renew`, `setAutorenew`, `setresendapproval`, `updateOrder` | order + `missing` completion flow; a CSR is refused if it carries a private key |
| Hosting | `hosting.create`, `cancel`, `controlPanel`, `getPrices`, `issuspended`, `list`, `reinstate`, `unsuspend`, `updatePeriod` | billing periods restricted to 1/3/6/12/18/24 months |
| DNSSEC | `dnssec.enablednssec`, `disablednssec`, `adddnskey`, `deletednskey`, `deleteall`, `info`, `listkeys` | DNSKEY/DS presentation strings parsed and checked; only `ZONE+SEP` keys (flag 257) accepted |
| Tags | `tag.create`, `delete`, `info`, `list`, `update` | a rename cannot be combined with add/remove (the API would silently drop them) |
| Nameserver sets | `nameserverset.create`, `delete`, `info`, `list`, `update` | `PRIMARY`/`SECONDARY`/`EXTERNAL`, duplicate nameservers refused |
| DynDNS | `dyndns.changepassword`, `check`, `create`, `delete`, `info`, `list`, `log`, `updateRecord`; `dyndnssubscription.create`, `cancel`, `list`, `listProducts` | usernames restricted to the documented 5–42 characters |
| Accounting | `accounting.accountBalance`, `creditLogById`, `getInvoice`, `getPreviewInvoice`, `getReceipt`, `getstatement`, `listInvoices`, `lockedFunds`, `log`, `refund`, `sendbypost` | PDFs decoded from base64 (`Document::pdf_bytes`); `refund` needs the acknowledgement |
| Contacts | `contact.create`, `contact.info`, `contact.list`, `contact.update`, `contact.delete` | documented field lengths and country codes enforced |
| Prices | `domain.getPrices`, `domain.getdomainprice` | `f64` quotes, not amounts to sum |
| Pagination | `Pagination`, `DomainPager`, `ContactPager`, `ZonePager`, `all_domains`, `all_contacts`, `all_zones` | bounded walk over `page`/`pagelimit` for `domain.list`, `contact.list`, `nameserver.list`; the item cap truncates, the request cap is an error |
| Anything else | `InwxClient::call(method, params)` | login, cookies, retries and error envelopes still apply |

### Design

* **Validate before you send.** `DomainName`, `Hostname`, `RecordSpec`,
  `RecordSet`, `ZoneCreate`, `ZoneUpdate`, `ContactRequest`, `Period` and the
  update builders reject what the API would reject, so a typo is a local error
  instead of a charged registration or an `2004 Parameter value range error`. `A` records must carry IPv4, `AAAA` IPv6,
  `CNAME`/`MX`/`NS`/`PTR`/`SRV` a host name (an IP literal is refused), TTLs must
  fit the documented `int`, and the record name rules allow `@`, `*` and
  `_service` labels while refusing whitespace and control characters.
* **Parse permissively.** Unknown fields are ignored; unknown enum values are
  carried (`RecordType::Other`, `RenewalMode::Other`, `ContactType::Other`);
  scalars are accepted as numbers *or* strings, because INWX is not consistent
  between methods (record ids are `token255` and arrive as strings, `avail` is an
  int, `transferLock` shows up as `1`/`true`).
* **Success is more than `1000`.** `1001` (action pending), `1300`, `1301` and
  `1500` (session end) are successes too; treating only `1000` as success turns a
  pending registration into an error.
* **Sessions, not tokens.** `account.login` returns a cookie; the client replays
  it, and on `2200`/`2201`/`2202` (or HTTP 401/403) it logs in once more before
  giving up. Concurrent first calls may each open a session — harmless, and the
  alternative (holding a lock across an await) buys nothing here.
* **Bounded retries.** Three attempts, exponential backoff from 500 ms to 8 s,
  only for transport failures, HTTP 429/5xx and result code `2300` (object pending
  transfer). A rejected command is never repeated.
* **Pagination you do not hand-roll.** The list methods take a 1-based `page` and a
  `pagelimit` and answer with one page plus a `count` of all matches, so a single
  call is never the whole list. `Pagination` sets the bounds - page size, item cap,
  request cap - and all three are checked locally before anything is sent, so a
  mistyped limit is a `Validation` error and not a request. `DomainPager`,
  `ContactPager` and `ZonePager` then walk every page and stop when the provider
  says there is nothing left. Reaching the item cap truncates quietly
  (`is_truncated`), because the caller asked for exactly that many items; reaching
  the request cap is `Error::Pagination`, because a list that stops early must never
  look complete.

## Feature flags

* `http` (default) — `reqwest` with rustls and `tokio/time`, providing
  `ReqwestTransport`. Without it the crate is request building plus response
  parsing only: no TLS stack, no runtime, and `cargo build --no-default-features`
  is enough to consume the types. The `reqwest` build is
  `default-features = false, features = ["json", "rustls"]`: since `reqwest`
  0.13 that means the rustls provider plus `rustls-platform-verifier`, so roots
  come from the platform trust store (the bundled `webpki-roots` feature is
  gone). A container without `ca-certificates` needs one installed, or a
  `Transport` of its own.

## Known gaps (tracked as issues)

Everything the INWX API documents is in scope. What is not implemented yet is tracked as an issue
and worked down in order - the list below is the backlog, not a boundary:

- `domain.log`, `domain.stats`, `domain.getRules`, `domain.getTldGroups` - [#14](https://github.com/floffel/inwx-client/issues/14)
- reseller/partner objects (`application.*`, `authinfo2.*`, `customer.*`, `document.*`, `host.*`,
  `message.*`, `news.*`, `nichandle.*`, `pdf.*`) - [#22](https://github.com/floffel/inwx-client/issues/22)

Two items are genuinely outside the crate, and here is why rather than a label:

- **API-key authentication** is marketed by INWX but not described in the public API documentation; we
  will not guess a scheme. Revisit when the docs cover it.
- **Live-endpoint verification** is not possible here (no credentials in CI); every test is offline
  against recorded fixtures, and the README says so per endpoint.
## Unverified

The API documentation was read, but **no call was made against a live endpoint**
while building this crate (there are no credentials in CI, and every test runs
against a mock transport). Points that rest on documentation alone, or that the
documentation does not state:

| Item | Status |
| --- | --- |
| Cookie name, `Path`, `HttpOnly`, expiry | **unverified** — the client never assumes a name; it replays every `Set-Cookie` pair it received, so the name does not matter. Whether the cookie alone is sufficient for every method is not documented. |
| Rate limits and `Retry-After` | **unverified** — the docs do not mention either. The client backs off on 429 without reading a header, so a sent header is ignored. |
| API-key authentication | **unverified** — no method is documented; the crate implements password login only. |
| `nameserver.info` returning the record array | documented (Table 2.208) and implemented; that it *also* serves as the record listing (there is no `nameserver.listRecords`) is an inference from the documented method list. |
| Prices as `float` | documented; parsed as `f64` and accepted from strings. Display-only: use the amount returned by `create`/`renew` for accounting. |
| `domain.getdomainprice` response shape | documented as `resData.domain[]`; older flat shapes are tolerated by the parser. |
| `nameserver.create` with `type=MASTER` and no `ns` | **unverified** — `ns` is optional in the docs; what INWX assigns in that case is not stated. Sent as documented. |
| `dyndns.updateRecord` account selection | **unverified** — Table 2.159 lists only `ipAddress` and `ipAddressV6`; no account selector is documented. Sent exactly as documented. |
| `hosting.getPrices` price fields | **unverified** — Table 2.181 lists only `id` and `product`, so no price is modelled. |
| `certificate.log` answer wrapper | **unverified** — flat fields documented; the parser accepts an array or a single object. |
| `tag.list` `count.domain` nesting | **unverified** — the table's indentation is ambiguous; both shapes are tolerated. |
| `dyndnssubscription.cancel` id semantics | **unverified** — Table 2.161 types `id` as "the customer's subscription id", while `create` uses the same name for the plan id; the crate takes two separate parameters so the two cannot be confused. |
| Every 0.2.0 write against a live endpoint | **unverified** — no credentials in CI; method names, parameters and datatypes come from the tables in `docs/contracts.md`. |
| `pagelimit` maximum | **unverified** — INWX types `pagelimit` as a plain `int` (Tables 2.99, 2.203, 2.209) and publishes no maximum, so `MAX_PAGE_SIZE = 1000` is a crate-side bound rather than a documented one; a larger value is refused locally. |
| Unicode → punycode | UTS-46 mapping via `idna`, so emoji become punycode and characters the mapping deletes disappear. The ACE form (`DomainName::as_str`) is what is sent, logged and compared. |

Two methods the predecessor implementation called do **not** exist in the
documented API and were replaced: `domain.cancel` (use `domain.delete` or
`domain.update` with `renewalMode`) and `domain.updateRenew` (use
`domain.update` with `renewalMode`). Record listing moved from a
`nameserver.listRecords` call to `nameserver.info`.

## Security

* `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`.
* The password is sent only in the `account.login` body — never in a URL, never
  in a header. Afterwards the opaque session cookie is the only credential on the
  wire.
* `Debug` redacts: `Credentials` prints `<redacted>` for the password, and
  `InwxClient` prints only whether a session exists. Session cookies never reach
  a log line through this crate.
* Credentials and session cookies are rejected if they contain control
  characters, so a value cannot smuggle a second header; the same check guards
  record content and update fields.
* `AuthCode` (the EPP transfer code) prints `<redacted>` in `Debug` and
  `Display`; `DynDnsAccount` redacts its password. A certificate CSR is refused
  if it contains a private key — the field takes a signing request only.
* Retries are bounded and only apply to transient failures, so a rejected
  registration cannot be submitted three times.

## Testing

```bash
cargo test                        # unit + integration + 657 doctests, no network
cargo test --no-default-features  # the same, without reqwest/tokio
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --no-deps --all-features
cargo llvm-cov --no-default-features --summary-only --fail-under-lines 95
cargo +nightly fuzz run parse_response
```

* **Unit** — permissive scalars, cookie collection, retry backoff, record and
  contact validation, error classification.
* **Integration** (`tests/`) — a recording `MockTransport` asserts method, URL,
  params and headers per call: login/replay/re-login, retry and exhaustion, HTTP
  error bodies, every record type and payload field, domain lifecycle, contacts,
  zones, prices, plus an edge-case matrix (empty credentials, malformed session
  ids, IP-in-hostname, TTL bounds, unicode/emoji domains, over-long names,
  truncated error bodies) and a 32-task concurrency test.
  Every 0.2.0 method has its own recording test asserting the method name and the
  exact parameters (`tests/zones.rs`, `tests/ownership.rs`, `tests/services.rs`,
  `tests/certificates.rs`); `tests/limits.rs` is the boundary matrix (63/64-byte
  label, 253/254-byte name, empty label, TTL bounds, IDN form, per-type record
  values, CSR size, auth-code and email shapes) and `tests/coverage.rs` calls the
  `Display`/`FromStr`/serde impls and error branches that doctests exercise —
  `cargo llvm-cov` does not count doctests.
* **Property** (`proptest`) — builders and parsers never panic over arbitrary
  input; accepted enum values round-trip through `Display`/`FromStr`; accepted
  emails and timestamps round-trip; zone params survive a JSON round trip;
  `RecordSet` never accepts an apex CNAME; an `Irreversible` acknowledgement only
  builds the request whose action it names.
* **Coverage** — 98.6 % lines / 99.6 % functions without the `http` feature. CI
  gates at 95 %; the reqwest adapter is the only code that needs a socket.
* **Fuzz** — `fuzz/fuzz_targets/parse_response.rs` feeds arbitrary bytes through
  the JSON-RPC parser and every typed decoder on `resData`; seeded with success,
  pending, error and hostile-shape bodies.

## License

Licensed under either of Apache-2.0 or MIT at your option.
