# inwx-client

Typed Rust client for the [INWX](https://www.inwx.com) DomRobot JSON-RPC API —
domains, DNS records, contacts and prices.

INWX is a German registrar and DNS provider. One endpoint
(`https://api.domrobot.com/jsonrpc/`, sandbox: `https://api.ote.domrobot.com/jsonrpc/`)
speaks a small JSON-RPC dialect where **transport success is not command
success**: every command answers HTTP 200 and reports failure in the body
(`{"code": 2303, "msg": "Object does not exist"}`). This crate models that
correctly — a non-success code is an `Error::Api`, not a parse problem.

```toml
[dependencies]
inwx-client = "0.1"
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
(`account.inwx.de/en/help/apidoc`, chapters 1–4).

| Area | Methods / types | Notes |
| --- | --- | --- |
| Session | `account.login`, `account.logout`, `account.check` (implicit), `account.info` | cookie session, lazy login, one re-login on `2200`/`2201`/`2202` |
| Domains | `domain.check`, `domain.create`, `domain.info`, `domain.list`, `domain.update`, `domain.renew`, `domain.delete`, `domain.whois` | auth code (`authCode`) via `domain.info wide=1`; renewal mode and transfer lock via `domain.update` |
| DNS records | `nameserver.info` (read), `nameserver.createRecord`, `nameserver.updateRecord`, `nameserver.deleteRecord` | typed payloads per record type, multi-id updates |
| Zones | `nameserver.list`, `nameserver.info`, `nameserver.delete`, `nameserver.check` | zone *creation* is out of scope, see below |
| Contacts | `contact.create`, `contact.info`, `contact.list`, `contact.update`, `contact.delete` | documented field lengths and country codes enforced |
| Prices | `domain.getPrices`, `domain.getdomainprice` | `f64` quotes, not amounts to sum |
| Anything else | `InwxClient::call(method, params)` | login, cookies, retries and error envelopes still apply |

### Design

* **Validate before you send.** `DomainName`, `Hostname`, `RecordSpec`,
  `ContactRequest`, `Period` and the update builders reject what the API would
  reject, so a typo is a local error instead of a charged registration or an
  `2004 Parameter value range error`. `A` records must carry IPv4, `AAAA` IPv6,
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

## Feature flags

* `http` (default) — `reqwest` with rustls and `tokio/time`, providing
  `ReqwestTransport`. Without it the crate is request building plus response
  parsing only: no TLS stack, no runtime, and `cargo build --no-default-features`
  is enough to consume the types.

## Deliberately out of scope

These are documented INWX surfaces this crate does not model. Each is reachable
through `InwxClient::call`, which keeps sessions, retries and error handling:

* **Registering and updating zones** (`nameserver.create`, `nameserver.update`,
  `nameserver.clone`, `nameserver.export*`) — slave/secondary zones and URL
  forwarding are a different workflow from record CRUD, and the parameters are
  mostly mutually exclusive.
* **Domain transfer, trade, push, restore, transfer cancel/out** — moves money
  and ownership; a wrong call is not recoverable by retrying.
* **Certificates, hosting, DynDNS, DNSSEC, tags, nameserver sets, accounting,
  invoices, documents, PDFs, messages, applications, sub-accounts** — adjacent
  products, each with its own object model.
* **`domain.log`, `domain.stats`, `domain.getRules`, `domain.getTldGroups`,
  `domain.getPromos`, `domain.getalldomainprices`, `domain.priceChanges`,
  `contact.log`, `contact.sendcontactverification`, `nameserver.export*`** —
  reporting and TLD metadata; `domain.getPrices` and `domain.getdomainprice`
  cover the price questions this crate was written for.
* **API-key authentication** — the public API documentation only describes
  `account.login` with username and password, even though INWX markets API keys
  elsewhere. Not implemented rather than guessed at (see *Unverified*).
* **Automatic pagination** — `list_domains`, `list_contacts` and `list_zones_page`
  take a page and return `count`, so the caller decides when to stop.

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
* Retries are bounded and only apply to transient failures, so a rejected
  registration cannot be submitted three times.

## Testing

```bash
cargo test                        # unit + integration + 229 doctests, no network
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
* **Property** (`proptest`) — builders and parsers never panic over arbitrary
  input; status classification always agrees with `into_result`.
* **Coverage** — 98.6 % lines / 99.5 % functions without the `http` feature
  (96.7 % / 97.7 % with it; the reqwest adapter is the only code that needs a
  socket). CI gates at 95 %.
* **Fuzz** — `fuzz/fuzz_targets/parse_response.rs` feeds arbitrary bytes through
  the JSON-RPC parser and every typed decoder on `resData`; seeded with success,
  pending, error and hostile-shape bodies.

## License

Licensed under either of Apache-2.0 or MIT at your option.
