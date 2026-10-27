# API contracts

Every shape this crate encodes was read from the published INWX DomRobot API
documentation, then written down here with the page and table it came from, so a
later change can be checked against the source instead of against our memory.

**Documentation source** (English, fetched 2026-10-26):

- chapter 2: `https://account.inwx.com/en/help/apidoc/f/ch02sNN.html` (one page
  per object, `NN` = the section number below)
- chapter 3 (datatypes): `https://account.inwx.com/en/help/apidoc/f/ch03.html`
- chapter 4 (result codes): `https://account.inwx.com/en/help/apidoc/f/ch04.html`

The table numbers below are the anchors inside those pages (`Table 2.NNN`), which
is what makes a claim checkable: `nameserver.create` is Table 2.195, not "somewhere
in the nameserver chapter".

Anything marked **unverified** further down is a point the documentation does not
settle. It is modelled as documented and flagged rather than guessed at.

## 0.1.x (extracted surface, unchanged)

| Area | Methods | Source |
| --- | --- | --- |
| Session | `account.login`, `account.logout`, `account.check`, `account.info` | ch02 §2.1, Tables 2.1–2.17 |
| Domains | `domain.check`, `create`, `info`, `list`, `update`, `renew`, `delete`, `whois` | ch02 §2.9 |
| DNS records | `nameserver.info`, `createRecord`, `updateRecord`, `deleteRecord` | ch02 §2.15, Tables 2.197–2.212 |
| Zones (read) | `nameserver.list`, `nameserver.info`, `nameserver.delete`, `nameserver.check` | ch02 §2.15 |
| Contacts | `contact.create`, `info`, `list`, `update`, `delete` | ch02 §2.6 |
| Prices | `domain.getPrices`, `domain.getdomainprice` | ch02 §2.9 |
| Envelope | `{"method":…,"params":…}` / `{"code":…,"resData":…}` | ch02 §1.2, §1.4; codes ch04 |

## 0.2.0 — zone lifecycle (`src/zone.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s15.html>

| Method | Wrapper | Input table | Output table | Notes |
| --- | --- | --- | --- | --- |
| `nameserver.create` | `ZoneCreate` → `create_zone` | 2.195 | 2.196 | `domain` `token255` + `type` `nsType` required; `ns` `nsList`, `masterIp` `ip`, `web` `token0255`, `mail` `text0255`, `soaEmail` `email`, `urlRedirectType`, `urlRedirectTitle/Description/FavIcon/Keywords` `token0255`, `testing`, `ignoreExisting`; output `roId` `int` |
| `nameserver.update` | `ZoneUpdate` → `update_zone` | 2.211 | — | `domain`/`roId`, `type`, `masterIp`, `ns`, `web`, `mail`, `urlRedirect*`, `testing`. **No record parameter, and no `soaEmail`** |
| `nameserver.delete` | `delete_zone` (0.1.x), `delete_zone_dry_run` | 2.199 | — | `domain`/`roId` + `testing` |
| `nameserver.clone` | `clone_zone` | 2.193 | 2.194 | `sourceDomain`, `targetDomain`; output `roId` |
| `nameserver.export` | `export_zone` | 2.201 | 2.202 | `domain`, `zonefile` (`boolean`, default `true`); output `export` `text` |
| `nameserver.exportlist` | `export_zone_list` | 2.203 | 2.204 | `format` `documentformat`, `domain`, `wide`, `page`, `pagelimit`; output `count` + `domains` |
| `nameserver.exportrecords` | `export_records` | 2.205 | 2.206 | `format`, `name`, `page`, `limit`; output `count` + `data` (CSV clear text) |
| `nameserver.list` (filter) | `find_zones` | 2.209 | 2.210 | same method, `domain` filter exposed |

Datatypes used: `nsType` = `MASTER` \| `SLAVE`; `urlRedirectType` = `HEADER301` \|
`HEADER302` \| `FRAME`; `documentformat` = `RAW`/`raw`, `PDF`/`pdf`, `CSV`
(ch03 §3.74, §3.109, §3.38).

Validation added on top of the documented types (all rejected before the wire):
label rules and the 253/63 limits (already in `DomainName`), `SLAVE` without
`masterIp`, `MASTER` with `masterIp`, duplicate nameservers, frame metadata
without a `FRAME` redirect, a redirect type without a `web` target, an unknown
`nsType` on create.

### Record set rules (`src/record.rs`)

Not an API shape but a DNS rule the API does not enforce:

- `nameserver.createRecord` takes one record (Table 2.197) and is additive; there
  is no batch or replace method. `RecordSet` exists so several records can be
  validated as a group before the first call.
- Apex CNAME is refused: the apex always carries `SOA` and `NS` (RFC 1034 §3.6.2
  rule "a CNAME cannot coexist with other data"), and INWX offers `ALIAS` for
  apex aliasing (`recordType` list, ch03 §3.62).
- `TXT` content must not be pre-quoted: `content` is documented as `text`
  (Table 2.197) and stored verbatim (Table 2.208), so presentation quotes would
  be published.

## 0.2.0 — ownership (`src/transfer.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s09.html>

| Method | Wrapper | Input table | Output table | Notes |
| --- | --- | --- | --- | --- |
| `domain.transfer` | `TransferRequest` → `transfer_domain` | 2.139 | 2.140 | `domain`, `agreedPrice` `float`, `registrant`/`admin`/`tech`/`billing` `int`, `ns` `nsList`, `nsTakeover` `boolean`, `contactTakeover` `boolean`, `transferLock` (default `1`), `authCode` `token255`, `renewalMode`, `whoisProvider`, `whoisUrl`, `extData`, `scDate` `timestamp`, `asynchron`, `voucher` `text64`, `testing`; output `roId`, `price`, `currency`, `notifications` |
| `domain.trade` | `TradeRequest` → `trade_domain` | 2.137 | 2.138 | `registrant` **required**; `admin`/`tech`/`billing`, `ns`, `authCode`, `whoisProvider`/`whoisUrl`, `scDate`, `extData`, `asynchron`, `testing` |
| `domain.push` | `PushRequest` → `push_domain` | 2.127 | — | `domain`, `target` `text64`, `scDate`, `testing` |
| `domain.restore` | `RestoreRequest` → `restore_domain` | 2.132 | 2.133 | `domain`, `renewalMode`, `testing`; output `domain`, `domainAce` |
| `domain.transfercancel` | `cancel_transfer` | 2.141 | — | `domain` only |
| `domain.transferOut` | `answer_transfer_out` | 2.142 | — | `domain`, `answer` `transferAnswer` (`ACK` \| `NACK`, ch03 §3.106) |

`extData` keys documented in ch03 §3.49: `NO-DOMAIN-CHECK` (`boolean`),
`NO-HOST-CHECK` (`boolean`), `BIRTH-DATE` (`date`), `BIRTH-CITY` (`text64`), plus
per-TLD codes carried verbatim through `ExtData::set`.

Guard: every wrapper needs an `Irreversible` acknowledgement naming the action and
the domain. That is a crate rule, not an API field — nothing is sent for it.

## 0.2.0 — DNSSEC (`src/dnssec.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s08.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `dnssec.enablednssec` | `enable_dnssec` | 2.96 | — |
| `dnssec.disablednssec` | `disable_dnssec` | 2.95 | — |
| `dnssec.adddnskey` | `AddDnsKeyRequest` → `add_dns_key` | 2.91 | 2.92 |
| `dnssec.deletednskey` | `delete_dns_key` | 2.94 | — |
| `dnssec.deleteall` | `delete_all_dns_keys` | 2.93 | — |
| `dnssec.info` | `dnssec_info` | 2.97 | 2.98 |
| `dnssec.listkeys` | `DnssecKeyQuery` → `list_dns_keys` | 2.99 | 2.100 |

Inputs: `domainName` `text255`, `dnskey` (presentation), `ds` (presentation),
`calculateDigest` `boolean`, `digestType` `dnssecDigestType` (2 = SHA256, 4 =
SHA384), `key` `int`, `domains` `array_text255`, and the `listkeys` filters
(`domainName`, `domainNameIdn`, `keyTag`, `flagId`, `algorithmId`, `publicKey`,
`digestTypeId`, `digest`, `createdBefore`, `createdAfter`, `status`, `active`,
`page`, `pagelimit`).

Datatypes (ch03 §3.33–3.37): algorithms 5, 7, 8, 10, 13, 14, 15, 16; digest types
2, 4; flags 256 (`ZONE`), 257 (`ZONE+SEP`); key status `CREATE`, `DELAYED`, `OK`,
`DELETED`, `IGNORE`; domain status `DELETE_ALL`, `MANUAL`, `UPDATE`.

Validation: the DNSKEY parser enforces `IN DNSKEY`, protocol `3`, flag **257
only** — the method's description says "only ZONE+SEP keys (flag value 257) are
accepted" — a documented algorithm and a documented digest type. `calculateDigest`
and `ds` are mutually exclusive because the documentation says the calculation
*overrides* `ds`, which would silently discard a caller's value.

## 0.2.0 — certificates (`src/certificate.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s05.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `certificate.cancel` | `cancel_certificate` | 2.50 | — |
| `certificate.create` | `CertificateOrder` → `order_certificate` | 2.51 | 2.52 |
| `certificate.getProduct` | `certificate_product` | 2.53 | 2.54 |
| `certificate.info` | `certificate_info` | 2.55 | 2.56 |
| `certificate.list` | `CertificateQuery` → `list_certificates` | 2.57 | 2.58 |
| `certificate.listProducts` | `CertificateProductQuery` → `list_certificate_products` | 2.59 | 2.60 |
| `certificate.listRemainingNeededData` | `certificate_missing_data` | 2.61 | 2.62 |
| `certificate.log` | `certificate_log` | 2.63 | 2.64 |
| `certificate.reissue` | `reissue_certificate` | 2.65 | 2.66 |
| `certificate.renew` | `CertificateUpdate` → `renew_certificate` | 2.67 | 2.68 |
| `certificate.setAutorenew` | `set_certificate_autorenew` | 2.69 | — |
| `certificate.setresendapproval` | `resend_certificate_approval` | 2.70 | — |
| `certificate.updateOrder` | `CertificateUpdate` → `update_certificate_order` | 2.71 | 2.72 |

Documented rules encoded: `productId` `int` required; `csr` `text` or
`commonName` `text255` needed; `period` is 1 or 2 years (`int`); `san` is a
comma-separated `text0`; `validationMethod` is `EMAIL`, `DNS` or `FILE`
(`text064`) and `validationEmail` (`email`) only applies to `EMAIL`; `ownerc`,
`adminc`, `techc` are contact ids. `missing` carries
`csr | validationMethod | validationEmail | ownerc | adminc | techc` (Table 2.62).

Local checks: CSR must look like a PEM request and must not contain
`PRIVATE KEY` — the field is a signing request, and a key pasted there would be
uploaded to a third party. Wildcard SANs are accepted (`*.example.com`) because
products sell them, with exactly one leftmost `*`.

## 0.2.0 — hosting (`src/hosting.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s13.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `hosting.cancel` | `cancel_hosting` | 2.177 | — |
| `hosting.controlPanel` | `hosting_control_panel` | 2.178 | 2.179 |
| `hosting.create` | `HostingOrder` → `create_hosting` | 2.180 | — |
| `hosting.getPrices` | `hosting_prices` | 2.181 | 2.181 |
| `hosting.issuspended` | `hosting_suspended` | 2.182 | 2.183 |
| `hosting.list` | `list_hosting` | 2.184 | 2.184 |
| `hosting.reinstate` | `reinstate_hosting` | 2.185 | — |
| `hosting.unsuspend` | `unsuspend_hosting` | 2.186 | 2.187 |
| `hosting.updatePeriod` | `update_hosting_period` | 2.188 | — |

`hostingId` is `token255` on cancel/create/reinstate and `int` on
controlPanel/issuspended/unsuspend/updatePeriod — the crate takes an `i64` and
sends a string where the table says `token255`. The billing period is 1, 3, 6,
12, 18 or 24 months ("but not less than default for the product").

## 0.2.0 — nameserver sets (`src/nameserverset.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s16.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `nameserverset.create` | `NameserverSetCreate` → `create_nameserver_set` | 2.213 | 2.214 |
| `nameserverset.delete` | `delete_nameserver_set` | 2.215 | — |
| `nameserverset.info` | `nameserver_set_info` | 2.216 | 2.217 |
| `nameserverset.list` | `list_nameserver_sets` | 2.218 | 2.219 |
| `nameserverset.update` | `NameserverSetUpdate` → `update_nameserver_set` | 2.220 | — |

Datatype `nsSetType` = `PRIMARY` \| `SECONDARY` \| `EXTERNAL` (ch03 §3.73);
`visible` defaults to `true` on create; `masterIp` belongs to a secondary set.

## 0.2.0 — tags (`src/tag.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s20.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `tag.create` | `create_tag` | 2.229 | 2.230 |
| `tag.delete` | `delete_tag` | 2.231 | — |
| `tag.info` | `tag_info` | 2.232 | 2.233 |
| `tag.list` | `list_tags` | 2.234 | 2.235 |
| `tag.update` | `TagUpdate` → `update_tag` | 2.236 | 2.237 |

`tag.update` renames **or** tags: "Updating tag name has priority and ignores
add/rem" (Table 2.236), so the crate refuses the combination instead of letting a
rename discard the lists. `add`/`rem` are `tagUpdateAdd`/`tagUpdateRem`, i.e.
`{"domainId": [array_int]}` (ch03 §3.90, §3.91).

## 0.2.0 — DynDNS (`src/dyndns.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s10.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `dyndns.changepassword` | `change_dyndns_password` | 2.147 | — |
| `dyndns.check` | `check_dyndns` | 2.148 | 2.149 |
| `dyndns.create` | `DynDnsAccount` → `create_dyndns` | 2.150 | 2.151 |
| `dyndns.delete` | `delete_dyndns` | 2.152 | — |
| `dyndns.info` | `dyndns_info` | 2.153 | 2.154 |
| `dyndns.list` | `list_dyndns` | 2.155 | 2.156 |
| `dyndns.log` | `dyndns_log` | 2.157 | 2.158 |
| `dyndns.updateRecord` | `dyndns_update_record` | 2.159 | 2.160 |

`username` datatype is 5–42 characters (ch03 §3.112) and is enforced locally;
`password` is `text64` for create and changepassword. The account selector is
`accountId` `int` or `username` on delete/info/list, which
`DynDnsAccountRef` makes mutually exclusive by construction.

## 0.2.0 — DynDNS subscriptions (`src/dyndnssubscription.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s11.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `dyndnssubscription.cancel` | `cancel_dyndns_subscription` | 2.161 | — |
| `dyndnssubscription.create` | `create_dyndns_subscription` | 2.162 | — |
| `dyndnssubscription.list` | `list_dyndns_subscriptions` | 2.163 | 2.164 |
| `dyndnssubscription.listProducts` | `list_dyndns_subscription_products` | 2.165 | 2.166 |

Both `create` and `cancel` take a parameter called `id`; in `create` it is the
plan id, in `cancel` the customer's subscription id (Table 2.161/2.162). The crate
keeps them as two differently named arguments so the pair cannot be swapped.

## 0.2.0 — accounting (`src/accounting.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s02.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `accounting.accountBalance` | `account_balance` | — | 2.18 |
| `accounting.creditLogById` | `credit_log` | 2.19 | 2.20 (`log` object) |
| `accounting.getInvoice` | `invoice_document` | 2.21 | 2.22 (`pdf` base64) |
| `accounting.getPreviewInvoice` | `preview_invoice` | 2.23 | 2.24 |
| `accounting.getReceipt` | `receipt` | 2.25 | 2.26 |
| `accounting.getstatement` | `StatementQuery` → `statement` | 2.27 | 2.28 (`pdf`, `raw`) |
| `accounting.listInvoices` | `list_invoices` | — | 2.29 |
| `accounting.lockedFunds` | `locked_funds` | 2.30 | 2.31 |
| `accounting.log` | `TransactionLogQuery` → `account_log` | 2.32 | 2.33 |
| `accounting.refund` | `RefundRequest` → `refund` | 2.34 | — |
| `accounting.sendbypost` | `PostalDelivery` → `send_invoice_by_post` | 2.35 | — |

Documents arrive base64-encoded (`base64`, ch03 §3.17); `Document::pdf_bytes`
decodes them with the `base64` crate and refuses invalid input rather than writing
a corrupt file. `accounting.refund` moves money and therefore requires the same
`Irreversible` acknowledgement as the ownership commands.

## Rules the API does not define

Not shapes from the documentation, but limits this crate imposes anyway:

- **Response size cap (`src/transport.rs`).** One answer may not exceed
  `DEFAULT_MAX_RESPONSE_BYTES` (4 MiB). INWX does not bound a body, so without a
  cap a misbehaving or compromised endpoint decides how much memory the process
  allocates before the parser sees a byte. The limit is checked against
  `Content-Length` before the body is read and against a running total while it
  streams, so a header that lies too small still fails at the chunk that crosses
  it. Documented answers sit far below the cap — a record list or an export page
  is tens to hundreds of kilobytes — and `nameserver.export` with `zonefile=true`
  (Table 2.202, the whole zone in one `text` field) is the one shape that could
  plausibly need more; that caller builds its transport with
  `ReqwestTransport::with_max_response_bytes`. Crossing the cap is
  `Error::ResponseTooLarge`, terminal on purpose: the command behind that
  response may already have been executed, so repeating it duplicates work.

## Unverified

Points the documentation does not settle. Each is modelled as documented and
flagged here; none is a guess about an endpoint's existence.

| Item | Status | Why |
| --- | --- | --- |
| `nameserver.create` with `type=MASTER` and no `ns` | **unverified** | `ns` is documented as optional (Table 2.195) and the description does not say what happens then; INWX presumably assigns its own nameservers. The crate sends the request as documented. |
| `dyndns.updateRecord` account selection | **unverified** | Table 2.159 lists only `ipAddress` and `ipAddressV6`; how the account is identified is not documented in the public chapter. The crate sends exactly those two parameters. |
| `hosting.create` id type | **partially documented** | `hostingId`/`productId` are `token255` there (Table 2.180) but `int` elsewhere (§2.13); the crate takes `i64` and sends strings for `hosting.create`, numbers for the `int` methods. |
| `hosting.getPrices` output shape | **unverified** | Table 2.181 documents `hosting[]` with only `id` and `product`; a price field is implied by the name but not listed, so no price is modelled. |
| `certificate.log` answer shape | **unverified** | Table 2.64 lists flat fields; whether the API wraps them in an array is not shown. The parser accepts an array or a single object. |
| `nameserver.exportlist` "export as file" | **unverified** | Table 2.203/2.204 promises a document but documents a `count`+`domains` payload; the crate parses the documented payload. |
| `tag.list` `count` nesting | **unverified** | Table 2.235 shows `count` → `domain` with an ambiguous indentation; parsed as `{"count": {"domain": N}}` with a scalar `count` also tolerated. |
| Live-endpoint behaviour for every 0.2.0 method | **unverified** | No credentials in CI; every test is offline against fixtures. Method names, parameters and datatypes are from the tables above. |
| `extData` per-TLD keys | **documented, not enumerated** | ch03 §3.49 lists the generic keys and then a long TLD-specific list; `ExtData::set` carries any upper-case token. |

## Deliberately not modelled

- **API-key authentication** — marketed by INWX but absent from the public API
  documentation; the crate implements password login only (see README).
- **`application.*`, `authinfo2.*`, `customer.*`, `document.*`, `host.*`,
  `message.*`, `news.list`, `nichandle.list`, `pdf.*`** — separate API objects for
  the reseller/partner product, not part of the registrar surface this crate
  claims. They are reachable through `InwxClient::call`, and the gap is tracked
  as an issue rather than presented as a boundary.
