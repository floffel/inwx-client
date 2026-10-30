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

## 0.2.0 — price surface (`src/price.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s09.html>

| Method | Wrapper | Input table | Output table | Notes |
| --- | --- | --- | --- | --- |
| `domain.getPrices` | `tld_prices` | §2.9 | §2.9 | `tld` array, each entry trimmed, stripped of a leading dot and lower-cased; an empty argument omits the key and asks for the account's whole table. Output `count` + `price[]` → `TldPrice`: `createPrice`, `transferPrice`, `renewalPrice`, `updatePrice`, `tradePrice`, `trusteePrice`, `createPeriod`, `transferPeriod`, `renewalPeriod`, `vat` |
| `domain.getdomainprice` | `domain_price` | §2.9 | §2.9 | `domain` as a one-element array, `pricetype` (`reg` \| `renewal` \| `transfer` \| `trade` \| `update` \| `restore`), optional `period` (`1Y` …). Reads `resData.domain[0]`; a single object under `domain` and a flat `resData` are both tolerated |
| `domain.getalldomainprices` | `all_domain_prices` | **unverified** | **unverified** | `tld` array (omitted when the list is empty or every entry is blank), `page` (clamped to 1), `pagelimit`; a `pagelimit` of 0 is refused locally. Decoded into the same `PriceList` as `domain.getPrices`, so the rows are read from `price`, `prices` or `domain` and `has_more()` compares them with `count` |
| `domain.getextradatarules` | `extra_data_rules` | **unverified** | **unverified** | `tld` when given (a blank one is refused locally) and the order type as `pricetype` when given. The rules are looked for under `extradata`, `extradataRules` or `rules`, one `ExtraDataRule` each; the order it applies to stays raw in `order_type` and is offered parsed by `price_type()`. This is the pre-flight for `domain.create`: it says which per-TLD extra data an order has to carry |
| `domain.getpromos` | `promo_codes` | **unverified** | **unverified** | `tld` when given, `page`, `pagelimit`. `Vec<PromoCode>` read from `promo` or `promos`; which keys a promo row carries (code, TLD, period, amount, validity) is not known here |
| `domain.pricechanges` | `price_changes` | **unverified** | **unverified** | `tld` when given, `page`, `pagelimit`. `Vec<PriceChange>` for the scheduled changes, read from `pricechange` or `pricechanges`; the change type stays raw in `action` and is offered parsed by `price_type()` |

Two of these are 0.1.x methods and stay listed in §0.1.x exactly as they were;
issue #63 added the other four to the same file, so the whole surface is recorded
in one place.

**No `Table 2.NNN` number is claimed for the four new methods.** The domain section
owns the block between `dnssec` (ends 2.100) and `dyndns` (starts 2.147), which is
far too wide a range to place a price table in, and the run that added them had no
network access, so `ch02s09` was not re-read at all. A derived number here would be
an invented number, so the two table columns say **unverified** instead.

Decoding follows the crate's usual rules, and that is what makes the guesses cheap:
unknown fields are ignored, an unrecognised order or change type is carried as a raw
string instead of failing the row, and snake_case and camelCase are both accepted.
An amount that is neither a JSON number nor a numeric string decodes to `None`. The
three list answers are read row by row, so a row that does not fit at all is skipped
rather than failing the call, and the list can come back short; the two `PriceList`
answers are deserialized whole, where an unreadable row is an error. Prices stay
`float` on the wire and `f64` here (`de::opt_f64`): quotes to display and compare,
never amounts to sum.

## Reseller/partner objects (issue #22)

Chapter 2 also documents the objects of the reseller/partner product. They are
modelled here with the same rules as the 0.2.0 surface: a typed request builder
per command, validation before the wire, permissive decoding of the answer.

**Provenance of the table numbers in this section.** They are *derived*, not
read: the run that added these objects had no network access, so the pages
`ch02s03/04/07/12/14/17/18/19/21` could not be fetched. Each number is computed
from the contiguous `Table 2.NNN` numbering that the sections above already pin
down — `certificate` starts at 2.50, `hosting` at 2.177, `nameserver` at 2.193,
`tag` at 2.229 — and is marked *(derived)* below. A maintainer with the pages
open should confirm them; the method names, parameter names and datatypes are
the part that still has to be checked against the documentation, and every row
of the Unverified table that belongs to this section says so.

### `application.*` (`src/application.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s03.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `application.check` | `ApplicationCheck` → `check_application` | 2.36 (derived) | 2.37 (derived) |
| `application.create` | `ApplicationCreate` → `create_application` | 2.38 (derived) | 2.39 (derived) |
| `application.delete` | `delete_application` | 2.40 (derived) | — |
| `application.info` | `application_info` | 2.41 (derived) | 2.42 (derived) |
| `application.list` | `ApplicationQuery` → `list_applications` | 2.43 (derived) | 2.44 (derived) |
| `application.update` | `ApplicationUpdate` → `update_application` | 2.45 (derived) | — |

The section ends where `authinfo2` begins, which is where `certificate` starts
at 2.50 — that is the anchor the derivation rests on.

Local checks: ids positive, `name` a `token0255`, comment ≤ 4096 characters, a
check needs at least one selector, an update needs at least one changed field,
`pagelimit` ≥ 1. The application type is not a frozen vocabulary — the list is
per-account — so it is a validated `[A-Z0-9_.-]` token (`ApplicationType`) that
upper-cases on the way in and carries anything on the way out.

### `authinfo2.*` (`src/authinfo2.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s04.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `authinfo2.create` | `create_auth_info2` | 2.46 (derived) | 2.47 (derived) |
| `authinfo2.getprice` | `auth_info2_price` | 2.48 (derived) | 2.49 (derived) |

The value is a secret: `AuthInfo2` prints `<redacted>` in `Debug` and `Display`
like `AuthCode`, refuses an empty value, and an unusable value in an answer
degrades to `None` instead of failing the record.

### `customer.*` (`src/customer.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s07.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `customer.contactverificationsettingsinfo` | `contact_verification_settings` | 2.80 (derived) | 2.81 (derived) |
| `customer.contactverificationsettingsupdate` | `ContactVerificationSettingsUpdate` → `update_contact_verification_settings` | 2.82 (derived) | — |
| `customer.delete` | `delete_customer` | 2.83 (derived) | — |
| `customer.info` | `customer_info` | 2.84 (derived) | 2.85 (derived) |
| `customer.listdownloads` | `CustomerDownloadQuery` → `list_customer_downloads` | 2.86 (derived) | 2.87 (derived) |
| `customer.requestdataexport` | `request_customer_data_export` | 2.88 (derived) | 2.89 (derived) |
| `customer.update` | `CustomerUpdate` → `update_customer` | 2.90 (derived) | — |

Seven methods, eleven tables, ending where `dnssec` demonstrably starts at
2.91 — that anchor is what fixes the block at 2.80–2.90, and it implies
`contact` (2.73–2.79) has seven tables. `contact`'s table count is the weakest
link in that chain, so the whole block shifts by one if a contact method has an
extra table.

There is **no `customer.list`** in this section: the documented method list is
the seven above, so the crate does not offer one, and an undocumented
`customer.*` stays on `InwxClient::call` until a page says otherwise.

Local checks: customer number positive, e-mail through `Email::parse`, country a
two-letter ISO code, address fields `token0255`, comment ≤ 4096 characters, an
update needs at least one changed field, verification settings need at least one
changed setting.

### `host.*` (`src/host.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s12.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `host.check` | `HostCheck` → `check_host` | 2.167 (derived) | 2.168 (derived) |
| `host.create` | `HostCreate` → `create_host` | 2.169 (derived) | 2.170 (derived) |
| `host.delete` | `delete_host` | 2.171 (derived) | — |
| `host.info` | `host_info` | 2.172 (derived) | 2.173 (derived) |
| `host.list` | `HostQuery` → `list_hosts` | 2.174 (derived) | 2.175 (derived) |
| `host.update` | `HostUpdate` → `update_host` | 2.176 (derived) | — |

Anchored: `hosting` starts at 2.177, and the ten tables of this section are what
lies between `dyndnssubscription` (ends 2.166) and it.

Datatypes: `name` is a host name (a single label is the usual spelling), the
address list is `ip`. Two rules the registry enforces are checked locally: a
fully qualified name must end in its own domain (anything else is a lame
delegation), and a host carries 1 to `MAX_HOST_ADDRESSES` = 13 addresses, the
number of address slots the host protocol reserves, without duplicates.

### `message.*` (`src/message.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s14.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `message.poll` | `poll_message` → `PolledMessage` | 2.189 (derived) | 2.190 (derived) |
| `message.ack` | `MessageAck` → `ack_message` | 2.191 (derived) | 2.192 (derived) |

Anchored between `hosting` (ends 2.188) and `nameserver` (starts 2.193).

`poll_message` accepts all three shapes the answer can take: the message flat in
`resData`, the message nested under `message`, and an empty mailbox as an empty
object (`PolledMessage::message == None`). An empty mailbox is not an error;
`message_id()` on it is.

### `news.list` (`src/news.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s17.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `news.list` | `list_news` | 2.221 (derived) | 2.222 (derived) |

### `nichandle.list` (`src/nichandle.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s18.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `nichandle.list` | `NicHandleQuery` → `list_nichandles` | 2.223 (derived) | 2.224 (derived) |

### `pdf.*` (`src/pdf.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s19.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `pdf.document` | `PdfRender` → `render_pdf` | 2.225 (derived) | 2.226 (derived) |
| `pdf.get` | `fetch_pdf` → `PdfFile` | 2.227 (derived) | 2.228 (derived) |

Anchored: `tag` starts at 2.229. `format` reuses `DocumentFormat` and refuses
`CSV`, which belongs to the zone exports; `dateFrom`/`dateTo` are `timestamp`
(ch03) and are rejected when inverted; the base64 body of `pdf.get` is size
checked before it is decoded.

### `document.*` (`src/document.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s21.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `document.delete` | `delete_document` | 2.238 (derived) | — |
| `document.download` | `download_document` → `DownloadedDocument` | 2.239 (derived) | 2.240 (derived) |
| `document.list` | `DocumentQuery` → `list_documents` | 2.241 (derived) | 2.242 (derived) |
| `document.upload` | `DocumentUpload` → `upload_document` | 2.243 (derived) | 2.244 (derived) |

The last section of chapter 2, after `tag` (ends 2.237).

Uploads are the risky direction, so they are checked hardest: the file name is
never a path (no separator, no `.`/`..`, no control characters, ≤ 255
characters), the body is neither empty nor larger than `MAX_DOCUMENT_BYTES`
(16 MiB) — checked on the caller's bytes, before base64 makes them a third
bigger again — and the body is absent from `Debug`, because these documents are
mandates and ID copies.

## Unverified

Points the documentation does not settle — and, since issue #63, the endpoints
whose pages could not be re-read here at all, because there is no network access.
Each is modelled as far as the documentation reaches and flagged here; none is a
guess about an endpoint's existence.

| Item | Status | Why |
| --- | --- | --- |
| `nameserver.create` with `type=MASTER` and no `ns` | **unverified** | `ns` is documented as optional (Table 2.195) and the description does not say what happens then; INWX presumably assigns its own nameservers. The crate sends the request as documented. |
| `dyndns.updateRecord` account selection | **unverified** | Table 2.159 lists only `ipAddress` and `ipAddressV6`; how the account is identified is not documented in the public chapter. The crate sends exactly those two parameters. |
| `hosting.create` id type | **partially documented** | `hostingId`/`productId` are `token255` there (Table 2.180) but `int` elsewhere (§2.13); the crate takes `i64` and sends strings for `hosting.create`, numbers for the `int` methods. |
| `hosting.getPrices` output shape | **unverified** | Table 2.181 documents `hosting[]` with only `id` and `product`; a price field is implied by the name but not listed, so no price is modelled. |
| `domain.getalldomainprices` request and answer | **unverified** | Added without network access, so `ch02s09` could not be re-read. `page`/`pagelimit` are the paging keys the other list methods use, and the row keys are inherited from `domain.getPrices` (`price`, `prices`, `domain`), which is not necessarily what this method answers; whether `count` comes back at all is unknown, so `has_more()` is only as good as those keys. |
| `domain.getextradatarules` parameter names | **unverified** | No network access. The order type is sent as `pricetype` because `domain.getdomainprice` spells it that way, `tld` as a single string, and reading the rules from `extradata`, `extradataRules` or `rules` in turn is a guess about the key the array arrives under. Whether the answer is an array of rules or a single object is modelled tolerantly as well. |
| `domain.getpromos` answer shape | **unverified** | No network access. Paging parameters, the row keys (`promo`, `promos`) and the field names of a promo row are modelled on the other list endpoints; one object where an array is expected is accepted, and a key that turns out to be different costs an empty list instead of a failed call. |
| `domain.pricechanges` answer shape | **unverified** | No network access. Same model: paging, the row keys (`pricechange`, `pricechanges`) and the row fields are guesses, the change type is carried as a raw `action` string because its vocabulary is not documented, and a single-object answer is accepted in place of the array. |
| `certificate.log` answer shape | **unverified** | Table 2.64 lists flat fields; whether the API wraps them in an array is not shown. The parser accepts an array or a single object. |
| `nameserver.exportlist` "export as file" | **unverified** | Table 2.203/2.204 promises a document but documents a `count`+`domains` payload; the crate parses the documented payload. |
| `tag.list` `count` nesting | **unverified** | Table 2.235 shows `count` → `domain` with an ambiguous indentation; parsed as `{"count": {"domain": N}}` with a scalar `count` also tolerated. |
| Live-endpoint behaviour for every 0.2.0 method | **unverified** | No credentials in CI; every test is offline against fixtures. Method names, parameters and datatypes are from the tables above. |
| Table numbers of the reseller sections | **derived, not read** | The run that added them had no network access; the numbers follow from the anchors `certificate` 2.50, `hosting` 2.177, `nameserver` 2.193 and `tag` 2.229. Confirm against the pages before quoting them. |
| Parameter names of the reseller objects | **unverified** | `applicationId`, `customerNumber`, `hostId`, `documentId`, `messageId`, `pdfId`, `domainName`, `cc`, `ip` and the `type`/`status`/`state` fields are the spellings the rest of the API uses, applied to the objects of chapter 2 §2.3–§2.21. Every response field is `Option`, ignores unknown keys and accepts snake_case as well as camelCase, so a spelling that turns out to be different costs a `None`, not a failed parse — but the *request* keys must be checked against the live pages. |
| `application.*` object shape | **unverified** | Chapter 2 §2.3 is the only description; which `type` values exist is account-specific, so the crate models the type as a validated token instead of an enum and never invents a vocabulary. |
| `message.ack` state parameter | **unverified** | Whether `message.ack` takes a completion state at all is not settled by the documentation. `MessageAck::with_state` is optional and off by default, so the default request carries only the message id. |
| `customer.requestdataexport` answer | **unverified** | Modelled as `{downloadId, status, filename}` because `customer.listdownloads` lists downloads; the crate carries any of them as `None`. |
| `host.create` address parameter | **unverified** | The address list is sent as `ip`, an array of address strings, matching `masterIp`/`ipAddress` elsewhere in the API; a single string is accepted on the way back. The 13-address limit is the registry host protocol, not the INWX page. |
| `extData` per-TLD keys | **documented, not enumerated** | ch03 §3.49 lists the generic keys and then a long TLD-specific list; `ExtData::set` carries any upper-case token. |

## Deliberately not modelled

- **API-key authentication** — marketed by INWX but absent from the public API
  documentation; the crate implements password login only (see README).
- Nothing else. The reseller/partner objects that used to be listed here
  (`application.*`, `authinfo2.*`, `customer.*`, `document.*`, `host.*`,
  `message.*`, `news.list`, `nichandle.list`, `pdf.*`) are modelled since
  issue #22; see the sections above for what is still unverified about them.
