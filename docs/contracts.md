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
| Session | `account.login`, `account.logout`, `account.check`, `account.info`, `account.unlock` | ch02 §2.1, Tables 2.1–2.17 |
| Domains | `domain.check`, `create`, `info`, `list`, `update`, `renew`, `delete`, `whois` | ch02 §2.9 |
| DNS records | `nameserver.info`, `createRecord`, `updateRecord`, `deleteRecord` | ch02 §2.15, Tables 2.197–2.212 |
| Zones (read) | `nameserver.list`, `nameserver.info`, `nameserver.delete`, `nameserver.check` | ch02 §2.15 |
| Contacts | `contact.create`, `info`, `list`, `update`, `delete` | ch02 §2.6 |
| Prices | `domain.getPrices`, `domain.getdomainprice` | ch02 §2.9 |
| Envelope | `{"method":…,"params":…}` / `{"code":…,"resData":…}` | ch02 §1.2, §1.4; codes ch04 |

## 0.2.0 — account object (`src/account.rs`) — issue #62

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s01.html> (ch02 §2.1,
Tables 2.1–2.17). This section covers the whole `account.*` namespace; the
0.1.x session row above already covered `account.login`, `account.logout`,
`account.info` and `account.unlock`.

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `account.check` | `account_check` → `AccountCheck` | — | §2.1, output `user` `text64` |
| `account.update` | `AccountUpdate` → `update_account` | §2.1, `account.update` | — |
| `account.changepassword` | `AccountPasswordChange` → `change_account_password` | §2.1, `account.changepassword` | — |
| `account.unlock` | `AccountUnlockRequest` → `unlock_account` | §2.1, `account.unlock` | — |
| `account.list` | `list_subaccounts` → `SubAccountList` | — | §2.1, `account.list` |
| `account.create` | `SubAccountCreate` → `create_subaccount` | §2.1, `account.create` | §2.1, output `id` `int` |
| `account.delete` | `delete_subaccounts` → `SubAccountsDeleted` | §2.1, `account.delete` | §2.1, output `countDeleted` `int` |
| `account.getroles` | `account_roles` → `AccountRoleEntry` | §2.1, optional `accountId` | §2.1, output `roles` array |
| `account.addrole` | `add_role` | §2.1, `accountId`, `roleId` | — |
| `account.removerole` | `remove_role` | §2.1, `accountId`, `roleId` | — |

`account.check` is a session liveness probe: cheap and read-only, so it may be
replayed after an uncertain failure. `account.update` sends only the fields the
builder was given and refuses an empty update, so a no-op cannot be sent by
accident. Every value type validates before the request leaves the process.

`account.changepassword` carries two secrets. Both go in the request body, never
in a URL or a header. They are `Password` values: validated, redacted from
`Debug`, zeroizing newtypes; the whole request also redacts itself. The locally
cached session cookie is dropped after a successful change, because it was
established with the old password.

`account.list`/`account.create`/`account.delete` manage reseller sub-accounts.
`SubAccountCreate` validates every documented required field before the wire.
`account.getroles`/`account.addrole`/`account.removerole` use numeric role ids;
an id this crate does not know is carried as `AccountRoleId::Other`, so a role
INWX adds later still round-trips.

Every mutation here is non-idempotent, so an uncertain failure (timeout, reset
or a transient status after the request was written) surfaces as
`Error::Uncertain` after a single attempt instead of being replayed. The reads
(`account.check`, `account.getroles`, `account.list` and `account.info`) are in
the read-only table and may be replayed.
## Pagination (`src/pagination.rs`) — issue #15

The list commands are paged the same way. Sources: ch02 §2.9 (`domain.list`),
§2.6 (`contact.list`) and §2.15 (`nameserver.list`, Tables 2.209/2.210 for the
filtered variant; `nameserver.exportlist` is Tables 2.203/2.204):

| Command | Paging in | Total out | Objects out |
| --- | --- | --- | --- |
| `domain.list` | `page` `int` (1-based), `pagelimit` `int` | `count` `int` | `domain` array |
| `contact.list` | `page`, `pagelimit` | `count` | `contact` array |
| `nameserver.list` | `page`, `pagelimit` | `count` | `domains` array |

`Pages` turns one of those commands into a walk (`list_all_domains`,
`list_all_contacts`, `list_all_zones`, `list_all_nichandles`,
`list_all_applications`, or `Pages::new` for a `Listing` of your own). Rules the
crate enforces, with the reason:

- The walk owns the cursor: `page` and `pagelimit` are set by the walker, so a
  query that pins a page cannot fight it. Filters (`domain`, `search`, `status`,
  `wide`) are sent unchanged on every request.
- Termination: a page shorter than requested, an empty page, `yielded >= count`,
  `with_max_items`, `with_max_pages`. `count` is documented but not guaranteed,
  so a full page without one asks for exactly one page more instead of stopping.
- A bound is always in force. `DEFAULT_PAGE_SIZE` is 100 (what `list_zones`
  already asked for); `MAX_PAGE_SIZE` 1000, `MAX_ITEMS` 100\_000 and
  `MAX_PAGES` 10\_000 are **crate-side ceilings** — see Unverified — and all
  three are validated in `Pagination::with_page_size`/`with_max_items`/
  `with_max_pages`, before any request.
- The zone page helpers pin the page: `list_zones` and `find_zones` ask for
  `page` 1 with `pagelimit` 100 (`export_zone_list` takes the caller's
  `limit`), so a single page is a cap, not the listing. `ZoneListPage::has_more`
  (issue #139) compares `zones.len()` with the `count` of the answer and is the
  guard that makes the cap visible; it is `false` when no `count` came back.
  `DomainListPage::has_more` does the same for `domain.list`, where the page
  size is the query's.
- The page that crosses `with_max_items` is truncated, so a walk never yields
  more objects than it promised, and `bound_reached()` distinguishes "stopped at
  the bound" from "reached the end".
- A `contact.list` answer that carries one object where the array belongs is a
  page of one handle, and a row that does not fit `Contact` is skipped rather
  than failing the page (issue #114) — the same tolerance the other list answers
  get from `parse_rows`. `count` is read independently of the rows.
- `nameserver.list` keeps the strict [`ZoneSummary`] row type but does not let
  one row fail the page: decodable zones stay in `ZoneListPage::zones`, and raw
  rows that fail [`DomainName`] validation or the row shape stay in
  `ZoneListPage::unparsed` (issue #140). The page walker counts both sides when
  deciding whether the answer was a full page.
- A rejected page is terminal: `Error::Api` is returned as-is and the request is
  not repeated (a list command is idempotent, but retrying a rejected command is
  the client's business, not the walker's). A transport failure is returned too
  and the failed page is *not* counted, so continuing the walk re-asks for it.

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
| `domain.transfercancel` | `TransferCancelRequest` → `cancel_transfer` | 2.141 | — | `domain`, `testing` |
| `domain.transferOut` | `TransferOutRequest` → `answer_transfer_out` | 2.142 | — | `domain`, `answer` `transferAnswer` (`ACK` \| `NACK`, ch03 §3.106), `testing` |

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

Responses are read leniently: `dnssec.listkeys` returns `keyTag` as `u16` and
`algorithmId`/`flagId`/`digestTypeId`/`status` as `DnssecAlgorithm`,
`DnssecFlag`, `DnssecDigestType` and `DnssecKeyStatus`. A number outside the
tables above is carried as `Other(..)` instead of failing the row, so a key
signed with a later-assigned algorithm does not disappear from the list; an
absent id is `None`, never a silently substituted `0`. The same holds for
`dnssecStatus`: `dnssec.info` leaves it out for a domain without DNSSEC, so
`DnssecState::status` is an `Option` and an absent or `null` field is `None`
— not a defaulted `MANUAL`, which would claim keys are managed through this
API and make "no status reported" indistinguishable from a real `MANUAL`.

Leniency stops at the row. The list itself is not optional: `dnssec.info` and
`dnssec.listkeys` answer `Error::UnexpectedAnswer` when the `data` / `dnskey`
array is absent or has another shape, and an entry that does not parse fails the
whole call with its index. A present but empty array stays `Ok`, so "this domain
has no manual keys" and "the answer did not carry the list" never read the same
to a caller that is about to delete or re-add keys.

Validation: the DNSKEY parser enforces `IN DNSKEY`, protocol `3`, flag **257
only** — the method's description says "only ZONE+SEP keys (flag value 257) are
accepted" — a documented algorithm, and key material that decodes as base64
(the crate's `base64`, joined over wrapped lines). The DS parser enforces
exactly seven fields, a documented algorithm and digest type, and a hex digest
whose **length follows from the digest type** (32 bytes for SHA-256, 48 for
SHA-384); both parsers cap the presentation at 1024 characters before splitting
it. Both records carry their owner, and `AddDnsKeyRequest` compares it with the
request's domain
(case-insensitively, ignoring the presentation's trailing dot): the API keys
the digest by `domainName`, so a key or DS string for a foreign zone is refused
instead of being published against the wrong domain. `calculateDigest`
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

Certainty of an order answer: `certificate.create`, `renew`, `reissue` and
`updateOrder` have already been executed and billed by the time their answer is
parsed, so a model failure is not `Error::Json` — that classification reads as a
local decode mistake behind a command that changed nothing. Only a JSON object is
handed to the model (`serde_json::from_value` reads an array into a struct
positionally and would invent an empty order), the id is read out of the raw
answer first (as a number, as text, or from the row of a wrapped answer), and the
failure is `Error::CertificateOrderUnreadable` carrying it plus the bounded body,
so `certificate_info` or `cancel_certificate` can be called on the order instead
of ordering it a second time. An answer that names no usable id is
`Error::Ambiguous`. Both answer `is_uncertain()` and are never replayed.

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

## 0.2.0 — push requests (`src/request.rs`, issue #59)

Source: **not read**. The public INWX chapter has no `request.*` page that this
run could reach, so every shape below is derived from the rest of the API and
from the push workflow (`domain.push` hands the domain over, the receiving
account answers it).

| Method | Wrapper | Input | Output |
| --- | --- | --- | --- |
| `request.list` | `RequestListing` → `list_requests` / `list_requests_page` / `list_all_requests` | `page`, `pagelimit` | `count`, `requests` array |
| `request.info` | `request_info` | `id` `int` | one `request` object |
| `request.accept` | `accept_request` | `id` `int` | one `request` object |
| `request.deny` | `deny_request` | `id` `int` | one `request` object |
| `request.cancel` | `cancel_request` | `id` `int` | one `request` object |

State values modelled as `RequestState`: `PENDING`, `ACCEPTED`, `DENIED`,
`CANCELED` (with `CANCELLED` accepted as a spelling); anything else is carried
in `RequestState::Other`. Every field of [`RequestEntry`] is `Option`, the row
reads both the camelCase and snake_case spellings of a renamed key, and a list
row that does not fit is skipped rather than failing the page — so a wrong
answer key costs a `None`, not a failed call. The **request** keys (`id`, `page`,
`pagelimit`) are the same ones the other methods use, applied here; they must be
checked against the live page before the mutations are used in production.

`request.accept` / `deny` / `cancel` are non-idempotent: a 5xx or a transport
failure after the request was written is `Error::Uncertain`, and a success whose
answer carries no readable request is `Error::Ambiguous`. Neither is replayed.

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
| `domain.getalldomainprices` | `all_domain_prices` | 2.106 | 2.107 | `domain` as a non-empty trimmed array, optional `period` (`1M`, `1Y`…`10Y`). Output `domain[]` → `TldPrice`: `premium`, `currency`, `period`, `promo`, `promoPrice`, `promoType`, `regPrice`, `updatePrice`, `transferPrice`, `tradePrice`, `renewalPrice`, `restorePrice`, and the `*WithVat` variants |
| `domain.getextradatarules` | `extra_data_rules` | 2.110 | 2.111 | `tld` when given, trimmed, without a leading dot and lower-cased (a blank one is refused locally). Output `rules[]` as `array_text255`; each string is kept verbatim in `ExtraDataRule` and exposed as `name`/`value`. This is the pre-flight for `domain.create`: it says which per-TLD extra data an order has to carry |
| `domain.getPromos` | `promo_prices` | 2.114 | 2.115 | `tlds` array (omitted when empty), `promoType` (`REG`, `RENEWAL`, …), `period` (`int`) with `periodUnit` (`Y`/`M`), optional `voucher` capped at 64 characters. Output `promos[]` → `PromoCode`: `tld`, `netPrice`, `currency`, `endTime` |
| `domain.priceChanges` | `price_changes` | none | 2.126 | No request parameters. Reads `futureChanges[]` and `pastChanges[]`, each row → `PriceChange`: `tld`, `affectsCustomer`, `currency`, `changeDate`, `createPrice`, monthly create, transfer, renewal, monthly renewal, update, trade, trustee, monthly trustee, restore; `chargedPrice` is left unmodelled |

Two of these are 0.1.x methods and stay listed in §0.1.x exactly as they were;
issue #63 added the other four to the same file, so the whole surface is recorded
in one place. The four additions were re-read from `ch02s09` on 2026-11-04; the
older 0.1.x rows are kept as they were.

Decoding follows the crate's usual rules: unknown fields are ignored, an
unrecognised order or change type is carried as a raw string instead of failing
the row, and snake_case and camelCase are both accepted. An amount that is
neither a JSON number nor a numeric string decodes to `None`. Promo and
scheduled-change answers are read row by row, so a row that does not fit at all
is skipped rather than failing the call, and the list can come back short;
`PriceList` answers are deserialized whole, where an unreadable row is an error.
Prices stay `float` on the wire and `f64` here (`de::opt_f64`): quotes to display
and compare, never amounts to sum.

## 0.2.0 — transfer lock and auth codes (`src/domain.rs`, issue #60)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s09.html> — the same
`domain.*` object as the ownership section above (the issue cites the published
index at <https://www.inwx.de/en/help/apidocs>).

| Method | Wrapper | Input table | Output table | Notes |
| --- | --- | --- | --- | --- |
| `domain.setAuthInfo` | `AuthInfoUpdate` → `set_auth_info` | not read | not read | `domain` `token255`, `authCode` `token255`; the EPP transfer code a gaining registrar presents. Distinct from the `authinfo2.*` object (§2.4), which is a registry-side object with methods of its own |
| `domain.setDomainTransferCode` | `TransferCodeUpdate` → `set_domain_transfer_code` | not read | not read | same two keys; the teleprovider code moves a domain between INWX customers, not between registrars |
| `domain.block` | `block_domain` | not read | not read | `domain` only; blocks the domain object against outgoing changes |
| `domain.unblock` | `unblock_domain` | not read | not read | `domain` only; releases the block, so the pair needs no `Irreversible` acknowledgement — it can be undone |

**The table numbers of these four rows were not read.** The run that added them
had no network access, so `ch02s09` could not be opened and no `Table 2.NNN` is
claimed here; that is the only difference from the sections above. The method
names are the ones the INWX documentation publishes, and the request/response
spellings they carry are listed under Unverified.

Validation added on top of the documented type, in `AuthCode`
(`src/types.rs`): a code that is empty after trimming, longer than
`MAX_AUTH_CODE_LEN` (255 characters), not printable ASCII, or carrying
whitespace/control characters is rejected before the request is built. The
length is checked on the caller's string, so an oversized input never causes a
second allocation, and the value stays out of `Debug`, `Display` and every error
message — only the request body carries it.

`domain.block` is the block of the domain object, not the `transferLock` flag
that `domain.update` and `domain.transfer` carry: the two are independent
controls and the crate exposes both (`set_transfer_lock` sets the flag).

All four are mutating and non-idempotent, so none of them is in the read-only
table in `src/client.rs`. A 5xx or a timeout after the request was written comes
back as `Error::Uncertain` and is never replayed: the code may already be
replaced or the lock already set, so the caller has to read the state
(`domain.info`) instead of resending.

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
| `application.list` | `ApplicationQuery` → `list_applications`; `ApplicationListing` → `list_all_applications` | 2.43 (derived) | 2.44 (derived) |
| `application.update` | `ApplicationUpdate` → `update_application` | 2.45 (derived) | — |

The section ends where `authinfo2` begins, which is where `certificate` starts
at 2.50 — that is the anchor the derivation rests on.

Local checks: ids positive, `name` a `token0255`, comment ≤ 4096 characters, a
check needs at least one selector, an update needs at least one changed field,
`pagelimit` ≥ 1. The application type is not a frozen vocabulary — the list is
per-account — so it is a validated `[A-Z0-9_.-]` token (`ApplicationType`) that
upper-cases on the way in and carries anything on the way out.

`list_applications` answers one [`ApplicationListPage`] and reads the answer's
`count` (or `total`) so the page can say whether it is the whole listing; the
default query asks for page 1 with a 50-row cap. `list_all_applications` walks
the pages with the same [`Pagination`] bound as the other list commands, so a
reseller with more than 50 applications can reach every row instead of silently
receiving the first page.

### `authinfo2.*` (`src/authinfo2.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s04.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `authinfo2.create` | `AuthInfo2Order` → `create_auth_info2` | 2.46 (derived) | 2.47 (derived) |
| `authinfo2.getprice` | `auth_info2_price` | — (none documented) | 2.49 (derived) |

The fields are the ones the chapter lists. `authinfo2.create` takes `domain`
(`text255`, required) and `testing` (`boolean`, optional, default false) and
answers `product`, `net_price`, `price`, `currency`, `message`;
`authinfo2.getprice` takes no input at all and answers the same fields without
`message`. Note the request key: this object sends `domain`, not the
`domainName` the rest of the API uses — the spelling here was read off the
page, unlike the reseller keys in the table below.

`domain` is taken as the validated `DomainName`, which is
stricter than `text255`: an empty, malformed or oversized name is a local
validation error instead of a charged call. `testing` is an explicit argument of
`AuthInfo2Order::new` and is omitted from the request when false, so a billable
order is never what a defaulted call does.

The answer of `create` is an order confirmation — a product name and the amount
charged — not a secret, so nothing in this module is redacted; the transfer-code
secret is `AuthCode`. Because `create` is a paid, non-idempotent order it is not
in `READ_ONLY_METHODS`: a 429, a 5xx or a mid-flight timeout answers
`Error::Uncertain` after a single attempt, and the caller checks the state
before ordering again.

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
`message_id()` on it is. A flat answer is recognised by the keys `Message`
decodes — `messageId` as well as `id` — so a counted answer that carries neither
shape, or two shapes that name different messages, is an `Error::UnexpectedAnswer`
instead of an empty mailbox.

### `news.list` (`src/news.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s17.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `news.list` | `NewsQuery` → `list_news` | 2.221 (derived) | 2.222 (derived) |

### `nichandle.list` (`src/nichandle.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s18.html>

| Method | Wrapper | Input table | Output table |
| --- | --- | --- | --- |
| `nichandle.list` | `NicHandleQuery` → `list_nichandles`; `NicHandleListing` → `list_all_nichandles` | 2.223 (derived) | 2.224 (derived) |

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

The download side carries its own claim and is held to it. `document.download`
reports `size` next to the base64 body; `DownloadedDocument::bytes` decodes the
body and compares the two, so a transfer cut short on a base64 boundary — which
still decodes, just shorter — fails as `Error::SizeMismatch` instead of being
written out as the document. The failure is certain (nothing was written, both
counts are known) and not retryable; a second attempt is the caller's call. A
negative `size` is refused when the answer is parsed, and by `bytes` on a
hand-built row.

The answer is a `DocumentUploadOutcome`, not a bare `DocumentEntry`. The row's
`id` is optional in the documented shape, so "stored, but the answer named no
id" and "nothing stored (a dry run)" would otherwise arrive as the same `Ok` —
one a document that can never be downloaded or deleted, the other no document at
all. `upload_document` therefore answers `Stored { id, entry }` only when the
answer carries a positive `documentId`; anything else on a real upload is
`Error::Ambiguous` (uncertain, never retried, "list the documents before
uploading again"), and a `with_testing(true)` request answers `DryRun`.

## Account roles (`src/account.rs`)

The role methods are part of the `account.*` object and are recorded in the
`0.2.0 — account object` section above (issue #62). Roles are identified by the
numeric `roleId` from ch02 §2.1 (`account.getroles`/`addrole`/`removerole`):

| Role id | Name |
| --- | --- |
| `20000` | Standard |
| `20001` | Accounting |
| `20002` | Domain |
| `20003` | Hosting |
| `20004` | DNS |
| `20005` | Authcodes |

`AccountRoleId::Other` carries any id this crate does not know, so a role INWX
adds later still round-trips; `AccountRole` remains as a permissive string
fallback for older callers. Reading is in the read-only table and may be
replayed after an uncertain failure; granting and revoking are not, because
replaying them would duplicate a permission change, so such an outcome surfaces
as `Error::Uncertain`.
## 0.2.0 — registry status (`src/domain.rs`)
Source: <https://account.inwx.com/en/help/apidoc/f/ch02s09.html> — §2.9.16
(`domain.setClientHold`) and §2.9.19 (`domain.removeClientHold`).
| Method | Wrapper | Input table | Output table | Notes |
| --- | --- | --- | --- | --- |
| `domain.setClientHold` | `SetClientHold` → `set_client_hold` | §2.9.16, anchor **unverified** | §2.9.16, anchor **unverified** | `domain` `token255` required, `testing` `boolean` default `false`; output `roId` `int` |
| `domain.removeClientHold` | `RemoveClientHold` → `remove_client_hold` | §2.9.19, anchor **unverified** | §2.9.19, anchor **unverified** | same input; output `roId` `int`. Documented note: removal only succeeds when the hold was set by the same account |
Both methods take the identical parameter pair, so the body is built in one
place and always carries both fields — `testing` explicitly, so a call never
inherits the API default by accident. `domain` is a `DomainName`, which applies
the `token255` limits (253 characters total, 63 per label) before the wire.
`ClientHoldResult.ro_id` is `Option<i64>`: a command that changes nothing
measurable is answered with an empty `resData`, and ids also arrive as strings.
Two separate request types rather than one with a flag, so set and remove cannot
be swapped at a call site. Both are mutations and stay out of
`READ_ONLY_METHODS`, so an `Error::Uncertain` (timeout or reset after the
request was written) is handed back after exactly one attempt instead of being
replayed; `domain_info` decides whether the hold is already in place.
## Rules the API does not define

Not shapes from the documentation, but limits this crate imposes anyway:

- **Unreadable answers (`src/rpc.rs`, `src/client.rs`).** INWX documents one
  envelope shape, so a `2xx` whose body is not that object came from something
  other than the API — a proxy error page, a cut-off `200`, an answer stripped by
  a middlebox. The request was written, so the command may have executed; that is
  reported as `Error::Undecodable` (`is_uncertain()`, never replayed) rather than
  as `Error::Json`, which stays the certain decode failure of a payload that
  arrived intact. `RpcResponse::parse` keeps answering `Json` because it cannot
  know whether a request preceded the bytes; the client re-classifies through
  `parse_answer`.
- **Response size cap (`src/transport.rs`, `src/rpc.rs`).** One answer may not
  exceed `DEFAULT_MAX_RESPONSE_BYTES` (4 MiB). INWX does not bound a body, so
  without a cap a misbehaving or compromised endpoint decides how much memory the
  process allocates before the parser sees a byte. The transport checks
  `Content-Length` before the body is read and a running total while it streams,
  so a header that lies too small still fails at the chunk that crosses it.
  `RpcResponse::parse` checks the byte slice it receives before handing anything
  to `serde_json`; a caller with its own cap can use
  `RpcResponse::parse_with_max_bytes`. Documented answers sit far below the cap —
  a record list or an export page is tens to hundreds of kilobytes — and
  `nameserver.export` with `zonefile=true` (Table 2.202, the whole zone in one
  `text` field) is the one shape that could plausibly need more; that caller
  builds its transport with `ReqwestTransport::with_max_response_bytes`. Crossing
  the cap is `Error::ResponseTooLarge`, terminal on purpose: the command behind
  that response may already have been executed, so repeating it duplicates work.

## Unverified

Points the documentation does not settle — and, since issue #63, the endpoints
whose pages could not be re-read here at all, because there is no network access.
Each is modelled as far as the documentation reaches and flagged here; none is a
guess about an endpoint's existence.

| Item | Status | Why |
| --- | --- | --- |
| `domain.setClientHold` / `domain.removeClientHold` table anchors | **unverified** | The methods, their parameters and the `roId` output are from ch02s09 §2.9.16/§2.9.19; the `Table 2.NNN` anchor numbers for those two blocks were not readable from the offline copy, so they are cited by section instead. |
| `nameserver.create` with `type=MASTER` and no `ns` | **unverified** | `ns` is documented as optional (Table 2.195) and the description does not say what happens then; INWX presumably assigns its own nameservers. The crate sends the request as documented. |
| `dyndns.updateRecord` account selection | **unverified** | Table 2.159 lists only `ipAddress` and `ipAddressV6`; how the account is identified is not documented in the public chapter. The crate sends exactly those two parameters. |
| `hosting.create` id type | **partially documented** | `hostingId`/`productId` are `token255` there (Table 2.180) but `int` elsewhere (§2.13); the crate takes `i64` and sends strings for `hosting.create`, numbers for the `int` methods. |
| `hosting.getPrices` output shape | **unverified** | Table 2.181 documents `hosting[]` with only `id` and `product`; a price field is implied by the name but not listed, so no price is modelled. |
| `domain.getalldomainprices` output coverage | **partially documented** | Tables 2.106/2.107 document the request and the `domain[]` row; `restorePrice` is kept as an alias for the older `domain.getPrices` shape and the exact VAT-row behaviour is not modelled beyond the documented `*WithVat` fields being available for future use. |
| `domain.getextradatarules` rule syntax | **unverified** | Table 2.111 documents only `array_text255`, not the grammar inside a rule string; the crate keeps the string and exposes a best-effort `name=value` split without rejecting unknown text. |
| `domain.getPromos` `code` / `orderType` fields | **unverified** | Table 2.115 documents only `tld`, `netPrice`, `currency` and `endTime`; `code`, `orderType` and `period` are accepted as permissive aliases for older or future shapes. |
| `domain.priceChanges` `chargedPrice` nesting | **unverified** | Table 2.126 documents a nested `chargedPrice`; the crate reads the top-level price fields and deliberately ignores the nested object. |
| `certificate.log` answer shape | **unverified** | Table 2.64 lists flat fields; whether the API wraps them in an array is not shown. The parser accepts an array or a single object. |
| `nameserver.exportlist` "export as file" | **unverified** | Table 2.203/2.204 promises a document but documents a `count`+`domains` payload; the crate parses the documented payload. |
| `tag.list` `count` nesting | **unverified** | Table 2.235 shows `count` → `domain` with an ambiguous indentation; parsed as `{"count": {"domain": N}}` with a scalar `count` also tolerated. |
| Live-endpoint behaviour for every 0.2.0 method | **unverified** | No credentials in CI; every test is offline against fixtures. Method names, parameters and datatypes are from the tables above. |
| Table numbers of the reseller sections | **derived, not read** | The run that added them had no network access; the numbers follow from the anchors `certificate` 2.50, `hosting` 2.177, `nameserver` 2.193 and `tag` 2.229. Confirm against the pages before quoting them. |
| Parameter names of the reseller objects | **unverified** | `applicationId`, `customerNumber`, `hostId`, `documentId`, `messageId`, `pdfId`, `domainName`, `cc`, `ip` and the `type`/`status`/`state` fields are the spellings the rest of the API uses, applied to the objects of chapter 2 §2.3–§2.21. Every response field is `Option`, ignores unknown keys and accepts snake_case as well as camelCase, so a spelling that turns out to be different costs a `None`, not a failed parse — but the *request* keys must be checked against the live pages. `authinfo2` is the exception: issue #54 read that chapter, so its `domain` key and its five output fields are taken from the page. |
| `application.*` object shape | **unverified** | Chapter 2 §2.3 is the only description; which `type` values exist is account-specific, so the crate models the type as a validated token instead of an enum and never invents a vocabulary. |
| `message.ack` state parameter | **unverified** | Whether `message.ack` takes a completion state at all is not settled by the documentation. `MessageAck::with_state` is optional and off by default, so the default request carries only the message id. |
| `customer.requestdataexport` answer | **unverified** | Modelled as `{downloadId, status, filename}` because `customer.listdownloads` lists downloads; the crate carries any of them as `None`. |
| `host.create` address parameter | **unverified** | The address list is sent as `ip`, an array of address strings, matching `masterIp`/`ipAddress` elsewhere in the API; a single string is accepted on the way back. The 13-address limit is the registry host protocol, not the INWX page. |
| `pagelimit` maximum | **unverified** | The tables document `page` and `pagelimit` but no upper bound, and no maximum is published for the number of objects a listing can return. `MAX_PAGE_SIZE`, `MAX_ITEMS` and `MAX_PAGES` are therefore crate-side ceilings, not API limits; they are validated before the wire. |
| `domain.setAuthInfo` / `domain.setDomainTransferCode` request key | **unverified** | The pages of the two setters could not be fetched in the run that added them. `authCode` is the spelling `domain.info`, `domain.update` and `domain.transfer` use for the same value (Table 2.139), applied here. A wrong request key would come back as an API error rather than a silent success, but it must be checked against the live page. |
| Output shape of the four transfer/lock commands | **unverified** | No page was read, so `DomainControlResult` models nothing as required: every field is `Option`, unknown keys are ignored, camelCase and snake_case are both accepted, and a `1000` without `resData` is an empty acknowledgement. A shape that differs from the modelled one therefore yields `None`s, not a parse failure. |
| What `domain.block` blocks | **unverified** | The command is documented as blocking the domain; which registry locks that maps to per TLD, and how it interacts with the `transferLock` flag of `domain.update`, is not stated on the page. The crate treats it as the broader, reversible control (it has `domain.unblock`) and therefore does not require an `Irreversible` acknowledgement for it. |
| Table numbers of the transfer-lock section | **not read** | Added without network access; unlike the reseller numbers above these were not even derived, because the section covers four methods inside an object whose numbering was already in use (`domain.*` spans 2.120–2.142) and a derived guess would be indistinguishable from a read number. |
| `extData` per-TLD keys | **documented, not enumerated** | ch03 §3.49 lists the generic keys and then a long TLD-specific list; `ExtData::set` carries any upper-case token. |
| `account.getroles`/`addrole`/`removerole` tables | read | ch02 §2.1, Tables 2.1–2.17; the request keys are `accountId` and `roleId`, the answer key is `roles`. |
| Account role vocabulary | read | The role ids `20000`–`20005` are from ch02 §2.1; `AccountRoleId::Other` carries any id this crate does not know. |
| `account.unlock` answer | **unverified** | `account.unlock` is documented as an acknowledgement. The crate treats `code == 1000` (with or without `resData`) as done and ignores `resData`; if the API does return data there, nothing is lost — `call` still exposes it. |
| `account.changepassword` answer | **unverified** | Treated like every other mutation: `code == 1000` means done and `resData` is ignored. If the API does return data there, nothing is lost — `call` still exposes it. |

## Deliberately not modelled

- **API-key authentication** — marketed by INWX but absent from the public API
  documentation; the crate implements password login only (see README).
- Nothing else. The reseller/partner objects that used to be listed here
  (`application.*`, `authinfo2.*`, `customer.*`, `document.*`, `host.*`,
  `message.*`, `news.list`, `nichandle.list`, `pdf.*`) are modelled since
  issue #22; `authinfo2.*` was re-checked against the page in issue #54. See the
  sections above for what is still unverified about the rest.

## 0.2.x — diagnostics (`src/diagnostics.rs`)

Source: <https://account.inwx.com/en/help/apidoc/f/ch02s09.html> — ch02 §2.9,
the `domain` object, the same page as `domain.create` and `domain.info`.

| Method | Wrapper | Parameters sent | Output table |
| --- | --- | --- | --- |
| `domain.log` | `DomainLogQuery` → `domain_log` | `domain` (required), `page` (int, starts at 1), `pagelimit` (int), `dateFrom`/`dateTo` (datetime) | not recorded |
| `domain.stats` | `domain_stats` | `domain` (optional; omit it for the whole account) | not recorded |
| `domain.getRules` | `tld_rules` | `tld` (one label, punycode, no leading dot) | not recorded |
| `domain.getTldGroups` | `tld_groups` | — | not recorded |

"not recorded" is literal: the `resData` field lists of these four methods were
not written down here with a `Table 2.NNN` anchor, and there is no live call to
check them against, so no number is invented. The consequence lives in the types
rather than in a comment: every response field is optional, a result set arrives
either as a JSON array or as the numerically keyed object INWX produces for a
one-entry set, `domain.stats` additionally answers with a flat object that puts
each counter under its own key, and unknown fields are kept in `extra` instead
of being dropped.

Validation before the wire: `domain` is a `DomainName` (punycode, 253/63 label
rules, no control characters), the `TLD` of `domain.getRules` goes through the
same normalisation and is refused above `MAX_LABEL_LEN` (63) bytes or when it
contains a dot, `page` must be at least 1, and `pagelimit` must be between 1 and
`MAX_PAGE_LIMIT`. `MAX_PAGE_LIMIT` (1 000) is the crate's own bound, not a
documented one — `pagelimit` is a plain `int` and no maximum is recorded for it
here — and the cap keeps a mistyped `100_000` from asking for a response nobody
can hold.
`dateTo` must be strictly after `dateFrom` — an empty window is a mistake, not
a query.

These four are read-only, so they sit outside the `Irreversible` acknowledgement
that the write commands require, and they are idempotent, so they are retried on
a transient failure like any other read.
