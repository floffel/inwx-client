//! Property tests: the parsers and builders never panic, and their invariants
//! hold for arbitrary input.

mod common;

use inwx_client::{
    retry_after_from_header, ContactListing, ContactQuery, ContactRequest, ContactType,
    ContactUpdate, Credentials, DomainListQuery, DomainListing, DomainName, Hostname, HttpBody,
    Listing, LockedFunds, NewsDate, Pagination, Period, RecordId, RecordSpec, RecordType,
    RemoveClientHold, RpcResponse, SetClientHold, SslFund, ZoneListPage, ZoneListing,
    MAX_HTTP_BODY_CHARS, MAX_ITEMS, MAX_PAGES, MAX_PAGE_SIZE, MAX_TTL,
};
use proptest::prelude::*;
use rust_decimal::Decimal;
use serde_json::Value;
use std::time::Duration;

/// Arbitrary record-type tokens, including ones the API does not know.
fn type_token() -> impl Strategy<Value = String> {
    "[A-Za-z][A-Za-z0-9]{0,9}"
}

/// Arbitrary free text, including control characters.
fn any_text() -> impl Strategy<Value = String> {
    "\\PC{0,40}"
}

/// The string fields `contact.create` and `contact.update` share.
const CONTACT_TEXT_FIELDS: [&str; 9] = [
    "name", "org", "street", "city", "pc", "sp", "voice", "fax", "remarks",
];

fn create_accepts(param: &str, value: &str) -> bool {
    let name = if param == "name" { value } else { "Erika" };
    let Ok(base) = ContactRequest::new(ContactType::Person, name, "a@b.test") else {
        return false;
    };
    let base = base
        .with_street("Weg 2")
        .with_city("Berlin")
        .with_postcode("10115")
        .with_country("DE")
        .with_voice("+49.891");
    let request = match param {
        "name" => base,
        "org" => base.with_org(value),
        "street" => base.with_street(value),
        "city" => base.with_city(value),
        "pc" => base.with_postcode(value),
        "sp" => base.with_state(value),
        "voice" => base.with_voice(value),
        "fax" => base.with_fax(value),
        "remarks" => base.with_remarks(value),
        other => unreachable!("{other} is not a contact text field"),
    };
    request.validate().is_ok()
}

fn update_accepts(param: &str, value: &str) -> bool {
    let update = ContactUpdate::new(991).expect("991 is a positive handle id");
    let update = match param {
        "name" => update.with_name(value),
        "org" => update.with_org(value),
        "street" => update.with_street(value),
        "city" => update.with_city(value),
        "pc" => update.with_postcode(value),
        "sp" => update.with_state(value),
        "voice" => update.with_voice(value),
        "fax" => update.with_fax(value),
        "remarks" => update.with_remarks(value),
        other => unreachable!("{other} is not a contact text field"),
    };
    update.params().is_ok()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The `text64` username limit holds for every length in and around it.
    #[test]
    fn credential_usernames_respect_the_text64_limit(length in 1usize..=128) {
        let username = "u".repeat(length);
        let result = Credentials::new(username, "pass");
        if length <= 64 {
            prop_assert!(result.is_ok());
        } else {
            prop_assert!(result.is_err());
        }
    }

    /// Display and parse are inverses for every known type.
    #[test]
    fn known_record_types_round_trip(index in 0usize..RecordType::ALL.len()) {
        let record_type = RecordType::ALL[index].clone();
        prop_assert_eq!(RecordType::parse(&record_type.to_string()).unwrap(), record_type.clone());
        prop_assert_eq!(record_type.to_string(), record_type.as_str());
    }

    /// `contact.create` and `contact.update` write the same fields, so they must
    /// judge a value the same way: whatever an update lets through, a create
    /// lets through too, and vice versa. #110 was a counter-example — the update
    /// path checked neither the length nor the control characters.
    #[test]
    fn contact_fields_are_judged_alike_on_create_and_update(
        chars in proptest::collection::vec(any::<char>(), 0..300),
    ) {
        let value: String = chars.into_iter().collect();
        for param in CONTACT_TEXT_FIELDS {
            prop_assert_eq!(
                create_accepts(param, &value),
                update_accepts(param, &value),
                "{} disagreed for {:?}",
                param,
                value
            );
        }
    }

    /// Any token parses, and unknown ones are carried upper-cased.
    #[test]
    fn arbitrary_record_types_parse(token in type_token()) {
        let parsed = RecordType::parse(&token).unwrap();
        prop_assert_eq!(parsed.to_string(), token.to_uppercase());
        let reparsed = RecordType::parse(&parsed.to_string()).unwrap();
        prop_assert_eq!(reparsed, parsed);
    }

    /// A record spec either fails validation or produces a payload with the
    /// documented keys and an in-range TTL.
    #[test]
    fn record_specs_are_consistent(
        name in "[@*A-Za-z_][A-Za-z0-9._-]{0,20}",
        content in any_text(),
        ttl in 0u32..=MAX_TTL + 10,
        type_index in 0usize..RecordType::ALL.len(),
    ) {
        let record_type = RecordType::ALL[type_index].clone();
        let built = RecordSpec::new(record_type.clone(), name.clone(), content.clone());

        match built {
            Ok(spec) => {
                let spec = spec.with_ttl(ttl);
                match spec {
                    Ok(spec) => {
                        // `with_ttl` accepted it, so `validate` must too.
                        prop_assert!(spec.validate().is_ok());
                        let params = spec.params();
                        prop_assert_eq!(params["name"].as_str(), Some(name.as_str()));
                        prop_assert_eq!(params["type"].as_str(), Some(record_type.as_str()));
                        prop_assert!(params["ttl"].as_u64().unwrap() <= u64::from(MAX_TTL));
                    }
                    Err(error) => {
                        prop_assert!(error.is_validation());
                        prop_assert!(ttl > MAX_TTL);
                    }
                }
            }
            Err(error) => prop_assert!(error.is_validation()),
        }
    }

    /// The record-type parser never rejects a content it accepted before a TTL
    /// change — TTL is independent of content.
    #[test]
    fn ttl_does_not_change_content_validation(
        content in any_text(),
        ttl in 0u32..=MAX_TTL,
    ) {
        let Ok(spec) = RecordSpec::new(RecordType::Txt, "@", content) else {
            return Ok(());
        };
        prop_assert!(spec.with_ttl(ttl).unwrap().validate().is_ok());
    }

    /// Domains either parse into a normalised ASCII name or are rejected.
    #[test]
    fn domain_names_are_normalised_or_rejected(input in any_text()) {
        match DomainName::parse(&input) {
            Ok(domain) => {
                let ascii = domain.as_str();
                prop_assert!(ascii.len() <= inwx_client::MAX_DOMAIN_LEN);
                prop_assert_eq!(ascii, ascii.to_lowercase());
                prop_assert!(ascii.contains('.'));
                prop_assert!(!ascii.starts_with('.'));
                prop_assert!(!ascii.ends_with('.'));
                for label in ascii.split('.') {
                    prop_assert!(!label.is_empty());
                    prop_assert!(label.len() <= inwx_client::MAX_LABEL_LEN);
                    prop_assert!(!label.starts_with('-'));
                    prop_assert!(!label.ends_with('-'));
                    prop_assert!(label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
                }
                // Serialisation round-trips through serde.
                let encoded = serde_json::to_string(&domain).unwrap();
                let decoded: DomainName = serde_json::from_str(&encoded).unwrap();
                prop_assert_eq!(decoded, domain);
            }
            Err(error) => prop_assert!(error.is_validation()),
        }
    }

    /// Hostnames are a superset of domains: whatever a domain accepts, a
    /// hostname accepts too.
    #[test]
    fn hostnames_accept_every_valid_domain(input in any_text()) {
        if let Ok(domain) = DomainName::parse(&input) {
            let host = Hostname::parse(domain.as_str()).unwrap();
            prop_assert_eq!(host.as_str(), domain.as_str());
        }
    }

    /// For every length around the total-name limit the decision is made by
    /// that limit alone: the name is built from four labels of at most 63
    /// characters, so nothing else can reject it.
    #[test]
    fn the_total_name_limit_decides_long_names(total in 240usize..=255) {
        // 63 + 1 + 63 + 1 + 63 + 1 = 192 characters before the last label.
        let last_label_len = total - (inwx_client::MAX_LABEL_LEN * 3 + 3);
        prop_assert!((1..=inwx_client::MAX_LABEL_LEN).contains(&last_label_len));
        let name = format!(
            "{}.{}.{}.{}",
            "a".repeat(inwx_client::MAX_LABEL_LEN),
            "b".repeat(inwx_client::MAX_LABEL_LEN),
            "c".repeat(inwx_client::MAX_LABEL_LEN),
            "d".repeat(last_label_len)
        );
        prop_assert_eq!(name.len(), total);

        let accepted = total <= inwx_client::MAX_DOMAIN_LEN;
        prop_assert_eq!(DomainName::parse(&name).is_ok(), accepted, "len {}", total);
        prop_assert_eq!(Hostname::parse(&name).is_ok(), accepted, "len {}", total);
    }

    /// Canonicalisation is idempotent: feeding an accepted name back in changes
    /// nothing, so a name never drifts when it is stored and re-read.
    #[test]
    fn name_canonicalisation_is_idempotent(input in any_text()) {
        let Ok(domain) = DomainName::parse(&input) else {
            return Ok(());
        };
        let reparsed = DomainName::parse(domain.as_str()).unwrap();
        prop_assert_eq!(&reparsed, &domain);
        let host = Hostname::parse(domain.as_str()).unwrap();
        prop_assert_eq!(&Hostname::parse(host.as_str()).unwrap(), &host);
    }

    /// Response parsing never panics, whatever bytes arrive.
    #[test]
    fn response_parsing_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        match RpcResponse::parse(&bytes) {
            Ok(response) => {
                // Parsed responses classify their own code consistently.
                prop_assert_eq!(
                    response.is_success(),
                    response
                        .code
                        .is_some_and(inwx_client::rpc::is_success_code)
                );
                let code = response.code;
                let result = response.into_result();
                if code.and_then(inwx_client::rpc::classify_code)
                    == Some(inwx_client::rpc::ResultCode::Success)
                {
                    prop_assert!(result.is_ok());
                } else if code.and_then(inwx_client::rpc::classify_code).is_some() {
                    let is_pending_error =
                        matches!(result, Err(inwx_client::Error::Pending { .. }));
                    prop_assert!(is_pending_error);
                } else if code.is_none() {
                    let is_uncertain_error = matches!(
                        &result,
                        Err(error) if error.is_uncertain()
                    );
                    prop_assert!(is_uncertain_error);
                } else {
                    let is_api_error = matches!(result, Err(inwx_client::Error::Api { .. }));
                    prop_assert!(is_api_error);
                }
            }
            Err(error) => {
                let is_json_error = matches!(error, inwx_client::Error::Json { .. });
                prop_assert!(is_json_error);
            }
        }
    }

    /// A record id built from a number is the decimal rendering of that number,
    /// and survives a serde round trip.
    #[test]
    fn record_ids_round_trip(id in 0i64..i64::MAX) {
        let record_id = RecordId::from_number(id);
        prop_assert_eq!(record_id.as_str(), id.to_string());
        let encoded = serde_json::to_string(&record_id).unwrap();
        let decoded: RecordId = serde_json::from_str(&encoded).unwrap();
        prop_assert_eq!(decoded, record_id);
    }

    /// Periods render as the documented tokens and parse back.
    #[test]
    fn periods_round_trip(years in 1u8..=10) {
        let period = Period::years(years).unwrap();
        prop_assert_eq!(period.to_string(), format!("{years}Y"));
        prop_assert_eq!(period.to_string().parse::<Period>().unwrap(), period);
        prop_assert!(Period::years(years + 10).is_err());
    }

    /// Whatever the API sends as a record payload, parsing either succeeds or
    /// errors — it never panics, and a parsed record keeps its content.
    #[test]
    fn record_parsing_never_panics(payload in any::<bool>(), content in any_text()) {
        let value = if payload {
            serde_json::json!({"id": "1", "type": "TXT", "content": content})
        } else {
            Value::Null
        };
        if let Ok(record) = serde_json::from_value::<inwx_client::DnsRecord>(value) {
            prop_assert_eq!(record.record_type, RecordType::Txt);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// A certificate lock reports its gross amount exactly when both amounts
    /// are readable; either missing amount stays `None`, and the zero default
    /// is only the named convenience.
    #[test]
    fn ssl_fund_gross_is_none_until_both_amounts_are_known(
        netto_cents in proptest::option::of(-100_000_000i64..100_000_000),
        vat_cents in proptest::option::of(-100_000_000i64..100_000_000),
    ) {
        let netto = netto_cents.map(|cents| Decimal::new(cents, 2));
        let vat = vat_cents.map(|cents| Decimal::new(cents, 2));
        let fund = SslFund {
            netto,
            vat,
            ..SslFund::default()
        };

        if let (Some(net), Some(tax)) = (netto, vat) {
            prop_assert_eq!(fund.gross(), Some(net + tax));
        } else {
            prop_assert_eq!(fund.gross(), None);
            prop_assert_eq!(fund.gross_or_zero(), Decimal::ZERO);
        }
    }

    /// The incomplete count is exactly the number of SSL locks whose gross
    /// amount cannot be read.
    #[test]
    fn locked_funds_count_incomplete_ssl_entries(
        netto_cents in proptest::option::of(0i64..1_000_000),
        vat_cents in proptest::option::of(0i64..1_000_000),
        complete in 0usize..8,
        incomplete in 0usize..8,
    ) {
        let netto = netto_cents.map(|cents| Decimal::new(cents, 2));
        let vat = vat_cents.map(|cents| Decimal::new(cents, 2));
        let mut ssl_funds = Vec::new();
        for _ in 0..complete {
            ssl_funds.push(SslFund {
                netto: Some(netto.unwrap_or_else(|| Decimal::new(10, 0))),
                vat: Some(vat.unwrap_or_else(|| Decimal::new(1, 0))),
                ..SslFund::default()
            });
        }
        for _ in 0..incomplete {
            ssl_funds.push(SslFund {
                netto,
                vat,
                ..SslFund::default()
            });
        }
        let funds = LockedFunds {
            ssl_funds,
            ..LockedFunds::default()
        };

        let expected = funds
            .ssl_funds
            .iter()
            .filter(|fund| fund.gross().is_none())
            .count();
        prop_assert_eq!(funds.incomplete_ssl_funds(), expected);
    }
}

// ------------------------------------------------- 0.2.0 builders and types

use std::str::FromStr;

use inwx_client::{
    is_read_only_method, parse_ip, AccountRole, ActionKind, AuthCode, CertificateOrder,
    CertificateTerm, DnsKey, DnssecAlgorithm, DnssecDigestType, DnssecDomainStatus, DnssecFlag,
    DnssecKeyQuery, DnssecKeyStatus, DocumentFormat, Email, Error, Handle, HostingPeriod,
    Irreversible, NameserverSetType, Password, RecordSet, Timestamp, TransferAnswer,
    TransportStage, UrlRedirectType, ZoneCreate, ZoneType, MAX_PASSWORD_LEN,
};

/// Arbitrary text for parsers that must never panic.
fn arbitrary() -> impl Strategy<Value = String> {
    "\\PC{0,60}"
}

/// Text for the password validator, including every shape it has to reject:
/// blanks, control characters and oversized values.
fn password_text() -> impl Strategy<Value = String> {
    prop_oneof![
        arbitrary(),
        "[ ]{0,5}",
        "\\p{Cc}{1,10}",
        "[\\PC\\p{Cc}]{200,300}",
    ]
}

/// Passwords the validator is guaranteed to accept: printable ASCII, at most
/// 41 characters and never blank, because the last class carries at least one
/// non-space. Tests that compare accepted passwords use this instead of
/// `password_text`, so no draw can fail validation and be mistaken for a bug.
fn accepted_password() -> impl Strategy<Value = String> {
    "[ -~]{0,20}[!-~][ -~]{0,20}"
}

/// A plausible `namespace.action` method name.
fn method_name() -> impl Strategy<Value = String> {
    "[a-z]{1,12}\\.[a-z]{1,12}"
}

/// Names that really are in the read-only table — the "just inside" side of the
/// lookup, as opposed to a name that merely looks plausible.
fn known_read_only() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::from("account.info")),
        Just(String::from("account.getroles")),
        Just(String::from("contact.info")),
        Just(String::from("domain.info")),
        Just(String::from("domain.list")),
        Just(String::from("nameserver.list")),
        Just(String::from("tag.info")),
    ]
}

/// A known method minus its last character — the "just outside" side. None of
/// these is in the table, so the lookup must stay exact.
fn almost_read_only() -> impl Strategy<Value = String> {
    known_read_only().prop_map(|name| name[..name.len() - 1].to_owned())
}

/// Surrounding whitespace, which the read-only lookup has to ignore.
fn padding() -> impl Strategy<Value = String> {
    "[ \t\n\r]{0,3}"
}

/// Every stage, as a strategy.
fn stage() -> impl Strategy<Value = TransportStage> {
    prop_oneof![
        Just(TransportStage::BeforeSend),
        Just(TransportStage::AfterSend),
        Just(TransportStage::Local),
    ]
}

/// The transient HTTP statuses — the "just inside" side of the rule in
/// `Error::is_retryable`.
fn transient_status() -> impl Strategy<Value = u16> {
    prop_oneof![Just(429u16), Just(502u16), Just(503u16), Just(504u16)]
}

/// The neighbours of those statuses plus the plain client errors — the "just
/// outside" side, none of which may be reported as retryable.
fn terminal_status() -> impl Strategy<Value = u16> {
    prop_oneof![
        Just(400u16),
        Just(401),
        Just(403),
        Just(404),
        Just(428),
        Just(430),
        Just(500),
        Just(501),
        Just(505),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn enum_parsers_never_panic(input in arbitrary()) {
        let _ = ZoneType::parse(&input);
        let _ = UrlRedirectType::from_str(&input);
        let _ = NameserverSetType::parse(&input);
        let _ = DocumentFormat::from_str(&input);
        let _ = TransferAnswer::from_str(&input);
        let _ = DnssecDomainStatus::parse(&input);
        let _ = DnssecKeyStatus::parse(&input);
        let _ = HostingPeriod::from_str(&input);
        let _ = CertificateTerm::try_from(u8::try_from(input.len() % 4).unwrap());
        let _ = parse_ip(&input);
        let _ = Timestamp::parse(&input);
        let _ = Email::parse(&input);
        let _ = AuthCode::new(&input);
        let _ = Password::new(&input);
        let _ = DnsKey::parse(&input);
        let _ = inwx_client::DsRecord::parse(&input);
        let _ = AccountRole::parse(&input);
    }

    #[test]
    fn accepted_enums_round_trip(input in arbitrary()) {
        if let Ok(zone_type) = ZoneType::parse(&input) {
            prop_assert_eq!(ZoneType::parse(zone_type.as_str()).unwrap(), zone_type);
        }
        if let Ok(redirect) = UrlRedirectType::from_str(&input) {
            prop_assert_eq!(UrlRedirectType::from_str(redirect.as_str()).unwrap(), redirect);
        }
        if let Ok(set_type) = NameserverSetType::parse(&input) {
            prop_assert_eq!(NameserverSetType::parse(set_type.as_str()).unwrap(), set_type);
        }
        if let Ok(format) = DocumentFormat::from_str(&input) {
            prop_assert_eq!(DocumentFormat::from_str(format.as_str()).unwrap(), format);
        }
        if let Ok(answer) = TransferAnswer::from_str(&input) {
            prop_assert_eq!(TransferAnswer::from_str(answer.as_str()).unwrap(), answer);
        }
        if let Ok(status) = DnssecDomainStatus::parse(&input) {
            prop_assert_eq!(DnssecDomainStatus::parse(status.as_str()).unwrap(), status);
        }
        if let Ok(status) = DnssecKeyStatus::parse(&input) {
            prop_assert_eq!(DnssecKeyStatus::parse(status.as_str()).unwrap(), status);
        }
        if let Ok(role) = AccountRole::parse(&input) {
            prop_assert_eq!(AccountRole::parse(role.as_str()).unwrap(), role);
        }
    }

    #[test]
    fn accepted_emails_round_trip(
        local in "[A-Za-z0-9._%+-]{3,20}",
        label in "[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?",
    ) {
        // `xn--` marks an A-label, and a label carrying the prefix is only a
        // domain when the punycode behind it decodes — which UTS-46 rightly
        // rejects for a random one. Such a label is outside this property: the
        // point is that an address the parser accepts survives the round trip.
        prop_assume!(!label.starts_with("xn--"));
        let address = format!("{local}@{label}.example.com");
        let email = Email::parse(&address).unwrap();
        prop_assert_eq!(email.as_str(), address.as_str());
        prop_assert_eq!(Email::parse(email.as_str()).unwrap(), email);
    }

    /// A password is accepted exactly when it is neither blank, oversized, nor
    /// carrying a control character — and it is then kept verbatim and stays
    /// redacted everywhere but on the wire.
    #[test]
    fn passwords_are_accepted_exactly_when_safe(input in password_text()) {
        let expected = !input.trim().is_empty()
            && input.chars().count() <= MAX_PASSWORD_LEN
            && !input.chars().any(char::is_control);
        prop_assert_eq!(Password::new(&input).is_ok(), expected);
        if let Ok(password) = Password::new(&input) {
            prop_assert_eq!(password.as_str(), input.as_str());
            prop_assert_eq!(password.to_string(), "<redacted>");
            prop_assert_eq!(format!("{password:?}"), "Password(<redacted>)");
            prop_assert_eq!(
                serde_json::to_string(&password).unwrap(),
                serde_json::to_string(&input).unwrap()
            );
        }
    }

    /// The length limit counts characters, not bytes, and sits exactly at
    /// `MAX_PASSWORD_LEN`: 255 pass, 256 do not.
    #[test]
    fn password_length_boundary(count in 0usize..=MAX_PASSWORD_LEN + 2) {
        let raw = "x".repeat(count);
        let expected = count > 0 && count <= MAX_PASSWORD_LEN;
        prop_assert_eq!(Password::new(raw).is_ok(), expected);
    }

    /// Multibyte secrets are measured in characters, so a 255-character
    /// non-ASCII password is inside the limit even though it is longer in
    /// bytes.
    #[test]
    fn password_length_counts_characters_not_bytes(count in 1usize..=MAX_PASSWORD_LEN) {
        let raw = "ö".repeat(count);
        prop_assert!(raw.len() > count);
        prop_assert!(Password::new(raw).is_ok());
    }

    /// Constant-time comparison still means exact comparison: appending
    /// anything makes two passwords unequal, and an independently built copy of
    /// the same secret still compares equal.
    #[test]
    fn password_equality_is_exact(left in accepted_password(), suffix in "[ -~]{1,20}") {
        let left = Password::new(&left).unwrap();
        let right = Password::new(format!("{}{suffix}", left.as_str())).unwrap();
        let same = Password::new(left.as_str()).unwrap();
        prop_assert!(left != right);
        prop_assert_eq!(left == right, left.as_str() == right.as_str());
        prop_assert!(left == same);
        prop_assert_eq!(left.as_str(), same.as_str());
    }

    #[test]
    fn accepted_timestamps_round_trip(year in 2000u16..2100, month in 1u8..13, day in 1u8..29) {
        let text = format!("{year:04}-{month:02}-{day:02}T03:04:05");
        let at = Timestamp::parse(&text).unwrap();
        prop_assert_eq!(at.as_str(), text.as_str());
        prop_assert_eq!(Timestamp::parse(at.as_str()).unwrap(), at);
    }

    /// Offset input names the same instant before and after canonicalization,
    /// and the text sent on the wire is the normalized UTC spelling.
    #[test]
    fn accepted_offset_timestamps_are_normalised_for_the_wire(
        year in 2000u16..2100,
        month in 1u8..13,
        day in 1u8..=28,
        hour in 0u8..24,
        minute in 0u8..60,
        second in 0u8..60,
        offset_hour in 0u8..24,
        offset_minute in 0u8..60,
        positive in any::<bool>(),
    ) {
        let text = format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{}{offset_hour:02}:{offset_minute:02}",
            if positive { '+' } else { '-' }
        );
        let zoned = inwx_client::Timestamp::parse(&text).unwrap();
        let canonical = inwx_client::Timestamp::parse(zoned.as_str()).unwrap();
        prop_assert_eq!(&canonical, &zoned);
        prop_assert_eq!(canonical.as_str().len(), 19);
        prop_assert_eq!(serde_json::to_string(&zoned).unwrap(), format!("\"{}\"", zoned.as_str()));
    }

    #[test]
    fn handles_survive_serde(id in 1i64..=i64::from(i32::MAX)) {
        let handle = Handle::new(id).unwrap();
        let encoded = serde_json::to_string(&handle).unwrap();
        prop_assert_eq!(&encoded, &id.to_string());
        let decoded: Handle = serde_json::from_str(&encoded).unwrap();
        prop_assert_eq!(decoded, handle);
    }

    #[test]
    fn zone_params_round_trip_through_json(label in "[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?") {
        // `xn--` begins an A-label; a random one is not valid punycode.
        prop_assume!(!label.starts_with("xn--"));
        let domain = DomainName::parse(&format!("{label}.example.com")).unwrap();
        let zone = ZoneCreate::master(domain.clone()).unwrap();
        let params = zone.params().unwrap();
        prop_assert_eq!(params["domain"].as_str().unwrap(), domain.as_str());
        let encoded = serde_json::to_string(&params).unwrap();
        let decoded: Value = serde_json::from_str(&encoded).unwrap();
        prop_assert_eq!(decoded, params);
    }

    #[test]
    fn record_sets_never_panic(names in proptest::collection::vec("[@*a-z_.-]{0,8}", 0..12)) {
        let mut set = RecordSet::new().unwrap();
        for (index, name) in names.iter().enumerate() {
            let content = format!("203.0.113.{}", index % 250);
            if let Ok(spec) = RecordSpec::a(name.as_str(), content) {
                let _ = set.push(spec);
            }
        }
        // Every accepted push is reflected in the length, and no apex CNAME
        // slips in.
        prop_assert!(set.len() <= names.len());
        for record in set.records() {
            prop_assert!(record.validate().is_ok());
            prop_assert!(!(record.record_type() == RecordType::Cname && record.name() == "@"));
        }
    }

    #[test]
    fn transfer_acknowledgements_name_what_they_authorise(label in "[a-z0-9]{1,20}") {
        let domain = DomainName::parse(&format!("{label}.de")).unwrap();
        let intent = Irreversible::acknowledge(ActionKind::Transfer, &domain);
        let rendered = format!("{intent:?}");
        prop_assert_eq!(intent.domain(), &domain);
        prop_assert_eq!(intent.action(), ActionKind::Transfer);
        prop_assert!(rendered.contains(domain.as_str()));
        // Only the matching action builds a transfer request.
        prop_assert!(inwx_client::TransferRequest::new(intent.clone()).is_ok());
        // The trade builder rejects the same acknowledgement in `build`; the
        // registrant is a required member, so it is supplied here.
        prop_assert!(inwx_client::TradeRequest::builder(
            intent)
            .with_registrant(inwx_client::Handle::new(1201).unwrap())
            .build()
            .is_err());
    }

    #[test]
    fn certificate_orders_require_an_identity(name in "[a-z0-9]{1,20}") {
        let domain = DomainName::parse(&format!("{name}.example.com")).unwrap();
        let order = CertificateOrder::new(17).unwrap();
        prop_assert!(order.params().is_err());
        prop_assert!(order
            .with_common_name(domain)
            .params()
            .is_ok());
    }

    #[test]
    fn dnssec_numeric_ids_round_trip(algorithm in 0u8..=32, digest in 0u8..=8, flag in 0u16..=300) {
        if let Ok(algorithm) = DnssecAlgorithm::from_u8(algorithm) {
            prop_assert_eq!(DnssecAlgorithm::from_u8(algorithm.as_u8()).unwrap(), algorithm);
        }
        if let Ok(digest) = DnssecDigestType::from_u8(digest) {
            prop_assert_eq!(DnssecDigestType::from_u8(digest.as_u8()).unwrap(), digest);
        }
        if let Ok(flag) = DnssecFlag::from_u16(flag) {
            prop_assert_eq!(DnssecFlag::from_u16(flag.as_u16()).unwrap(), flag);
        }
    }

    /// A response id survives as it arrived: the lenient parsers never lose a
    /// number, they only stop recognising it.
    #[test]
    fn dnssec_response_ids_survive(algorithm in any::<u8>(), digest in any::<u8>(), flag in any::<u16>()) {
        prop_assert_eq!(DnssecAlgorithm::from_u8_lenient(algorithm).as_u8(), algorithm);
        prop_assert_eq!(DnssecDigestType::from_u8_lenient(digest).as_u8(), digest);
        prop_assert_eq!(DnssecFlag::from_u16_lenient(flag).as_u16(), flag);
    }

    #[test]
    fn dnssec_queries_keep_their_filters(page in 0u32..10, limit in 0u32..100) {
        let query = DnssecKeyQuery::new().with_page(page, limit);
        let params = query.params();
        prop_assert_eq!(params["page"].as_u64().unwrap(), u64::from(page.max(1)));
        prop_assert_eq!(params["pagelimit"].as_u64().unwrap(), u64::from(limit));
    }

    /// The read-only lookup only folds case and trims: it never grows or shrinks
    /// the set of methods it recognises.
    #[test]
    fn read_only_lookup_ignores_case_and_padding(
        name in method_name(),
        lead in padding(),
        trail in padding(),
    ) {
        let plain = is_read_only_method(&name);
        prop_assert_eq!(plain, is_read_only_method(&name.to_uppercase()));
        let padded = format!("{lead}{name}{trail}");
        prop_assert_eq!(plain, is_read_only_method(&padded));
        // Only a dotted `namespace.action` can ever be known.
        if plain {
            prop_assert!(name.contains('.'));
        }
    }

    /// Folding is idempotent: looking a name up twice, the second time already
    /// trimmed and lower-cased, gives the same verdict for any input at all.
    #[test]
    fn read_only_verdict_survives_canonical_folding(input in arbitrary()) {
        let folded = input.trim().to_ascii_lowercase();
        prop_assert_eq!(is_read_only_method(&input), is_read_only_method(&folded));
    }

    /// Fail closed: without a dot there is no namespace, so nothing can match —
    /// an unknown name is treated as mutating and never replayed.
    #[test]
    fn a_name_without_a_dot_is_never_read_only(input in "[a-z0-9_-]{0,24}") {
        prop_assert!(!is_read_only_method(&input));
    }

    /// Boundary pair: a name in the table is read-only whatever the case or the
    /// padding, and the same name one character shorter is not.
    #[test]
    fn read_only_boundary_is_exact(
        inside in known_read_only(),
        outside in almost_read_only(),
        lead in padding(),
        trail in padding(),
    ) {
        let padded = format!("{lead}{inside}{trail}");
        prop_assert!(is_read_only_method(&padded));
        prop_assert!(is_read_only_method(&inside.to_uppercase()));
        prop_assert!(!is_read_only_method(&outside));
        prop_assert!(!is_read_only_method(&outside.to_uppercase()));
    }

    /// The stage alone decides the error, and the error alone decides the retry.
    #[test]
    fn stage_decides_retryability_exactly(stage in stage(), message in arbitrary()) {
        let error = Error::transport_at(stage, message.clone());
        prop_assert_eq!(error.is_retryable(), stage.is_safe_to_retry());
        prop_assert_eq!(error.is_uncertain(), stage == TransportStage::AfterSend);
        // Only an after-send failure is ambiguous about the mutation.
        prop_assert_eq!(
            error.to_string().contains("may have been executed"),
            stage == TransportStage::AfterSend
        );
        prop_assert!(error.to_string().contains(&message));
    }

    /// The HTTP verdict is the boundary pair made explicit: a transient status
    /// is retryable, the status right next to it is not, and the body never
    /// changes the answer.
    #[test]
    fn http_retryability_boundary_is_exact(
        inside in transient_status(),
        outside in terminal_status(),
        body in arbitrary(),
    ) {
        let transient = Error::Http {
            status: inside,
            body: body.clone().into(),
            retry_after: None,
            source: None,
        };
        prop_assert!(transient.is_retryable());
        prop_assert!(!transient.is_uncertain());
        // The message carries exactly the bounded, redacted body.
        prop_assert_eq!(
            transient.to_string(),
            format!("http {inside}: {}", HttpBody::new(&body))
        );

        let terminal = Error::Http {
            status: outside,
            body: body.into(),
            retry_after: None,
            source: None,
        };
        prop_assert!(!terminal.is_retryable());
        prop_assert!(!terminal.is_uncertain());
    }

    /// Whatever the endpoint sent, the body kept in the error is bounded, and
    /// bounding it again changes nothing.
    #[test]
    fn http_bodies_are_bounded_and_idempotent(body in arbitrary()) {
        let once = HttpBody::new(&body);
        prop_assert!(
            once.as_str().chars().count() <= MAX_HTTP_BODY_CHARS + " [truncated]".len()
        );
        let twice = HttpBody::new(once.as_str());
        prop_assert_eq!(twice.as_str(), once.as_str());
        prop_assert!(once.as_str().is_char_boundary(0));
        prop_assert!(once.as_str().chars().count() <= MAX_HTTP_BODY_CHARS || once.as_str().ends_with(" [truncated]"));
    }

    /// A body echoing a secret loses the value, in JSON and in form encoding.
    #[test]
    fn echoed_secrets_never_reach_the_message(
        secret in "[a-f0-9]{8,32}",
        quoted in any::<bool>(),
    ) {
        let body = if quoted {
            format!(r#"{{"password":"{secret}","user":"bob"}}"#)
        } else {
            format!("password={secret}&user=bob")
        };
        let error = Error::Http {
            status: 400,
            body: body.into(),
            retry_after: None,
            source: None,
        };
        prop_assert!(!error.to_string().contains(&secret));
        prop_assert!(error.to_string().contains("<redacted>"));
        let debug = format!("{error:?}");
        prop_assert!(!debug.contains(&secret));
        prop_assert!(error.to_string().contains("bob"));
    }

    /// Sweeping the whole `u16` range keeps the set exactly the four documented
    /// statuses — a future widening to "all of 5xx" would fail here.
    #[test]
    fn only_the_four_http_statuses_are_retryable(status in any::<u16>()) {
        let error = Error::Http {
            status,
            body: String::new().into(),
            retry_after: None,
            source: None,
        };
        prop_assert_eq!(error.is_retryable(), matches!(status, 429 | 502 | 503 | 504));
    }

    /// The delay a server asks for survives the trip into the error unchanged,
    /// whatever it is, and never moves the retry verdict.
    #[test]
    fn a_retry_after_round_trips_unchanged(
        status in any::<u16>(),
        secs in any::<u64>(),
        nanos in 0u32..1_000_000_000,
    ) {
        let delay = Duration::new(secs, nanos);
        let error = Error::http(status, "answer")
            .with_retry_after(delay);
        prop_assert_eq!(error.retry_after(), Some(delay));
        // The header is advisory only: the status alone decides.
        prop_assert_eq!(error.is_retryable(), matches!(status, 429 | 502 | 503 | 504));

        // A held header reads back as the duration that was written.
        let written = error.retry_after().unwrap_or_default();
        prop_assert_eq!((written.as_secs(), written.subsec_nanos()), (secs, nanos));
    }

    /// The public reader never panics on arbitrary text, and a value made only
    /// of digits is exactly that many seconds.
    #[test]
    fn reading_a_retry_after_header_is_total(text in "\\PC{0,40}") {
        let parsed = retry_after_from_header(&text);
        let trimmed = text.trim();
        if !trimmed.is_empty() && trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
            prop_assert_eq!(
                parsed,
                trimmed.parse::<u64>().ok().map(Duration::from_secs)
            );
        }
        // Whatever the text, a delay never exceeds what a `Duration` holds.
        if let Some(delay) = parsed {
            prop_assert!(delay <= Duration::from_secs(u64::MAX));
        }
    }

    /// Any delay written as the header's number form reads back unchanged.
    #[test]
    fn retry_after_numbers_round_trip(secs in any::<u64>()) {
        prop_assert_eq!(
            retry_after_from_header(&secs.to_string()),
            Some(Duration::from_secs(secs))
        );
    }
}

// --------------------------------------------------- reseller objects (#22)

use inwx_client::{
    Application, ApplicationCheckResult, ApplicationQuery, ApplicationType, AuthInfo2Order,
    AuthInfo2OrderResult, AuthInfo2PriceQuote, ContactVerificationSettings, Customer,
    CustomerDownload, CustomerDownloadQuery, CustomerUpdate, DataExport, DocumentEntry,
    DocumentQuery, DocumentUpload, DownloadedDocument, HostCheckResult, HostCreate, HostQuery,
    HostRecord, HostUpdate, Message, MessageAck, NicHandle, NicHandleQuery, PdfFile, PdfHandle,
    PdfRender, PolledMessage, SavedName, MAX_HOST_ADDRESSES,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// An application type is a validated token: upper-cased, reparseable, and
    /// an unknown one is carried rather than refused. The strategy stops one
    /// character short so the property can add the last accepted character and
    /// the first rejected one.
    #[test]
    fn application_type_tokens_stop_at_sixty_four_characters(token in "[A-Za-z0-9_.-]{1,63}") {
        let inside = format!("{token}x");
        let outside = format!("{token}xx");
        let parsed = ApplicationType::parse(&inside).unwrap();
        prop_assert_eq!(parsed.as_str(), inside.to_ascii_uppercase());
        prop_assert_eq!(ApplicationType::parse(parsed.as_str()).unwrap(), parsed.clone());
        prop_assert_eq!(parsed.to_string(), parsed.as_str());
        prop_assert_eq!(
            ApplicationType::parse(&outside).is_ok(),
            outside.chars().count() <= 64
        );
    }

    /// A handle class is validated against the `text064` field: an unknown
    /// class is carried on the response side, but `with_type` refuses a token
    /// past 64 characters instead of sending it.
    #[test]
    fn handle_class_tokens_stop_at_sixty_four_characters(token in "[A-Za-z0-9_.-]{1,63}") {
        let inside = format!("{token}x");
        let outside = format!("{token}xx");
        let query = NicHandleQuery::new()
            .with_type(ContactType::parse(&inside).unwrap())
            .unwrap();
        let params = query.params().unwrap();
        prop_assert_eq!(params["type"].as_str().unwrap(), inside.to_ascii_uppercase());
        prop_assert_eq!(
            NicHandleQuery::new()
                .with_type(ContactType::parse(&outside).unwrap())
                .is_ok(),
            outside.chars().count() <= 64
        );
    }

    /// A document file name is a name: never empty, never a dot pair.
    #[test]
    fn document_file_names_are_names_never_paths(name in "[A-Za-z0-9 ._-]{0,10}") {
        let trimmed = name.trim();
        let expected = !trimmed.is_empty() && trimmed != "." && trimmed != "..";
        prop_assert_eq!(DocumentUpload::new(&name, b"x").is_ok(), expected);
    }

    /// A name that a download hands out is a name on the way out too: whatever
    /// the answer carries, an accepted value has no separator, no control
    /// character, is not empty and stays within 255 characters.
    #[test]
    fn a_parsed_saved_name_can_never_leave_the_directory(name in any_text()) {
        if let Ok(saved) = SavedName::parse(&name) {
            let text = saved.as_str();
            prop_assert!(!text.is_empty());
            prop_assert!(!text.contains('/') && !text.contains('\\'));
            prop_assert!(!text.chars().any(char::is_control));
            prop_assert!(text.chars().count() <= 255);
            let reparsed = SavedName::parse(text).unwrap();
            prop_assert_eq!(reparsed.as_str(), text);
        }
    }

    /// Whatever body is uploaded arrives base64-encoded and decodes back
    /// unchanged; the empty body is the documented rejection.
    #[test]
    fn document_bodies_round_trip_through_base64(body in any_text()) {
        let upload = DocumentUpload::new("note.txt", body.as_bytes());
        if body.is_empty() {
            prop_assert!(upload.unwrap_err().is_validation());
            return Ok(());
        }
        let encoded = upload.unwrap().params()["content"]
            .as_str()
            .unwrap()
            .to_owned();
        let downloaded = DownloadedDocument {
            content: Some(encoded),
            ..DownloadedDocument::default()
        };
        prop_assert_eq!(downloaded.bytes().unwrap(), body.as_bytes());
    }

    /// A host carries at least one and at most `MAX_HOST_ADDRESSES` addresses;
    /// both outside values are refused before the wire.
    #[test]
    fn host_address_counts_are_bounded(count in 0usize..=16) {
        let addresses: Vec<std::net::IpAddr> = (0..count)
            .map(|index| format!("198.51.100.{index}").parse().unwrap())
            .collect();
        let created = HostCreate::new(
            DomainName::parse("example.com").unwrap(),
            Hostname::parse("ns1").unwrap(),
            &addresses,
        )
        .is_ok();
        prop_assert_eq!(created, (1..=MAX_HOST_ADDRESSES).contains(&count));
    }

    /// Every reseller id parameter accepts exactly the positive numbers in the
    /// API's documented `int` range.
    #[test]
    fn reseller_ids_must_be_positive(id in i64::MIN..2i64) {
        prop_assert_eq!(MessageAck::new(id).is_ok(), id > 0);
        prop_assert_eq!(HostUpdate::new(id).is_ok(), id > 0);
        prop_assert_eq!(CustomerUpdate::new(id).is_ok(), id > 0);
        prop_assert_eq!(CustomerDownloadQuery::new(id).is_ok(), id > 0);
        prop_assert_eq!(PdfRender::new("invoice", id).is_ok(), id > 0);
        prop_assert_eq!(
            ApplicationQuery::new().with_id(id).is_ok(),
            id > 0
        );
        prop_assert_eq!(
            NicHandleQuery::new().with_customer_number(id).is_ok(),
            id > 0
        );
    }

    #[test]
    fn reseller_ids_must_fit_the_documented_int_range(id in i64::from(i32::MAX) + 1..=i64::MAX) {
        prop_assert!(MessageAck::new(id).is_err());
        prop_assert!(HostUpdate::new(id).is_err());
        prop_assert!(CustomerUpdate::new(id).is_err());
        prop_assert!(CustomerDownloadQuery::new(id).is_err());
        prop_assert!(PdfRender::new("invoice", id).is_err());
        prop_assert!(ApplicationQuery::new().with_id(id).is_err());
        prop_assert!(NicHandleQuery::new().with_customer_number(id).is_err());
    }

    /// The reseller list queries keep the paging contract: the page is
    /// one-based, the limit is sent as given, and a limit of zero is refused.
    /// `DocumentQuery` refuses a page of zero instead of clamping it.
    #[test]
    fn reseller_queries_keep_paging(page in 0u32..10, limit in 1u32..100) {
        let host = HostQuery::new().with_page(page, limit).unwrap().params().unwrap();
        prop_assert_eq!(host["page"].as_u64().unwrap(), u64::from(page.max(1)));
        prop_assert_eq!(host["pagelimit"].as_u64().unwrap(), u64::from(limit));

        let handles = NicHandleQuery::new().with_page(page, limit).unwrap().params().unwrap();
        prop_assert_eq!(handles["page"].as_u64().unwrap(), u64::from(page.max(1)));

        if page == 0 {
            prop_assert!(DocumentQuery::new().with_page(page, limit).is_err());
        } else {
            let documents = DocumentQuery::new().with_page(page, limit).unwrap().params();
            prop_assert_eq!(documents["page"].as_u64().unwrap(), u64::from(page));
            prop_assert_eq!(documents["pagelimit"].as_u64().unwrap(), u64::from(limit));
        }

        let applications = ApplicationQuery::new().with_page(page, limit).unwrap().params().unwrap();
        prop_assert_eq!(applications["page"].as_u64().unwrap(), u64::from(page.max(1)));

        let downloads = CustomerDownloadQuery::new(1)
            .unwrap()
            .with_page(page, limit)
            .unwrap()
            .params()
            .unwrap();
        prop_assert_eq!(downloads["pagelimit"].as_u64().unwrap(), u64::from(limit));

        prop_assert!(HostQuery::new().with_page(1, 0).is_err());
        prop_assert!(DocumentQuery::new().with_page(1, 0).is_err());
        prop_assert!(DocumentQuery::new().with_page(0, limit).is_err());
        prop_assert!(ApplicationQuery::new().with_page(1, 0).is_err());
        prop_assert!(NicHandleQuery::new().with_page(1, 0).is_err());
        prop_assert!(CustomerDownloadQuery::new(1).unwrap().with_page(1, 0).is_err());
    }

    /// The `authinfo2.create` parameters echo the validated domain verbatim
    /// under the `domain` key, and carry `testing` exactly when it was asked
    /// for — never a stated default, never an extra key.
    #[test]
    fn auth_info2_order_params_echo_the_domain(
        name in "[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?",
        testing in proptest::bool::ANY,
    ) {
        let order_domain = DomainName::parse(&format!("{name}.de")).unwrap();
        let order = AuthInfo2Order::new(order_domain.clone(), testing);
        let params = order.params();
        prop_assert_eq!(order.domain(), &order_domain);
        prop_assert_eq!(order.is_testing(), testing);
        prop_assert_eq!(params["domain"].as_str(), Some(order_domain.as_str()));
        prop_assert_eq!(params.get("testing").is_some(), testing);
        if testing {
            prop_assert_eq!(&params["testing"], &Value::Bool(true));
        }
        prop_assert_eq!(
            params.as_object().map_or(0, serde_json::Map::len),
            if testing { 2 } else { 1 }
        );
        // Those two fields are the whole order, so they decide equality too.
        prop_assert_eq!(order, AuthInfo2Order::new(order_domain, testing));
    }

    /// Every reseller decoder either yields a value or reports an error — a
    /// payload from the wire never panics and never unwraps.
    #[test]
    fn reseller_decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        if let Ok(payload) = serde_json::from_str::<Value>(&String::from_utf8_lossy(&bytes)) {
            decode_every_reseller_row(&payload);
        }
    }
    /// Whatever the name and the flag, a clientHold request body is exactly
    /// `{"domain": …, "testing": …}` with the name verbatim — no dropped flag,
    /// no extra field, for any valid input.
    #[test]
    fn client_hold_params_are_exactly_two_fields(
        label in "[a-z][a-z0-9]{0,10}",
        tld in "[a-z]{2,6}",
        testing in proptest::bool::ANY,
    ) {
        let name = DomainName::parse(&format!("{label}.{tld}")).unwrap();
        let set = SetClientHold::new(name.clone());
        let remove = RemoveClientHold::new(name.clone());
        let set = if testing { set.dry_run() } else { set };
        let remove = if testing { remove.dry_run() } else { remove };
        for params in [set.params(), remove.params()] {
            let object = params.as_object().unwrap();
            prop_assert_eq!(object.len(), 2, "{}", params);
            prop_assert_eq!(&object["domain"], &Value::String(name.as_str().to_owned()));
            prop_assert_eq!(&object["testing"], &Value::Bool(testing));
        }
    }
}

/// Runs every reseller decoder over one payload. The point is that none of them
/// panics, so the results are dropped.
fn decode_every_reseller_row(payload: &Value) {
    let _ = serde_json::from_value::<Application>(payload.clone());
    let _ = serde_json::from_value::<Vec<Application>>(payload.clone());
    let _ = serde_json::from_value::<ApplicationCheckResult>(payload.clone())
        .map(|check| check.is_available());
    let _ = serde_json::from_value::<AuthInfo2PriceQuote>(payload.clone());
    let _ = serde_json::from_value::<AuthInfo2OrderResult>(payload.clone());
    let _ = serde_json::from_value::<ContactVerificationSettings>(payload.clone())
        .map(|settings| settings.is_verified());
    let _ = serde_json::from_value::<Customer>(payload.clone());
    let _ = serde_json::from_value::<Vec<Customer>>(payload.clone());
    let _ = serde_json::from_value::<CustomerDownload>(payload.clone());
    let _ = serde_json::from_value::<DataExport>(payload.clone()).map(|export| export.is_pending());
    let _ = serde_json::from_value::<DocumentEntry>(payload.clone());
    let _ = serde_json::from_value::<DownloadedDocument>(payload.clone()).map(|doc| {
        let _ = doc.bytes();
        doc.kind()
    });
    let _ = serde_json::from_value::<HostCheckResult>(payload.clone())
        .map(|check| check.is_available());
    let _ = serde_json::from_value::<HostRecord>(payload.clone());
    let _ = serde_json::from_value::<Message>(payload.clone()).map(|message| message.message_id());
    let _ = serde_json::from_value::<PolledMessage>(payload.clone())
        .map(|message| message.message_id());
    let _ =
        serde_json::from_value::<inwx_client::NewsItem>(payload.clone()).map(|item| item.is_read());
    let _ = serde_json::from_value::<NicHandle>(payload.clone()).map(|handle| handle.is_deleted());
    let _ = serde_json::from_value::<PdfHandle>(payload.clone());
    let _ = serde_json::from_value::<PdfFile>(payload.clone()).map(|file| file.bytes());
}

// ---------------------------------------------------------- price surface (#63)

use inwx_client::{DomainPriceQuote, ExtraDataRule, PriceChange, PriceList, PromoCode, TldPrice};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// INWX writes an amount either as a JSON number or as a decimal string.
    /// A cents-precise amount has to arrive as the same value either way, for
    /// every row type that carries one — and the string form is what the API
    /// actually sends for a promo or a scheduled change.
    #[test]
    fn an_amount_is_the_same_whether_it_arrives_as_a_number_or_as_text(
        cents in 0i32..10_000_000,
    ) {
        let amount = f64::from(cents) / 100.0;
        let text = format!("{amount:.2}");

        let from_number: PriceChange = serde_json::from_value(serde_json::json!({
            "tld": "de", "createPrice": amount, "renewalPrice": amount,
        }))
        .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let from_text: PriceChange = serde_json::from_value(serde_json::json!({
            "tld": "de", "create_price": text.as_str(), "renewal_price": text.as_str(),
        }))
        .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(from_number.create, Some(amount));
        prop_assert_eq!(from_text.create, from_number.create);
        prop_assert_eq!(from_text.renewal, from_number.renewal);

        let from_number: TldPrice = serde_json::from_value(serde_json::json!({
            "tld": "de", "createPrice": amount, "renewalPrice": amount,
        }))
        .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let from_text: TldPrice = serde_json::from_value(serde_json::json!({
            "tld": "de", "create_price": text.as_str(), "renewal_price": text.as_str(),
        }))
        .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(from_number.create, Some(amount));
        prop_assert_eq!(from_text, from_number);

        let from_number: PromoCode =
            serde_json::from_value(serde_json::json!({"netPrice": amount}))
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let from_text: PromoCode =
            serde_json::from_value(serde_json::json!({"net_price": text.as_str()}))
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(from_number.price, Some(amount));
        prop_assert_eq!(from_text.price, from_number.price);

        let from_number: DomainPriceQuote =
            serde_json::from_value(serde_json::json!({"price": amount}))
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let from_text: DomainPriceQuote =
            serde_json::from_value(serde_json::json!({"price": text.as_str()}))
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(from_number.price, Some(amount));
        prop_assert_eq!(from_text.price, from_number.price);
    }

    /// A rule string is kept verbatim, and its `name=value` split stays stable
    /// for every text the API can return.
    #[test]
    fn a_rule_string_keeps_its_raw_text_and_split(raw in any_text()) {
        let rule = ExtraDataRule::from(raw.as_str());
        prop_assert_eq!(rule.as_str(), raw.as_str());
        if let Some((name, value)) = raw.split_once('=') {
            prop_assert_eq!(rule.name(), Some(name.trim()));
            prop_assert_eq!(rule.value(), Some(value.trim()));
        } else {
            prop_assert_eq!(rule.name(), None);
            prop_assert_eq!(rule.value(), None);
        }
    }

    /// No payload off the wire panics a price decoder, and a row that cannot be
    /// read costs at most its amount — never the answer.
    #[test]
    fn price_decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(payload) = serde_json::from_str::<Value>(&String::from_utf8_lossy(&bytes)) {
            decode_every_price_row(&payload);
        }
    }
}

/// Runs every price decoder over one payload. The point is that none of them
/// panics, so the results are dropped.
fn decode_every_price_row(payload: &Value) {
    let _ = serde_json::from_value::<PriceList>(payload.clone())
        .map(|list| list.has_more() || list.find("de").is_some() || !list.is_empty());
    let _ = serde_json::from_value::<TldPrice>(payload.clone());
    let _ = serde_json::from_value::<DomainPriceQuote>(payload.clone());
    let _ = serde_json::from_value::<Vec<TldPrice>>(payload.clone());
    let _ = serde_json::from_value::<ExtraDataRule>(payload.clone())
        .map(|rule| rule.is_empty() || rule.name().is_some());
    let _ = serde_json::from_value::<Vec<ExtraDataRule>>(payload.clone());
    let _ = serde_json::from_value::<PromoCode>(payload.clone())
        .map(|promo| promo.normalised_tld().is_some() || promo.price.is_some());
    let _ = serde_json::from_value::<Vec<PromoCode>>(payload.clone());
    let _ = serde_json::from_value::<PriceChange>(payload.clone())
        .map(|change| change.is_past || change.create.is_some() || change.change_date.is_some());
    let _ = serde_json::from_value::<Vec<PriceChange>>(payload.clone());
}

// ---------------------------------------- 0.2.x diagnostics (issue #14)

use inwx_client::{
    DomainLog, DomainLogEntry, DomainLogQuery, DomainRule, DomainStat, DomainStats, TldGroup,
    TldGroupList, TldRules, MAX_PAGE_LIMIT,
};

/// A `TLD`-shaped timestamp string, valid in every month.
fn timestamps() -> impl Strategy<Value = Timestamp> {
    (2000u16..2100, 1u8..13, 1u8..29, 0u8..24, 0u8..60, 0u8..60).prop_map(
        |(year, month, day, hour, minute, second)| {
            Timestamp::parse(&format!(
                "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"
            ))
            .unwrap()
        },
    )
}

/// Arbitrary JSON, shallow enough to stay cheap and deep enough to reach the
/// nested shapes the diagnostics answers can take.
fn json_values() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        any::<f64>().prop_map(Value::from),
        "\\PC{0,12}".prop_map(Value::String),
    ];
    let keys = "[A-Za-z_][A-Za-z0-9_]{0,8}";
    leaf.prop_recursive(3, 24, 4, move |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            proptest::collection::vec((keys, inner), 0..4).prop_map(|entries| {
                let mut map = serde_json::Map::new();
                for (key, value) in entries {
                    map.insert(key, value);
                }
                Value::Object(map)
            }),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// `with_page` accepts exactly pages from 1 and limits up to
    /// `MAX_PAGE_LIMIT`, and rejects everything else without panicking.
    #[test]
    fn log_pages_follow_the_documented_window(
        page in 0u32..(MAX_PAGE_LIMIT + 2),
        limit in 0u32..(MAX_PAGE_LIMIT + 2),
    ) {
        let query = DomainLogQuery::new(DomainName::parse("example.com").unwrap());
        let accepted = page >= 1 && (1..=MAX_PAGE_LIMIT).contains(&limit);
        let built = query.with_page(page, limit);
        prop_assert_eq!(built.is_ok(), accepted);
        if let Ok(built) = built {
            let params = built.params();
            prop_assert_eq!(params["page"].as_u64(), Some(u64::from(page)));
            prop_assert_eq!(params["pagelimit"].as_u64(), Some(u64::from(limit)));
            prop_assert_eq!(params["domain"].as_str(), Some("example.com"));
        }
    }

    /// A range is accepted exactly when it spans at least one second.
    #[test]
    fn log_ranges_need_a_positive_span(
        from in timestamps(),
        to in timestamps(),
    ) {
        let query = DomainLogQuery::new(DomainName::parse("example.com").unwrap());
        let accepted = to.as_str() > from.as_str();
        let built = query.with_range(from.clone(), to.clone());
        prop_assert_eq!(built.is_ok(), accepted);
        if let Ok(built) = built {
            let params = built.params();
            prop_assert_eq!(params["dateFrom"].as_str(), Some(from.as_str()));
            prop_assert_eq!(params["dateTo"].as_str(), Some(to.as_str()));
        }
    }

    /// Every diagnostics decoder survives any payload, and the derived helpers
    /// agree with the fields they read.
    #[test]
    fn diagnostics_decodes_never_panic(payload in json_values()) {
        if let Ok(log) = serde_json::from_value::<DomainLog>(payload.clone()) {
            prop_assert_eq!(log.len(), log.entries.len());
            prop_assert_eq!(log.is_empty(), log.entries.is_empty());
            prop_assert_eq!(
                log.has_more(),
                log.count.is_some_and(|count| i64::try_from(log.len()).unwrap_or(i64::MAX) < count)
            );
            for entry in &log.entries {
                let _ = entry.occurred_at();
            }
        }
        if let Ok(stats) = serde_json::from_value::<DomainStats>(payload.clone()) {
            prop_assert_eq!(stats.len(), stats.stats.len());
            prop_assert_eq!(stats.is_empty(), stats.stats.is_empty());
            if let Some(name) = stats.stats.first().and_then(|stat| stat.name.as_deref()) {
                prop_assert!(stats.find(name).is_some());
            }
            for stat in &stats.stats {
                let _ = (stat.count, stat.amount, &stat.text);
            }
        }
        if let Ok(rules) = serde_json::from_value::<TldRules>(payload.clone()) {
            prop_assert_eq!(rules.len(), rules.rules.len());
            prop_assert_eq!(rules.is_empty(), rules.rules.is_empty());
            if let Some(name) = rules.rules.first().and_then(|rule| rule.name.as_deref()) {
                prop_assert!(rules.find(name).is_some());
            }
            for rule in &rules.rules {
                let _ = (rule.integer(), rule.number(), rule.flag());
            }
        }
        if let Ok(groups) = serde_json::from_value::<TldGroupList>(payload.clone()) {
            prop_assert_eq!(groups.len(), groups.groups.len());
            prop_assert_eq!(groups.is_empty(), groups.groups.is_empty());
            if let Some(name) = groups.groups.first().and_then(|group| group.name.as_deref()) {
                prop_assert!(groups.find(name).is_some());
            }
            for group in &groups.groups {
                prop_assert_eq!(group.tld_count(), group.tlds.len());
                prop_assert_eq!(group.is_empty(), group.tlds.is_empty());
                if let Some(tld) = group.tlds.first() {
                    prop_assert!(group.contains(tld));
                }
            }
        }
        // The single-entry shapes only have to not panic.
        let _ = serde_json::from_value::<DomainLogEntry>(payload.clone());
        let _ = serde_json::from_value::<DomainStat>(payload.clone());
        let _ = serde_json::from_value::<DomainRule>(payload.clone());
        let _ = serde_json::from_value::<TldGroup>(payload);
    }

    /// A decoded entry keeps whatever date text arrived, and only converts a
    /// well-formed one to a timestamp.
    #[test]
    fn log_entry_dates_stay_verbatim(date in "\\PC{0,25}") {
        let entry: DomainLogEntry =
            serde_json::from_value(serde_json::json!({ "date": date.clone() })).unwrap();
        prop_assert_eq!(entry.date.as_deref(), Some(date.as_str()));
        prop_assert_eq!(
            entry.occurred_at().is_some(),
            Timestamp::parse(&date).is_ok()
        );
    }

    /// News dates accept exactly the two documented layouts and render back in
    /// the same shape they parsed.
    #[test]
    fn news_dates_round_trip_both_documented_layouts(
        year in 1i32..=9999,
        month in 1u8..=12,
        day in 1u8..=31,
        hour in 0u8..=23,
        minute in 0u8..=59,
        second in 0u8..=59,
    ) {
        let month = time::Month::try_from(month).unwrap();
        let Ok(date) = time::Date::from_calendar_date(year, month, day) else {
            return Ok(());
        };
        let day = date.to_string();
        let day_date = NewsDate::parse(&day).unwrap();
        prop_assert!(!day_date.has_time());
        prop_assert_eq!(day_date.to_string(), day.clone());
        prop_assert_eq!(serde_json::from_str::<NewsDate>(&format!("{day:?}")).unwrap(), day_date);

        let at = format!("{day} {hour:02}:{minute:02}:{second:02}");
        let at_date = NewsDate::parse(&at).unwrap();
        prop_assert!(at_date.has_time());
        prop_assert_eq!(at_date.to_string(), at.clone());
        prop_assert_eq!(serde_json::from_str::<NewsDate>(&format!("{at:?}")).unwrap(), at_date);
        prop_assert!(day_date < at_date);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The paging limits accept exactly `1..=MAX_*` and nothing else, so the
    /// boundary pair is covered for every value near the edge.
    #[test]
    fn pagination_limits_accept_exactly_their_range(
        page_size in 0u32..=MAX_PAGE_SIZE + 1,
        max_pages in 0u32..=MAX_PAGES + 1,
        max_items in 0usize..=MAX_ITEMS + 1,
    ) {
        prop_assert_eq!(
            Pagination::new().with_page_size(page_size).is_ok(),
            (1..=MAX_PAGE_SIZE).contains(&page_size)
        );
        prop_assert_eq!(
            Pagination::new().with_max_pages(max_pages).is_ok(),
            (1..=MAX_PAGES).contains(&max_pages)
        );
        prop_assert_eq!(
            Pagination::new().with_max_items(max_items).is_ok(),
            (1..=MAX_ITEMS).contains(&max_items)
        );
        if let Ok(pagination) = Pagination::new().with_page_size(page_size) {
            prop_assert_eq!(pagination.page_size(), page_size);
        }
        if let Ok(pagination) = Pagination::new().with_max_items(max_items) {
            prop_assert_eq!(pagination.max_items(), Some(max_items));
        }
    }

    /// A walk owns the cursor: whatever the query asked for, the parameters of
    /// a page carry the walker's page and page size, and keep the filter.
    #[test]
    fn a_page_carries_the_cursor_and_keeps_the_filter(
        page in 1u32..u32::MAX,
        page_size in 1u32..=MAX_PAGE_SIZE,
        filter in "[a-z0-9.*-]{0,30}",
    ) {
        let listing = DomainListing::new(DomainListQuery::new().with_filter(filter.clone()));
        let params = listing.params(page, page_size);
        prop_assert_eq!(params["page"].as_u64().unwrap(), u64::from(page));
        prop_assert_eq!(params["pagelimit"].as_u64().unwrap(), u64::from(page_size));
        prop_assert_eq!(params["domain"][0].as_str().unwrap(), filter.as_str());

        let listing = ContactListing::new(ContactQuery::new().with_search(filter.clone()));
        let params = listing.params(page, page_size);
        prop_assert_eq!(params["page"].as_u64().unwrap(), u64::from(page));
        prop_assert_eq!(params["search"].as_str().unwrap(), filter);
    }

    /// A zone filter is refused exactly when it is empty after trimming, so a
    /// walk never sends an empty `domain`.
    #[test]
    fn a_zone_filter_is_refused_exactly_when_empty(filter in "[a-z*.-]{0,20} {0,3}") {
        let blank = filter.trim().is_empty();
        prop_assert_eq!(ZoneListing::with_filter(&filter).is_ok(), !blank);
        if let Ok(listing) = ZoneListing::with_filter(&filter) {
            prop_assert_eq!(listing.filter(), Some(filter.trim()));
            let params = listing.params(3, 7);
            prop_assert_eq!(params["domain"].as_str().unwrap(), filter.trim());
            prop_assert_eq!(params["wide"].as_u64().unwrap(), 1);
            prop_assert_eq!(params["page"].as_u64().unwrap(), 3);
        }
    }
    /// A zone page claims more exactly when the reported total exceeds the
    /// number of zones on it, and never when the answer carries no `count`.
    #[test]
    fn a_zone_page_has_more_exactly_when_the_count_is_higher(
        len in 0usize..=200,
        count in proptest::option::of(0i64..=200),
    ) {
        let zones: Vec<Value> = (0..len)
            .map(|n| serde_json::json!({ "domain": format!("z{n}.de") }))
            .collect();
        let mut payload = serde_json::json!({ "domains": zones });
        if let Some(count) = count {
            payload["count"] = serde_json::json!(count);
        }
        let page: ZoneListPage = serde_json::from_value(payload)?;

        prop_assert_eq!(page.len(), len);
        prop_assert_eq!(page.is_empty(), len == 0);
        prop_assert_eq!(
            page.has_more(),
            count.is_some_and(|count| i64::try_from(len).unwrap() < count)
        );
    }
}

// ------------------------------------- transfer lock and auth codes (#60)

use inwx_client::{AuthInfoUpdate, DomainControlResult, TransferCodeUpdate, MAX_AUTH_CODE_LEN};

/// A code the validator accepts: printable ASCII, so never empty after trimming
/// and never carrying whitespace or a control character. Every value starts
/// with a marker that cannot occur in a redacted rendering, so the leak
/// assertions cannot pass by accident.
fn marked_code_text() -> impl Strategy<Value = String> {
    "[\\x21-\\x7e]{1,40}".prop_map(|suffix| format!("secret{suffix}"))
}

/// The four transfer/lock commands added for #60.
fn control_method() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("domain.setAuthInfo"),
        Just("domain.setDomainTransferCode"),
        Just("domain.block"),
        Just("domain.unblock"),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The auth-code check is a predicate, not a panic: for any input at all it
    /// either accepts the trimmed value or refuses it with a validation error
    /// that never quotes a long code back.
    #[test]
    fn auth_code_validation_is_total_and_exact(input in arbitrary()) {
        let trimmed = input.trim();
        let expected = !trimmed.is_empty()
            && trimmed.len() <= MAX_AUTH_CODE_LEN
            && trimmed.is_ascii()
            && !trimmed.chars().any(|c| c.is_whitespace() || c.is_control());
        let outcome = AuthCode::new(&input);
        prop_assert_eq!(outcome.is_ok(), expected);
        if let Err(error) = outcome {
            prop_assert!(error.is_validation());
            let quoted = error.to_string();
            prop_assert!(!quoted.contains(trimmed) || trimmed.len() < 3);
        }
    }

    /// An accepted code survives validation twice, and no rendering of it
    /// besides `as_str` carries the value.
    #[test]
    fn accepted_auth_codes_round_trip_and_stay_redacted(raw in marked_code_text()) {
        let code = AuthCode::new(&raw).unwrap();
        prop_assert_eq!(code.as_str(), raw.as_str());
        prop_assert_eq!(format!("{code:?}"), "AuthCode(<redacted>)");
        prop_assert_eq!(code.to_string(), "<redacted>");
        // The wire form carries the real code; parsing it back proves the
        // value was written verbatim, escaping included.
        let wire = serde_json::to_string(&code).unwrap();
        let parsed = serde_json::from_str::<Value>(&wire).unwrap();
        prop_assert_eq!(parsed, Value::String(raw));
        let again = AuthCode::new(code.as_str()).unwrap();
        prop_assert_eq!(again, code);
    }

    /// Boundary pair for the cap: the last accepted length and the first
    /// rejected one, walked up from the limit.
    #[test]
    fn auth_code_cap_is_exact(extra in 0usize..4) {
        let inside = "x".repeat(MAX_AUTH_CODE_LEN - extra);
        let outside = "x".repeat(MAX_AUTH_CODE_LEN + 1 + extra);
        prop_assert_eq!(inside.len(), MAX_AUTH_CODE_LEN - extra);
        prop_assert!(AuthCode::new(&inside).is_ok());
        let error = AuthCode::new(&outside).unwrap_err();
        prop_assert!(error.is_validation());
        prop_assert!(error.to_string().contains("at most"));
    }

    /// Both request builders send exactly the domain and the code, and keep the
    /// code out of `Debug`.
    #[test]
    fn control_requests_send_domain_and_code_only(
        label in "[a-z]{1,10}",
        raw in marked_code_text(),
    ) {
        let name = DomainName::parse(&format!("{label}.com")).unwrap();
        let code = AuthCode::new(&raw).unwrap();

        let auth = AuthInfoUpdate::new(name.clone(), code.clone());
        let auth_params = auth.params();
        prop_assert_eq!(auth_params["domain"].as_str().unwrap(), name.as_str());
        prop_assert_eq!(auth_params["authCode"].as_str().unwrap(), raw.as_str());
        prop_assert_eq!(auth_params.as_object().map(serde_json::Map::len), Some(2));
        let auth_debug = format!("{auth:?}");
        prop_assert!(!auth_debug.contains(&raw));

        let transfer = TransferCodeUpdate::new(name, code);
        let transfer_params = transfer.params();
        prop_assert_eq!(transfer_params["authCode"].as_str().unwrap(), raw.as_str());
        prop_assert_eq!(
            transfer_params.as_object().map(serde_json::Map::len),
            Some(2)
        );
        let transfer_debug = format!("{transfer:?}");
        prop_assert!(!transfer_debug.contains(&raw));
    }

    /// The four controls are mutations: never read-only, whatever the case or
    /// the padding, and their one-character-shorter prefixes are not either.
    #[test]
    fn transfer_controls_are_never_read_only(
        name in control_method(),
        lead in padding(),
        trail in padding(),
    ) {
        prop_assert!(!is_read_only_method(name));
        prop_assert!(!is_read_only_method(&name.to_uppercase()));
        let padded = format!("{lead}{name}{trail}");
        prop_assert!(!is_read_only_method(&padded));
        prop_assert!(!is_read_only_method(&name[..name.len() - 1]));
        // The read-only neighbour in the same namespace stays readable.
        prop_assert!(is_read_only_method("domain.info"));
    }

    /// The acknowledgement decoder is total: any payload yields a value or an
    /// error, never a panic, and an echoed code stays behind the redaction.
    #[test]
    fn control_answers_decode_without_panic(
        bytes in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        if let Ok(payload) = serde_json::from_str::<Value>(&String::from_utf8_lossy(&bytes)) {
            if let Ok(ack) = serde_json::from_value::<DomainControlResult>(payload.clone()) {
                let debug = format!("{ack:?}");
                if let Some(code) = ack.auth_code {
                    prop_assert!(debug.contains("AuthCode(<redacted>)"));
                    prop_assert_eq!(code.to_string(), "<redacted>");
                }
            }
            let _ = serde_json::from_value::<Vec<DomainControlResult>>(payload);
        }
    }
}

// ------------------------------------------------------- mailbox poll (#137)

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// `messageId` is the key `Message` documents, so a flat poll answer spelled
    /// that way must arrive — and every documented shape has to decode to the
    /// same message id, whatever the spelling.
    #[test]
    fn a_polled_message_keeps_its_id_in_every_documented_shape(
        id in 1i64..i64::MAX,
        title in any_text(),
    ) {
        let shapes = [
            serde_json::json!({ "count": 1, "messageId": id, "title": title.clone() }),
            serde_json::json!({ "count": 1, "id": id, "title": title.clone() }),
            serde_json::json!({ "message": { "messageId": id, "title": title.clone() } }),
            serde_json::json!({
                "count": 1,
                "messageId": id,
                "message": { "messageId": id, "title": title.clone() },
            }),
        ];
        for payload in shapes {
            let polled: PolledMessage = serde_json::from_value(payload.clone())
                .map_err(|error| TestCaseError::fail(format!("{payload}: {error}")))?;
            prop_assert_eq!(polled.message_id().ok(), Some(id));
        }
    }

    /// A count that promises a message never turns into an empty mailbox: with
    /// no key that names a message the answer is refused, whatever unknown keys
    /// travel beside it.
    #[test]
    fn a_counted_poll_answer_is_refused_instead_of_empty(
        count in 1i64..10_000,
        extra in proptest::collection::vec("[a-z]{0,6}", 0..4),
    ) {
        let mut data = serde_json::Map::new();
        data.insert("count".to_owned(), serde_json::json!(count));
        for key in extra {
            data.insert(format!("xUnknown{key}"), serde_json::json!("x"));
        }
        let refused = serde_json::from_value::<PolledMessage>(Value::Object(data));
        prop_assert!(refused.is_err(), "count {count} decoded to {refused:?}");

        // Just outside: the same shape with nothing waiting is an empty mailbox.
        let empty = serde_json::from_value::<PolledMessage>(serde_json::json!({ "count": 0 }))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert!(empty.message.is_none());
        prop_assert!(empty.message_id().is_err());
    }
}

// --------------------------------------------- 0.2.0 contact field validators

mod contact_fields {
    use inwx_client::{ContactRequest, ContactType, ContactUpdate, Email};
    use proptest::prelude::*;

    /// A complete handle with the country and the address under test.
    fn handle(address: &str, country: &str) -> ContactRequest {
        ContactRequest::new(ContactType::Person, "Erika", address)
            .expect("the fixed address is valid")
            .with_street("Weg 2")
            .with_city("Berlin")
            .with_postcode("10115")
            .with_country(country)
            .with_voice("+49.891")
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// The address that is checked is the address that is sent: whatever
        /// padding surrounds the value never reaches the payload.
        #[test]
        fn a_contact_address_is_sent_trimmed(
            local in "[A-Za-z0-9._%+-]{1,20}",
            label in "[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?",
            pad_left in " {0,3}",
            pad_right in " {0,3}",
        ) {
            // `xn--` begins an A-label; a random one is not valid punycode.
            prop_assume!(!label.starts_with("xn--"));
            let address = format!("{local}@{label}.example.com");
            let padded = format!("{pad_left}{address}{pad_right}");
            let request = handle(&padded, "DE");
            let params = request.params();
            prop_assert_eq!(params["email"].as_str(), Some(address.as_str()));
            prop_assert!(request.validate().is_ok());

            let update = ContactUpdate::new(1)
                .expect("a positive handle id")
                .with_email(padded);
            let updated = update.params().expect("a changed field");
            prop_assert_eq!(updated["email"].as_str(), Some(address.as_str()));
        }

        /// `Email` and the contact field agree, and both are fixed points: an
        /// accepted value is accepted again unchanged.
        #[test]
        fn an_accepted_address_survives_a_second_pass(address in "\\PC{0,40}") {
            let Ok(email) = Email::parse(&address) else {
                return Ok(());
            };
            prop_assert_eq!(email.as_str(), address.trim());
            let reparsed = Email::parse(email.as_str());
            prop_assert!(reparsed.is_ok());
            if let Ok(reparsed) = reparsed {
                prop_assert_eq!(reparsed.as_str(), email.as_str());
            }
            prop_assert!(handle(email.as_str(), "DE").validate().is_ok());
        }

        /// The country is an ISO 3166-1 lookup: the same code in either case is
        /// the same country, and an accepted code travels upper-cased.
        #[test]
        fn a_country_code_is_a_table_lookup(code in "[A-Za-z]{2}") {
            let upper = handle("erika@example.com", &code.to_uppercase());
            let lower = handle("erika@example.com", &code.to_lowercase());
            prop_assert_eq!(upper.validate().is_ok(), lower.validate().is_ok());
            if upper.validate().is_ok() {
                let expected = code.to_uppercase();
                let upper_params = upper.params();
                let lower_params = lower.params();
                prop_assert_eq!(upper_params["cc"].as_str(), Some(expected.as_str()));
                prop_assert_eq!(upper_params["cc"].as_str(), lower_params["cc"].as_str());
            }
        }
    }
}

// ------------------------------------------------------ retry jitter (#108)

mod retry_jitter {
    use inwx_client::RetryPolicy;
    use proptest::prelude::*;
    use std::time::Duration;

    // A policy, an attempt and a sample: the jittered wait must stay inside the
    // deterministic ceiling for every combination, including a sample that is
    // `NaN` or infinite.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn a_jittered_wait_never_exceeds_the_ceiling(
            attempt in 0u32..12,
            base_ms in 0u64..2_000,
            max_ms in 0u64..8_000,
            unit in proptest::num::f64::ANY,
        ) {
            let policy = RetryPolicy::new(6)
                .with_base_delay(Duration::from_millis(base_ms))
                .with_max_delay(Duration::from_millis(max_ms));

            let jittered = policy.delay_with_jitter(attempt, unit);
            let ceiling = policy.delay(attempt);
            prop_assert_eq!(jittered.is_some(), ceiling.is_some());

            if let (Some(waited), Some(ceiling)) = (jittered, ceiling) {
                prop_assert!(
                    waited <= ceiling,
                    "unit {unit}: {waited:?} is above {ceiling:?}"
                );
            }
        }

        /// Both ends of the interval are exact whatever the policy: a zero
        /// sample waits not at all, a full sample waits the whole ceiling.
        #[test]
        fn the_ends_of_the_jitter_interval_are_exact(
            attempt in 1u32..6,
            base_ms in 0u64..1_000,
        ) {
            let policy = RetryPolicy::new(6)
                .with_base_delay(Duration::from_millis(base_ms))
                .with_max_delay(Duration::from_secs(30));

            prop_assert_eq!(policy.delay_with_jitter(attempt, 0.0), Some(Duration::ZERO));
            prop_assert_eq!(
                policy.delay_with_jitter(attempt, 1.0),
                policy.delay(attempt)
            );
        }

        /// A larger sample never waits less, so a generator that trends high
        /// cannot silently shorten the backoff.
        #[test]
        fn a_larger_sample_never_waits_less(
            attempt in 1u32..6,
            first in 0u32..1000,
            second in 0u32..1000,
            base_ms in 0u64..1_000,
        ) {
            let policy = RetryPolicy::new(6)
                .with_base_delay(Duration::from_millis(base_ms))
                .with_max_delay(Duration::from_secs(30));

            let (low, high) = if first <= second {
                (first, second)
            } else {
                (second, first)
            };
            let low_wait = policy
                .delay_with_jitter(attempt, f64::from(low) / 1000.0)
                .expect("the attempt is inside the budget");
            let high_wait = policy
                .delay_with_jitter(attempt, f64::from(high) / 1000.0)
                .expect("the attempt is inside the budget");
            prop_assert!(low_wait <= high_wait, "{low} -> {low_wait:?}, {high} -> {high_wait:?}");
        }
    }
}
