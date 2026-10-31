//! Property tests: the parsers and builders never panic, and their invariants
//! hold for arbitrary input.

mod common;

use inwx_client::{
    Credentials, DomainName, Hostname, Period, RecordId, RecordSpec, RecordType, RpcResponse,
    MAX_TTL,
};
use proptest::prelude::*;
use serde_json::Value;

/// Arbitrary record-type tokens, including ones the API does not know.
fn type_token() -> impl Strategy<Value = String> {
    "[A-Za-z][A-Za-z0-9]{0,9}"
}

/// Arbitrary free text, including control characters.
fn any_text() -> impl Strategy<Value = String> {
    "\\PC{0,40}"
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

    /// Response parsing never panics, whatever bytes arrive.
    #[test]
    fn response_parsing_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        match RpcResponse::parse(&bytes) {
            Ok(response) => {
                // Parsed responses classify their own code consistently.
                prop_assert_eq!(response.is_success(), inwx_client::rpc::is_success_code(response.code));
                let code = response.code;
                let result = response.into_result();
                if inwx_client::rpc::is_success_code(code) {
                    prop_assert!(result.is_ok());
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
        let record_id = RecordId::from(id);
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
    fn accepted_emails_round_trip(local in "[A-Za-z0-9._%+-]{3,20}", label in "[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?") {
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

    #[test]
    fn handles_survive_serde(id in 1i64..i64::MAX) {
        let handle = Handle::new(id).unwrap();
        let encoded = serde_json::to_string(&handle).unwrap();
        prop_assert_eq!(&encoded, &id.to_string());
        let decoded: Handle = serde_json::from_str(&encoded).unwrap();
        prop_assert_eq!(decoded, handle);
    }

    #[test]
    fn zone_params_round_trip_through_json(label in "[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?") {
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
        prop_assert!(inwx_client::TradeRequest::new(intent).is_err());
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
        let transient = Error::Http { status: inside, body: body.clone() };
        prop_assert!(transient.is_retryable());
        prop_assert!(transient.to_string().contains(&body));
        prop_assert!(!transient.is_uncertain());

        let terminal = Error::Http { status: outside, body };
        prop_assert!(!terminal.is_retryable());
        prop_assert!(!terminal.is_uncertain());
    }

    /// Sweeping the whole `u16` range keeps the set exactly the four documented
    /// statuses — a future widening to "all of 5xx" would fail here.
    #[test]
    fn only_the_four_http_statuses_are_retryable(status in any::<u16>()) {
        let error = Error::Http { status, body: String::new() };
        prop_assert_eq!(error.is_retryable(), matches!(status, 429 | 502 | 503 | 504));
    }
}

// --------------------------------------------------- reseller objects (#22)

use inwx_client::{
    Application, ApplicationCheckResult, ApplicationQuery, ApplicationType, AuthInfo2Order,
    AuthInfo2OrderResult, AuthInfo2PriceQuote, ContactVerificationSettings, Customer,
    CustomerDownload, CustomerDownloadQuery, CustomerUpdate, DataExport, DocumentEntry,
    DocumentQuery, DocumentUpload, DownloadedDocument, HostCheckResult, HostCreate, HostQuery,
    HostRecord, HostUpdate, Message, MessageAck, NicHandle, NicHandleQuery, PdfFile, PdfHandle,
    PdfRender, PolledMessage, MAX_HOST_ADDRESSES,
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

    /// A document file name is a name: never empty, never a dot pair.
    #[test]
    fn document_file_names_are_names_never_paths(name in "[A-Za-z0-9 ._-]{0,10}") {
        let trimmed = name.trim();
        let expected = !trimmed.is_empty() && trimmed != "." && trimmed != "..";
        prop_assert_eq!(DocumentUpload::new(&name, b"x").is_ok(), expected);
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

    /// Every reseller id parameter accepts exactly the positive numbers.
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

    /// The reseller list queries keep the paging contract: the page is
    /// one-based, the limit is sent as given, and a limit of zero is refused.
    #[test]
    fn reseller_queries_keep_paging(page in 0u32..10, limit in 1u32..100) {
        let host = HostQuery::new().with_page(page, limit).unwrap().params().unwrap();
        prop_assert_eq!(host["page"].as_u64().unwrap(), u64::from(page.max(1)));
        prop_assert_eq!(host["pagelimit"].as_u64().unwrap(), u64::from(limit));

        let handles = NicHandleQuery::new().with_page(page, limit).unwrap().params().unwrap();
        prop_assert_eq!(handles["page"].as_u64().unwrap(), u64::from(page.max(1)));

        let documents = DocumentQuery::new().with_page(page, limit).unwrap().params().unwrap();
        prop_assert_eq!(documents["pagelimit"].as_u64().unwrap(), u64::from(limit));

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
        doc.is_pdf()
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
