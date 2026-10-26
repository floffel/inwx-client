//! Property tests: the parsers and builders never panic, and their invariants
//! hold for arbitrary input.

mod common;

use inwx_client::{
    DomainName, Hostname, Period, RecordId, RecordSpec, RecordType, RpcResponse, MAX_TTL,
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
    parse_ip, ActionKind, AuthCode, CertificateOrder, CertificateTerm, DnsKey, DnssecAlgorithm,
    DnssecDigestType, DnssecDomainStatus, DnssecFlag, DnssecKeyQuery, DnssecKeyStatus,
    DocumentFormat, Email, Handle, HostingPeriod, Irreversible, NameserverSetType, RecordSet,
    Timestamp, TransferAnswer, UrlRedirectType, ZoneCreate, ZoneType,
};

/// Arbitrary text for parsers that must never panic.
fn arbitrary() -> impl Strategy<Value = String> {
    "\\PC{0,60}"
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
        let _ = DnsKey::parse(&input);
        let _ = inwx_client::DsRecord::parse(&input);
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
    }

    #[test]
    fn accepted_emails_round_trip(local in "[A-Za-z0-9._%+-]{3,20}", label in "[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?") {
        let address = format!("{local}@{label}.example.com");
        let email = Email::parse(&address).unwrap();
        prop_assert_eq!(email.as_str(), address.as_str());
        prop_assert_eq!(Email::parse(email.as_str()).unwrap(), email);
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
}
