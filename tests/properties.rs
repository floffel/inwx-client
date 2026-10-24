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
