//! Fuzz target: the JSON-RPC response parser, and every typed decode that runs
//! on top of it, must never panic — whatever bytes arrive from the endpoint.
//!
//! Run with `cargo +nightly fuzz run parse_response` (see the README for the
//! corpus and how to reproduce a crash).

#![no_main]

use inwx_client::{
    Contact, DnsRecord, DomainCheck, DomainInfo, DomainLog, DomainLogEntry, DomainRule, DomainStat,
    DomainStats, RecordType, RpcResponse, TldGroup, TldGroupList, TldRules, ZoneInfo,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The framing layer: any byte string either parses or returns a Json error.
    let Ok(response) = RpcResponse::parse(data) else {
        return;
    };

    // Classification and rendering are pure and must not panic.
    let _ = response.is_success();
    let _ = response.is_authentication();
    let _ = response.error_message();

    // Every typed decoder this crate runs on `resData` gets the same payload.
    if let Some(payload) = response.res_data.clone() {
        let _ = serde_json::from_value::<DnsRecord>(payload.clone());
        let _ = serde_json::from_value::<ZoneInfo>(payload.clone());
        let _ = serde_json::from_value::<DomainInfo>(payload.clone());
        let _ = serde_json::from_value::<DomainCheck>(payload.clone());
        let _ = serde_json::from_value::<Contact>(payload.clone());
        let _ = serde_json::from_value::<Vec<DnsRecord>>(payload.clone());
        // The diagnostics reads (issue #14) answer with a list, an indexed map
        // or a flat object, so all three shapes reach the same decoder.
        let _ = serde_json::from_value::<DomainLog>(payload.clone());
        let _ = serde_json::from_value::<DomainLogEntry>(payload.clone());
        let _ = serde_json::from_value::<DomainStats>(payload.clone());
        let _ = serde_json::from_value::<DomainStat>(payload.clone());
        let _ = serde_json::from_value::<TldRules>(payload.clone());
        let _ = serde_json::from_value::<DomainRule>(payload.clone());
        let _ = serde_json::from_value::<TldGroupList>(payload.clone());
        let _ = serde_json::from_value::<TldGroup>(payload.clone());
        // The lookups over those decoded answers are pure and must not panic
        // either, whatever key arrives.
        for key in ["", "de", "totalDomains", "MIN-PERIOD", "\u{0}"] {
            if let Ok(stats) = serde_json::from_value::<DomainStats>(payload.clone()) {
                let _ = (
                    stats.find(key),
                    stats.counter(key),
                    stats.amount_for(key),
                    stats.text_for(key),
                );
            }
            if let Ok(rules) = serde_json::from_value::<TldRules>(payload.clone()) {
                let _ = (
                    rules.find(key),
                    rules.value_for(key),
                    rules.integer_for(key),
                );
            }
            if let Ok(groups) = serde_json::from_value::<TldGroupList>(payload.clone()) {
                let _ = groups.find(key);
            }
            if let Ok(group) = serde_json::from_value::<TldGroup>(payload.clone()) {
                let _ = group.contains(key);
            }
        }
        // A `domain.check` answer may be a single object or an array.
        if let Some(entries) = payload.get("domain").and_then(|value| value.as_array()) {
            for entry in entries {
                let _ = serde_json::from_value::<DomainCheck>(entry.clone());
            }
        }
    }

    // Error conversion must not panic either, and success codes must agree with
    // `is_success`.
    let code = response.code;
    let result = response.into_result();
    debug_assert_eq!(result.is_ok(), inwx_client::rpc::is_success_code(code));

    // Record types are parsed from user input, so feed them the same bytes.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = RecordType::parse(text);
    }
});
