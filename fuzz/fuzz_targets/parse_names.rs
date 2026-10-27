//! Fuzz target: the hand-rolled string parsers must never panic, and must
//! never claim to have normalised something they did not.
//!
//! `parse_response` covers the JSON-RPC envelope. This target covers the
//! parsers that tokenise user input by hand: `DomainName::parse` and
//! `Hostname::parse` (labels, punycode, the length limits) and the record
//! surface (`RecordSpec` name/content/TTL validation, `RecordId`, `RecordType`).
//!
//! Seeds live in `fuzz/corpus/parse_names/`. `tests/fuzz_seeds.rs` replays them
//! on the stable toolchain, so a seed regression shows up in `cargo test` and
//! not only in a nightly fuzz run.
//!
//! Run with `cargo +nightly fuzz run parse_names`.

#![no_main]

use inwx_client::{
    DomainName, Error, Hostname, RecordId, RecordSpec, RecordType, DEFAULT_TTL, MAX_DOMAIN_LEN,
    MAX_LABEL_LEN, MAX_TTL,
};
use libfuzzer_sys::fuzz_target;

/// Longest legal record id, mirroring the limit inside `RecordId::parse`.
const MAX_RECORD_ID_LEN: usize = 64;

/// Separates the fields of a record fixture, so one input carries
/// `name \0 content \0 ttl`.
const FIELD_SEPARATOR: char = '\u{0}';

/// The record types whose content validators differ. `MX`, `NS`, `PTR`, `SRV`
/// and `ALIAS` share the host-name path of `CNAME` and add no coverage here.
const CONTENT_PROBES: [RecordType; 5] = [
    RecordType::A,
    RecordType::Aaaa,
    RecordType::Txt,
    RecordType::Cname,
    RecordType::Url,
];

fuzz_target!(|data: &[u8]| {
    // Lossy on purpose: requiring valid UTF-8 would discard nearly every raw
    // byte mutation libFuzzer produces, and NUL bytes are exactly what the
    // label and field splitters have to survive.
    let text = String::from_utf8_lossy(data);
    check_domain_name(&text);
    check_hostname(&text);
    check_record_type(&text);
    check_record_id(&text);
    check_record_specs(&text);
});

// ------------------------------------------------------------------ names --

/// `DomainName::parse` either normalises or rejects, and its output obeys the
/// documented shape.
fn check_domain_name(text: &str) {
    match DomainName::parse(text) {
        Ok(domain) => {
            let ascii = domain.as_str();
            assert_normalised("DomainName", ascii, true);
            if domain.to_string() != ascii || domain.as_ref() != ascii {
                panic!("the DomainName accessors disagree about {ascii:?}");
            }
            if domain.tld().is_empty() || domain.sld().is_empty() {
                panic!("an accepted domain must have a TLD and a SLD: {ascii:?}");
            }
            // A host name is a domain name without the TLD requirement, so the
            // looser parser must accept what the stricter one produced.
            match Hostname::parse(ascii) {
                Ok(host) if host.as_str() == ascii => {}
                Ok(host) => panic!("Hostname normalised {ascii:?} into {host}"),
                Err(error) => panic!("Hostname rejected its own domain form {ascii:?}: {error}"),
            }
            // Normalisation is a fixed point.
            match DomainName::parse(ascii) {
                Ok(again) if again == domain => {}
                Ok(again) => panic!("DomainName::parse is not a fixed point: {ascii:?} -> {again}"),
                Err(error) => panic!("DomainName rejected its own output {ascii:?}: {error}"),
            }
            assert_domain_serde(&domain);
        }
        Err(error) => assert_validation("DomainName::parse", text, &error),
    }
}

/// `Hostname::parse` on its own, including the single-label case a domain
/// rejects.
fn check_hostname(text: &str) {
    match Hostname::parse(text) {
        Ok(host) => {
            let ascii = host.as_str();
            assert_normalised("Hostname", ascii, false);
            if host.to_string() != ascii || host.as_ref() != ascii {
                panic!("the Hostname accessors disagree about {ascii:?}");
            }
            match Hostname::parse(ascii) {
                Ok(again) if again == host => {}
                Ok(again) => panic!("Hostname::parse is not a fixed point: {ascii:?} -> {again}"),
                Err(error) => panic!("Hostname rejected its own output {ascii:?}: {error}"),
            }
            assert_hostname_serde(&host);
        }
        Err(error) => assert_validation("Hostname::parse", text, &error),
    }
}

/// The shape both name parsers promise for accepted input.
fn assert_normalised(parser: &str, ascii: &str, require_dot: bool) {
    if ascii.is_empty() || ascii.len() > MAX_DOMAIN_LEN {
        panic!(
            "{parser} accepted a name of {} bytes: {ascii:?}",
            ascii.len()
        );
    }
    let allowed = ascii.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
    });
    if !allowed {
        panic!("{parser} left a character outside [a-z0-9-.] in {ascii:?}");
    }
    if ascii.starts_with('.') || ascii.ends_with('.') || ascii.contains("..") {
        panic!("{parser} kept an empty or root dot in {ascii:?}");
    }
    let labels = ascii.split('.').collect::<Vec<_>>();
    if require_dot && labels.len() < 2 {
        panic!("{parser} accepted a name without a TLD: {ascii:?}");
    }
    for label in labels {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            panic!(
                "{parser} accepted a label of {} bytes: {ascii:?}",
                label.len()
            );
        }
        if label.starts_with('-') || label.ends_with('-') {
            panic!("{parser} accepted the hyphen edges of label {label:?}");
        }
    }
}

/// A serialised name must decode back to the same value: decoding runs the very
/// same parser, so a name that survived validation must survive the round trip.
fn assert_domain_serde(domain: &DomainName) {
    let encoded = match serde_json::to_string(domain) {
        Ok(encoded) => encoded,
        Err(error) => panic!("DomainName could not be serialised: {error}"),
    };
    let decoded: DomainName = match serde_json::from_str(&encoded) {
        Ok(decoded) => decoded,
        Err(error) => panic!("DomainName decoding rejected its own form {encoded:?}: {error}"),
    };
    if &decoded != domain {
        panic!("the DomainName serde round trip changed {domain} into {decoded}");
    }
}

/// The same round trip for host names.
fn assert_hostname_serde(host: &Hostname) {
    let encoded = match serde_json::to_string(host) {
        Ok(encoded) => encoded,
        Err(error) => panic!("Hostname could not be serialised: {error}"),
    };
    let decoded: Hostname = match serde_json::from_str(&encoded) {
        Ok(decoded) => decoded,
        Err(error) => panic!("Hostname decoding rejected its own form {encoded:?}: {error}"),
    };
    if &decoded != host {
        panic!("the Hostname serde round trip changed {host} into {decoded}");
    }
}

// ---------------------------------------------------------------- records --

/// The record-type tokeniser: unknown names are carried upper-cased, never
/// rejected (except when empty).
fn check_record_type(text: &str) {
    match RecordType::parse(text) {
        Ok(kind) => {
            let expected = text.trim().to_ascii_uppercase();
            if kind.as_str() != expected {
                panic!("RecordType::parse did not upper-case {text:?}, it produced {kind}");
            }
            match RecordType::parse(kind.as_str()) {
                Ok(again) if again == kind => {}
                Ok(again) => panic!("RecordType::parse is not a fixed point: {kind} -> {again}"),
                Err(error) => panic!("RecordType::parse rejected its own output {kind}: {error}"),
            }
        }
        Err(error) => assert_validation("RecordType::parse", text, &error),
    }
}

/// The record-id tokeniser: trim, length bound, no control characters.
fn check_record_id(text: &str) {
    match RecordId::parse(text) {
        Ok(id) => {
            let token = id.as_str();
            if token != text.trim() {
                panic!(
                    "RecordId::parse did not trim {text:?} down to {:?}",
                    text.trim()
                );
            }
            if token.is_empty() || token.len() > MAX_RECORD_ID_LEN {
                panic!("RecordId::parse accepted an id of {} bytes", token.len());
            }
            if token.chars().any(char::is_control) {
                panic!("RecordId::parse kept control characters: {token:?}");
            }
        }
        Err(error) => assert_validation("RecordId::parse", text, &error),
    }
}

/// Record specs, reached the way a zone line reaches them: one input carries the
/// relative name, the content and the TTL token.
fn check_record_specs(text: &str) {
    let mut fields = text.split(FIELD_SEPARATOR);
    let first = fields.next().unwrap_or("");
    let second = fields.next().unwrap_or("");
    let ttl = fields.next().unwrap_or("");

    // The name validator is type independent, so two types are enough to reach
    // it; `Other` additionally carries the fuzzed token itself.
    check_spec(&RecordType::Txt, first, "203.0.113.7", ttl);
    check_spec(
        &RecordType::Other(first.to_owned()),
        first,
        "203.0.113.7",
        ttl,
    );

    // The content validator branches on the type. The first field doubles as
    // content, so a single-token mutation reaches it without the fuzzer having
    // to invent a separator first.
    for probe in &CONTENT_PROBES {
        check_spec(probe, "@", first, ttl);
    }
    check_spec(&RecordType::Other(first.to_owned()), "@", first, ttl);

    // With a separator present the three fields are independent, so every
    // documented type gets the full triple.
    if text.contains(FIELD_SEPARATOR) {
        for record_type in RecordType::ALL {
            check_spec(record_type, first, second, ttl);
        }
    }
}

/// One `RecordSpec` construction: either a validation error, or a spec that
/// keeps its inputs and agrees with its own `validate`, `params` and TTL bound.
fn check_spec(record_type: &RecordType, name: &str, content: &str, ttl: &str) {
    match RecordSpec::new(record_type.clone(), name, content) {
        Err(error) => assert_validation("RecordSpec::new", content, &error),
        Ok(spec) => check_accepted_spec(record_type, name, content, ttl, spec),
    }
}

/// The invariants of an accepted record spec.
fn check_accepted_spec(
    record_type: &RecordType,
    name: &str,
    content: &str,
    ttl: &str,
    spec: RecordSpec,
) {
    if spec.name() != name || spec.content() != content {
        panic!(
            "RecordSpec rewrote its input: {:?}/{:?} became {:?}/{:?}",
            name,
            content,
            spec.name(),
            spec.content()
        );
    }
    if spec.record_type() != *record_type {
        panic!(
            "RecordSpec changed the type {record_type} into {}",
            spec.record_type()
        );
    }
    if spec.ttl() != DEFAULT_TTL {
        panic!(
            "a fresh RecordSpec must carry the default TTL, got {}",
            spec.ttl()
        );
    }
    if let Err(error) = spec.validate() {
        panic!("RecordSpec::new accepted a {record_type} record that validate() rejects: {error}");
    }
    let params = spec.params();
    if params["name"].as_str() != Some(name)
        || params["type"].as_str() != Some(record_type.as_str())
        || params["ttl"].as_u64() != Some(u64::from(DEFAULT_TTL))
    {
        panic!("RecordSpec::params rendered {params} for {record_type}/{name:?}");
    }

    // The TTL ceiling is `i32::MAX`; the fuzzed token drives that boundary.
    if let Ok(parsed) = ttl.trim().parse::<u32>() {
        let accepted = spec.with_ttl(parsed).is_ok();
        if accepted != (parsed <= MAX_TTL) {
            panic!("with_ttl({parsed}) disagreed with the documented ceiling {MAX_TTL}");
        }
    }
}

// ----------------------------------------------------------------- errors --

/// A parser that refuses input refuses it with a typed validation error; a
/// transport or API error leaking out of a pure parser is a bug.
fn assert_validation(parser: &str, input: &str, error: &Error) {
    if !error.is_validation() {
        panic!("{parser} rejected {input:?} with a non-validation error: {error}");
    }
}
