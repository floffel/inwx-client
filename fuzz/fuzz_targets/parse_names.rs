//! Fuzz target: the hand-rolled string parsers.
//!
//! `parse_response` covers the JSON-RPC envelope and the typed decoders that run
//! on top of it. This target covers the parsers that tokenize their input by
//! hand — `DomainName::parse`, `Hostname::parse` and the record surface
//! (`RecordSpec::new` with its name/content checks, `RecordType::parse`,
//! `RecordId::parse`). Every accepted byte string goes to all of them, and none
//! may panic: an invalid value must be an `Err`, never a crash.
//!
//! Run with `cargo +nightly fuzz run parse_names`. The corpus in
//! `fuzz/corpus/parse_names` seeds it with valid names, unicode/IDN labels, the
//! 63/64-byte label and 253/254-byte name limits, duplicate and trailing dots,
//! NUL bytes, invalid UTF-8 and record payloads; `tests/fuzz_seeds.rs` keeps
//! those fixtures honest in the stable test run.

#![no_main]

use inwx_client::{DomainName, Hostname, RecordId, RecordSpec, RecordType, DEFAULT_TTL};
use libfuzzer_sys::fuzz_target;

/// Feed one candidate string through every string parser in the crate.
///
/// A panic here is a bug in the parser, not a bug in the input.
fn consume(text: &str) {
    // Names: trim, drop one root dot, punycode through `idna`, then the label
    // loop that enforces the length, hyphen and alphabet rules.
    if let Ok(name) = DomainName::parse(text) {
        // The normalised ACE form is a fixed point of the parser, renders
        // unchanged, and is a valid host name as well.
        assert_eq!(DomainName::parse(name.as_str()).ok(), Some(name.clone()));
        assert_eq!(name.to_string(), name.as_str());
        assert!(Hostname::parse(name.as_str()).is_ok());
        assert!(name.as_str().ends_with(name.tld()));
    }
    if let Ok(host) = Hostname::parse(text) {
        assert_eq!(Hostname::parse(host.as_str()).ok(), Some(host.clone()));
        assert_eq!(host.to_string(), host.as_str());
    }

    // `FromStr` and `TryFrom` are aliases of `parse` and must agree with it.
    assert_eq!(
        text.parse::<DomainName>().is_ok(),
        DomainName::try_from(text).is_ok()
    );

    // Record types: known tokens map to a variant, everything else is carried.
    if let Ok(record_type) = RecordType::parse(text) {
        assert_eq!(
            RecordType::parse(record_type.as_str()).ok(),
            Some(record_type.clone())
        );
    }

    // Record ids are a trimmed, bounded, control-free token.
    if let Ok(id) = RecordId::parse(text) {
        assert_eq!(RecordId::parse(id.as_str()).ok(), Some(id.clone()));
        assert_eq!(id.to_string(), id.as_str());
    }

    // Record names are checked independently of the type, so one type is enough
    // to hunt the 253-byte name limit and the whitespace/dot rules.
    check_spec(&RecordType::Txt, text, "@");
    // Content gets the same text at the apex name, so the type-specific shape
    // checks — IPv4, IPv6, host name, quoted `TXT`, free text — actually run
    // instead of being shadowed by a rejected name.
    for record_type in RecordType::ALL {
        check_spec(record_type, "@", text);
    }
}

/// Build one record spec and check what [`RecordSpec::new`] promises.
fn check_spec(record_type: &RecordType, name: &str, content: &str) {
    match RecordSpec::new(record_type.clone(), name, content) {
        Ok(spec) => {
            assert_eq!(&spec.record_type(), record_type);
            assert_eq!(spec.name(), name);
            assert_eq!(spec.content(), content);
            assert_eq!(spec.ttl(), DEFAULT_TTL);
            // `new` validates, so re-validating must agree.
            assert!(spec.validate().is_ok());
        }
        Err(error) => assert!(error.is_validation()),
    }
}

fuzz_target!(|data: &[u8]| {
    // The parsers take `&str`, so invalid UTF-8 is mapped in lossily: every byte
    // string still reaches the tokenizer, and a NUL or a truncated sequence is
    // exercised rather than skipped.
    let candidate = String::from_utf8_lossy(data);
    consume(&candidate);
});
