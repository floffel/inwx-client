//! Fuzz target: the hand-rolled value parsers in `src/types.rs`.
//!
//! `parse_response` covers the JSON-RPC framing and every typed decode that runs
//! on top of it. This target covers the four parsers that tokenize their input
//! themselves and are reached with plain user input rather than through the
//! envelope:
//!
//! * `Period` — `1M` and `1Y`..`10Y`, a numeric prefix plus a unit suffix;
//! * `RenewalMode` — trims, upper-cases and carries unknown values verbatim;
//! * `ContactType` — same shape, different keywords;
//! * `PriceType` — trims, lower-cases and rejects unknown values.
//!
//! Every byte string is fed to all four parsers, so one seed exercises the accept
//! path of the carry-unknown types and the reject path of the closed ones at the
//! same time. Non-UTF-8 input is converted lossily on purpose: the replacement
//! character is exactly the noise a hand-written tokenizer has to survive, and
//! skipping those bytes would hide half of the interesting input space.
//!
//! Nothing here invents an expectation. Each assertion restates an invariant the
//! parsers document: an accepted value renders to a wire form that parses back
//! unchanged, a rejected value is refused with `Error::Validation` (a parser runs
//! before any request exists, so it has nothing else to report), and the period
//! range is exactly `1M` plus `1Y`..=`10Y`.
//!
//! Run with `cargo +nightly fuzz run parse_types`. The curated seeds — valid
//! values, case variants, empty and whitespace-only input, NUL bytes, invalid
//! UTF-8, unicode whitespace, and the just-outside values `0Y`, `2M`, `4M`, `11Y`
//! — live in `fuzz/corpus/parse_types`; `tests/fuzz_fixtures.rs` replays them
//! with their exact expected outcome, so CI pins behaviour and not merely the
//! absence of a panic. Reproduce one seed with
//! `cargo +nightly fuzz run parse_types fuzz/corpus/parse_types/<file>`.

#![no_main]

use inwx_client::{ContactType, Error, Period, PriceType, RenewalMode};
use libfuzzer_sys::fuzz_target;

/// One parser's contract, applied to one input.
///
/// * accepted → `Display` renders a non-empty wire form, and that wire form
///   parses back to the same wire form, so a value never changes shape between
///   what is sent and what a later response reports about it;
/// * rejected → the error is `Error::Validation` on the documented field. A
///   different variant would mean a parser claiming a network or decoding
///   failure it cannot possibly have seen.
fn check<T, F>(label: &str, expected_field: &'static str, text: &str, parse: F)
where
    T: std::fmt::Debug + std::fmt::Display + PartialEq,
    F: Fn(&str) -> inwx_client::Result<T>,
{
    match parse(text) {
        Ok(value) => {
            let wire = value.to_string();
            assert!(!wire.is_empty(), "{label}: accepted {text:?} and rendered it empty");
            match parse(&wire) {
                Ok(again) => assert_eq!(
                    again, value,
                    "{label}: the wire form {wire:?} (from {text:?}) must parse back to the \
                     same value"
                ),
                Err(error) => panic!("{label}: the wire form {wire:?} is not accepted: {error}"),
            }
        }
        Err(Error::Validation { field, message }) => {
            assert!(
                !message.is_empty(),
                "{label}: a validation error must explain itself"
            );
            assert_eq!(
                field, expected_field,
                "{label}: {text:?} was refused on field {field:?}, expected {expected_field:?} \
                 ({message})"
            );
        }
        Err(error) => panic!(
            "{label}: {text:?} was refused with {error:?}; a parser may only report \
             Error::Validation"
        ),
    }
}

/// `Period` accepts exactly `1M` and `1Y`..=`10Y`. Feeding the input length in as
/// a year count walks that boundary without the fuzzer having to invent numbers:
/// lengths 0, 1 and 10 appear early, 11 and 256 soon after.
fn check_period_range(data: &[u8]) {
    let years = u64::try_from(data.len()).unwrap_or(u64::MAX);
    let text = format!("{years}Y");
    match text.parse::<Period>() {
        Ok(period) => {
            assert_eq!(
                period.to_string(),
                text,
                "{text} must render back exactly as it was written"
            );
            let constructed = Period::years(u8::try_from(years).unwrap_or(u8::MAX))
                .unwrap_or_else(|error| panic!("{text} parsed but does not construct: {error}"));
            assert_eq!(period, constructed, "{text}: parser and constructor must agree");
            assert!(
                (1..=10).contains(&years),
                "{text} is outside the documented period range but was accepted"
            );
        }
        Err(error) => {
            assert!(
                error.is_validation(),
                "{text} must be refused with a validation error, got {error:?}"
            );
            assert!(
                !(1..=10).contains(&years),
                "{text} is inside the documented period range but was refused"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    check("period", "period", &text, str::parse::<Period>);
    check("renewalMode", "renewalMode", &text, str::parse::<RenewalMode>);
    check("contact.type", "contact.type", &text, ContactType::parse);
    check("pricetype", "pricetype", &text, str::parse::<PriceType>);

    check_period_range(data);

    // The wire form is also what the serde impls write, and the two
    // carry-unknown types are read back out of `resData` through theirs. There a
    // rejection surfaces as a serde error by design, so only the accepted
    // direction is asserted — a panic is a bug either way.
    if let Ok(period) = text.parse::<Period>() {
        assert_eq!(
            serde_json::to_value(period).ok(),
            Some(serde_json::Value::String(period.to_string())),
            "period: serde must encode the wire form"
        );
    }
    if let Ok(mode) = text.parse::<RenewalMode>() {
        let wire = mode.to_string();
        let encoded = serde_json::Value::String(wire.clone());
        assert_eq!(serde_json::to_value(&mode).ok(), Some(encoded.clone()));
        assert!(
            serde_json::from_value::<RenewalMode>(encoded).is_ok(),
            "renewalMode: {wire:?} must deserialize"
        );
    }
    if let Ok(kind) = ContactType::parse(&text) {
        let wire = kind.to_string();
        let encoded = serde_json::Value::String(wire.clone());
        assert_eq!(serde_json::to_value(&kind).ok(), Some(encoded.clone()));
        assert!(
            serde_json::from_value::<ContactType>(encoded).is_ok(),
            "contact.type: {wire:?} must deserialize"
        );
    }
    // `PriceType` has no serde impl of its own; it reaches the wire through
    // `as_str`, which is what the params builder uses.
    if let Ok(price_type) = text.parse::<PriceType>() {
        let wire = price_type.as_str();
        assert_eq!(
            wire,
            price_type.to_string(),
            "pricetype: Display and as_str must agree"
        );
        assert!(
            wire.chars().all(|c| c.is_ascii_lowercase()),
            "pricetype: {wire} must be lower-case ASCII"
        );
    }
});
