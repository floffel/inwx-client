//! Replay of the curated `parse_types` fuzz corpus.
//!
//! `fuzz/fuzz_targets/parse_types.rs` asserts "never panics, only validation
//! errors" for arbitrary bytes. That is not enough for CI: a parser can start
//! accepting `11Y`, or stop trimming unicode whitespace, without ever panicking.
//! So every seed in `fuzz/corpus/parse_types` is replayed here against its exact
//! expected outcome — the canonical wire form it must produce, or the field of
//! the `Error::Validation` it must be refused with.
//!
//! Each seed is fed to all four parsers (`Period`, `RenewalMode`, `ContactType`,
//! `PriceType`), exactly like the fuzz target does, and non-UTF-8 seeds are
//! converted lossily so the bytes still reach the parsers.
//!
//! Adding a seed therefore needs a row in the seed tables below. Curated seeds are
//! named `<subject>_<detail>.txt` (or `.bin` for byte strings that are not valid
//! UTF-8); the test that enforces this ignores extension-less files, which is how
//! libFuzzer names the inputs it discovers on its own.

use std::fs;
use std::path::Path;

use inwx_client::{ContactType, Error, Period, PriceType, RenewalMode};
use proptest::prelude::*;

/// The seeds that feed the fuzz target.
const CORPUS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus/parse_types");
/// The target they feed, checked for wiring below.
const FUZZ_TARGET: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fuzz/fuzz_targets/parse_types.rs"
);
/// The fuzz workspace that declares the target as a binary.
const FUZZ_MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/Cargo.toml");

/// What one parser must do with one seed.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    /// Accepted; holds the canonical wire form `Display` renders.
    Wire(String),
    /// Refused with `Error::Validation { field, .. }`.
    Invalid(&'static str),
}

/// An accepted seed, with the wire form it must render to.
fn ok(wire: &str) -> Outcome {
    Outcome::Wire(wire.to_owned())
}

/// A refused seed, with the field its validation error must name.
fn bad(field: &'static str) -> Outcome {
    Outcome::Invalid(field)
}

/// Runs one parser and reports what it did, insisting on the error contract: a
/// value parser runs before any request exists, so `Error::Validation` is the
/// only failure it may report — never an API, JSON or transport error, and never
/// something a caller might mistake for a retryable outcome.
fn outcome_of<T, F>(text: &str, parse: F) -> Outcome
where
    F: Fn(&str) -> inwx_client::Result<T>,
    T: std::fmt::Display,
{
    match parse(text) {
        Ok(value) => Outcome::Wire(value.to_string()),
        Err(error) => {
            // Matching on a reference keeps `error` whole for the checks below.
            let field = match &error {
                Error::Validation { field, message } => {
                    assert!(
                        !message.is_empty(),
                        "a validation error must explain itself"
                    );
                    *field
                }
                other => {
                    panic!("a value parser may only report Error::Validation, got {other:?}")
                }
            };
            assert!(
                error.code().is_none(),
                "a validation error carries no API code"
            );
            assert!(
                !error.is_retryable(),
                "a validation error is terminal, never retryable"
            );
            Outcome::Invalid(field)
        }
    }
}

fn period(text: &str) -> Outcome {
    outcome_of(text, str::parse::<Period>)
}

fn renewal(text: &str) -> Outcome {
    outcome_of(text, str::parse::<RenewalMode>)
}

fn contact(text: &str) -> Outcome {
    outcome_of(text, ContactType::parse)
}

fn price(text: &str) -> Outcome {
    outcome_of(text, str::parse::<PriceType>)
}

/// One corpus seed and the outcome each parser must produce for it.
struct Seed {
    /// File name inside `fuzz/corpus/parse_types`.
    file: &'static str,
    /// The exact bytes the file must hold.
    input: Vec<u8>,
    period: Outcome,
    renewal: Outcome,
    contact: Outcome,
    price: Outcome,
}

/// Builds a seed; the four outcomes are in parser order: period, renewal mode,
/// contact type, price type.
fn seed(
    file: &'static str,
    input: &[u8],
    period: Outcome,
    renewal: Outcome,
    contact: Outcome,
    price: Outcome,
) -> Seed {
    Seed {
        file,
        input: input.to_vec(),
        period,
        renewal,
        contact,
        price,
    }
}

/// The seed table in six groups. Columns: `Period`, `RenewalMode`,
/// `ContactType`, `PriceType`.
///
/// Most rows are mechanical once two rules are understood: `RenewalMode` and
/// `ContactType` carry unknown values verbatim (trimmed, ASCII-upper-cased), so
/// they accept almost everything non-empty; `Period` and `PriceType` are closed
/// sets and refuse the rest. That is exactly the asymmetry the fuzz target relies
/// on to reach both paths with one input.
fn seeds() -> Vec<Seed> {
    let mut seeds = degenerate_seeds();
    seeds.extend(period_tokens());
    seeds.extend(period_out_of_range());
    seeds.extend(period_noise());
    seeds.extend(renewal_modes());
    seeds.extend(contact_types());
    seeds.extend(price_types());
    seeds
}

/// Input that is empty, whitespace-only or not text at all: every parser has to
/// refuse it, and none may panic on it.
fn degenerate_seeds() -> Vec<Seed> {
    vec![
        seed(
            "empty.txt",
            b"",
            bad("period"),
            bad("renewalMode"),
            bad("contact.type"),
            bad("pricetype"),
        ),
        seed(
            "spaces.txt",
            b"   \t\r\n",
            bad("period"),
            bad("renewalMode"),
            bad("contact.type"),
            bad("pricetype"),
        ),
        // NBSP is whitespace, so this is empty input in disguise.
        seed(
            "nbsp_only.txt",
            "\u{a0}\u{a0}".as_bytes(),
            bad("period"),
            bad("renewalMode"),
            bad("contact.type"),
            bad("pricetype"),
        ),
        seed(
            "ideographic_space.txt",
            "\u{3000}".as_bytes(),
            bad("period"),
            bad("renewalMode"),
            bad("contact.type"),
            bad("pricetype"),
        ),
        // A zero width space is *not* whitespace: the carry types keep it.
        seed(
            "zero_width_space.txt",
            "\u{200b}".as_bytes(),
            bad("period"),
            ok("\u{200b}"),
            ok("\u{200b}"),
            bad("pricetype"),
        ),
        seed(
            "nul.txt",
            "\0".as_bytes(),
            bad("period"),
            ok("\0"),
            ok("\0"),
            bad("pricetype"),
        ),
        // Not UTF-8; the fuzz target feeds the lossy conversion, U+FFFD A U+FFFD.
        seed(
            "invalid_utf8.bin",
            b"\xffA\xfe",
            bad("period"),
            ok("\u{fffd}A\u{fffd}"),
            ok("\u{fffd}A\u{fffd}"),
            bad("pricetype"),
        ),
        seed(
            "replacement_char.txt",
            "\u{fffd}".as_bytes(),
            bad("period"),
            ok("\u{fffd}"),
            ok("\u{fffd}"),
            bad("pricetype"),
        ),
    ]
}

/// `Period`: the documented `1M` plus `1Y`..`10Y`, in the case and padding
/// variants the API sends back.
fn period_tokens() -> Vec<Seed> {
    vec![
        seed(
            "period_1M.txt",
            b"1M",
            ok("1M"),
            ok("1M"),
            ok("1M"),
            bad("pricetype"),
        ),
        seed(
            "period_1m_lowercase.txt",
            b"1m",
            ok("1M"),
            ok("1M"),
            ok("1M"),
            bad("pricetype"),
        ),
        // Just inside the documented range at both ends.
        seed(
            "period_1Y_min.txt",
            b"1Y",
            ok("1Y"),
            ok("1Y"),
            ok("1Y"),
            bad("pricetype"),
        ),
        seed(
            "period_10Y_max.txt",
            b"10Y",
            ok("10Y"),
            ok("10Y"),
            ok("10Y"),
            bad("pricetype"),
        ),
        seed(
            "period_10y_lowercase_padded.txt",
            b" 10y\t",
            ok("10Y"),
            ok("10Y"),
            ok("10Y"),
            bad("pricetype"),
        ),
    ]
}

/// Values that have the shape of a period but sit outside `1M` and `1Y`..`10Y`:
/// the range edges, the sign `u8` accepts or refuses, and the digit runs that no
/// longer fit in it.
fn period_out_of_range() -> Vec<Seed> {
    vec![
        seed(
            "period_11Y_outside.txt",
            b"11Y",
            bad("period"),
            ok("11Y"),
            ok("11Y"),
            bad("pricetype"),
        ),
        seed(
            "period_0Y_outside.txt",
            b"0Y",
            bad("period"),
            ok("0Y"),
            ok("0Y"),
            bad("pricetype"),
        ),
        seed(
            "period_2M_outside.txt",
            b"2M",
            bad("period"),
            ok("2M"),
            ok("2M"),
            bad("pricetype"),
        ),
        seed(
            "period_4M_outside.txt",
            b"4M",
            bad("period"),
            ok("4M"),
            ok("4M"),
            bad("pricetype"),
        ),
        // The last value `u8` can hold, and the first one it cannot: both are
        // outside the documented range, and the parser must not overflow.
        seed(
            "period_255Y_u8_max.txt",
            b"255Y",
            bad("period"),
            ok("255Y"),
            ok("255Y"),
            bad("pricetype"),
        ),
        seed(
            "period_256Y_overflow.txt",
            b"256Y",
            bad("period"),
            ok("256Y"),
            ok("256Y"),
            bad("pricetype"),
        ),
        // `u8` accepts a leading `+`, so `+1Y` is the documented `1Y`; a `-` is
        // refused. Pinned here so a change of mind is a deliberate one.
        seed(
            "period_plus_1Y.txt",
            b"+1Y",
            ok("1Y"),
            ok("+1Y"),
            ok("+1Y"),
            bad("pricetype"),
        ),
        seed(
            "period_minus_1Y.txt",
            b"-1Y",
            bad("period"),
            ok("-1Y"),
            ok("-1Y"),
            bad("pricetype"),
        ),
    ]
}

/// Tokenizer noise around a period: a missing or non-ASCII unit suffix, NUL bytes
/// inside the digits, a space in the middle, unicode whitespace that has to be
/// trimmed, and a digit run long enough to overflow `u8`.
fn period_noise() -> Vec<Seed> {
    vec![
        seed(
            "period_unit_only.txt",
            b"Y",
            bad("period"),
            ok("Y"),
            ok("Y"),
            bad("pricetype"),
        ),
        seed(
            "period_digits_only.txt",
            b"7",
            bad("period"),
            ok("7"),
            ok("7"),
            bad("pricetype"),
        ),
        seed(
            "period_inner_space.txt",
            b"1 Y",
            bad("period"),
            ok("1 Y"),
            ok("1 Y"),
            bad("pricetype"),
        ),
        seed(
            "period_nul_inner.bin",
            b"1\x00Y",
            bad("period"),
            ok("1\0Y"),
            ok("1\0Y"),
            bad("pricetype"),
        ),
        // A fullwidth `Ｙ` is not the ASCII unit suffix, and is not trimmed.
        seed(
            "period_fullwidth_unit.txt",
            "1\u{ff39}".as_bytes(),
            bad("period"),
            ok("1\u{ff39}"),
            ok("1\u{ff39}"),
            bad("pricetype"),
        ),
        seed(
            "period_ideographic_space_2Y.txt",
            "\u{3000}2Y\u{3000}".as_bytes(),
            ok("2Y"),
            ok("2Y"),
            ok("2Y"),
            bad("pricetype"),
        ),
        seed(
            "period_line_separators_3Y.txt",
            "\u{2028}3Y\u{2029}".as_bytes(),
            ok("3Y"),
            ok("3Y"),
            ok("3Y"),
            bad("pricetype"),
        ),
        // 400 digits: far past `u8`, so a clean refusal and no allocation drama.
        seed(
            "period_huge_digits.txt",
            huge_digits().as_bytes(),
            bad("period"),
            ok(&huge_digits()),
            ok(&huge_digits()),
            bad("pricetype"),
        ),
    ]
}

/// `RenewalMode`: the three documented modes, and the values this crate has to
/// carry verbatim for a mode INWX adds later.
fn renewal_modes() -> Vec<Seed> {
    vec![
        seed(
            "renewal_autorenew_lower.txt",
            b"autorenew",
            bad("period"),
            ok("AUTORENEW"),
            ok("AUTORENEW"),
            bad("pricetype"),
        ),
        seed(
            "renewal_AutoDelete_mixed.txt",
            b"AutoDelete",
            bad("period"),
            ok("AUTODELETE"),
            ok("AUTODELETE"),
            bad("pricetype"),
        ),
        seed(
            "renewal_AUTOEXPIRE_padded.txt",
            b"\tAUTOEXPIRE ",
            bad("period"),
            ok("AUTOEXPIRE"),
            ok("AUTOEXPIRE"),
            bad("pricetype"),
        ),
        seed(
            "renewal_unknown.txt",
            b"SOMETHING_NEW",
            bad("period"),
            ok("SOMETHING_NEW"),
            ok("SOMETHING_NEW"),
            bad("pricetype"),
        ),
        seed(
            "renewal_single_char.txt",
            b"x",
            bad("period"),
            ok("X"),
            ok("X"),
            bad("pricetype"),
        ),
        seed(
            "renewal_nul_inner.bin",
            b"AUTO\x00RENEW",
            bad("period"),
            ok("AUTO\0RENEW"),
            ok("AUTO\0RENEW"),
            bad("pricetype"),
        ),
        // Normalisation is ASCII-only: a soft hyphen survives, untouched.
        seed(
            "renewal_soft_hyphen.txt",
            "auto\u{ad}renew".as_bytes(),
            bad("period"),
            ok("AUTO\u{ad}RENEW"),
            ok("AUTO\u{ad}RENEW"),
            bad("pricetype"),
        ),
        // No length cap on a carried value — pinned so a future limit is a
        // deliberate change rather than a surprise.
        seed(
            "renewal_long_token.txt",
            &[b'R'; 1000],
            bad("period"),
            ok(&"R".repeat(1000)),
            ok(&"R".repeat(1000)),
            bad("pricetype"),
        ),
    ]
}

/// `ContactType`: `ORG`, `PERSON`, `ROLE`, and an unknown value carried verbatim.
fn contact_types() -> Vec<Seed> {
    vec![
        seed(
            "contact_org_mixed.txt",
            b"OrG",
            bad("period"),
            ok("ORG"),
            ok("ORG"),
            bad("pricetype"),
        ),
        seed(
            "contact_PERSON_upper.txt",
            b"PERSON",
            bad("period"),
            ok("PERSON"),
            ok("PERSON"),
            bad("pricetype"),
        ),
        seed(
            "contact_role_newlines.txt",
            b"\nrole\r\n",
            bad("period"),
            ok("ROLE"),
            ok("ROLE"),
            bad("pricetype"),
        ),
        seed(
            "contact_trustee_unknown.txt",
            b"TRUSTEE",
            bad("period"),
            ok("TRUSTEE"),
            ok("TRUSTEE"),
            bad("pricetype"),
        ),
        // `ß` has no ASCII upper-case form, so it is carried as it stands.
        seed(
            "contact_german_sharp_s.txt",
            "stra\u{df}e".as_bytes(),
            bad("period"),
            ok("STRA\u{df}E"),
            ok("STRA\u{df}E"),
            bad("pricetype"),
        ),
    ]
}

/// `PriceType`: the six priced actions and the nearest values that are not one
/// of them.
fn price_types() -> Vec<Seed> {
    vec![
        seed(
            "price_reg_lower.txt",
            b"reg",
            bad("period"),
            ok("REG"),
            ok("REG"),
            ok("reg"),
        ),
        seed(
            "price_RENEWAL_upper.txt",
            b"RENEWAL",
            bad("period"),
            ok("RENEWAL"),
            ok("RENEWAL"),
            ok("renewal"),
        ),
        seed(
            "price_transfer_padded.txt",
            b"  transfer\t",
            bad("period"),
            ok("TRANSFER"),
            ok("TRANSFER"),
            ok("transfer"),
        ),
        seed(
            "price_Trade_mixed.txt",
            b"Trade",
            bad("period"),
            ok("TRADE"),
            ok("TRADE"),
            ok("trade"),
        ),
        seed(
            "price_UPDATE_upper.txt",
            b"UPDATE",
            bad("period"),
            ok("UPDATE"),
            ok("UPDATE"),
            ok("update"),
        ),
        seed(
            "price_ReStOrE_mixed.txt",
            b"ReStOrE",
            bad("period"),
            ok("RESTORE"),
            ok("RESTORE"),
            ok("restore"),
        ),
        // A plausible-looking action that INWX does not price.
        seed(
            "price_refund_unknown.txt",
            b"refund",
            bad("period"),
            ok("REFUND"),
            ok("REFUND"),
            bad("pricetype"),
        ),
        seed(
            "price_reg_spaced.txt",
            b"R E G",
            bad("period"),
            ok("R E G"),
            ok("R E G"),
            bad("pricetype"),
        ),
    ]
}

/// The `period_huge_digits.txt` payload: 400 nines and the unit suffix.
///
/// Long enough to overflow `u8` by a mile, which is the point — the parser has
/// to refuse those digits instead of wrapping them or allocating up front.
fn huge_digits() -> String {
    format!("{}Y", "9".repeat(400))
}

/// The corpus files that look curated, i.e. carry the `.txt`/`.bin` suffix the
/// seeds are named with. libFuzzer writes the inputs it discovers next to them
/// without a suffix, so a local fuzz session does not have to be cleaned up
/// before `cargo test` passes.
/// Whether a corpus file carries one of the extensions curated seeds use.
///
/// Case-insensitive, because the point of the suffix is to tell a human-named
/// seed apart from a hash-named libFuzzer entry, not to police the case.
fn is_curated(name: &str) -> bool {
    let extension = name.rsplit_once('.').map_or("", |(_, extension)| extension);
    extension.eq_ignore_ascii_case("txt") || extension.eq_ignore_ascii_case("bin")
}

fn curated_files(dir: &Path) -> Vec<String> {
    let mut names = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("{} must exist and be readable: {error}", dir.display()))
        .map(|entry| {
            entry
                .expect("a readable corpus entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| is_curated(name))
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn read_seed(dir: &Path, name: &str) -> Vec<u8> {
    let path = dir.join(name);
    fs::read(&path).unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()))
}

#[test]
fn the_corpus_holds_exactly_the_pinned_seeds() {
    let dir = Path::new(CORPUS_DIR);
    let mut expected = seeds()
        .iter()
        .map(|seed| seed.file.to_owned())
        .collect::<Vec<_>>();
    expected.sort();

    assert_eq!(
        curated_files(dir),
        expected,
        "every curated seed needs a row in the table above, and every row needs its file"
    );

    for seed in seeds() {
        assert_eq!(
            read_seed(dir, seed.file),
            seed.input,
            "{} must hold the bytes the table pins",
            seed.file
        );
    }
}

#[test]
fn every_seed_produces_the_pinned_outcome() {
    for seed in seeds() {
        // Exactly what the fuzz target does with the bytes.
        let text = String::from_utf8_lossy(&seed.input);
        assert_eq!(period(&text), seed.period, "{}: Period", seed.file);
        assert_eq!(renewal(&text), seed.renewal, "{}: RenewalMode", seed.file);
        assert_eq!(contact(&text), seed.contact, "{}: ContactType", seed.file);
        assert_eq!(price(&text), seed.price, "{}: PriceType", seed.file);
    }
}

/// One parser's view of a seed: its name, the outcome pinned in the table and
/// the function that recomputes the outcome from the seed text.
type SeedCheck = (&'static str, Outcome, fn(&str) -> Outcome);

#[test]
fn an_accepted_wire_form_survives_a_round_trip() {
    for seed in seeds() {
        let text = String::from_utf8_lossy(&seed.input);
        // Every parser's own wire form has to parse back to itself with that same
        // parser: what is sent must be what a later response reports about it.
        let checks: [SeedCheck; 4] = [
            ("Period", period(&text), period),
            ("RenewalMode", renewal(&text), renewal),
            ("ContactType", contact(&text), contact),
            ("PriceType", price(&text), price),
        ];
        for (label, outcome, parse) in checks {
            let Outcome::Wire(wire) = outcome else {
                continue;
            };
            assert!(
                !wire.is_empty(),
                "{}: {label} accepted {text:?} and rendered it empty",
                seed.file
            );
            assert_eq!(
                parse(&wire),
                Outcome::Wire(wire.clone()),
                "{}: {label} wire form {wire:?} must parse back to itself",
                seed.file
            );
        }
    }
}

#[test]
fn serde_agrees_with_the_wire_form() {
    for seed in seeds() {
        let text = String::from_utf8_lossy(&seed.input);

        if let Ok(period) = text.parse::<Period>() {
            let wire = period.to_string();
            assert_eq!(
                serde_json::to_value(period).ok(),
                Some(serde_json::Value::String(wire)),
                "{}: Period must serialize as its wire form",
                seed.file
            );
        }
        if let Ok(mode) = text.parse::<RenewalMode>() {
            let wire = mode.to_string();
            let encoded = serde_json::Value::String(wire.clone());
            assert_eq!(serde_json::to_value(&mode).ok(), Some(encoded.clone()));
            assert_eq!(
                serde_json::from_value::<RenewalMode>(encoded)
                    .unwrap()
                    .to_string(),
                wire,
                "{}: RenewalMode must survive a serde round trip",
                seed.file
            );
        }
        if let Ok(kind) = ContactType::parse(&text) {
            let wire = kind.to_string();
            let encoded = serde_json::Value::String(wire.clone());
            assert_eq!(serde_json::to_value(&kind).ok(), Some(encoded.clone()));
            assert_eq!(
                serde_json::from_value::<ContactType>(encoded)
                    .unwrap()
                    .to_string(),
                wire,
                "{}: ContactType must survive a serde round trip",
                seed.file
            );
        }
        if let Ok(price_type) = text.parse::<PriceType>() {
            assert_eq!(
                price_type.as_str(),
                price_type.to_string(),
                "{}: PriceType::as_str and Display must agree",
                seed.file
            );
        }
    }
}

// ----------------------------------------------------------- boundary pairs --

#[test]
fn period_boundary_pair() {
    // Just inside, and the value just outside on each side.
    assert_eq!("1M".parse::<Period>().unwrap(), Period::ONE_MONTH);
    assert_eq!("1Y".parse::<Period>().unwrap(), Period::years(1).unwrap());
    assert_eq!("10Y".parse::<Period>().unwrap(), Period::years(10).unwrap());
    assert!("2M".parse::<Period>().is_err());
    assert!("4M".parse::<Period>().is_err());
    assert!("0Y".parse::<Period>().is_err());
    assert!("11Y".parse::<Period>().is_err());
    // The unit is case-insensitive and surrounding whitespace is trimmed.
    assert_eq!(
        " 10y ".parse::<Period>().unwrap(),
        Period::years(10).unwrap()
    );

    // `Period::years` and the parser agree on the same boundary.
    assert!(Period::years(0).is_err());
    assert!(Period::years(1).is_ok());
    assert!(Period::years(10).is_ok());
    assert!(Period::years(11).is_err());
    for years in 0u8..=12 {
        let text = format!("{years}Y");
        assert_eq!(
            text.parse::<Period>().is_ok(),
            (1..=10).contains(&years),
            "{text} is on the wrong side of the documented range"
        );
    }
    // Past `u8` the digits are refused rather than wrapped.
    assert!("255Y".parse::<Period>().is_err());
    assert!("256Y".parse::<Period>().is_err());
    assert_eq!("+1Y".parse::<Period>().unwrap(), Period::years(1).unwrap());
    assert!("-1Y".parse::<Period>().is_err());
}

#[test]
fn renewal_mode_boundary_pair() {
    for (input, expected) in [
        ("autorenew", RenewalMode::AutoRenew),
        ("AUTODELETE", RenewalMode::AutoDelete),
        (" AutoExpire\t", RenewalMode::AutoExpire),
    ] {
        assert_eq!(input.parse::<RenewalMode>().unwrap(), expected, "{input}");
        assert_eq!(expected.as_str(), expected.to_string());
    }
    // The shortest accepted value is one character; the shortest refused one is
    // nothing but whitespace.
    assert_eq!(
        "x".parse::<RenewalMode>().unwrap(),
        RenewalMode::Other("X".into())
    );
    assert!("".parse::<RenewalMode>().is_err());
    assert!("  ".parse::<RenewalMode>().is_err());
    // NBSP counts as whitespace, so a lone NBSP is empty input.
    let error = "\u{a0}".parse::<RenewalMode>().unwrap_err();
    assert!(matches!(
        error,
        Error::Validation {
            field: "renewalMode",
            ..
        }
    ));
}

#[test]
fn contact_type_boundary_pair() {
    assert_eq!(ContactType::parse("OrG").unwrap(), ContactType::Org);
    assert_eq!(ContactType::parse("person").unwrap(), ContactType::Person);
    assert_eq!(ContactType::parse("\nrole\r\n").unwrap(), ContactType::Role);
    assert_eq!(
        ContactType::parse("T").unwrap(),
        ContactType::Other("T".into()),
        "one character is the shortest accepted value"
    );
    assert!(ContactType::parse("").unwrap_err().is_validation());
    assert!(ContactType::parse(" ").is_err());
    assert_eq!(
        ContactType::parse(" trustee ").unwrap(),
        ContactType::Other("TRUSTEE".into())
    );
    assert_eq!(
        "org".parse::<ContactType>().unwrap(),
        ContactType::parse("org").unwrap(),
        "FromStr and parse must be the same parser"
    );
}

#[test]
fn price_type_boundary_pair() {
    for (input, expected) in [
        ("reg", PriceType::Reg),
        ("RENEWAL", PriceType::Renewal),
        (" Transfer ", PriceType::Transfer),
        ("trade", PriceType::Trade),
        ("update", PriceType::Update),
        ("ReStOrE", PriceType::Restore),
    ] {
        assert_eq!(input.parse::<PriceType>().unwrap(), expected, "{input}");
        assert_eq!(
            expected.as_str(),
            expected.to_string(),
            "the wire form is lower-case"
        );
    }
    // The closest neighbours of an accepted value: a real INWX action that is not
    // a price type, one character short, one character long, and the empty input
    // that is left once the trim has run.
    for input in ["refund", "r", "regs", "renew", "R E G", "", " "] {
        let error = input.parse::<PriceType>().unwrap_err();
        assert!(error.is_validation(), "{input:?} must be refused: {error}");
        assert!(matches!(
            error,
            Error::Validation {
                field: "pricetype",
                ..
            }
        ));
    }
}

// ------------------------------------------------------------------ wiring --

#[test]
fn the_fuzz_target_is_wired_into_the_fuzz_workspace() {
    let manifest = fs::read_to_string(FUZZ_MANIFEST).expect("fuzz/Cargo.toml must be readable");
    assert!(
        manifest.contains("name = \"parse_types\"")
            && manifest.contains("path = \"fuzz_targets/parse_types.rs\""),
        "cargo fuzz only builds binaries declared in fuzz/Cargo.toml"
    );

    let target = fs::read_to_string(FUZZ_TARGET).expect("the parse_types target must be readable");
    assert!(
        target.contains("#![no_main]"),
        "a fuzz target is a no_main binary"
    );
    assert!(
        target.contains("fuzz_target!"),
        "the target must define a fuzz entry point"
    );
    for parser in ["Period", "RenewalMode", "ContactType", "PriceType"] {
        assert!(
            target.contains(parser),
            "the target must feed its input to {parser}"
        );
    }
    // The corpus this test replays is the one the target documents, so a rename
    // of either side has to touch both.
    assert!(
        target.contains("fuzz/corpus/parse_types"),
        "the target must document where its seeds live"
    );
}

// ----------------------------------------------------------- property tests --

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The fuzz target's two invariants, run deterministically in CI: arbitrary
    /// text never panics a parser, and a refusal is always a validation error.
    #[test]
    fn parsers_never_panic_and_only_report_validation(input in "\\PC{0,40}") {
        let _ = period(&input);
        let _ = renewal(&input);
        let _ = contact(&input);
        let _ = price(&input);
    }

    /// Whatever a parser accepts must render to a wire form that parses back to
    /// the same value — the property the fuzz oracle asserts.
    #[test]
    fn accepted_values_round_trip(input in "\\PC{0,40}") {
        if let Ok(parsed) = input.parse::<Period>() {
            prop_assert_eq!(parsed.to_string().parse::<Period>().ok(), Some(parsed));
        }
        if let Ok(parsed) = input.parse::<RenewalMode>() {
            let wire = parsed.to_string();
            prop_assert!(!wire.is_empty());
            prop_assert_eq!(wire.parse::<RenewalMode>().ok(), Some(parsed));
        }
        if let Ok(parsed) = ContactType::parse(&input) {
            let wire = parsed.to_string();
            prop_assert!(!wire.is_empty());
            prop_assert_eq!(ContactType::parse(&wire).ok(), Some(parsed));
        }
        if let Ok(parsed) = input.parse::<PriceType>() {
            prop_assert_eq!(parsed.as_str(), parsed.to_string());
            prop_assert_eq!(parsed.as_str().parse::<PriceType>().ok(), Some(parsed));
        }
    }

    /// The period range is exactly `1M` plus `1Y..=10Y` — no off-by-one at either
    /// end, and no wrap-around above `u8`.
    #[test]
    fn period_range_is_exact(years in 0u32..=300) {
        let text = format!("{years}Y");
        let accepted = text.parse::<Period>().is_ok();
        prop_assert_eq!(accepted, (1..=10).contains(&years), "period input: {}", text);
        if (1..=10).contains(&years) {
            let parsed = text.parse::<Period>().unwrap();
            prop_assert_eq!(parsed, Period::years(u8::try_from(years).unwrap()).unwrap());
            prop_assert_eq!(parsed.to_string(), text.as_str());
        }
        if let Err(error) = text.parse::<Period>() {
            prop_assert!(error.is_validation());
        }
    }

    /// Surrounding whitespace is trimmed before the token is read, ASCII and
    /// unicode alike — the path the hand-rolled tokenizer gets wrong.
    #[test]
    fn surrounding_whitespace_is_trimmed(
        leading in prop::sample::select(vec![' ', '\t', '\n', '\r', '\u{a0}', '\u{3000}', '\u{2028}']),
        trailing in prop::sample::select(vec![' ', '\t', '\n', '\u{a0}', '\u{3000}', '\u{2029}']),
        years in 1u8..=10,
    ) {
        let text = format!("{leading}{years}Y{trailing}");
        prop_assert_eq!(
            text.parse::<Period>().ok(),
            Some(Period::years(years).unwrap())
        );
        let mode = format!("{leading}autorenew{trailing}");
        prop_assert_eq!(mode.parse::<RenewalMode>().ok(), Some(RenewalMode::AutoRenew));
        let kind = format!("{leading}org{trailing}");
        prop_assert_eq!(ContactType::parse(&kind).ok(), Some(ContactType::Org));
        let price = format!("{leading}reg{trailing}");
        prop_assert_eq!(price.parse::<PriceType>().ok(), Some(PriceType::Reg));
        // Whitespace alone is empty input, and empty input is refused.
        let only = format!("{leading}{trailing}");
        prop_assert!(only.parse::<Period>().is_err());
        prop_assert!(only.parse::<RenewalMode>().is_err());
        prop_assert!(ContactType::parse(&only).is_err());
        prop_assert!(only.parse::<PriceType>().is_err());
    }
}
