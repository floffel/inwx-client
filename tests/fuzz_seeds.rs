//! Stable mirror of the `parse_names` fuzz target.
//!
//! CI only *builds* the fuzz targets, so the corpus and the invariants the target
//! asserts are checked here instead: every seed in `fuzz/corpus/parse_names` is
//! replayed through the string parsers, the boundary seeds are pinned to the
//! expected side of each limit (just inside and just outside), and the fixture
//! set the issue asks for is verified to be present.

use std::fs;
use std::path::PathBuf;

use inwx_client::{DomainName, Hostname, RecordId, RecordSpec, RecordType, DEFAULT_TTL};

/// The `parse_names` corpus, or `None` when the fuzz workspace is absent (it is
/// excluded from the published package).
fn corpus_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("corpus")
        .join("parse_names");
    dir.exists().then_some(dir)
}

/// One seed: the file name and its content as text (invalid UTF-8 is mapped in
/// lossily, exactly like the fuzz target does).
struct Seed {
    name: String,
    text: String,
}

fn seeds() -> Vec<Seed> {
    let Some(dir) = corpus_dir() else {
        return Vec::new();
    };
    let mut seeds: Vec<Seed> = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("reading {}: {error}", dir.display()))
        .map(|entry| {
            let entry = entry.expect("corpus entry");
            let bytes =
                fs::read(entry.path()).unwrap_or_else(|error| panic!("reading seed: {error}"));
            Seed {
                name: entry.file_name().to_string_lossy().into_owned(),
                text: String::from_utf8_lossy(&bytes).into_owned(),
            }
        })
        .collect();
    seeds.sort_by(|left, right| left.name.cmp(&right.name));
    seeds
}

/// The seed called `name`.
fn seed(name: &str) -> String {
    seeds()
        .into_iter()
        .find(|seed| seed.name == name)
        .unwrap_or_else(|| panic!("missing corpus seed {name:?}"))
        .text
}

/// The invariants the `parse_names` target asserts, replayed on stable Rust.
fn replay(text: &str) {
    if let Ok(name) = DomainName::parse(text) {
        assert_eq!(DomainName::parse(name.as_str()).ok(), Some(name.clone()));
        assert_eq!(name.to_string(), name.as_str());
        assert!(Hostname::parse(name.as_str()).is_ok());
        assert!(name.as_str().ends_with(name.tld()));
    }
    if let Ok(host) = Hostname::parse(text) {
        assert_eq!(Hostname::parse(host.as_str()).ok(), Some(host.clone()));
        assert_eq!(host.to_string(), host.as_str());
    }
    // `FromStr` and `TryFrom` are aliases of `parse`.
    assert_eq!(
        text.parse::<DomainName>().is_ok(),
        DomainName::try_from(text).is_ok()
    );

    if let Ok(record_type) = RecordType::parse(text) {
        assert_eq!(
            RecordType::parse(record_type.as_str()).ok(),
            Some(record_type.clone())
        );
    }
    if let Ok(id) = RecordId::parse(text) {
        assert_eq!(RecordId::parse(id.as_str()).ok(), Some(id.clone()));
        assert_eq!(id.to_string(), id.as_str());
    }

    // Record names are type-independent; content is checked at the apex name so
    // the per-type shape rules are actually reached.
    replay_spec(&RecordType::Txt, text, "@");
    for record_type in RecordType::ALL {
        replay_spec(record_type, "@", text);
    }
}

fn replay_spec(record_type: &RecordType, name: &str, content: &str) {
    match RecordSpec::new(record_type.clone(), name, content) {
        Ok(spec) => {
            assert_eq!(&spec.record_type(), record_type);
            assert_eq!(spec.name(), name);
            assert_eq!(spec.content(), content);
            assert_eq!(spec.ttl(), DEFAULT_TTL);
            assert!(spec.validate().is_ok());
        }
        Err(error) => assert!(error.is_validation()),
    }
}

// ------------------------------------------------------------------- corpus --

/// Every seed survives every parser: a bad value is an `Err`, never a panic.
#[test]
fn every_parse_names_seed_survives_the_string_parsers() {
    let seeds = seeds();
    if seeds.is_empty() {
        eprintln!("fuzz corpus not present, skipping");
        return;
    }
    for seed in &seeds {
        replay(&seed.text);
    }
    assert!(seeds.len() >= 40, "expected a seeded corpus");
}

/// The fixtures the issue asks for are all in the corpus.
#[test]
fn corpus_covers_the_documented_seed_shapes() {
    let names: Vec<String> = seeds().into_iter().map(|seed| seed.name).collect();
    for required in [
        "valid_ascii",
        "upper_with_spaces",
        "empty",
        "spaces",
        "nul_bytes",
        "nul_in_label",
        "invalid_utf8",
        "idn_umlaut",
        "idn_cyrillic",
        "idn_punycode",
        "idn_emoji",
        "punycode_invalid",
        "label_63",
        "label_64",
        "name_253",
        "name_254",
        "duplicate_dots",
        "trailing_dot",
        "leading_dot",
        "root_dot_only",
        "record_name_253",
        "record_name_254",
        "content_1024",
        "content_1025",
    ] {
        assert!(
            names.iter().any(|name| name == required),
            "missing seed {required:?}"
        );
    }
}

// ------------------------------------------------------- boundary fixtures --

#[test]
fn label_seeds_straddle_the_63_byte_label_limit() {
    let inside = seed("label_63");
    let outside = seed("label_64");
    assert_eq!(DomainName::parse(&inside).unwrap().as_str(), inside);
    assert!(DomainName::parse(&outside).is_err());
    // A host name is bounded the same way.
    assert!(Hostname::parse(&inside).is_ok());
    assert!(Hostname::parse(&outside).is_err());
}

#[test]
fn name_seeds_straddle_the_253_byte_name_limit() {
    assert!(DomainName::parse(&seed("name_253")).is_ok());
    assert!(DomainName::parse(&seed("name_254")).is_err());
}

#[test]
fn record_name_seeds_straddle_the_record_name_limit() {
    assert!(RecordSpec::txt(seed("record_name_253"), "x").is_ok());
    assert!(RecordSpec::txt(seed("record_name_254"), "x").is_err());
}

#[test]
fn content_seeds_straddle_the_record_content_limit() {
    assert!(RecordSpec::new(RecordType::Txt, "@", seed("content_1024")).is_ok());
    assert!(RecordSpec::new(RecordType::Txt, "@", seed("content_1025")).is_err());
}

#[test]
fn dot_seeds_show_where_the_root_dot_stops_being_trimmed() {
    assert_eq!(
        DomainName::parse(&seed("trailing_dot")).unwrap().as_str(),
        "example.com"
    );
    assert!(DomainName::parse(&seed("duplicate_dots")).is_err());
    assert!(DomainName::parse(&seed("leading_dot")).is_err());
    assert!(DomainName::parse(&seed("root_dot_only")).is_err());
    // A record name is relative: neither a leading nor a trailing dot is legal.
    assert!(RecordSpec::txt(seed("trailing_dot"), "x").is_err());
    assert!(RecordSpec::txt(seed("leading_dot"), "x").is_err());
}

#[test]
fn idn_seeds_land_on_the_expected_side_of_punycode() {
    for name in ["idn_umlaut", "idn_punycode", "punycode_upper"] {
        assert_eq!(
            DomainName::parse(&seed(name)).unwrap().as_str(),
            "xn--mnchen-3ya.de",
            "{name} should normalise to the ACE form"
        );
    }
    assert!(DomainName::parse(&seed("punycode_invalid")).is_err());
    assert!(DomainName::parse(&seed("punycode_bare_prefix")).is_err());
    // A unicode label is measured after punycode, so 63 `ü` do not fit.
    assert!(DomainName::parse(&seed("idn_label_63")).is_err());
}

#[test]
fn empty_and_control_seeds_are_rejected_as_names_and_accepted_as_data() {
    for name in [
        "empty",
        "spaces",
        "nul_bytes",
        "nul_in_label",
        "invalid_utf8",
    ] {
        let text = seed(name);
        assert!(DomainName::parse(&text).is_err(), "{name} is not a domain");
        assert!(Hostname::parse(&text).is_err(), "{name} is not a host name");
    }
    // `@` is not a domain, but it is the zone apex for a record name.
    assert!(DomainName::parse(&seed("at_apex")).is_err());
    assert!(RecordSpec::txt(seed("at_apex"), "x").is_ok());
    // `localhost` is a host name, never a domain.
    assert!(DomainName::parse(&seed("single_label")).is_err());
    assert_eq!(
        Hostname::parse(&seed("single_label")).unwrap().as_str(),
        "localhost"
    );
}

#[test]
fn content_shape_seeds_match_their_record_type() {
    let ipv4 = seed("content_ipv4");
    assert!(RecordSpec::new(RecordType::A, "@", &ipv4).is_ok());
    assert!(RecordSpec::new(RecordType::Aaaa, "@", &ipv4).is_err());

    let ipv6 = seed("content_ipv6");
    assert!(RecordSpec::new(RecordType::Aaaa, "@", &ipv6).is_ok());
    assert!(RecordSpec::new(RecordType::A, "@", &ipv6).is_err());

    // A quoted `TXT` value is refused; free text and a host name are not.
    assert!(RecordSpec::new(RecordType::Txt, "@", seed("content_txt_quoted")).is_err());
    assert!(RecordSpec::new(RecordType::Txt, "@", seed("content_txt_spf")).is_ok());
    assert!(RecordSpec::new(RecordType::Mx, "@", "mx.example.com").is_ok());
}
