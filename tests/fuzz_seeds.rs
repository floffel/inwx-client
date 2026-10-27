//! Replay gate for the fuzz seed corpus.
//!
//! `fuzz/corpus/parse_names/` holds the bytes `cargo +nightly fuzz run
//! parse_names` starts from. Nightly is not part of the normal test run, so this
//! file drives the same seeds through the same parsers and asserts what each
//! shape must do. Two things are proven here: the corpus still contains every
//! shape the parsers need (issue #17), and the boundary fixtures really sit just
//! inside and just outside each documented limit.

use std::fs;
use std::path::{Path, PathBuf};

use inwx_client::{
    DomainName, Error, Hostname, RecordId, RecordSpec, RecordType, MAX_DOMAIN_LEN, MAX_LABEL_LEN,
    MAX_TTL,
};

/// Field separator of the record fixtures, matching the fuzz target.
const SEPARATOR: char = '\u{0}';

/// Longest record content the API documents.
const MAX_CONTENT_LEN: usize = 1024;

/// Longest record id `RecordId::parse` accepts.
const MAX_RECORD_ID_LEN: usize = 64;

/// One seed: file name and raw bytes.
struct Seed {
    name: String,
    bytes: Vec<u8>,
}

impl Seed {
    /// The seed as text, with invalid UTF-8 replaced — the same conversion the
    /// fuzz target uses.
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    /// The seed split into `name`, `content` and `ttl`, the way a zone line and
    /// the fuzz target split it.
    fn fields(&self) -> (String, String, String) {
        let text = self.text();
        let mut fields = text.split(SEPARATOR);
        (
            fields.next().unwrap_or_default().to_owned(),
            fields.next().unwrap_or_default().to_owned(),
            fields.next().unwrap_or_default().to_owned(),
        )
    }
}

/// The seed corpus, or `None` outside a repository checkout: crates.io tarballs
/// exclude `fuzz/`, so the fuzz target is the marker for "the corpus should be
/// here".
fn seeds() -> Option<Vec<Seed>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    if !root.join("fuzz/fuzz_targets/parse_names.rs").is_file() {
        return None;
    }
    let dir: PathBuf = root.join("fuzz/corpus/parse_names");
    let mut corpus = Vec::new();
    for entry in fs::read_dir(&dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display())) {
        let path = entry.unwrap().path();
        let bytes = fs::read(&path).unwrap();
        corpus.push(Seed {
            name: path.file_name().unwrap().to_string_lossy().into_owned(),
            bytes,
        });
    }
    corpus.sort_by(|left, right| left.name.cmp(&right.name));
    assert!(
        !corpus.is_empty(),
        "the seed corpus at {} is empty",
        dir.display()
    );
    Some(corpus)
}

/// One seed by file name.
fn seed<'a>(corpus: &'a [Seed], name: &str) -> &'a Seed {
    corpus
        .iter()
        .find(|candidate| candidate.name == name)
        .unwrap_or_else(|| panic!("the corpus has no seed named {name}"))
}

/// The shape every accepted name must have, checked without trusting the
/// parsers' own reporting. The reparse is left to the caller, which knows which
/// parser produced the value.
fn assert_normalised_name(ascii: &str, seed_name: &str) {
    assert!(
        !ascii.is_empty() && ascii.len() <= MAX_DOMAIN_LEN,
        "{seed_name}: {ascii:?} is outside the 1..={MAX_DOMAIN_LEN} length limit"
    );
    assert!(
        ascii.bytes().all(|byte| byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || byte == b'-'
            || byte == b'.'),
        "{seed_name}: {ascii:?} keeps a character outside [a-z0-9-.]"
    );
    assert!(
        !ascii.starts_with('.') && !ascii.ends_with('.') && !ascii.contains(".."),
        "{seed_name}: {ascii:?} keeps a root or empty label"
    );
    for label in ascii.split('.') {
        assert!(
            !label.is_empty() && label.len() <= MAX_LABEL_LEN,
            "{seed_name}: label {label:?} of {ascii:?} is outside the 1..={MAX_LABEL_LEN} limit"
        );
        assert!(
            !label.starts_with('-') && !label.ends_with('-'),
            "{seed_name}: label {label:?} of {ascii:?} keeps a hyphen at an edge"
        );
    }
}

/// A rejected name is a validation error, never a transport or API error.
fn assert_validation(error: Error, seed_name: &str, field: &str) {
    match error {
        Error::Validation { field: got, .. } => {
            assert_eq!(got, field, "{seed_name}: wrong field in {got:?}");
        }
        other => panic!("{seed_name}: expected a validation error, got {other}"),
    }
}

/// One corpus shape the acceptance criteria demand, by name.
fn requires(corpus: &[Seed], label: &str, predicate: impl Fn(&Seed) -> bool) {
    assert!(
        corpus.iter().any(predicate),
        "fuzz/corpus/parse_names has no seed for: {label}"
    );
}

#[test]
fn every_seed_survives_the_name_and_record_parsers() {
    let Some(corpus) = seeds() else {
        return;
    };
    for seed in &corpus {
        let text = seed.text();
        match DomainName::parse(&text) {
            Ok(domain) => {
                assert_normalised_name(domain.as_str(), &seed.name);
                assert_eq!(
                    DomainName::parse(domain.as_str()).unwrap().as_str(),
                    domain.as_str(),
                    "{}: normalisation is not a fixed point",
                    seed.name
                );
            }
            Err(error) => assert!(error.is_validation(), "{}: {error}", seed.name),
        }
        match Hostname::parse(&text) {
            Ok(host) => {
                assert_normalised_name(host.as_str(), &seed.name);
                assert_eq!(
                    Hostname::parse(host.as_str()).unwrap().as_str(),
                    host.as_str(),
                    "{}: normalisation is not a fixed point",
                    seed.name
                );
            }
            Err(error) => assert!(error.is_validation(), "{}: {error}", seed.name),
        }
        match RecordId::parse(&text) {
            Ok(id) => {
                assert_eq!(
                    id.as_str(),
                    text.trim(),
                    "{}: the id was not trimmed",
                    seed.name
                );
                assert!(
                    id.as_str().len() <= MAX_RECORD_ID_LEN,
                    "{}: id too long",
                    seed.name
                );
            }
            Err(error) => assert!(error.is_validation(), "{}: {error}", seed.name),
        }
        if let Err(error) = RecordType::parse(&text) {
            assert!(error.is_validation(), "{}: {error}", seed.name);
        }

        let (name, content, ttl) = seed.fields();
        for record_type in RecordType::ALL {
            match RecordSpec::new(record_type.clone(), name.as_str(), content.as_str()) {
                Ok(spec) => {
                    assert_eq!(
                        spec.record_type(),
                        record_type.clone(),
                        "{}: the type changed",
                        seed.name
                    );
                    assert_eq!(spec.name(), name, "{}: the name changed", seed.name);
                    assert_eq!(
                        spec.content(),
                        content,
                        "{}: the content changed",
                        seed.name
                    );
                    assert!(
                        spec.validate().is_ok(),
                        "{}: validate() rejected a built spec",
                        seed.name
                    );
                    if let Ok(parsed) = ttl.trim().parse::<u32>() {
                        assert_eq!(
                            spec.with_ttl(parsed).is_ok(),
                            parsed <= MAX_TTL,
                            "{}: with_ttl({parsed}) against the {MAX_TTL} ceiling",
                            seed.name
                        );
                    }
                }
                Err(error) => assert!(error.is_validation(), "{}: {error}", seed.name),
            }
        }
    }
}

#[test]
fn the_corpus_covers_every_required_shape() {
    let Some(corpus) = seeds() else {
        return;
    };
    requires(&corpus, "empty input", |seed| seed.bytes.is_empty());
    requires(&corpus, "invalid UTF-8", |seed| {
        std::str::from_utf8(&seed.bytes).is_err()
    });
    requires(&corpus, "a NUL byte", |seed| seed.bytes.contains(&0));
    requires(&corpus, "a control character besides NUL", |seed| {
        seed.text()
            .chars()
            .any(|ch| ch != SEPARATOR && ch.is_control())
    });
    requires(&corpus, "a valid ASCII domain", |seed| {
        DomainName::parse(&seed.text()).is_ok()
    });
    requires(&corpus, "a unicode label that becomes punycode", |seed| {
        seed.bytes.iter().any(|byte| *byte > 127)
            && DomainName::parse(&seed.text()).is_ok_and(|domain| domain.is_idn())
    });
    requires(&corpus, "a punycode label spelled in ASCII", |seed| {
        std::str::from_utf8(&seed.bytes).is_ok() && seed.text().starts_with("xn--")
    });
    requires(&corpus, "a duplicate dot", |seed| {
        seed.text().contains("..")
    });
    requires(&corpus, "a trailing root dot", |seed| {
        seed.text().ends_with('.')
    });
    requires(&corpus, "a leading dot", |seed| {
        seed.text().starts_with('.')
    });
    requires(&corpus, "a single label, valid as a host only", |seed| {
        Hostname::parse(&seed.text()).is_ok() && DomainName::parse(&seed.text()).is_err()
    });
    requires(&corpus, "a hyphen at a label edge", |seed| {
        seed.text().starts_with('-')
    });
    requires(&corpus, "whitespace inside a name", |seed| {
        seed.text().chars().any(char::is_whitespace) && DomainName::parse(&seed.text()).is_err()
    });
    requires(&corpus, "a label of exactly 63 characters", |seed| {
        seed.text().split('.').any(|label| label.len() == 63)
            && DomainName::parse(&seed.text()).is_ok()
    });
    requires(&corpus, "a label of 64 characters", |seed| {
        seed.text().split('.').any(|label| label.len() == 64)
            && DomainName::parse(&seed.text()).is_err()
    });
    requires(&corpus, "a name of exactly 253 characters", |seed| {
        seed.bytes.len() == MAX_DOMAIN_LEN && DomainName::parse(&seed.text()).is_ok()
    });
    requires(&corpus, "a name of 254 characters", |seed| {
        seed.bytes.len() == MAX_DOMAIN_LEN + 1 && DomainName::parse(&seed.text()).is_err()
    });
    requires(
        &corpus,
        "a record line with name, content and TTL",
        |seed| {
            let (name, content, ttl) = seed.fields();
            !name.is_empty() && !content.is_empty() && ttl.parse::<u32>().is_ok()
        },
    );
    requires(&corpus, "content at the 1024-character limit", |seed| {
        seed.fields().1.len() == MAX_CONTENT_LEN
            && RecordSpec::txt(&seed.fields().0, seed.fields().1).is_ok()
    });
    requires(&corpus, "content past the 1024-character limit", |seed| {
        seed.fields().1.len() == MAX_CONTENT_LEN + 1
            && RecordSpec::txt(&seed.fields().0, seed.fields().1).is_err()
    });
    requires(&corpus, "a TTL at the i32::MAX ceiling", |seed| {
        seed.fields().2 == MAX_TTL.to_string()
    });
    requires(&corpus, "a TTL past the ceiling", |seed| {
        seed.fields()
            .2
            .parse::<u64>()
            .is_ok_and(|ttl| ttl > u64::from(MAX_TTL))
    });
    requires(&corpus, "a record id of exactly 64 characters", |seed| {
        seed.bytes.len() == MAX_RECORD_ID_LEN && RecordId::parse(seed.text()).is_ok()
    });
    requires(&corpus, "a record id past 64 characters", |seed| {
        seed.bytes.len() == MAX_RECORD_ID_LEN + 1 && RecordId::parse(seed.text()).is_err()
    });
}

#[test]
fn name_seeds_sit_just_inside_and_just_outside_the_limits() {
    let Some(corpus) = seeds() else {
        return;
    };
    let inside = seed(&corpus, "label_63.txt").text();
    let outside = seed(&corpus, "label_64.txt").text();
    assert_eq!(inside.split('.').next().unwrap().len(), MAX_LABEL_LEN);
    assert_eq!(outside.split('.').next().unwrap().len(), MAX_LABEL_LEN + 1);
    assert_eq!(DomainName::parse(&inside).unwrap().as_str(), inside);
    assert_eq!(Hostname::parse(&inside).unwrap().as_str(), inside);
    assert_validation(
        DomainName::parse(&outside).unwrap_err(),
        "label_64.txt",
        "domain",
    );
    assert_validation(
        Hostname::parse(&outside).unwrap_err(),
        "label_64.txt",
        "hostname",
    );

    let inside = seed(&corpus, "name_253.txt").text();
    let outside = seed(&corpus, "name_254.txt").text();
    assert_eq!(inside.len(), MAX_DOMAIN_LEN);
    assert_eq!(outside.len(), MAX_DOMAIN_LEN + 1);
    assert_eq!(DomainName::parse(&inside).unwrap().as_str(), inside);
    assert_eq!(Hostname::parse(&inside).unwrap().as_str(), inside);
    assert_validation(
        DomainName::parse(&outside).unwrap_err(),
        "name_254.txt",
        "domain",
    );
    assert_validation(
        Hostname::parse(&outside).unwrap_err(),
        "name_254.txt",
        "hostname",
    );
}

#[test]
fn name_seeds_classify_as_documented() {
    let Some(corpus) = seeds() else {
        return;
    };
    // Case folds and one trailing root dot is trimmed.
    for fixture in [
        "domain.txt",
        "domain_upper_trailing_dot.txt",
        "trailing_dot.txt",
    ] {
        assert_eq!(
            DomainName::parse(&seed(&corpus, fixture).text())
                .unwrap()
                .as_str(),
            "example.com",
            "{fixture}"
        );
    }
    // Empty, root and duplicate labels are refused, as are hyphen edges,
    // underscores, spaces and wildcards.
    for fixture in [
        "empty.txt",
        "nul_only.txt",
        "leading_dot.txt",
        "duplicate_dot.txt",
        "hyphen_edges.txt",
        "underscore.txt",
        "space_inside.txt",
        "wildcard.txt",
        "invalid_utf8.txt",
    ] {
        let text = seed(&corpus, fixture).text();
        assert_validation(DomainName::parse(&text).unwrap_err(), fixture, "domain");
        assert_validation(Hostname::parse(&text).unwrap_err(), fixture, "hostname");
    }
    // One label is a host name but not a domain name.
    let single = seed(&corpus, "single_label.txt").text();
    assert_eq!(Hostname::parse(&single).unwrap().as_str(), "localhost");
    assert_validation(
        DomainName::parse(&single).unwrap_err(),
        "single_label.txt",
        "domain",
    );

    // Unicode arrives in its ACE form and matches the punycode spelling.
    let unicode = DomainName::parse(&seed(&corpus, "idn_umlaut.txt").text()).unwrap();
    assert_eq!(unicode.as_str(), "xn--mnchen-3ya.de");
    assert!(unicode.is_idn());
    assert_eq!(unicode.tld(), "de");
    assert_eq!(unicode.sld(), "xn--mnchen-3ya");
    assert_eq!(
        DomainName::parse(&seed(&corpus, "idn_punycode.txt").text()).unwrap(),
        unicode
    );
    let emoji = DomainName::parse(&seed(&corpus, "idn_emoji.txt").text()).unwrap();
    assert_eq!(emoji.as_str(), "xn--938h.example");
    assert!(emoji.is_idn());
}

#[test]
fn record_seeds_sit_just_inside_and_just_outside_the_limits() {
    let Some(corpus) = seeds() else {
        return;
    };
    // Content: 1024 characters are the documented ceiling.
    let (name, content, _) = seed(&corpus, "content_1024.txt").fields();
    assert_eq!(content.len(), MAX_CONTENT_LEN);
    let spec = RecordSpec::txt(&name, &content).unwrap();
    assert_eq!(spec.content().len(), MAX_CONTENT_LEN);
    let (name, content, _) = seed(&corpus, "content_1025.txt").fields();
    assert_eq!(content.len(), MAX_CONTENT_LEN + 1);
    assert_validation(
        RecordSpec::txt(&name, &content).unwrap_err(),
        "content_1025.txt",
        "record.content",
    );
    // One character less is the same payload and must fit: the limit really is
    // the length, not something else about the content.
    let one_less = content.get(..MAX_CONTENT_LEN).unwrap();
    assert!(RecordSpec::txt(&name, one_less).is_ok());

    // TTL: the parameter is an `int`, so `i32::MAX` is the last legal value.
    for fixture in ["record_ttl_at_limit.txt", "record_ttl_over_limit.txt"] {
        let (name, content, ttl) = seed(&corpus, fixture).fields();
        let ttl = ttl.parse::<u64>().unwrap();
        let accepted = RecordSpec::a(&name, &content)
            .unwrap()
            .with_ttl(u32::try_from(ttl).unwrap_or(MAX_TTL))
            .is_ok();
        assert_eq!(
            accepted,
            ttl <= u64::from(MAX_TTL),
            "{fixture}: with_ttl({ttl}) against the {MAX_TTL} ceiling"
        );
    }

    // Record ids: 64 characters are the last legal token.
    let inside = seed(&corpus, "record_id_64.txt");
    let outside = seed(&corpus, "record_id_65.txt");
    assert_eq!(inside.bytes.len(), MAX_RECORD_ID_LEN);
    assert_eq!(
        RecordId::parse(inside.text()).unwrap().as_str().len(),
        MAX_RECORD_ID_LEN
    );
    assert_eq!(outside.bytes.len(), MAX_RECORD_ID_LEN + 1);
    assert_validation(
        RecordId::parse(outside.text()).unwrap_err(),
        "record_id_65.txt",
        "record.id",
    );
}

#[test]
fn record_seeds_classify_as_documented() {
    let Some(corpus) = seeds() else {
        return;
    };
    // `www \0 203.0.113.7 \0 3600` is a complete, valid line.
    let (name, content, ttl) = seed(&corpus, "record_line_nul.txt").fields();
    assert_eq!(
        (name.as_str(), content.as_str(), ttl.as_str()),
        ("www", "203.0.113.7", "3600")
    );
    let params = RecordSpec::a(&name, &content)
        .unwrap()
        .with_ttl(ttl.parse().unwrap())
        .unwrap()
        .params();
    assert_eq!(params["type"], "A");
    assert_eq!(params["name"], "www");
    assert_eq!(params["content"], "203.0.113.7");
    assert_eq!(params["ttl"], 3600);

    // An `MX` at the apex carries a host name, and the priority stays separate.
    let (name, content, prio) = seed(&corpus, "record_apex_mx.txt").fields();
    let spec = RecordSpec::mx(
        &name,
        prio.parse().unwrap(),
        &Hostname::parse(&content).unwrap(),
    )
    .unwrap();
    assert_eq!(spec.params()["prio"], 10);
    assert_eq!(spec.params()["content"], "mail.example.com");

    // A `TXT` value copied out of a zone file keeps its quotes — and must not be
    // published with them.
    let (name, content, _) = seed(&corpus, "record_txt_quoted.txt").fields();
    assert_validation(
        RecordSpec::txt(&name, &content).unwrap_err(),
        "record_txt_quoted.txt",
        "record.content",
    );

    // Whitespace and control characters never reach the wire.
    for fixture in [
        "record_line_space.txt",
        "newline_in_record.txt",
        "control_bell.txt",
    ] {
        let (name, _, _) = seed(&corpus, fixture).fields();
        let error = RecordSpec::txt(&name, "203.0.113.7").unwrap_err();
        assert_validation(error, fixture, "record.name");
    }
}
