//! Fuzz target: DNS name parsing must never panic, whatever bytes arrive, and
//! whatever it accepts must already be in the canonical ASCII form the client
//! puts on the wire.
//!
//! Run with `cargo +nightly fuzz run parse_name` (see the README for the
//! corpus and how to reproduce a crash).

#![no_main]

use inwx_client::{DomainName, Hostname, MAX_DOMAIN_LEN, MAX_LABEL_LEN};

/// Everything the crate promises about a name it accepted.
fn assert_canonical(ascii: &str) {
    assert!(ascii.len() <= MAX_DOMAIN_LEN);
    assert_eq!(ascii, ascii.to_lowercase());
    assert!(!ascii.starts_with('.'));
    assert!(!ascii.ends_with('.'));
    for label in ascii.split('.') {
        assert_ne!(label, "");
        assert!(label.len() <= MAX_LABEL_LEN);
        assert!(!label.starts_with('-'));
        assert!(!label.ends_with('-'));
        assert!(label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-'));
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // A host name is the weaker of the two parsers: it accepts every domain.
    let Ok(host) = Hostname::parse(text) else {
        return;
    };
    assert_canonical(host.as_str());

    // Canonicalising an accepted name a second time must be a no-op.
    let again = Hostname::parse(host.as_str())
        .map(|again| again.as_str().to_owned())
        .ok();
    assert_eq!(again.as_deref(), Some(host.as_str()), "re-parsing {text:?}");

    // A domain is a host name that carries a TLD, so the two parsers have to
    // agree as soon as the canonical form has a dot.
    let domain = DomainName::parse(text)
        .map(|domain| domain.as_str().to_owned())
        .ok();
    if host.as_str().contains('.') {
        assert_eq!(domain.as_deref(), Some(host.as_str()), "domain {text:?}");
    } else {
        assert!(domain.is_none(), "{text:?} was accepted without a TLD");
    }
});
