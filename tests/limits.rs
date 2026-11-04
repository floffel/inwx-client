//! Boundary matrix for the types added in 0.2.0: every check gets the value
//! just inside the limit and the one just outside it.

use inwx_client::{
    parse_ip, AddDnsKeyRequest, ApplicationUpdate, AuthCode, AuthInfoUpdate, CertificateId,
    CertificateOrder, CertificateTerm, CertificateUpdate, Credentials, CustomerDownloadQuery,
    CustomerUpdate, DnsKey, DnssecKeyQuery, DomainLogQuery, DomainName, DsRecord, Email, Error,
    Handle, HostUpdate, HostingPeriod, Hostname, MessageAck, NameserverSetCreate,
    NameserverSetType, NicHandleQuery, Password, PdfRender, PostalDelivery, RefundRequest,
    RemoveClientHold, SetClientHold, StatementQuery, TagUpdate, Timestamp, TldGroup, TldRules,
    TransferCodeUpdate, ZoneCreate, ZoneUpdate, MAX_AUTH_CODE_LEN, MAX_DOMAIN_LEN, MAX_LABEL_LEN,
    MAX_PAGE_LIMIT, MAX_PASSWORD_LEN,
};
use zeroize::Zeroize as _;

fn domain(name: &str) -> DomainName {
    DomainName::parse(name).unwrap()
}

// ------------------------------------------------------------- credentials --

#[test]
fn usernames_of_64_characters_are_accepted_and_65_are_not() {
    let shortest = "u";
    let longest = "u".repeat(64);
    let too_long = "u".repeat(65);

    assert!(Credentials::new(shortest, "pass").is_ok());
    assert!(Credentials::new(longest.as_str(), "pass").is_ok());
    assert!(matches!(
        Credentials::new(too_long.as_str(), "pass").unwrap_err(),
        inwx_client::Error::Validation {
            field: "credentials.username",
            ..
        }
    ));

    // `text64` counts characters, not UTF-8 bytes.
    let unicode = "ü".repeat(64);
    assert!(Credentials::new(unicode.as_str(), "pass").is_ok());
    assert!(Credentials::new(format!("{unicode}ü").as_str(), "pass").is_err());
}

// ------------------------------------------------------------------ labels --

#[test]
fn a_label_of_63_bytes_is_accepted_and_64_is_not() {
    let ok = format!("{}.com", "a".repeat(63));
    let too_long = format!("{}.com", "a".repeat(64));
    assert_eq!(domain(&ok).as_str(), ok);
    assert!(DomainName::parse(&too_long).is_err());
    assert!(Hostname::parse(&too_long).is_err());

    // The same limit applies to a nested label.
    assert!(DomainName::parse(&format!("www.{ok}")).is_ok());
    assert!(DomainName::parse(&format!("www.{too_long}")).is_err());
}

#[test]
fn a_name_of_253_bytes_is_accepted_and_254_is_not() {
    assert_eq!(MAX_DOMAIN_LEN, 253);
    assert_eq!(MAX_LABEL_LEN, 63);

    // 253 characters: 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253. Every label is legal
    // on its own, so only the total-name limit can decide these outcomes.
    let name = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(name.len(), MAX_DOMAIN_LEN);
    assert!(name.split('.').all(|label| label.len() <= MAX_LABEL_LEN));
    assert_eq!(DomainName::parse(&name).unwrap().as_str(), name);
    assert_eq!(Hostname::parse(&name).unwrap().as_str(), name);

    // One byte more, added to a label that stays within 63 characters.
    let too_long = format!("{name}e");
    assert_eq!(too_long.len(), MAX_DOMAIN_LEN + 1);
    assert!(too_long
        .split('.')
        .all(|label| label.len() <= MAX_LABEL_LEN));
    for (expected_field, error) in [
        ("domain", DomainName::parse(&too_long).unwrap_err()),
        ("hostname", Hostname::parse(&too_long).unwrap_err()),
    ] {
        let Error::Validation { field, message } = error else {
            panic!("expected a validation error, got {error}");
        };
        assert_eq!(field, expected_field);
        // The length check lives in `idna`, so the message quotes both limits
        // it enforces instead of a byte count the caller cannot act on.
        assert!(message.contains("253"), "{message}");
        assert!(message.contains("63"), "{message}");
        assert!(
            !message.contains("is not a valid"),
            "a length rejection must not be reported as a shape rejection: {message}"
        );
    }
}

/// The clientHold pair takes `domain` as `token255`, and the builders only
/// accept an already validated [`DomainName`] — so the boundary is the name
/// type's, and a request can never carry an oversized or empty name to the wire.
#[test]
fn a_client_hold_request_carries_the_longest_name_and_refuses_longer_ones() {
    let name = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(name.len(), MAX_DOMAIN_LEN);

    // Just inside the limit: the name survives into both parameter bodies
    // byte for byte.
    let held = DomainName::parse(&name).unwrap();
    for params in [
        SetClientHold::new(held.clone()).params(),
        RemoveClientHold::new(held.clone()).params(),
    ] {
        assert_eq!(params["domain"], name);
        assert_eq!(params.as_object().unwrap().len(), 2);
    }

    // Just outside it, and empty: no request object can be built at all.
    let too_long = format!("{name}e");
    assert_eq!(too_long.len(), MAX_DOMAIN_LEN + 1);
    for bad in [&too_long, ""] {
        let error = DomainName::parse(bad).unwrap_err();
        let Error::Validation { field, .. } = error else {
            panic!("expected a validation error, got {error}");
        };
        assert_eq!(field, "domain");
    }
}

#[test]
fn an_empty_label_is_refused_everywhere() {
    assert!(DomainName::parse("a..com").is_err());
    assert!(DomainName::parse("a..").is_err());
    assert!(DomainName::parse(".com").is_err());
    assert!(DomainName::parse("a.com.").is_ok()); // the root dot is trimmed
    assert!(DomainName::parse("a.com..").is_err());
    assert!(Hostname::parse("ns1..example.com").is_err());
    assert!(Hostname::parse("ns1...").is_err());
    assert!(Email::parse("a@.example.com").is_err());
    assert!(ZoneCreate::master(domain("example.com")).is_ok());
}

#[test]
fn a_hyphen_is_allowed_inside_a_label_but_not_at_its_edges() {
    assert_eq!(domain("a-b.com").as_str(), "a-b.com");
    // A doubled hyphen in the middle is legal — it is what an `xn--` label is
    // made of — so the rule really is about the edges, not about hyphens.
    assert_eq!(domain("aaa--bbb.de").as_str(), "aaa--bbb.de");
    assert_eq!(domain("xn--bcher-kva.de").as_str(), "xn--bcher-kva.de");
    for bad in [
        "-ab.com",
        "ab-.com",
        "a.-b.com",
        "a.b-.com",
        "-localhost",
        "localhost-",
    ] {
        assert!(DomainName::parse(bad).is_err(), "{bad:?}");
        assert!(Hostname::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_character_outside_the_std3_alphabet_is_refused() {
    // Letters, digits and a hyphen in the middle: the whole legal alphabet, in
    // one name.
    assert_eq!(domain("a-1.com").as_str(), "a-1.com");
    for bad in [
        "a_b.com", "a+b.com", "a!b.com", "a%b.com", "a~b.com", "a b.com",
    ] {
        assert!(DomainName::parse(bad).is_err(), "{bad:?}");
        assert!(Hostname::parse(bad).is_err(), "{bad:?}");
    }
    // U+FF3F FULLWIDTH LOW LINE maps onto `_` under UTS-46, so it trips the very
    // same rule as a plain underscore.
    assert!(DomainName::parse("a\u{FF3F}b.com").is_err());
    assert!(Hostname::parse("a\u{FF3F}b.com").is_err());
}

#[test]
fn a_rejected_name_says_which_rule_it_broke() {
    let message = |input: &str| match DomainName::parse(input) {
        Err(Error::Validation { field, message }) => {
            assert_eq!(field, "domain");
            message
        }
        other => panic!("expected a validation error for {input:?}, got {other:?}"),
    };

    assert_eq!(message(""), "must not be empty");
    // Length: the message quotes both limits, a shape rejection must not.
    let too_long = format!("{}.com", "a".repeat(250));
    assert!(message(&too_long).contains("253"), "{}", message(&too_long));
    let long_label = format!("{}.com", "a".repeat(64));
    assert!(
        message(&long_label).contains("63"),
        "{}",
        message(&long_label)
    );
    assert!(message("a..com").contains("empty labels"));
    assert!(message("under_score.com").contains("not a valid domain name"));
    assert!(!message("under_score.com").contains("253"));
    assert!(message("localhost").contains("at least one dot"));

    let host = match Hostname::parse("under_score.com") {
        Err(Error::Validation { field, message }) => {
            assert_eq!(field, "hostname");
            message
        }
        other => panic!("expected a validation error, got {other:?}"),
    };
    assert!(host.contains("not a valid host name"), "{host}");
}

#[test]
fn a_unicode_name_is_sent_in_its_idn_form() {
    let zone = ZoneCreate::master(domain("München.de")).unwrap();
    let params = zone.params().unwrap();
    assert_eq!(params["domain"], "xn--mnchen-3ya.de");

    let host = Hostname::parse("Bücher.Example.COM").unwrap();
    assert_eq!(host.as_str(), "xn--bcher-kva.example.com");
}

// ------------------------------------------------------------------- email --

#[test]
fn email_boundaries() {
    assert!(Email::parse("hostmaster@example.com").is_ok());
    assert_eq!(
        Email::parse(" Hostmaster@Example.COM ").unwrap().as_str(),
        "Hostmaster@Example.COM"
    );
    let local_64 = format!("{}@example.com", "a".repeat(64));
    let local_65 = format!("{}@example.com", "a".repeat(65));
    assert!(Email::parse(&local_64).is_ok());
    assert!(Email::parse(&local_65).is_err());
    let long_domain = format!("a@{}", "b".repeat(250));
    assert!(Email::parse(&long_domain).is_err());
    for bad in [
        "",
        " ",
        "no-at-sign",
        "@example.com",
        "a@",
        "a@@example.com",
        "a b@example.com",
        "a@localhost",
        "a@exa mple.com",
        "with\nnewline@example.com",
    ] {
        assert!(Email::parse(bad).is_err(), "{bad:?}");
    }
}

// --------------------------------------------------------------- auth codes --

#[test]
fn auth_code_boundaries() {
    assert_eq!(MAX_AUTH_CODE_LEN, 255);

    assert!(AuthCode::new("a").is_ok());
    // Just inside the cap, exactly on it, and one character outside.
    let at_limit = "x".repeat(MAX_AUTH_CODE_LEN);
    let one_shorter = "x".repeat(MAX_AUTH_CODE_LEN - 1);
    let one_longer = "x".repeat(MAX_AUTH_CODE_LEN + 1);
    assert_eq!(AuthCode::new(&one_shorter).unwrap().as_str(), one_shorter);
    assert_eq!(AuthCode::new(&at_limit).unwrap().as_str(), at_limit);
    let Error::Validation { field, message } = AuthCode::new(&one_longer).unwrap_err() else {
        panic!("an oversized code must be rejected");
    };
    assert_eq!(field, "authCode");
    assert!(message.contains("at most"), "{message}");

    // Empty, whitespace-only and every shape that hides behind trimming.
    for bad in ["", " ", "\t\n", "   "] {
        let error = AuthCode::new(bad).unwrap_err();
        let Error::Validation { field, .. } = error else {
            panic!("{bad:?} must be rejected");
        };
        assert_eq!(field, "authCode");
    }
    // Surrounding whitespace is trimmed, so this is the same code as "a".
    assert_eq!(AuthCode::new("  a  ").unwrap().as_str(), "a");

    // Embedded whitespace, control characters and NUL never get in.
    for bad in [
        "with space",
        "two\twords",
        "line\nbreak",
        "a\u{0}b",
        "bell\u{7}",
        "del\u{7f}",
    ] {
        let error = AuthCode::new(bad).unwrap_err();
        let Error::Validation { field, .. } = error else {
            panic!("{bad:?} must be rejected");
        };
        assert_eq!(field, "authCode");
    }

    // Non-ASCII is refused; the error text never carries the code itself.
    for bad in ["Ümlaut", "日本", "\u{200b}zero", "emoji\u{1f600}"] {
        let error = AuthCode::new(bad).unwrap_err();
        let Error::Validation { message, .. } = error else {
            panic!("{bad:?} must be rejected");
        };
        assert!(!message.contains(bad), "the error leaks the code");
    }

    // The size check runs on bytes before the character checks, so a
    // multi-byte string that passes the cap still fails on the alphabet, and
    // one that exceeds it is reported as oversized rather than non-ASCII.
    let just_inside = "\u{e4}".repeat(MAX_AUTH_CODE_LEN / 2);
    assert_eq!(just_inside.len(), 254);
    let Error::Validation { message, .. } = AuthCode::new(&just_inside).unwrap_err() else {
        panic!("non-ASCII must be rejected");
    };
    assert!(message.contains("printable ASCII"), "{message}");
    let just_outside = "\u{e4}".repeat(MAX_AUTH_CODE_LEN / 2 + 1);
    assert_eq!(just_outside.len(), 256);
    let Error::Validation { message, .. } = AuthCode::new(&just_outside).unwrap_err() else {
        panic!("an oversized non-ASCII string must be rejected");
    };
    assert!(message.contains("at most"), "{message}");

    // Every printable ASCII byte round-trips unchanged.
    for byte in 0x21u8..=0x7e {
        let code = format!("{}", char::from(byte));
        assert_eq!(AuthCode::new(&code).unwrap().as_str(), code);
    }
}

// ---------------------------------------------- transfer lock and auth codes --

/// The longest name the type accepts, built so no single label is the reason.
fn longest_domain() -> String {
    format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    )
}

#[test]
fn transfer_control_requests_take_the_largest_valid_input() {
    let name = longest_domain();
    assert_eq!(name.len(), MAX_DOMAIN_LEN);
    let code = "x".repeat(MAX_AUTH_CODE_LEN);

    for kind in ["authInfo", "transferCode"] {
        let params = match kind {
            "authInfo" => AuthInfoUpdate::new(
                DomainName::parse(&name).unwrap(),
                AuthCode::new(code.clone()).unwrap(),
            )
            .params(),
            _ => TransferCodeUpdate::new(
                DomainName::parse(&name).unwrap(),
                AuthCode::new(code.clone()).unwrap(),
            )
            .params(),
        };
        assert_eq!(params["domain"], name);
        assert_eq!(params["authCode"].as_str().unwrap(), code);
        assert_eq!(
            params.as_object().map(serde_json::Map::len),
            Some(2),
            "{kind}"
        );
    }

    // One byte outside either limit cannot be built at all, so it can never
    // reach the wire.
    assert!(DomainName::parse(&format!("{name}e")).is_err());
    assert!(AuthCode::new("x".repeat(MAX_AUTH_CODE_LEN + 1)).is_err());
    assert!(AuthCode::new("").is_err());
}

// ---------------------------------------------------------------- passwords --

#[test]
fn password_boundaries() {
    // Just inside the limit, and one character outside it.
    assert!(Password::new("x").is_ok());
    assert!(Password::new("x".repeat(MAX_PASSWORD_LEN)).is_ok());
    assert!(Password::new("x".repeat(MAX_PASSWORD_LEN + 1)).is_err());

    // The limit is measured in characters, so a two-byte secret crosses it at
    // the same place an ASCII one does.
    assert!(Password::new("ö".repeat(MAX_PASSWORD_LEN)).is_ok());
    assert!(Password::new("ö".repeat(MAX_PASSWORD_LEN + 1)).is_err());

    // Fail closed on blank, and on control characters (they would break the
    // JSON body / terminal echo).
    for bad in ["", " ", "  \n "] {
        assert!(Password::new(bad).is_err(), "{bad:?}");
    }
    for bad in ["line\nbreak", "tab\there", "nul\0byte"] {
        assert!(Password::new(bad).is_err(), "{bad:?}");
    }

    // Unlike an auth code, spaces and non-ASCII characters are legal; they are
    // kept exactly as given instead of being trimmed.
    for good in ["p4ss wörd", "  kept  ", "ünicode ✓"] {
        let password = Password::new(good).unwrap();
        assert_eq!(password.as_str(), good);
    }

    // The secret never leaks through the two formatting traits.
    let password = Password::new("s3cret").unwrap();
    assert_eq!(format!("{password:?}"), "Password(<redacted>)");
    assert_eq!(password.to_string(), "<redacted>");

    // One character apart is still unequal; identical values are equal.
    assert_eq!(password, Password::new("s3cret").unwrap());
    assert_ne!(password, Password::new("s3creu").unwrap());

    // Zeroizing wipes the buffer instead of leaving it for the allocator.
    let mut wipe = Password::new("s3cret").unwrap();
    wipe.zeroize();
    assert_eq!(wipe.as_str(), "");
}

// ------------------------------------------------------------------ handles --

#[test]
fn handle_boundaries() {
    assert!(Handle::new(1).is_ok());
    assert!(Handle::new(i64::from(i32::MAX)).is_ok());
    assert!(Handle::new(0).is_err());
    assert!(Handle::new(-1).is_err());
    assert!(Handle::new(i64::from(i32::MAX) + 1).is_err());
    assert!(Handle::try_from(i64::MIN).is_err());
}

#[test]
fn validate_id_backed_types_share_the_documented_int_boundaries() {
    for (valid, just_above) in [
        (1_i64, i64::from(i32::MAX) + 1),
        (i64::from(i32::MAX), i64::from(i32::MAX) + 1),
    ] {
        assert!(ApplicationUpdate::new(valid).is_ok());
        assert!(CustomerUpdate::new(valid).is_ok());
        assert!(CustomerDownloadQuery::new(valid).is_ok());
        assert!(HostUpdate::new(valid).is_ok());
        assert!(MessageAck::new(valid).is_ok());
        assert!(PdfRender::new("invoice", valid).is_ok());
        assert!(NicHandleQuery::new().with_customer_number(valid).is_ok());

        assert!(ApplicationUpdate::new(just_above).is_err());
        assert!(CustomerUpdate::new(just_above).is_err());
        assert!(CustomerDownloadQuery::new(just_above).is_err());
        assert!(HostUpdate::new(just_above).is_err());
        assert!(MessageAck::new(just_above).is_err());
        assert!(PdfRender::new("invoice", just_above).is_err());
        assert!(NicHandleQuery::new()
            .with_customer_number(just_above)
            .is_err());
    }

    for invalid in [0, -1] {
        assert!(ApplicationUpdate::new(invalid).is_err());
        assert!(CustomerUpdate::new(invalid).is_err());
        assert!(CustomerDownloadQuery::new(invalid).is_err());
        assert!(HostUpdate::new(invalid).is_err());
        assert!(MessageAck::new(invalid).is_err());
        assert!(PdfRender::new("invoice", invalid).is_err());
        assert!(NicHandleQuery::new().with_customer_number(invalid).is_err());
    }
}

// --------------------------------------------------------------- timestamps --

#[test]
fn timestamp_boundaries() {
    let at = Timestamp::parse("2026-11-01T03:00:00").unwrap();
    assert_eq!(at.as_str(), "2026-11-01T03:00:00");
    assert_eq!(
        Timestamp::parse(" 2026-11-01T03:00:00 ").unwrap().as_str(),
        "2026-11-01T03:00:00"
    );
    // Offsets are normalised for comparison and rewritten for the wire.
    let zoned = Timestamp::parse("2026-11-01T04:00:00+01:00").unwrap();
    assert_eq!(zoned, at);
    assert_eq!(zoned.as_str(), "2026-11-01T03:00:00");
    assert_eq!(zoned.to_string(), "2026-11-01T03:00:00");
    assert_eq!(
        serde_json::to_string(&zoned).unwrap(),
        "\"2026-11-01T03:00:00\""
    );
    assert_eq!(
        Timestamp::parse("2026-11-01T03:00:00Z").unwrap().as_str(),
        "2026-11-01T03:00:00"
    );
    assert!(Timestamp::parse("2026-11-01T05:00:00+01:00").unwrap() > at);

    for bad in [
        "",
        "2026-11-01",                // a date is not a timestamp
        "2026-13-01T00:00:00",       // month 13
        "2026-02-30T00:00:00",       // impossible day
        "2026-11-01T24:00:00",       // hour 24
        "01.11.2026 03:00:00",       // German format
        "2026-11-01T03:00:00+99:00", // offset out of range
        "2026-11-01T03:00:00.5",     // fractional seconds are undocumented
        "2026-11-01T03:00:00+0100",  // offset must carry the colon
    ] {
        assert!(Timestamp::parse(bad).is_err(), "{bad:?}");
    }
}

// ------------------------------------------------------------------- DNSSEC --

#[test]
fn dnskey_boundaries() {
    assert!(DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12").is_ok());
    // A ZONE key is rejected: only ZONE+SEP is accepted by the API.
    assert!(DnsKey::parse("example.com. IN DNSKEY 256 3 13 ac12").is_err());
    // Protocol must be 3.
    assert!(DnsKey::parse("example.com. IN DNSKEY 257 2 13 ac12").is_err());
    // Too few tokens.
    assert!(DnsKey::parse("example.com. IN DNSKEY 257 3 13").is_err());
    // Undocumented algorithm.
    assert!(DnsKey::parse("example.com. IN DNSKEY 257 3 99 ac12").is_err());
    // Wrong record type / class.
    assert!(DnsKey::parse("example.com. IN DS 257 3 13 ac12").is_err());
    assert!(DnsKey::parse("example.com. CH DNSKEY 257 3 13 ac12").is_err());
    // Over-long presentation.
    assert!(DnsKey::parse(&"x".repeat(1025)).is_err());

    assert!(DsRecord::parse("example.com. IN DS 0 13 2 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").is_ok());
    assert!(DsRecord::parse("example.com. IN DS 65535 13 2 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").is_ok());
    assert!(DsRecord::parse("example.com. IN DS 65536 13 2 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").is_err());
    assert!(DsRecord::parse("example.com. IN DS 1 13 2 ZZ").is_err());
    assert!(DsRecord::parse("example.com. IN DS 1 99 2 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").is_err());
}

#[test]
fn ds_owner_boundary() {
    let request = || {
        AddDnsKeyRequest::new(
            domain("example.com"),
            DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12").unwrap(),
        )
        .unwrap()
    };
    let ds = |owner: &str| {
        DsRecord::parse(&format!("{owner} IN DS 1234 13 2 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")).unwrap()
    };

    // Just inside: the zone itself, with or without the presentation dot and
    // in any ASCII case — `DomainName` stores the lower-cased form.
    for owner in ["example.com.", "example.com", "Example.COM."] {
        assert!(request().with_ds(ds(owner)).is_ok(), "{owner}");
        assert_eq!(ds(owner).owner(), owner);
    }

    // Just outside: a parent, a child, a sibling and a name that only looks
    // like the zone. Each is a different zone, so the digest would be keyed
    // to the wrong `domainName`.
    for owner in [
        "com.",
        "sub.example.com.",
        "example.net.",
        "example.com.evil.",
        "example.co",
    ] {
        assert!(request().with_ds(ds(owner)).is_err(), "{owner}");
    }
}

#[test]
fn ds_digest_is_checked_against_its_type() {
    // 32 bytes for SHA-256, 48 for SHA-384 — the lengths RFC 4034 and RFC 6605 fix.
    let sha256 = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
    let sha384 = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF\
                  00112233445566778899AABBCCDDEEFF";
    assert_eq!(sha256.len(), 64);
    assert_eq!(sha384.len(), 96);

    // Just inside.
    assert!(DsRecord::parse(&format!("example.com. IN DS 1 13 2 {sha256}")).is_ok());
    assert!(DsRecord::parse(&format!("example.com. IN DS 1 13 4 {sha384}")).is_ok());

    // Just outside, on both sides: 31 and 33 bytes, 47 and 49 bytes.
    for digest in [sha256[..62].to_owned(), format!("{sha256}0000")] {
        assert!(
            DsRecord::parse(&format!("example.com. IN DS 1 13 2 {digest}")).is_err(),
            "{digest}"
        );
    }
    for digest in [sha384[..94].to_owned(), format!("{sha384}0000")] {
        assert!(
            DsRecord::parse(&format!("example.com. IN DS 1 13 4 {digest}")).is_err(),
            "{digest}"
        );
    }

    // A digest of the other type's length is not "close enough".
    assert!(DsRecord::parse(&format!("example.com. IN DS 1 13 4 {sha256}")).is_err());

    // The six-character digest the old parser accepted, and the error that now
    // says what was expected instead of "not hex".
    let error = DsRecord::parse("example.com. IN DS 1234 13 2 56DC12")
        .unwrap_err()
        .to_string();
    assert!(error.contains("32 bytes"), "{error}");
}

#[test]
fn ds_token_count_is_exact() {
    let digest = "00".repeat(32);

    assert!(DsRecord::parse(&format!("example.com. IN DS 1 13 2 {digest}")).is_ok());

    // An eighth token: `raw` is what gets sent, so trailing text is refused
    // rather than shipped along with the digest.
    assert!(DsRecord::parse(&format!("example.com. IN DS 1 13 2 {digest} garbage")).is_err());
    // A sixth: the digest type and the digest are both missing.
    assert!(DsRecord::parse("example.com. IN DS 1 13 2").is_err());

    // The 1024-character cap is checked before the split, so neither a huge
    // input nor its neighbour is buffered and parsed.
    let error = DsRecord::parse(&"x".repeat(1025)).unwrap_err().to_string();
    assert!(error.contains("1024"), "{error}");
    assert!(DsRecord::parse(&"x".repeat(1024)).is_err());
}

#[test]
fn dnskey_material_must_be_base64() {
    // Just inside: canonical base64 for three bytes.
    assert!(DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12").is_ok());

    // Just outside: a lone symbol, a character outside the alphabet, and a
    // length whose last character carries bits that are not there.
    for key in ["k", "ac12!", "ac12c2", "===="] {
        assert!(
            DnsKey::parse(&format!("example.com. IN DNSKEY 257 3 13 {key}")).is_err(),
            "{key}"
        );
    }

    // Key material wrapped over two lines by a zone-file dump is still one
    // base64 string, and the presentation is kept as written.
    let wrapped = DnsKey::parse("example.com. IN DNSKEY 257 3 13 ac12 ac12").unwrap();
    assert_eq!(
        wrapped.as_str(),
        "example.com. IN DNSKEY 257 3 13 ac12 ac12"
    );
}

#[test]
fn dnssec_query_ranges_are_ordered() {
    let early = Timestamp::parse("2026-01-01T00:00:00").unwrap();
    let late = Timestamp::parse("2026-12-31T23:59:59").unwrap();
    assert!(DnssecKeyQuery::new()
        .created_after(&early)
        .unwrap()
        .created_before(&late)
        .is_ok());
    assert!(DnssecKeyQuery::new()
        .created_before(&early)
        .unwrap()
        .created_after(&late)
        .is_err());
    // The same instant on both sides is a valid (empty) range.
    assert!(DnssecKeyQuery::new()
        .created_after(&early)
        .unwrap()
        .created_before(&early)
        .is_ok());
}

// ------------------------------------------------------------ certificates --

#[test]
fn certificate_limits() {
    let base = || {
        CertificateOrder::new(17)
            .unwrap()
            .with_common_name(domain("example.com"))
    };

    // 10 000 characters of CSR is the documented maximum.
    let csr = format!(
        "-----BEGIN CERTIFICATE REQUEST-----{}-----END CERTIFICATE REQUEST-----",
        "A".repeat(9_900)
    );
    assert!(base().with_csr(&csr).is_ok());
    let too_long = format!("-----BEGIN CERTIFICATE REQUEST-----{}", "A".repeat(10_001));
    assert!(base().with_csr(&too_long).is_err());

    // SAN counts fit the `int` the API asks for; the builder takes u16.
    assert_eq!(
        base().with_san_count(u16::MAX, 0).params().unwrap()["numberOfSan"],
        65535
    );

    // Terms are 1 or 2 years.
    assert!(CertificateTerm::try_from(1u8).is_ok());
    assert!(CertificateTerm::try_from(2u8).is_ok());
    assert!(CertificateTerm::try_from(0u8).is_err());
    assert!(CertificateTerm::try_from(3u8).is_err());

    // Certificate ids are positive.
    assert!(CertificateId::new(1).is_ok());
    assert!(CertificateId::new(i64::MAX).is_ok());
    assert!(CertificateId::new(0).is_err());
    assert!(CertificateId::new(-1).is_err());

    // An update with no change is refused.
    assert!(CertificateUpdate::new(CertificateId::new(1).unwrap())
        .unwrap()
        .params()
        .is_err());
}

// ------------------------------------------------------------------ zones --

#[test]
fn zone_builders_have_limits_too() {
    let ns = Hostname::parse("ns1.example.net").unwrap();

    // Nameserver lists are non-empty and unique.
    assert!(ZoneCreate::master(domain("a.de"))
        .unwrap()
        .with_nameservers(&[])
        .is_err());
    assert!(ZoneUpdate::new(domain("a.de"))
        .with_nameservers(&[])
        .is_err());

    // A token field rejects 256 characters and accepts 255.
    let long = "x".repeat(255);
    assert!(ZoneCreate::master(domain("a.de"))
        .unwrap()
        .with_web(&long)
        .is_ok());
    assert!(ZoneCreate::master(domain("a.de"))
        .unwrap()
        .with_web(format!("{long}x"))
        .is_err());

    // Frame metadata needs a FRAME redirect.
    assert!(ZoneCreate::master(domain("a.de"))
        .unwrap()
        .with_web("https://example.net")
        .unwrap()
        .with_redirect_type(inwx_client::UrlRedirectType::Header301)
        .unwrap()
        .with_frame_title("x")
        .is_err());

    assert!(
        NameserverSetCreate::new(NameserverSetType::Primary, std::slice::from_ref(&ns)).is_ok()
    );
    assert!(NameserverSetCreate::new(NameserverSetType::Primary, &[]).is_err());
}

// ------------------------------------------------------------------- misc --

#[test]
fn hosting_and_tag_limits() {
    for months in [1u32, 3, 6, 12, 18, 24] {
        assert!(HostingPeriod::try_from(months).is_ok());
    }
    for months in [0u32, 2, 9, 25, 100] {
        assert!(HostingPeriod::try_from(months).is_err());
    }

    assert!(TagUpdate::new(1).unwrap().tagging(&[1]).is_ok());
    assert!(TagUpdate::new(1).unwrap().tagging(&[0]).is_err());
    assert!(TagUpdate::new(i64::MAX).is_ok());
    assert!(TagUpdate::new(0).is_err());
}

#[test]
fn postal_and_refund_limits() {
    assert!(PostalDelivery::new(&"i".repeat(255), true).is_ok());
    assert!(PostalDelivery::new(&"i".repeat(256), true).is_err());

    let intent =
        inwx_client::Irreversible::acknowledge(inwx_client::ActionKind::Refund, &domain("a.de"));
    assert!(RefundRequest::new(intent.clone(), i64::MAX, 0.01).is_ok());
    assert!(RefundRequest::new(intent.clone(), 1, f64::INFINITY).is_err());
    assert!(RefundRequest::new(intent, 1, -0.01).is_err());
}

#[test]
fn statement_ranges_are_strict() {
    let earlier = Timestamp::parse("2026-01-01T00:00:00").unwrap();
    let later = Timestamp::parse("2026-12-31T00:00:00").unwrap();
    assert!(StatementQuery::new(earlier.clone(), later.clone()).is_ok());
    // Equal endpoints are not a range.
    assert!(StatementQuery::new(later.clone(), later.clone()).is_err());
    assert!(StatementQuery::new(later, earlier).is_err());
}

#[test]
fn ip_parsing_covers_both_families() {
    assert!(parse_ip("0.0.0.0").unwrap().is_ipv4());
    assert!(parse_ip("255.255.255.255").unwrap().is_ipv4());
    assert!(parse_ip("::").unwrap().is_ipv6());
    assert!(parse_ip("2001:db8::1").unwrap().is_ipv6());
    for bad in [
        "",
        "256.0.0.1",
        "1.2.3",
        "1.2.3.4/24",
        "fe80::1%eth0",
        "localhost",
    ] {
        assert!(parse_ip(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_log_range_needs_one_second_of_span() {
    let start = Timestamp::parse("2026-01-01T00:00:00").unwrap();
    let one_second_on = Timestamp::parse("2026-01-01T00:00:01").unwrap();
    // The smallest legal range, then the one just outside it (empty), then the
    // inverted one.
    assert!(DomainLogQuery::new(domain("example.com"))
        .with_range(start.clone(), one_second_on.clone())
        .is_ok());
    // Empty (equal endpoints) and inverted are both refused.
    assert!(DomainLogQuery::new(domain("example.com"))
        .with_range(start.clone(), start.clone())
        .is_err());
    assert!(DomainLogQuery::new(domain("example.com"))
        .with_range(one_second_on, start)
        .is_err());
}

// ------------------------------------------------------------- diagnostics --

#[test]
fn a_pagelimit_of_1000_is_accepted_and_1001_is_not() {
    // Just inside the upper bound, and one below it.
    assert!(DomainLogQuery::new(domain("example.com"))
        .with_page(1, MAX_PAGE_LIMIT)
        .is_ok());
    assert!(DomainLogQuery::new(domain("example.com"))
        .with_page(1, MAX_PAGE_LIMIT - 1)
        .is_ok());
    // Just outside it, and the smallest legal value at the other end.
    assert!(DomainLogQuery::new(domain("example.com"))
        .with_page(1, MAX_PAGE_LIMIT + 1)
        .is_err());
    assert!(DomainLogQuery::new(domain("example.com"))
        .with_page(1, 1)
        .is_ok());
    assert!(DomainLogQuery::new(domain("example.com"))
        .with_page(1, 0)
        .is_err());
}

#[test]
fn a_tld_group_counts_its_tlds_without_losing_the_empty_case() {
    let one: TldGroup = serde_json::from_str(r#"{"tld":"de"}"#).unwrap();
    assert_eq!(one.tld_count(), 1);
    assert!(!one.is_empty());
    let none: TldGroup = serde_json::from_str(r#"{"tldGroup":"empty","tld":[]}"#).unwrap();
    assert_eq!(none.tld_count(), 0);
    assert!(none.is_empty());

    let rules: TldRules =
        serde_json::from_str(r#"{"count":2,"rules":[{"name":"A","value":"1"}]}"#).unwrap();
    assert_eq!(rules.len(), 1);
    assert!(rules.has_more());
}

#[test]
fn log_pages_start_at_one() {
    assert!(DomainLogQuery::new(domain("example.com"))
        .with_page(1, 10)
        .is_ok());
    // One below the first page number is refused; the first page itself is not.
    assert!(DomainLogQuery::new(domain("example.com"))
        .with_page(0, 10)
        .is_err());
}
