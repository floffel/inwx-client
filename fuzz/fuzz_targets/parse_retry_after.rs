#![no_main]

//! A `Retry-After` value comes straight off the wire, so it must never panic
//! and must never invent a delay it cannot read.
//!
//! The one invariant a second implementation can state without repeating the
//! parser: a value made only of digits is that many whole seconds, or `None`
//! when the number does not fit a `u64` — never a wrapped, short delay.

use libfuzzer_sys::fuzz_target;
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    // The header is text; invalid UTF-8 has already been rejected by the header
    // layer, but a lossy conversion keeps the fuzzer exploring instead of
    // bailing out on the first non-ASCII byte.
    let value = String::from_utf8_lossy(data);
    let parsed = inwx_client::retry_after_from_header(&value);

    let trimmed = (*value).trim();
    if !trimmed.is_empty() && trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        let expected = trimmed.parse::<u64>().ok().map(Duration::from_secs);
        assert_eq!(parsed, expected, "{trimmed:?} is delay-seconds");
    }

    // No text can produce a delay larger than the format itself can express.
    if let Some(delay) = parsed {
        assert!(delay <= Duration::from_secs(u64::MAX));
    }
});
