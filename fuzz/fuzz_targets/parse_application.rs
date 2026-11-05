//! Fuzz target: the permissive `Application` decoders fed by the remote API.
//!
//! `ApplicationType` is the only hand-written `Deserialize` impl in this area,
//! and `ApplicationCheckResult` reaches that same parser through its optional
//! `type` field. Both values arrive from a remote system, so arbitrary bytes
//! must either decode or return `serde_json::Error`; no input may panic.
//!
//! Run with `cargo +nightly fuzz run parse_application`.

#![no_main]

use inwx_client::{Application, ApplicationCheckResult};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<Application>(data);
    let _ = serde_json::from_slice::<ApplicationCheckResult>(data);
});
