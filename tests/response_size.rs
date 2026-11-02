//! Issue #18: a response must not decide how much memory the process allocates.
//!
//! The boundary matrix for the transport's body cap — exactly at the cap, one
//! byte over, with and without `Content-Length`, and the empty body — driven
//! through the shared `MockTransport`, which runs a scripted body through the
//! very same [`read_capped_body`] the reqwest transport streams over.

mod common;

use std::sync::OnceLock;

use common::{client, BufferChunks, MockTransport, Reply, CHUNK_LEN};
use inwx_client::transport::Response;
use inwx_client::{read_capped_body, Error, DEFAULT_MAX_RESPONSE_BYTES};
use proptest::prelude::*;
use serde_json::json;

/// A success envelope; every test sizes its cap from this body's byte length, so
/// the boundary is a real answer and not a padded stand-in.
fn success_body() -> String {
    json!({"code": 1000, "msg": "Command completed successfully", "resData": {"count": 1}})
        .to_string()
}

/// One runtime for the synchronous property test.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| tokio::runtime::Runtime::new().expect("a runtime for the property test"))
}

fn is_too_large(error: &Error, limit: u64, observed: Option<u64>) -> bool {
    matches!(
        error,
        Error::ResponseTooLarge { limit: seen, observed: seen_observed }
            if *seen == limit && *seen_observed == observed
    )
}

// ------------------------------------------------------- the boundary matrix --

#[tokio::test]
async fn a_body_exactly_at_the_cap_is_delivered_and_parsed() {
    let body = success_body();
    let transport = MockTransport::new().with_max_response_bytes(body.len() as u64);
    transport.push(Reply::Body(body));

    let data = client(transport)
        .call("account.info", json!({}))
        .await
        .expect("exactly at the cap is inside it");
    assert_eq!(data["count"], 1);
}

#[tokio::test]
async fn one_byte_over_the_cap_is_refused_and_never_retried() {
    let body = success_body();
    let len = body.len() as u64;
    let transport = MockTransport::new().with_max_response_bytes(len - 1);
    transport.push(Reply::Body(body));

    // `client()` retries three times, so a single call proves the error is
    // terminal rather than a transport hiccup.
    let error = client(transport.clone())
        .call("account.info", json!({}))
        .await
        .unwrap_err();

    assert!(is_too_large(&error, len - 1, Some(len)), "{error}");
    assert!(!error.is_retryable());
    assert_eq!(
        transport.call_count(),
        1,
        "a terminal error must not be retried"
    );
}

#[tokio::test]
async fn a_declared_content_length_over_the_cap_refuses_before_the_body_arrives() {
    // The body is small; the header claims 4096 bytes, and the header alone is
    // enough to refuse the answer.
    let transport = MockTransport::new().with_max_response_bytes(32);
    transport.push(Reply::Response(Response::new(
        200,
        [("content-length".to_owned(), "4096".to_owned())],
        success_body().into_bytes(),
    )));

    let error = client(transport.clone())
        .call("account.info", json!({}))
        .await
        .unwrap_err();
    assert!(is_too_large(&error, 32, Some(4096)), "{error}");
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn a_declared_content_length_exactly_at_the_cap_is_accepted() {
    let body = success_body();
    let transport = MockTransport::new().with_max_response_bytes(body.len() as u64);
    transport.push(Reply::Response(Response::new(
        200,
        [("content-length".to_owned(), body.len().to_string())],
        body.into_bytes(),
    )));

    let data = client(transport)
        .call("account.info", json!({}))
        .await
        .expect("a declared length at the cap is inside it");
    assert_eq!(data["count"], 1);
}

#[tokio::test]
async fn a_lying_content_length_is_caught_by_the_running_total() {
    // Declares 8 bytes and delivers the whole envelope: a header that lies small
    // cannot buy a bigger read than the cap allows.
    let body = success_body();
    let len = body.len() as u64;
    let transport = MockTransport::new().with_max_response_bytes(64);
    transport.push(Reply::Response(Response::new(
        200,
        [("content-length".to_owned(), "8".to_owned())],
        body.into_bytes(),
    )));

    let error = client(transport)
        .call("account.info", json!({}))
        .await
        .unwrap_err();
    // Delivered in 48-byte pieces, the running total is 48 (inside) and then 74
    // (over) — the header's claim of 8 bytes bought nothing.
    assert!(len > 64 && len < 128, "the envelope is {len} bytes");
    assert!(is_too_large(&error, 64, Some(len)), "{error}");
}

#[tokio::test]
async fn an_empty_body_fits_a_zero_cap_and_one_byte_does_not() {
    let empty = MockTransport::new().with_max_response_bytes(0);
    empty.push(Reply::Response(Response::new(
        200,
        std::iter::empty(),
        Vec::new(),
    )));
    let error = client(empty)
        .call("account.info", json!({}))
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::Json { .. }),
        "the cap must let an empty body through to the parser, got: {error}"
    );

    let one_byte = MockTransport::new().with_max_response_bytes(0);
    one_byte.push(Reply::Response(Response::new(
        200,
        std::iter::empty(),
        b"{".to_vec(),
    )));
    let error = client(one_byte)
        .call("account.info", json!({}))
        .await
        .unwrap_err();
    assert!(is_too_large(&error, 0, Some(1)), "{error}");
}

#[tokio::test]
async fn the_error_never_echoes_the_body() {
    let body = json!({"code": 1000, "msg": "ok", "resData": {"token": "s3cr3t-value"}}).to_string();
    let transport = MockTransport::new().with_max_response_bytes(8);
    transport.push(Reply::Body(body));

    let error = client(transport)
        .call("account.info", json!({}))
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::ResponseTooLarge { limit: 8, observed: Some(seen) } if seen > 8),
        "{error}"
    );
    assert!(
        error.to_string().contains('8'),
        "the cap belongs in the message"
    );
    assert!(!error.to_string().contains("s3cr3t-value"));
    assert!(!format!("{error:?}").contains("s3cr3t-value"));
}

// -------------------------------------------------------- the reqwest side ---

#[test]
fn the_documented_cap_is_four_mebibytes() {
    assert_eq!(DEFAULT_MAX_RESPONSE_BYTES, 4 * 1024 * 1024);
}

#[test]
#[cfg(feature = "http")]
fn the_reqwest_transport_starts_at_the_documented_cap() {
    use inwx_client::ReqwestTransport;

    assert_eq!(
        ReqwestTransport::new().max_response_bytes(),
        DEFAULT_MAX_RESPONSE_BYTES
    );
    assert_eq!(
        ReqwestTransport::new()
            .with_max_response_bytes(1024)
            .max_response_bytes(),
        1024
    );
}

// --------------------------------------------------------------- properties --

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The cap is the only thing that decides: `declared > limit` or
    /// `total > limit` — never anything else — and an accepted body arrives
    /// whole. When it refuses, the reported size is the running total at the
    /// chunk that crossed, so at most one chunk is ever read past the cap.
    #[test]
    fn the_cap_is_the_only_thing_that_decides(
        chunk_count in 0usize..8,
        chunk_len in 0usize..17,
        limit in 0u64..64,
        declared in prop::option::weighted(0.5, 0u64..80),
    ) {
        let bytes = vec![b'k'; chunk_count * chunk_len];
        let total = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let chunk_len = u64::try_from(CHUNK_LEN).unwrap_or(u64::MAX);

        let mut source = BufferChunks::new(bytes.clone());
        let outcome = runtime().block_on(read_capped_body(&mut source, declared, limit));

        let reported = match &outcome {
            Ok(_) => None,
            Err(Error::ResponseTooLarge { limit: seen, observed }) => {
                prop_assert_eq!(*seen, limit);
                *observed
            }
            Err(other) => {
                prop_assert!(false, "unexpected error: {other}");
                None
            }
        };

        let declared_over = declared.is_some_and(|declared| declared > limit);
        if declared_over || total > limit {
            let Some(seen) = reported else {
                prop_assert!(
                    false,
                    "a {total}-byte body (declared {declared:?}) passed a {limit}-byte cap"
                );
                return Ok(());
            };
            if let Some(declared) = declared.filter(|declared| *declared > limit) {
                prop_assert_eq!(seen, declared, "the header alone must refuse");
            } else {
                prop_assert!(seen > limit, "the reported total must be over the cap");
                prop_assert!(seen <= total, "only body bytes may be counted");
                prop_assert!(
                    seen <= limit + chunk_len,
                    "the read must stop at the chunk that crosses the cap"
                );
            }
        } else {
            match outcome {
                Ok(body) => prop_assert_eq!(body, bytes),
                Err(error) => prop_assert!(
                    false,
                    "a {total}-byte body inside a {limit}-byte cap was refused: {error}"
                ),
            }
        }
    }
}
