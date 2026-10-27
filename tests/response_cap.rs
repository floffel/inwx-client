//! Issue #18: an inbound body is capped *while* it streams, never buffered
//! first and measured afterwards. Every case is the edge pair — the value just
//! inside the limit and the one just outside it — against the shared mock
//! transport, which replays bodies chunk by chunk through the same
//! [`inwx_client::BoundedBody`] the reqwest transport uses.

mod common;

use common::{client, MockTransport, Reply};
use inwx_client::transport::Request;
use inwx_client::{BoundedBody, Error, Response, Transport, DEFAULT_MAX_RESPONSE_BYTES};

/// Cap used by the boundary tests, small enough to build bodies by hand.
const CAP: usize = 128;

/// A success envelope padded to exactly `len` bytes, so a test can hit the cap
/// to the byte.
fn envelope(len: usize) -> Vec<u8> {
    let prefix = br#"{"code":1000,"msg":"ok","pad":""#;
    let suffix = br#""}"#;
    assert!(len > prefix.len() + suffix.len(), "test body too short");
    let mut body = prefix.to_vec();
    body.resize(len - suffix.len(), b'x');
    body.extend_from_slice(suffix);
    assert_eq!(body.len(), len);
    body
}

/// `size` single-byte chunks — the arrival pattern a socket produces.
fn bytes(size: usize) -> Vec<Vec<u8>> {
    (0..size).map(|_| vec![b'x']).collect()
}

/// Replays one streamed answer through the capped mock transport.
async fn stream(
    transport: &MockTransport,
    declared: Option<u64>,
    chunks: Vec<Vec<u8>>,
) -> inwx_client::Result<Response> {
    transport.push(Reply::Streamed {
        content_length: declared,
        chunks,
    });
    transport
        .execute(Request::post_json("https://inwx.test/jsonrpc/", b"{}"))
        .await
}

/// Asserts an over-cap rejection and hands back the numbers it reported.
fn assert_too_large(error: Error, limit: u64, declared: Option<u64>, observed: u64) {
    match error {
        Error::ResponseTooLarge {
            limit: seen_limit,
            declared: seen_declared,
            observed: seen_observed,
        } => {
            assert_eq!(seen_limit, limit);
            assert_eq!(seen_declared, declared);
            assert_eq!(seen_observed, observed);
        }
        other => panic!("expected ResponseTooLarge, got {other:?}"),
    }
}

// ------------------------------------------------ the body itself: edge pair --

#[tokio::test]
async fn a_body_of_exactly_the_cap_is_accepted() {
    let transport = MockTransport::new().with_max_response_bytes(CAP);
    let response = stream(&transport, None, vec![envelope(CAP)])
        .await
        .expect("exactly the cap is inside the limit");
    assert_eq!(response.body().len(), CAP);
    assert_eq!(response.json().unwrap()["code"], 1000);
}

#[tokio::test]
async fn one_byte_over_the_cap_is_refused_without_content_length() {
    let transport = MockTransport::new().with_max_response_bytes(CAP);
    let error = stream(&transport, None, vec![envelope(CAP + 1)])
        .await
        .expect_err("one byte over the cap must fail");
    // Nothing was announced, so the running total is what caught it.
    assert_too_large(error, CAP as u64, None, CAP as u64 + 1);
}

#[tokio::test]
async fn an_empty_body_is_accepted_and_stays_empty() {
    let transport = MockTransport::new().with_max_response_bytes(CAP);
    let response = stream(&transport, None, Vec::new())
        .await
        .expect("an empty body is well inside the cap");
    assert_eq!(response.body(), b"");

    // Same when the endpoint announces zero bytes.
    let response = stream(&transport, Some(0), Vec::new())
        .await
        .expect("a declared zero length is inside the cap");
    assert_eq!(response.body(), b"");
    assert_eq!(response.header("content-length"), Some("0"));
}

// -------------------------------------------- the announced Content-Length --

#[tokio::test]
async fn a_content_length_of_exactly_the_cap_is_accepted() {
    let transport = MockTransport::new().with_max_response_bytes(CAP);
    let response = stream(&transport, Some(CAP as u64), vec![envelope(CAP)])
        .await
        .expect("an announced length at the cap is inside the limit");
    assert_eq!(response.body().len(), CAP);
}

#[tokio::test]
async fn a_content_length_one_byte_over_the_cap_fails_before_any_body_arrives() {
    let transport = MockTransport::new().with_max_response_bytes(CAP);
    let error = stream(&transport, Some(CAP as u64 + 1), Vec::new())
        .await
        .expect_err("an announced length over the cap must fail");
    // `observed: 0` — not one byte was read.
    assert_too_large(error, CAP as u64, Some(CAP as u64 + 1), 0);
}

#[tokio::test]
async fn a_lying_content_length_still_stops_at_the_cap() {
    // Announces 1 byte, then streams past the cap one byte at a time. The
    // header is useless here, so the running total has to hold — and it must
    // trip on exactly the first byte past the line.
    let transport = MockTransport::new().with_max_response_bytes(CAP);
    let error = stream(&transport, Some(1), bytes(CAP + 1))
        .await
        .expect_err("a body longer than announced must still be capped");
    assert_too_large(error, CAP as u64, Some(1), CAP as u64 + 1);
}

#[tokio::test]
async fn a_single_giant_chunk_never_gets_buffered() {
    // One 1 MiB chunk against a 128 byte cap: the read is refused, and the
    // guard stays within one chunk of the line instead of buffering the rest.
    let transport = MockTransport::new().with_max_response_bytes(CAP);
    let error = stream(&transport, Some(1), vec![vec![b'x'; 1024 * 1024]])
        .await
        .expect_err("an oversized chunk must be refused");
    assert_too_large(error, CAP as u64, Some(1), 1024 * 1024);
}

// --------------------------------------------------------- the default cap --

#[tokio::test]
async fn the_default_cap_holds_a_normal_answer_and_still_bounds_a_huge_one() {
    let transport = MockTransport::new();
    let size = 64 * 1024;
    let response = stream(&transport, None, vec![vec![b'x'; size]])
        .await
        .expect("a 64 KiB answer is far below the default cap");
    assert_eq!(response.body().len(), size);

    let error = stream(
        &transport,
        Some(DEFAULT_MAX_RESPONSE_BYTES as u64 + 1),
        Vec::new(),
    )
    .await
    .expect_err("the default cap still applies");
    assert_too_large(
        error,
        DEFAULT_MAX_RESPONSE_BYTES as u64,
        Some(DEFAULT_MAX_RESPONSE_BYTES as u64 + 1),
        0,
    );
}

// ------------------------------------------------ through the client itself --

#[tokio::test]
async fn an_over_cap_answer_reaches_the_caller_and_is_never_retried() {
    let transport = MockTransport::new().with_max_response_bytes(CAP);
    // A body that would be a perfectly good answer two bytes too many.
    transport.push(Reply::Streamed {
        content_length: Some(CAP as u64 + 2),
        chunks: vec![envelope(CAP + 2)],
    });
    // Retries are enabled here: an over-cap answer must not trigger one.
    let client = client(transport.clone());

    let error = client
        .call("account.info", serde_json::json!({}))
        .await
        .expect_err("the over-cap body must surface");
    assert!(matches!(error, Error::ResponseTooLarge { .. }));
    assert!(!error.is_retryable(), "an ambiguous answer is terminal");
    assert_eq!(
        transport.call_count(),
        1,
        "the endpoint already answered, so a retry could duplicate the command"
    );
}

#[tokio::test]
async fn the_error_never_quotes_the_body() {
    let transport = MockTransport::new().with_max_response_bytes(64);
    let canary = b"{\"session\":\"leak-me-please\",\"pad\":\"";
    let mut body = canary.to_vec();
    body.resize(200, b'!');
    let error = stream(&transport, None, vec![body])
        .await
        .expect_err("200 bytes over a 64 byte cap");

    let message = error.to_string();
    assert!(message.contains("64"), "{message}");
    assert!(!message.contains("leak-me-please"), "{message}");
    assert!(!message.contains('!'), "{message}");
}

// ------------------------------------------------------- the guard directly --

#[test]
fn the_guard_allocates_nothing_past_the_cap() {
    let mut body = BoundedBody::new(8).unwrap();
    body.push(b"1234").unwrap();
    body.push(b"5678").unwrap(); // exactly at the cap
    assert_eq!(body.bytes_seen(), 8);
    assert_eq!(body.limit(), 8);

    let error = body.push(b"9").expect_err("one byte over the cap");
    assert!(matches!(
        error,
        Error::ResponseTooLarge {
            limit: 8,
            observed: 9,
            ..
        }
    ));
    // The rejected chunk was never copied in.
    assert_eq!(body.finish().len(), 8);
}

#[test]
fn a_zero_cap_is_a_misconfiguration() {
    let error = BoundedBody::new(0).expect_err("an empty answer is never usable");
    assert!(error.is_validation());
}
