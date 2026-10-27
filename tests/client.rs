//! Session handling, retries and HTTP/JSON-RPC error mapping.
//!
//! Every test here runs against [`MockTransport`]; nothing touches the network.

mod common;

use common::{anonymous_client, client, client_without_retries, no_wait, MockTransport, Reply};
use inwx_client::{
    transport::{Response, Transport},
    DomainListQuery, DomainName, Error, InwxClient, RetryPolicy,
};
use serde_json::json;

#[tokio::test]
async fn first_call_logs_in_and_replays_the_cookie() {
    let transport = MockTransport::new();
    transport.login("domrobot=abc123");
    transport.ok(json!({"accountId": 1}));

    let client = anonymous_client(transport.clone());
    let info = client.account_info().await.unwrap();

    assert_eq!(info.account_id, Some(1));
    let calls = transport.calls();
    assert_eq!(calls.len(), 2);

    let login = &calls[0];
    assert_eq!(login.method, "account.login");
    assert_eq!(login.params["user"], "test-user");
    assert_eq!(login.params["pass"], "test-pass");
    // The password never becomes a header.
    assert!(login.header("authorization").is_none());
    assert!(
        !login
            .headers
            .iter()
            .any(|(_, value)| value.contains("test-pass")),
        "password leaked into a header: {:?}",
        login.headers
    );

    let info_call = &calls[1];
    assert_eq!(info_call.method, "account.info");
    assert_eq!(info_call.header("cookie"), Some("domrobot=abc123"));
    assert_eq!(info_call.url, "https://inwx.test/jsonrpc/");
    assert_eq!(info_call.header("content-type"), Some("application/json"));
    assert!(info_call
        .header("user-agent")
        .unwrap()
        .starts_with("inwx-client/"));
}

#[tokio::test]
async fn the_session_is_reused_across_calls() {
    let transport = MockTransport::new();
    transport.login("domrobot=abc123");
    transport.ok_empty();
    transport.ok_empty();

    let client = anonymous_client(transport.clone());
    client
        .delete_domain(&DomainName::parse("a.de").unwrap())
        .await
        .unwrap();
    client
        .delete_domain(&DomainName::parse("b.de").unwrap())
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].method, "account.login");
    for call in &calls[1..] {
        assert_eq!(call.header("cookie"), Some("domrobot=abc123"));
    }
}

#[tokio::test]
async fn an_expired_session_is_renewed_once() {
    let transport = MockTransport::new();
    transport.login("domrobot=first");
    transport.api_error(2200, "Authentication error");
    transport.login("domrobot=second");
    transport.ok(json!({"domain": []}));

    let client = anonymous_client(transport.clone());
    client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[0].method, "account.login");
    assert_eq!(calls[1].header("cookie"), Some("domrobot=first"));
    assert_eq!(calls[2].method, "account.login");
    assert_eq!(calls[3].header("cookie"), Some("domrobot=second"));
}

#[tokio::test]
async fn a_second_auth_failure_surfaces_as_an_api_error() {
    let transport = MockTransport::new();
    transport.login("domrobot=first");
    transport.api_error(2200, "Authentication error");
    transport.login("domrobot=second");
    transport.api_error(2201, "Authorization error");

    let client = anonymous_client(transport.clone());
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();

    assert_eq!(error.code(), Some(2201));
    assert!(error.is_authentication());
    assert_eq!(transport.call_count(), 4);
}

#[tokio::test]
async fn http_401_also_triggers_one_relogin() {
    let transport = MockTransport::new();
    transport.login("domrobot=first");
    transport.status(401, "");
    transport.login("domrobot=second");
    transport.ok(json!({"domain": "a.de"}));

    let client = anonymous_client(transport.clone());
    client
        .zone_info(&DomainName::parse("a.de").unwrap())
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[2].method, "account.login");
    assert!(calls[3].header("cookie").unwrap().contains("second"));
}

#[tokio::test]
async fn no_session_and_no_credentials_is_not_authenticated() {
    let transport = MockTransport::new();
    let client = InwxClient::new(transport.clone());
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();

    assert!(matches!(error, Error::NotAuthenticated));
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn login_without_a_cookie_is_an_authentication_error() {
    let transport = MockTransport::new();
    transport.ok_empty(); // a "successful" login that sets no cookie

    let client = anonymous_client(transport);
    let error = client.login().await.unwrap_err();

    match error {
        Error::Authentication { message } => assert!(message.contains("cookie")),
        other => panic!("unexpected: {other}"),
    }
}

#[tokio::test]
async fn a_rejected_login_is_an_api_error() {
    let transport = MockTransport::new();
    transport.api_error(2200, "Authentication error");

    let client = anonymous_client(transport);
    let error = client.login().await.unwrap_err();

    assert_eq!(error.code(), Some(2200));
    assert!(!client.is_authenticated());
}

#[tokio::test]
async fn a_login_server_error_is_ambiguous_and_not_retried() {
    for status in [500, 599] {
        let transport = MockTransport::new();
        transport.status(status, "<html>bad gateway</html>");
        transport.login("domrobot=abc");

        let client = anonymous_client(transport.clone());
        let error = client.login().await.unwrap_err();

        assert!(error.is_ambiguous(), "{status}: {error}");
        assert!(!error.is_retryable(), "{status}");
        assert!(!client.is_authenticated(), "{status}");
        assert_eq!(transport.call_count(), 1, "{status}");
    }
}

#[tokio::test]
async fn a_login_timeout_is_ambiguous_and_not_retried() {
    let transport = MockTransport::new();
    transport.ambiguous_failure("request timed out");
    transport.login("domrobot=abc");

    let client = anonymous_client(transport.clone());
    let error = client.login().await.unwrap_err();

    assert!(error.is_ambiguous());
    assert!(!error.is_retryable());
    assert!(!client.is_authenticated());
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn non_server_error_login_statuses_are_not_ambiguous() {
    for status in [499, 600] {
        let transport = MockTransport::new();
        transport.status(status, r#"{"code":2005,"msg":"rejected"}"#);
        transport.login("domrobot=abc");

        let client = anonymous_client(transport.clone());
        let error = client.login().await.unwrap_err();

        assert!(!error.is_ambiguous(), "{status}: {error}");
        assert_eq!(error.code(), Some(2005), "{status}");
        assert!(!client.is_authenticated(), "{status}");
        assert_eq!(transport.call_count(), 1, "{status}");
    }
}

#[tokio::test]
async fn logout_drops_the_session_even_when_the_call_fails() {
    let transport = MockTransport::new();
    transport.api_error(2303, "Object does not exist");

    let client = client(transport);
    assert!(client.is_authenticated());
    let error = client.logout().await.unwrap_err();

    assert_eq!(error.code(), Some(2303));
    assert!(!client.is_authenticated());
}

#[tokio::test]
async fn retryable_http_statuses_are_retried() {
    let transport = MockTransport::new();
    transport.status(500, "upstream failed");
    transport.status(429, "");
    transport.ok(json!({"domain": []}));

    let client = client(transport.clone());
    client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap();

    assert_eq!(transport.call_count(), 3);
}

#[tokio::test]
async fn a_mutating_server_error_is_ambiguous_even_with_an_api_envelope() {
    let transport = MockTransport::new();
    transport.status(503, r#"{"code":2300,"msg":"Object pending transfer"}"#);
    transport.ok_empty();

    let client = client(transport.clone());
    let error = client
        .delete_domain(&DomainName::parse("a.de").unwrap())
        .await
        .unwrap_err();

    assert!(error.is_ambiguous());
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn server_error_boundaries_for_a_mutating_call() {
    for status in [500, 599] {
        let transport = MockTransport::new();
        transport.status(status, "");
        transport.ok_empty();

        let client = client(transport.clone());
        let error = client
            .delete_domain(&DomainName::parse("a.de").unwrap())
            .await
            .unwrap_err();

        assert!(error.is_ambiguous(), "{status}: {error}");
        assert_eq!(transport.call_count(), 1, "{status}");
    }

    for status in [499, 600] {
        let transport = MockTransport::new();
        transport.status(status, "");
        transport.ok_empty();

        let client = client(transport.clone());
        let error = client
            .delete_domain(&DomainName::parse("a.de").unwrap())
            .await
            .unwrap_err();

        assert!(matches!(error, Error::Http { .. }), "{status}: {error}");
        assert_eq!(transport.call_count(), 1, "{status}");
    }
}

#[tokio::test]
async fn server_error_boundaries_for_an_idempotent_call() {
    let transport = MockTransport::new();
    transport.status(500, "");
    transport.status(599, "");
    transport.ok(json!({"domain": []}));

    let retrying_client = client(transport.clone());
    retrying_client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap();
    assert_eq!(transport.call_count(), 3);

    for status in [499, 600] {
        let transport = MockTransport::new();
        transport.status(status, "");
        transport.ok(json!({"domain": []}));

        let terminal_client = client(transport.clone());
        let error = terminal_client
            .list_domains(&DomainListQuery::default())
            .await
            .unwrap_err();

        assert!(matches!(error, Error::Http { status: actual, .. } if actual == status));
        assert_eq!(transport.call_count(), 1, "{status}");
    }
}

#[tokio::test]
async fn an_unknown_raw_method_is_treated_as_mutating() {
    let transport = MockTransport::new();
    transport.status(502, "");
    transport.ok(json!({"ok": true}));

    let client = client(transport.clone());
    let error = client
        .call("unmodelled.command", json!({}))
        .await
        .unwrap_err();

    assert!(error.is_ambiguous());
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn rate_limit_status_boundaries_do_not_retry_neighbouring_statuses() {
    for status in [428, 430] {
        let transport = MockTransport::new();
        transport.status(status, "");
        transport.ok_empty();

        let client = client(transport.clone());
        let error = client
            .delete_domain(&DomainName::parse("a.de").unwrap())
            .await
            .unwrap_err();

        assert!(matches!(error, Error::Http { status: actual, .. } if actual == status));
        assert_eq!(transport.call_count(), 1, "{status}");
    }
}

#[tokio::test]
async fn retries_stop_at_the_policy_limit() {
    let transport = MockTransport::new();
    transport.status(503, "");
    transport.status(503, "");
    transport.status(503, "");

    let client = client(transport.clone()).with_retry(RetryPolicy::new(2));
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();

    match error {
        Error::Http { status, .. } => assert_eq!(status, 503),
        other => panic!("unexpected: {other}"),
    }
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn a_non_json_error_body_becomes_an_http_error() {
    let transport = MockTransport::new();
    transport.status(400, "<html>bad request</html>");

    let client = client_without_retries(transport);
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();

    match error {
        Error::Http { status, body } => {
            assert_eq!(status, 400);
            assert!(body.contains("bad request"));
        }
        other => panic!("unexpected: {other}"),
    }
}

#[tokio::test]
async fn an_api_error_envelope_is_parsed_even_on_a_non_2xx_status() {
    let transport = MockTransport::new();
    transport.status(
        400,
        r#"{"code":2005,"msg":"Parameter value syntax error","reason":"domain"}"#,
    );

    let client = client_without_retries(transport);
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();

    assert_eq!(error.code(), Some(2005));
    assert!(error.to_string().contains("domain"));
}

#[tokio::test]
async fn transport_failures_are_retried_and_terminal_ones_are_not() {
    let transport = MockTransport::new();
    transport.transport_failure("connection reset");
    transport.ok(json!({"domain": []}));

    let client = client(transport.clone());
    client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap();
    assert_eq!(transport.call_count(), 2);

    let transport = MockTransport::new();
    transport.terminal_failure("unsupported scheme");
    let client = common::client(transport.clone());
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();

    assert!(!error.is_retryable());
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn a_definite_transport_failure_on_a_mutating_call_is_retried() {
    let transport = MockTransport::new();
    transport.transport_failure("connection refused");
    transport.ok_empty();

    let client = client(transport.clone());
    client
        .delete_domain(&DomainName::parse("a.de").unwrap())
        .await
        .unwrap();

    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn an_ambiguous_failure_on_a_mutating_call_is_not_retried() {
    let transport = MockTransport::new();
    transport.ambiguous_failure("timeout");
    transport.ok_empty();

    let client = client(transport.clone());
    let error = client
        .delete_domain(&DomainName::parse("a.de").unwrap())
        .await
        .unwrap_err();

    assert!(error.is_ambiguous());
    assert!(!error.is_retryable());
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn an_ambiguous_failure_on_an_idempotent_call_is_retried() {
    let transport = MockTransport::new();
    transport.ambiguous_failure("timeout");
    transport.ok(json!({"domain": []}));

    let client = client(transport.clone());
    client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap();

    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn ambiguous_retries_respect_the_attempt_limit() {
    let transport = MockTransport::new();
    transport.ambiguous_failure("timeout");
    let one_attempt = client(transport.clone()).with_retry(RetryPolicy::new(1));
    let error = one_attempt
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();
    assert!(error.is_ambiguous());
    assert_eq!(transport.call_count(), 1);

    let transport = MockTransport::new();
    transport.ambiguous_failure("timeout");
    transport.ambiguous_failure("timeout");
    let two_attempts = client(transport.clone()).with_retry(RetryPolicy::new(2));
    let error = two_attempts
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();
    assert!(error.is_ambiguous());
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn a_5xx_on_a_mutating_call_is_ambiguous_and_not_retried() {
    let transport = MockTransport::new();
    transport.status(500, "upstream failed");
    transport.ok_empty();

    let client = client(transport.clone());
    let error = client
        .delete_domain(&DomainName::parse("a.de").unwrap())
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Ambiguous { .. }));
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn a_429_on_a_mutating_call_is_retried() {
    let transport = MockTransport::new();
    transport.status(429, "slow down");
    transport.ok_empty();

    let client = client(transport.clone());
    client
        .delete_domain(&DomainName::parse("a.de").unwrap())
        .await
        .unwrap();

    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn an_api_error_is_terminal() {
    let transport = MockTransport::new();
    transport.api_error(2303, "Object does not exist");

    let client = client(transport.clone());
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();

    assert_eq!(error.code(), Some(2303));
    assert!(error.to_string().contains("Object does not exist"));
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn pending_transfer_code_is_treated_as_retryable_but_success_is_not_retried() {
    // 2300 is documented as "object pending transfer"; the policy retries it.
    let transport = MockTransport::new();
    transport.api_error(2300, "Object pending transfer");
    transport.ok_empty();

    let client = client(transport.clone());
    client
        .delete_domain(&DomainName::parse("a.de").unwrap())
        .await
        .unwrap();
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn the_language_parameter_is_sent_when_configured() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let client = client(transport.clone()).with_language(inwx_client::Language::De);
    client
        .delete_domain(&DomainName::parse("a.de").unwrap())
        .await
        .unwrap();

    assert_eq!(transport.only_call().params["lang"], "de");
}

#[tokio::test]
async fn the_sandbox_url_is_used_when_asked() {
    let transport = MockTransport::new();
    transport.login("domrobot=abc");
    transport.ok_empty();

    let client = InwxClient::sandbox(transport.clone())
        .with_credentials("u", "p")
        .unwrap();
    client
        .delete_domain(&DomainName::parse("a.de").unwrap())
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls[0].url, "https://api.ote.domrobot.com/jsonrpc/");
    assert_eq!(calls[1].url, "https://api.ote.domrobot.com/jsonrpc/");
}

#[tokio::test]
async fn account_info_accepts_numeric_strings() {
    let transport = MockTransport::new();
    transport.ok(json!({"accountId": "61140", "customerNo": 110_069, "username": "florian"}));

    let client = client(transport);
    let info = client.account_info().await.unwrap();

    assert_eq!(info.account_id, Some(61_140));
    assert_eq!(info.customer_no, Some(110_069));
    assert_eq!(info.username.as_deref(), Some("florian"));
}

#[tokio::test]
async fn the_raw_call_escape_hatch_still_handles_sessions() {
    let transport = MockTransport::new();
    transport.login("domrobot=abc");
    transport.ok(json!({"balance": 12.5}));

    let client = anonymous_client(transport.clone());
    let data = client
        .call("accounting.accountBalance", json!({}))
        .await
        .unwrap();

    assert_eq!(data["balance"], 12.5);
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn a_200_with_a_non_object_body_is_a_json_error() {
    let transport = MockTransport::new();
    transport.status(200, "[1,2,3]");

    let client = client(transport);
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Json { .. }));
}

#[tokio::test]
async fn debug_output_hides_the_session_cookie() {
    let transport = MockTransport::new();
    let client = client(transport);
    let rendered = format!("{client:?}");

    assert!(rendered.contains("authenticated: true"));
    assert!(!rendered.contains("test-session"));
}

#[test]
fn retry_policy_is_bounded() {
    let policy = no_wait();
    assert_eq!(policy.delay(1), Some(std::time::Duration::ZERO));
    assert_eq!(policy.delay(3), None);
}

/// A transport that fails every call proves the retry counter is what stops it.
#[tokio::test]
async fn a_transport_that_always_fails_is_tried_exactly_three_times() {
    struct AlwaysFails;
    impl Transport for AlwaysFails {
        async fn execute(
            &self,
            _request: inwx_client::transport::Request<'_>,
        ) -> inwx_client::Result<Response> {
            std::future::ready(()).await;
            Err(Error::transport("down"))
        }
    }

    let client = InwxClient::new(AlwaysFails)
        .with_session("s=1")
        .unwrap()
        .with_retry(no_wait());
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();

    assert!(error.is_retryable());
    assert!(matches!(
        error,
        Error::Transport {
            retryable: true,
            ..
        }
    ));
}

/// A reply that is a success envelope with a bogus code must not be accepted.
#[tokio::test]
async fn code_zero_is_not_success() {
    let transport = MockTransport::new();
    transport.push(Reply::Body(r#"{"msg":"no code"}"#.to_owned()));

    let client = client(transport);
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();

    assert_eq!(error.code(), Some(0));
}
