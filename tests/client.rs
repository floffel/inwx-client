//! Session handling, retries and HTTP/JSON-RPC error mapping.
//!
//! Every test here runs against [`MockTransport`]; nothing touches the network.

mod common;

use common::{anonymous_client, client, client_without_retries, no_wait, MockTransport, Reply};
use inwx_client::{
    transport::{Request, Response, Transport},
    DomainListQuery, DomainName, Error, InwxClient, Password, RetryPolicy, UnlockAccount,
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
        Error::Authentication { message, .. } => assert!(message.contains("cookie")),
        other => panic!("unexpected: {other}"),
    }
}

#[tokio::test]
async fn login_with_a_non_utf8_cookie_is_an_uncertain_transport_error() {
    let transport = MockTransport::new();
    transport.push(Reply::Response(Response::from_header_bytes(
        200,
        [("Set-Cookie".to_owned(), vec![0xff, 0xfe])],
        br#"{"code":1000,"msg":"Login successful"}"#.to_vec(),
    )));

    let client = anonymous_client(transport.clone());
    let error = client.login().await.unwrap_err();

    assert!(matches!(error, Error::Uncertain { .. }), "{error:?}");
    assert!(error.is_uncertain());
    assert!(!error.is_retryable());
    assert!(error.to_string().contains("Set-Cookie"), "{error}");
    assert_eq!(transport.call_count(), 1);
    assert!(!client.is_authenticated());
}

/// A login is one transition of one session: a second login would invalidate
/// the cookie the first one handed out, so an installed session is reused
/// instead of replaced. Dropping it is what asks for a new one.
#[tokio::test]
async fn login_reuses_the_installed_session() {
    let transport = MockTransport::new();
    transport.login("domrobot=abc123");

    let client = InwxClient::new(transport.clone())
        .with_credentials("test-user", "test-pass")
        .unwrap()
        .with_retry(no_wait());

    client.login().await.unwrap();
    assert!(client.is_authenticated());
    client.login().await.unwrap();
    assert_eq!(transport.call_count(), 1, "the second login posted again");

    // An explicit drop is what makes the next login open a session of its own.
    client.clear_session();
    transport.login("domrobot=def456");
    client.login().await.unwrap();
    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].method, "account.login");
    assert_eq!(calls[1].header("cookie"), None);
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

/// A login is the one command that writes and is still replayed: it opens a
/// session and nothing else, so a transient status costs an attempt instead of
/// aborting the call that needed the session.
#[tokio::test]
async fn a_transient_status_on_login_is_retried() {
    let transport = MockTransport::new();
    transport.status(503, "upstream failed");
    transport.status(429, "");
    transport.login("domrobot=abc123");
    transport.ok(json!({ "accountId": 7 }));

    let client = anonymous_client(transport.clone());
    client.login().await.unwrap();
    assert!(client.is_authenticated());
    // The retried login still produced the cookie the next call needs.
    let info = client.account_info().await.unwrap();
    assert_eq!(info.account_id, Some(7));

    let calls = transport.calls();
    assert_eq!(calls.len(), 4);
    assert!(calls[..3].iter().all(|call| call.method == "account.login"));
    assert_eq!(calls[3].header("cookie"), Some("domrobot=abc123"));
}

/// One attempt is one attempt: a policy without a second try repeats nothing.
#[tokio::test]
async fn a_single_attempt_policy_does_not_repeat_a_login() {
    let transport = MockTransport::new();
    transport.status(503, r#"{"code":2200,"msg":"Authentication error"}"#);

    let client = anonymous_client(transport.clone()).with_retry(RetryPolicy::new(1));
    let error = client.login().await.unwrap_err();

    // The verdict inside the transient answer outranks the bare status.
    assert_eq!(error.code(), Some(2200));
    assert_eq!(transport.call_count(), 1);
    assert!(!client.is_authenticated());
}

/// Two attempts repeat a login exactly once, and the last answer is what the
/// caller sees — the verdict in it, not the status that carried it.
#[tokio::test]
async fn login_retries_stop_at_the_policy_limit() {
    let transport = MockTransport::new();
    for _ in 0..3 {
        transport.status(503, r#"{"code":2303,"msg":"Object does not exist"}"#);
    }

    let client = anonymous_client(transport.clone()).with_retry(RetryPolicy::new(2));
    let error = client.login().await.unwrap_err();

    assert_eq!(error.code(), Some(2303));
    assert_eq!(transport.call_count(), 2);
    assert!(!client.is_authenticated());
}

/// A login whose request never left the process reached nobody, so repeating it
/// cannot have reached anybody twice.
#[tokio::test]
async fn a_login_that_never_left_the_process_is_retried() {
    let transport = MockTransport::new();
    transport.transport_failure("dns lookup failed");
    transport.login("domrobot=abc123");

    let client = anonymous_client(transport.clone());
    client.login().await.unwrap();

    assert!(client.is_authenticated());
    assert_eq!(transport.call_count(), 2);
}

/// The one write that stays safe after a lost answer: the session the first
/// attempt may have opened is replaced by the second, not duplicated.
#[tokio::test]
async fn an_uncertain_login_is_retried() {
    let transport = MockTransport::new();
    transport.uncertain_failure("timeout waiting for the login answer");
    transport.login("domrobot=abc123");

    let client = anonymous_client(transport.clone());
    client.login().await.unwrap();

    assert!(client.is_authenticated());
    assert_eq!(transport.call_count(), 2);
}

/// A failure that is terminal stays terminal for a login as well.
#[tokio::test]
async fn a_terminal_login_failure_is_not_retried() {
    let transport = MockTransport::new();
    transport.terminal_failure("unsupported scheme");

    let client = anonymous_client(transport.clone());
    let error = client.login().await.unwrap_err();

    assert!(!error.is_retryable());
    assert_eq!(transport.call_count(), 1);
}

/// Neither is a status no repeat could improve on.
#[tokio::test]
async fn a_non_transient_status_on_login_is_terminal() {
    let transport = MockTransport::new();
    transport.status(400, "<html>bad request</html>");

    let client = anonymous_client(transport.clone());
    assert!(client.login().await.is_err());
    assert!(!client.is_authenticated());
    assert_eq!(transport.call_count(), 1);
}

/// The retry lives in `login`, so the implicit login a call performs gets it
/// too: a session renewed behind a transient 503 still reaches the API.
#[tokio::test]
async fn a_relogin_after_an_expired_session_retries_a_transient_status() {
    let transport = MockTransport::new();
    transport.login("domrobot=first");
    transport.api_error(2200, "Authentication error");
    transport.status(503, "");
    transport.login("domrobot=second");
    transport.ok(json!({ "domain": [] }));

    let client = anonymous_client(transport.clone());
    client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls.len(), 5);
    assert_eq!(calls[2].method, "account.login");
    assert_eq!(calls[3].method, "account.login");
    assert_eq!(calls[4].header("cookie"), Some("domrobot=second"));
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

/// `logout` once leaned on a `null` payload being read as `{}`. It sends the
/// empty object itself, so the wire is the same and no call has to tolerate a
/// non-object any more.
#[tokio::test]
async fn logout_sends_an_explicit_empty_object() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let client = client(transport.clone());
    client.logout().await.unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "account.logout");
    assert_eq!(call.params, json!({}));
}

/// A `params` that is not an object is refused before a session is opened and
/// before a single byte is written. Sending `{}` instead — what the old
/// `unwrap_or_default` did — would drop the caller's payload without a word: a
/// `nameserver.update` with all-optional fields would go out empty, a
/// `domain.info` without its domain would come back as a server-side rejection.
#[tokio::test]
async fn a_non_object_params_is_refused_without_a_request() {
    for params in [
        json!(null),
        json!(["example.com"]),
        json!("example.com"),
        json!(2024),
        json!(true),
    ] {
        let transport = MockTransport::new();
        let client = anonymous_client(transport.clone());

        let error = client
            .call("domain.info", params.clone())
            .await
            .unwrap_err();

        assert!(error.is_validation(), "`{params}` was not refused");
        assert_eq!(transport.call_count(), 0, "`{params}` reached the wire");
        // Refused before `ensure_session`, so no login was attempted either.
        assert!(!client.is_authenticated());
    }
}

/// Both secrets belong in the JSON body. A password in a URL ends up in access
/// logs, and one in a header is easy to echo back, so neither is allowed.
#[tokio::test]
async fn change_password_sends_both_secrets_in_the_body_only() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let client = client(transport.clone());
    client
        .change_account_password("old secret", &Password::new("brand new secret").unwrap())
        .await
        .unwrap();

    let call = transport.only_call();
    assert_eq!(call.method, "account.changepassword");
    assert_eq!(call.params["password"], "old secret");
    assert_eq!(call.params["newPassword"], "brand new secret");
    assert!(call
        .params
        .as_object()
        .is_some_and(|params| params.len() == 2));
    assert!(
        !call.url.contains("secret"),
        "url leaked a secret: {}",
        call.url
    );
    for (name, value) in &call.headers {
        assert!(!value.contains("secret"), "header `{name}` leaked a secret");
    }
}

/// Changing the password invalidates the cookie that was established with
/// the old one, so the client must not keep a session it cannot re-establish.
#[tokio::test]
async fn change_password_drops_the_session_after_success() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let client = client(transport.clone());
    assert!(client.is_authenticated());
    client
        .change_account_password("old", &Password::new("brand new").unwrap())
        .await
        .unwrap();

    assert!(!client.is_authenticated());
    assert_eq!(transport.call_count(), 1);
}

/// Without a session the wrapper logs in first, exactly like any other
/// non-public method.
#[tokio::test]
async fn change_password_logs_in_first_when_there_is_no_session() {
    let transport = MockTransport::new();
    transport.login("domrobot=abc123");
    transport.ok_empty();

    let client = anonymous_client(transport.clone());
    client
        .change_account_password("test-pass", &Password::new("brand new").unwrap())
        .await
        .unwrap();

    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].method, "account.login");
    assert_eq!(calls[1].header("cookie"), Some("domrobot=abc123"));
    assert!(!client.is_authenticated());
}

/// A refusal means the password is unchanged, so the session is still valid
/// and has to survive — unlike the success path, which wipes it on purpose.
#[tokio::test]
async fn a_rejected_change_keeps_the_session() {
    let transport = MockTransport::new();
    transport.api_error(2005, "Parameter value syntax error");

    let client = client(transport.clone());
    let error = client
        .change_account_password("old", &Password::new("brand new").unwrap())
        .await
        .unwrap_err();

    assert_eq!(error.code(), Some(2005));
    assert!(client.is_authenticated());
    assert_eq!(transport.call_count(), 1);
}

/// Once the old password stops working, a replay is not a harmless repeat of a
/// read: an unconfirmed change is reported as `Uncertain` and never retried.
#[tokio::test]
async fn an_uncertain_change_password_is_not_retried() {
    let transport = MockTransport::new();
    transport.uncertain_failure("timeout waiting for response");
    transport.ok_empty();

    let client = client(transport.clone());
    let error = client
        .change_account_password("old", &Password::new("brand new").unwrap())
        .await
        .unwrap_err();

    assert!(error.is_uncertain());
    assert!(!error.is_retryable());
    assert_eq!(transport.call_count(), 1);
    assert!(client.is_authenticated());
}

/// The current password goes through the same validator as the new one, and a
/// blank one is refused before a byte leaves the process.
#[tokio::test]
async fn a_blank_current_password_is_refused_before_the_call() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let client = client(transport.clone());
    let error = client
        .change_account_password("   ", &Password::new("brand new").unwrap())
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Validation { .. }));
    assert_eq!(transport.call_count(), 0);
    assert!(client.is_authenticated());
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
        Error::Http { status, body, .. } => {
            assert_eq!(status, 400);
            assert!(body.contains("bad request"));
        }
        other => panic!("unexpected: {other}"),
    }
}

/// The status alone cannot say whether the endpoint answered with a page that is
/// not JSON or with JSON in a shape no envelope has; the parse failure kept as
/// the cause can, and it stays walkable down to `serde_json`'s line and column.
#[tokio::test]
async fn an_unreadable_error_body_keeps_the_parse_failure_as_its_cause() {
    use std::error::Error as _;

    let transport = MockTransport::new();
    transport.status(400, "<html>bad request</html>");

    let client = client_without_retries(transport);
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Http { status: 400, .. }), "{error}");
    let cause = error.source().expect("the parse failure is kept");
    assert!(
        cause.to_string().contains("expected value"),
        "the cause names the parse failure: {cause}"
    );
    let below = cause.source().expect("serde_json stays below the parser");
    assert!(
        below.to_string().contains("line 1 column 1"),
        "the position survives: {below}"
    );
    // Whatever the cause says, the body itself stays bounded and redacted.
    assert!(!error.to_string().contains("serde_json"), "{error}");
}

/// The neighbour of the case above: the same status, a body that *is* an
/// envelope, so the API's verdict wins and no `Http` error is built at all.
#[tokio::test]
async fn an_envelope_on_a_non_2xx_status_is_a_verdict_not_an_http_error() {
    use std::error::Error as _;

    let transport = MockTransport::new();
    transport.status(400, "[]");
    transport.status(400, r#"{"code":2005,"msg":"Parameter value syntax error"}"#);

    let client = client_without_retries(transport.clone());
    // JSON, but an array: no envelope is an array, so it is the HTTP failure
    // and keeps the shape error as its cause.
    let wrong_shape = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();
    assert!(
        matches!(wrong_shape, Error::Http { status: 400, .. }),
        "{wrong_shape}"
    );
    let cause = wrong_shape.source().expect("the shape error is kept");
    assert!(cause.to_string().contains("expected a map"), "{cause}");

    let client = client_without_retries(transport);
    let verdict = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();
    assert_eq!(verdict.code(), Some(2005));
    assert!(
        verdict.source().is_none(),
        "a verdict needs no parse cause: {verdict}"
    );
}

#[tokio::test]
async fn a_retry_after_header_reaches_the_error_a_caller_sees() {
    let transport = MockTransport::new();
    transport.push(Reply::Response(Response::new(
        429,
        [("Retry-After".to_owned(), "7".to_owned())],
        b"<html>too many requests</html>".to_vec(),
    )));

    let client = client_without_retries(transport);
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();

    assert!(error.is_retryable());
    assert_eq!(error.retry_after(), Some(std::time::Duration::from_secs(7)));
}

#[tokio::test]
async fn a_transient_status_on_a_write_carries_no_retry_after() {
    // The outcome is unknown, so there is nothing to pace a replay on.
    let transport = MockTransport::new();
    transport.push(Reply::Response(Response::new(
        429,
        [("Retry-After".to_owned(), "7".to_owned())],
        b"too many requests".to_vec(),
    )));

    let client = client_without_retries(transport);
    let error = client
        .unlock_account(&UnlockAccount::new("sub-account").unwrap())
        .await
        .unwrap_err();

    assert!(error.is_uncertain());
    assert_eq!(error.retry_after(), None);
}

#[tokio::test]
async fn a_secret_echoed_in_an_error_body_is_redacted() {
    let transport = MockTransport::new();
    transport.status(400, "user=bob&password=hunter2&action=login");

    let client = client_without_retries(transport);
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();

    let message = error.to_string();
    assert!(!message.contains("hunter2"), "{message}");
    assert!(message.contains("<redacted>"), "{message}");
    assert!(!format!("{error:?}").contains("hunter2"));
    match error {
        Error::Http { status, body, .. } => {
            assert_eq!(status, 400);
            assert!(!body.contains("hunter2"));
            assert!(body.contains("bob"));
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

/// A timeout after `domain.create` may already have registered the domain, so
/// the client must hand the ambiguity back instead of registering twice.
#[tokio::test]
async fn an_uncertain_failure_is_not_retried_for_a_mutating_command() {
    let transport = MockTransport::new();
    transport.uncertain_failure("timeout waiting for response");
    transport.ok_empty();

    let client = client(transport.clone());
    let error = client
        .call("domain.create", json!({"domain": "example.com"}))
        .await
        .unwrap_err();

    assert!(error.is_uncertain());
    assert!(!error.is_retryable());
    assert!(error.to_string().contains("may have been executed"));
    assert_eq!(transport.call_count(), 1);
}

/// The same failure on a command that only reads cannot duplicate anything, so
/// the retry is free and worth taking.
#[tokio::test]
async fn an_uncertain_failure_is_retried_for_a_read_only_command() {
    let transport = MockTransport::new();
    transport.uncertain_failure("timeout waiting for response");
    transport.ok(json!({"domain": []}));

    let client = client(transport.clone());
    client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap();

    assert_eq!(transport.call_count(), 2);
}

/// Replaying a read-only command still stops at the policy limit.
#[tokio::test]
async fn an_uncertain_read_only_failure_stops_at_the_policy_limit() {
    let transport = MockTransport::new();
    transport.uncertain_failure("timeout 1");
    transport.uncertain_failure("timeout 2");
    transport.uncertain_failure("timeout 3");

    let client = client(transport.clone());
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();

    assert!(error.is_uncertain());
    assert_eq!(transport.call_count(), 3);
}

/// Just inside the read-only table is replayed; one character outside is not.
#[tokio::test]
async fn the_read_only_boundary_decides_the_replay() {
    for (method, attempts) in [("domain.info", 2usize), ("domain.inf", 1)] {
        let transport = MockTransport::new();
        transport.uncertain_failure("timeout waiting for response");
        transport.ok(json!({"domain": []}));

        let client = client(transport.clone());
        let _ = client.call(method, json!({})).await;

        assert_eq!(transport.call_count(), attempts, "method `{method}`");
    }
}

/// A failure before the request bytes were written cannot have reached the API,
/// so even a mutation is replayed.
#[tokio::test]
async fn a_failure_before_the_request_was_written_is_retried_even_for_a_mutation() {
    let transport = MockTransport::new();
    transport.transport_failure("dns lookup failed");
    transport.transport_failure("connect error");
    transport.ok_empty();

    let client = client(transport.clone());
    client
        .call("domain.create", json!({"domain": "example.com"}))
        .await
        .unwrap();

    assert_eq!(transport.call_count(), 3);
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

/// `2300` is "object pending transfer": a read only has to wait for the object
/// to leave the transfer, so the replay is free and worth taking.
#[tokio::test]
async fn a_pending_transfer_code_is_replayed_for_a_read_only_command() {
    let transport = MockTransport::new();
    transport.api_error(2300, "Object pending transfer");
    transport.ok(json!({"domain": []}));

    let client = client(transport.clone());
    client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap();
    assert_eq!(transport.call_count(), 2);
}

/// The same code on a mutation means the command already reached the object.
/// Replaying it once the transfer settled would order, charge or delete a
/// second time, so the answer is handed back after one attempt.
#[tokio::test]
async fn a_pending_transfer_code_is_not_replayed_for_a_mutating_command() {
    for method in ["domain.create", "domain.transfer", "delete_domain"] {
        let transport = MockTransport::new();
        transport.api_error(2300, "Object pending transfer");
        transport.ok_empty();

        let client = client(transport.clone());
        let error = if method == "delete_domain" {
            client
                .delete_domain(&DomainName::parse("a.de").unwrap())
                .await
                .err()
        } else {
            client.call(method, json!({"domain": "a.de"})).await.err()
        };
        let error = error.expect("a mutating 2300 must not be replayed into a success");

        assert_eq!(error.code(), Some(2300), "method `{method}`");
        assert!(error.to_string().contains("pending transfer"));
        assert_eq!(transport.call_count(), 1, "method `{method}`");
    }
}

/// Just inside the read-only table is replayed; one character outside is not.
#[tokio::test]
async fn the_read_only_boundary_decides_the_pending_transfer_replay() {
    for (method, attempts) in [("domain.info", 2usize), ("domain.inf", 1)] {
        let transport = MockTransport::new();
        transport.api_error(2300, "Object pending transfer");
        transport.ok_empty();

        let client = client(transport.clone());
        let _ = client.call(method, json!({})).await;

        assert_eq!(transport.call_count(), attempts, "method `{method}`");
    }
}

/// One code past `2300` is not a pending transfer: it is a verdict, and a
/// verdict is never repeated, not even for a read.
#[tokio::test]
async fn a_code_next_to_2300_is_terminal_even_for_a_read_only_command() {
    let transport = MockTransport::new();
    transport.api_error(2301, "Object is locked");
    transport.ok(json!({"domain": []}));

    let client = client(transport.clone());
    let error = client
        .list_domains(&DomainListQuery::default())
        .await
        .unwrap_err();

    assert_eq!(error.code(), Some(2301));
    assert_eq!(transport.call_count(), 1);
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

/// A 2xx whose body is not an envelope: the request was written, so the command
/// may have run. That is an `Undecodable` answer — uncertain, never replayed —
/// not the certain decode failure a garbage `resData` payload is.
#[tokio::test]
async fn a_200_with_a_non_envelope_body_is_an_uncertain_undecodable_answer() {
    for body in ["[1,2,3]", "<html>502 Bad Gateway</html>", "{\"code\":1000"] {
        let transport = MockTransport::new();
        transport.status(200, body);

        let client = client(transport.clone());
        let error = client
            .list_domains(&DomainListQuery::default())
            .await
            .unwrap_err();

        assert!(matches!(error, Error::Undecodable { .. }), "{body}");
        assert!(error.is_uncertain(), "{body}");
        assert!(!error.is_retryable(), "{body}");
        assert_eq!(
            transport.call_count(),
            1,
            "{body}: an unreadable answer is not replayed"
        );
        assert!(
            error.to_string().contains("may have been executed"),
            "{body}"
        );
    }
}

/// The case the classification exists for: a mutating command whose answer
/// cannot be read. One attempt only — the record may already be gone — and the
/// error says the command may have run instead of reading like a parse bug.
#[tokio::test]
async fn a_mutating_command_with_an_unreadable_answer_is_not_replayed() {
    let transport = MockTransport::new();
    transport.status(200, "<html>502 Bad Gateway</html>");
    transport.ok_empty();

    let client = client(transport.clone());
    let error = client
        .delete_domain(&DomainName::parse("a.de").unwrap())
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Undecodable { .. }), "{error:?}");
    assert!(error.is_uncertain(), "{error:?}");
    assert!(!error.is_retryable(), "{error:?}");
    assert_eq!(
        transport.call_count(),
        1,
        "the delete must not be replayed: it may already have run"
    );
    assert!(
        std::error::Error::source(&error).is_some(),
        "the parser error keeps the line and column"
    );
}

/// A login whose answer cannot be read is uncertain as well: the session may
/// have been opened server-side even though no cookie reached the client.
#[tokio::test]
async fn an_unreadable_login_answer_is_uncertain() {
    let transport = MockTransport::new();
    transport.status(200, "<html>502 Bad Gateway</html>");

    let client = anonymous_client(transport.clone());
    let error = client.login().await.unwrap_err();

    assert!(matches!(error, Error::Undecodable { .. }), "{error:?}");
    assert!(error.is_uncertain(), "{error:?}");
    assert!(!error.is_retryable(), "{error:?}");
    assert_eq!(transport.call_count(), 1);
    assert!(!client.is_authenticated(), "no cookie was read");
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
fn request_debug_output_hides_header_values_and_body_bytes() {
    let body = br#"{"method":"account.login","params":{"pass":"hunter2"}}"#;
    let request = Request::post_json("https://inwx.test/jsonrpc/", body)
        .with_header("Cookie", "domrobot=test-session")
        .with_header("Content-Type", "application/json");

    let rendered = format!("{request:?}");

    assert!(rendered.contains("POST"));
    assert!(rendered.contains("https://inwx.test/jsonrpc/"));
    assert!(rendered.contains("Cookie"));
    assert!(rendered.contains("body_len"));
    assert!(!rendered.contains("domrobot=test-session"));
    assert!(!rendered.contains("hunter2"));
}

#[test]
fn response_debug_output_hides_header_values_and_body_bytes() {
    let response = Response::new(
        200,
        [
            (
                "Set-Cookie".to_owned(),
                "domrobot=test-session; Path=/".to_owned(),
            ),
            ("X-Trace".to_owned(), "trace-secret".to_owned()),
        ],
        br#"{"code":1000,"msg":"ok","resData":{"token":"body-secret"}}"#.to_vec(),
    );

    let rendered = format!("{response:?}");

    assert!(rendered.contains("status"));
    assert!(rendered.contains("200"));
    assert!(rendered.contains("set-cookie"));
    assert!(rendered.contains("body_len"));
    assert!(!rendered.contains("domrobot=test-session"));
    assert!(!rendered.contains("trace-secret"));
    assert!(!rendered.contains("body-secret"));
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
            Err(Error::transport_before_send("down"))
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
    assert!(!error.is_uncertain());
    assert!(matches!(error, Error::Transport { .. }));
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

/// `account.unlock` is a mutating command on the main account, so it must land
/// on the wire with exactly the derived parameter name and nothing else.
#[tokio::test]
async fn unlocking_sends_the_sub_account_name() {
    let transport = MockTransport::new();
    transport.ok(json!({"username": "sub-account", "state": "OPEN"}));

    let client = client(transport.clone());
    let answer = client
        .unlock_account(&UnlockAccount::new("sub-account").unwrap())
        .await
        .unwrap();

    assert_eq!(answer.username.as_deref(), Some("sub-account"));
    assert_eq!(answer.state.as_deref(), Some("OPEN"));

    let call = transport.only_call();
    assert_eq!(call.method, "account.unlock");
    assert_eq!(call.params, json!({"user": "sub-account"}));
    assert_eq!(call.url, "https://inwx.test/jsonrpc/");
}

/// The method is not one of the public ones, so a client without a session has
/// to log in first and replay the fresh cookie on the unlock itself.
#[tokio::test]
async fn unlocking_logs_in_lazily() {
    let transport = MockTransport::new();
    transport.login("domrobot=abc123");
    transport.ok(json!({"username": "sub-account", "state": "OPEN"}));

    let client = anonymous_client(transport.clone());
    let answer = client
        .unlock_account(&UnlockAccount::new("sub-account").unwrap())
        .await
        .unwrap();

    assert_eq!(answer.state.as_deref(), Some("OPEN"));
    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].method, "account.login");
    assert_eq!(calls[1].method, "account.unlock");
    assert_eq!(calls[1].header("cookie"), Some("domrobot=abc123"));
}

/// The answer shape is derived, so a field the API adds later must not break a
/// successful unlock.
#[tokio::test]
async fn an_unlock_answer_with_unknown_fields_still_decodes() {
    let transport = MockTransport::new();
    transport.ok(json!({
        "username": "sub-account",
        "state": "OPEN",
        "unknown": 1,
        "type": {"nested": true},
    }));

    let client = client(transport);
    let answer = client
        .unlock_account(&UnlockAccount::new("sub-account").unwrap())
        .await
        .unwrap();

    assert_eq!(answer.username.as_deref(), Some("sub-account"));
    assert_eq!(answer.state.as_deref(), Some("OPEN"));
}

/// A success envelope without `resData` is still a completed unlock; nothing in
/// the derived shape is required.
#[tokio::test]
async fn an_unlock_answer_may_be_empty() {
    let transport = MockTransport::new();
    transport.ok_empty();

    let client = client(transport);
    let answer = client
        .unlock_account(&UnlockAccount::new("sub-account").unwrap())
        .await
        .unwrap();

    assert_eq!(answer, inwx_client::AccountUnlock::default());
}

/// An unknown sub-account is a plain API error, mapped with its code.
#[tokio::test]
async fn unlocking_an_unknown_sub_account_is_an_api_error() {
    let transport = MockTransport::new();
    transport.api_error(2303, "Object does not exist");

    let client = client(transport.clone());
    let error = client
        .unlock_account(&UnlockAccount::new("nobody").unwrap())
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Api { code: 2303, .. }));
    assert_eq!(error.code(), Some(2303));
    assert_eq!(transport.call_count(), 1);
}

/// The boundary of the answer shape, from both sides: an explicit `resData: null`
/// and an empty object are both a completed unlock with nothing reported, while
/// a `resData` that is not an object at all is a malformed answer and must be
/// reported as [`Error::Json`] instead of being swallowed.
#[tokio::test]
async fn a_non_object_unlock_answer_is_a_json_error() {
    for answer in [json!(null), json!({})] {
        let transport = MockTransport::new();
        transport.ok(answer);

        let client = client(transport.clone());
        let result = client
            .unlock_account(&UnlockAccount::new("sub-account").unwrap())
            .await;

        assert_eq!(result.unwrap(), inwx_client::AccountUnlock::default());
        assert_eq!(transport.call_count(), 1);
    }

    let transport = MockTransport::new();
    transport.ok(json!(5));

    let client = client(transport.clone());
    let error = client
        .unlock_account(&UnlockAccount::new("sub-account").unwrap())
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Json { .. }), "{error}");
    assert!(!error.is_retryable());
    assert_eq!(transport.call_count(), 1);
}

/// A timeout after `account.unlock` may already have unlocked the sub-account,
/// so the client hands the ambiguity back instead of unlocking twice.
#[tokio::test]
async fn an_uncertain_unlock_is_not_replayed() {
    let transport = MockTransport::new();
    transport.uncertain_failure("timeout waiting for response");
    transport.ok(json!({"state": "OPEN"}));

    let client = client(transport.clone());
    let error = client
        .unlock_account(&UnlockAccount::new("sub-account").unwrap())
        .await
        .unwrap_err();

    assert!(error.is_uncertain());
    assert!(!error.is_retryable());
    assert!(error.to_string().contains("may have been executed"));
    assert_eq!(transport.call_count(), 1);
}

/// A retryable failure that happened before the request was written is safe to
/// replay even for a mutating command.
#[tokio::test]
async fn an_unlock_that_never_left_is_retried() {
    let transport = MockTransport::new();
    transport.transport_failure("connection reset");
    transport.ok(json!({"state": "OPEN"}));

    let client = client(transport.clone());
    let answer = client
        .unlock_account(&UnlockAccount::new("sub-account").unwrap())
        .await
        .unwrap();

    assert_eq!(answer.state.as_deref(), Some("OPEN"));
    assert_eq!(transport.call_count(), 2);
}

/// The 64-character limit is proven from both sides where it is enforced: on the
/// way into the request. A name at the limit goes on the wire unchanged; one
/// character more is refused before a client is ever consulted, so the transport
/// sees nothing.
#[tokio::test]
async fn a_name_at_the_limit_goes_on_the_wire_and_one_more_does_not() {
    let at_limit = "a".repeat(inwx_client::MAX_SUBACCOUNT_USERNAME_LEN);
    let transport = MockTransport::new();
    transport.ok(json!({"username": at_limit.clone(), "state": "OPEN"}));

    let client = client(transport.clone());
    let answer = client
        .unlock_account(&UnlockAccount::new(at_limit.clone()).unwrap())
        .await
        .unwrap();

    assert_eq!(answer.username.as_deref(), Some(at_limit.as_str()));
    let call = transport.only_call();
    assert_eq!(call.params["user"], at_limit);

    // One character past the limit: the request cannot even be built.
    let error = UnlockAccount::new(format!("{at_limit}x")).unwrap_err();
    assert!(error.is_validation());
    assert!(error.to_string().contains("unlock.user"), "{error}");

    // Blank never identifies a sub-account either, and stays off the wire.
    assert!(UnlockAccount::new("").is_err());
    assert!(UnlockAccount::new("   ").is_err());
    assert_eq!(transport.call_count(), 1);
}

/// Without a session and without credentials there is nothing to unlock with.
#[tokio::test]
async fn unlocking_without_authentication_never_reaches_the_transport() {
    let transport = MockTransport::new();
    let client = InwxClient::new(transport.clone());
    let error = client
        .unlock_account(&UnlockAccount::new("sub-account").unwrap())
        .await
        .unwrap_err();

    assert!(matches!(error, Error::NotAuthenticated));
    assert_eq!(transport.call_count(), 0);
}
