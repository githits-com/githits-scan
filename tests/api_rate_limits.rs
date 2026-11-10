//! Bounded throttling recovery at each request in one accepted-job lifecycle.
#![expect(clippy::expect_used, reason = "test fixtures fail loudly")]
mod support;

use std::ffi::OsString;
use std::time::Duration;

use githits_scan::api::http::HttpSbomApi;
use githits_scan::api::{ApiError, OutputFormat, ProgressEvent, SbomApi, UploadFile, UploadSet};
use githits_scan::env;
use support::jobs::{
    ScriptedServer, accept_response, events_response, rate_limited as limited, snapshot,
};
use support::{body, head, response};

fn client(server: &ScriptedServer) -> HttpSbomApi {
    HttpSbomApi::new(
        env::from_source(|key| match key {
            "GITHITS_API_TOKEN" => Some(OsString::from("test-token")),
            "GITHITS_API_URL" => Some(OsString::from(server.origin())),
            _ => None,
        })
        .expect("environment"),
    )
    .expect("client")
}

fn upload() -> UploadSet {
    UploadSet::try_new(vec![UploadFile {
        path: "résumé/Cargo.lock".into(),
        contents: "original lock bytes\n".into(),
    }])
    .expect("upload")
}

fn result() -> Vec<u8> {
    response("200 OK", &[("Content-Type", "text/plain")], b"document")
}

fn events(terminal: bool) -> Vec<u8> {
    let mut value = if terminal {
        snapshot("succeeded", "succeeded", 1)
    } else {
        snapshot("queued", "queued", 0)
    };
    value["format"] = "text".into();
    events_response(&[value])
}

#[test]
fn rate_limit_recovers_at_submission_events_reopening_and_result() {
    let server = ScriptedServer::respond_with(vec![
        limited("0"),
        accept_response(),
        limited("0"),
        events(false),
        limited("0"),
        events(true),
        limited("0"),
        result(),
    ]);
    let mut notices = Vec::new();
    let doc = client(&server)
        .generate(upload(), OutputFormat::Text, &mut |event| {
            notices.push(event.clone());
            Ok(())
        })
        .expect("recovered");
    assert_eq!(doc.bytes, b"document");
    assert_retry_notices(&notices);
    assert_replayed_requests(&server.requests());
}

fn assert_retry_notices(notices: &[ProgressEvent]) {
    let retries: Vec<_> = notices
        .iter()
        .filter_map(|event| match event {
            ProgressEvent::RateLimited {
                attempt,
                delay,
                request_id,
                ..
            } => Some((*attempt, *delay, request_id.as_deref())),
            _ => None,
        })
        .collect();
    assert_eq!(
        retries,
        (1..=4)
            .map(|n| (n, Duration::ZERO, Some("req-limit")))
            .collect::<Vec<_>>()
    );
}

fn assert_replayed_requests(requests: &[Vec<u8>]) {
    assert_eq!(requests.len(), 8);
    for (first, second) in [(0, 1), (2, 3), (4, 5), (6, 7)] {
        assert_eq!(
            head(&requests[first]).lines().next(),
            head(&requests[second]).lines().next()
        );
    }
    for request in &requests[..2] {
        assert!(body(request).contains("filename=\"résumé/Cargo.lock\""));
        assert!(body(request).contains("original lock bytes\n"));
    }
    assert_eq!(
        requests
            .iter()
            .filter(|r| head(r).starts_with("post "))
            .count(),
        2
    );
    assert!(
        requests
            .iter()
            .all(|r| head(r).contains("authorization: bearer test-token"))
    );
}

#[test]
fn rate_limit_stops_after_exactly_five_retries() {
    let server = ScriptedServer::respond_with(vec![limited("0"); 6]);
    let mut notices = 0;
    let error = client(&server)
        .generate(upload(), OutputFormat::Text, &mut |event| {
            if matches!(event, ProgressEvent::RateLimited { .. }) {
                notices += 1;
            }
            Ok(())
        })
        .expect_err("exhausted");
    assert_eq!(notices, 5);
    assert!(
        matches!(error, ApiError::Problem { problem, retry_after } if problem.instance == "req-limit" && retry_after.as_deref() == Some("0"))
    );
    assert_eq!(server.requests().len(), 6);
}

#[test]
fn rate_limit_budget_is_not_reset_by_accepted_job_or_stream_reopen() {
    let mut responses = vec![limited("0"); 3];
    responses.extend([
        accept_response(),
        limited("0"),
        events(false),
        limited("0"),
        events(true),
        limited("0"),
    ]);
    let server = ScriptedServer::respond_with(responses);
    let error = client(&server)
        .generate(upload(), OutputFormat::Text, &mut |_| Ok(()))
        .expect_err("shared budget exhausted");
    assert!(
        matches!(error, ApiError::Problem { problem, .. } if problem.code.as_str() == "RATE_LIMITED")
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 9);
    assert!(head(&requests[8]).contains("/result "));
}

#[test]
fn rate_limit_invalid_missing_and_excessive_delays_stop_immediately() {
    for delay in [
        None,
        Some("invalid"),
        Some("301"),
        Some("18446744073709551616"),
    ] {
        let reply = delay.map_or_else(
            || {
                response(
                    "429 Too Many Requests",
                    &[("X-Request-ID", "req-raw")],
                    b"proxy rejection",
                )
            },
            limited,
        );
        let server = ScriptedServer::respond_with(vec![reply]);
        let mut retries = 0;
        let error = client(&server)
            .generate(upload(), OutputFormat::Text, &mut |event| {
                retries += usize::from(matches!(event, ProgressEvent::RateLimited { .. }));
                Ok(())
            })
            .expect_err("terminal 429");
        assert_eq!(retries, 0);
        assert!(matches!(
            error,
            ApiError::Problem { .. } | ApiError::Unexpected { status: 429, .. }
        ));
        assert_eq!(server.requests().len(), 1);
    }
}

#[test]
fn rate_limit_notice_failure_stops_before_wait_or_next_request() {
    let server = ScriptedServer::respond_with(vec![limited("60")]);
    let error = client(&server)
        .generate(upload(), OutputFormat::Text, &mut |_| {
            Err(std::io::Error::other("notice failed"))
        })
        .expect_err("failed callback");
    assert!(matches!(error, ApiError::Progress(_)));
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn rate_limit_eligibility_uses_http_status_and_header_instead_of_problem_body() {
    for payload in [
        b"proxy HTML".as_slice(),
        br#"{"status":429,"code":"FUTURE_LIMIT"}"#.as_slice(),
    ] {
        let denied = response("429 Too Many Requests", &[("Retry-After", "0")], payload);
        let server =
            ScriptedServer::respond_with(vec![denied, accept_response(), events(true), result()]);
        let document = client(&server)
            .generate(upload(), OutputFormat::Text, &mut |_| Ok(()))
            .expect("HTTP refusal recovered");
        assert_eq!(document.bytes, b"document");
        assert_eq!(server.requests().len(), 4);
    }
}
