//! Public job transport boundaries: recovery, failures, canonical links and bounded bodies.

#![expect(clippy::expect_used, reason = "test helpers fail loudly")]
mod support;

use std::ffi::OsString;

use githits_scan::api::http::HttpSbomApi;
use githits_scan::api::jobs::{FailureCode, Phase};
use githits_scan::api::{
    ApiError, Code, Document, MAX_EVENT_BYTES, MAX_PROBLEM_BYTES, OutputFormat, ProgressEvent,
    SbomApi, UploadFile, UploadSet,
};
use githits_scan::env;
use support::jobs::{BASE, ScriptedServer, accept_response, accepted, events_response, snapshot};
use support::{head, response};

fn api(server: &ScriptedServer) -> HttpSbomApi {
    let environment = env::from_source(|name| match name {
        "GITHITS_API_TOKEN" => Some(OsString::from("test-token")),
        "GITHITS_API_URL" => Some(OsString::from(server.origin())),
        _ => None,
    })
    .expect("environment");
    HttpSbomApi::new(environment).expect("client")
}

fn generate(server: &ScriptedServer, format: OutputFormat) -> Result<Document, ApiError> {
    api(server).generate(upload(), format, &mut |_| Ok(()))
}

fn upload() -> UploadSet {
    UploadSet::try_new(vec![UploadFile {
        path: "Cargo.lock".into(),
        contents: "# lock".into(),
    }])
    .expect("upload")
}

fn result(bytes: &[u8]) -> Vec<u8> {
    response(
        "200 OK",
        &[(
            "Content-Type",
            "application/vnd.cyclonedx+json; charset=utf-8",
        )],
        bytes,
    )
}

#[test]
fn reconnect_applies_equal_revision_latest_state_and_authenticates_each_open() {
    let mut first = snapshot("running", "resolving", 0);
    first["counts"] = serde_json::json!({"resolved": 12});
    let mut next = snapshot("running", "enriching", 0);
    next["attempt"] = 2.into();
    next["counts"] = serde_json::json!({"coordinates_done": 0, "coordinates_total": 14});
    let server = ScriptedServer::respond_with(vec![
        accept_response(),
        events_response(&[first]),
        events_response(&[next, snapshot("succeeded", "succeeded", 1)]),
        result(b"{}"),
    ]);
    let mut progress = Vec::new();
    let doc = api(&server)
        .generate(upload(), OutputFormat::CycloneDx, &mut |p| {
            progress.push(p.clone());
            Ok(())
        })
        .expect("recovered");
    assert_eq!(doc.bytes, b"{}");
    assert_eq!(progress.len(), 5);
    assert_eq!(progress[1], ProgressEvent::Reconnecting);
    assert_eq!(progress[4], ProgressEvent::Downloading);
    let next = match &progress[2] {
        ProgressEvent::Snapshot(next) => Some(next),
        ProgressEvent::Reconnecting | ProgressEvent::Downloading => None,
    }
    .expect("replacement snapshot");
    assert_eq!(next.phase, Phase::Enriching);
    assert_eq!(next.attempt, 2);
    assert_eq!(next.counts.resolved, None);
    assert_eq!(next.counts.coordinates_done, Some(0));
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert!(
        head(&requests[0])
            .starts_with("post /v1/experimental/lockfile-jobs?kind=sbom&format=cyclonedx ")
    );
    for request in &requests[1..] {
        let headers = head(request);
        assert!(headers.contains("authorization: bearer test-token\r\n"));
        assert!(headers.contains("x-githits-client-name: githits-scan\r\n"));
        assert!(!headers.contains("last-event-id"));
    }
    assert!(head(&requests[1]).starts_with(&format!("get {BASE}/events ")));
    assert!(head(&requests[2]).starts_with(&format!("get {BASE}/events ")));
    for request in &requests[1..=2] {
        assert!(head(request).contains("accept: text/event-stream\r\n"));
    }
    assert!(head(&requests[3]).starts_with(&format!("get {BASE}/result ")));
}

#[test]
fn every_allowlisted_terminal_failure_stops_without_download_or_reconnect() {
    let codes = [
        (
            FailureCode::ResolutionTimeout,
            "dependency resolution exceeded the service deadline; try scanning a smaller tree",
        ),
        (
            FailureCode::ResolutionFailed,
            "inspect the selected manifests; report persistent resolution failures with the request id",
        ),
        (
            FailureCode::OutputTooLarge,
            "scan a smaller tree or exclude unneeded lockfiles with --exclude",
        ),
        (
            FailureCode::UnrepresentableSpdx,
            "run again with --format cyclonedx",
        ),
        (
            FailureCode::ParserContractChanged,
            "the service could not complete analysis; report the failure code and request id to GitHits",
        ),
        (
            FailureCode::ExecutionFailed,
            "the service could not complete analysis; report the failure code and request id to GitHits",
        ),
        (
            FailureCode::ExecutionRecordUnavailable,
            "the service no longer has the execution record; run again",
        ),
        (
            FailureCode::InvalidResponse,
            "the service could not complete analysis; report the failure code and request id to GitHits",
        ),
        (
            FailureCode::NoManifestEvidence,
            "inspect the selected lockfiles and manifests for package evidence",
        ),
    ];
    for (code, action) in codes {
        let mut failed = snapshot("failed", "failed", 2);
        failed["error"] = code.as_str().into();
        let server =
            ScriptedServer::respond_with(vec![accept_response(), events_response(&[failed])]);
        let error = generate(&server, OutputFormat::CycloneDx).expect_err("failed job");
        assert!(
            matches!(&error, ApiError::JobFailed { code: actual, request_id: Some(id) } if *actual == code && id == "req-events")
        );
        assert!(error.to_string().contains(code.as_str()));
        assert_eq!(
            error.to_string(),
            format!(
                "analysis failed: {} (request id req-events)\n  action: {action}",
                code.as_str()
            )
        );
        assert_eq!(server.requests().len(), 2);
    }
}

#[test]
fn lifecycle_callback_failure_stops_before_reopen_or_result_request() {
    for event in [ProgressEvent::Reconnecting, ProgressEvent::Downloading] {
        lifecycle_callback_failure(&event);
    }
}

fn lifecycle_callback_failure(event: &ProgressEvent) {
    let (state, phase) = if *event == ProgressEvent::Reconnecting {
        ("running", "enriching")
    } else {
        ("succeeded", "succeeded")
    };
    let server = ScriptedServer::respond_with(vec![
        accept_response(),
        events_response(&[snapshot(state, phase, 1)]),
    ]);
    let mut observed = Vec::new();
    let error = api(&server)
        .generate(upload(), OutputFormat::CycloneDx, &mut |p| {
            observed.push(p.clone());
            if p == event {
                Err(std::io::Error::other("closed progress writer"))
            } else {
                Ok(())
            }
        })
        .expect_err("callback failure");
    assert!(matches!(error, ApiError::Progress(_)));
    assert_eq!(observed.len(), 2);
    assert_eq!(&observed[1], event);
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn any_opening_without_a_first_snapshot_fails_immediately() {
    for reopen in [false, true] {
        let mut responses = vec![accept_response()];
        if reopen {
            responses.push(events_response(&[snapshot("queued", "queued", 0)]));
        }
        responses.push(response(
            "200 OK",
            &[("Content-Type", "text/event-stream")],
            b": keepalive\n\n",
        ));
        let server = ScriptedServer::respond_with(responses);
        let error = generate(&server, OutputFormat::CycloneDx).expect_err("empty opening");
        assert!(matches!(
            error,
            ApiError::Protocol {
                reason: "stream ended before its first snapshot",
                ..
            }
        ));
        assert_eq!(server.requests().len(), if reopen { 3 } else { 2 });
    }
}

#[test]
fn opening_auth_terms_rate_and_absent_errors_do_not_retry() {
    for (status, code) in [
        ("401 Unauthorized", "AUTHENTICATION_REQUIRED"),
        ("403 Forbidden", "TERMS_ACCEPTANCE_REQUIRED"),
        ("404 Not Found", "ANALYSIS_NOT_FOUND"),
        ("429 Too Many Requests", "RATE_LIMITED"),
        ("503 Service Unavailable", "ANALYSIS_UNAVAILABLE"),
    ] {
        for reopen in [false, true] {
            opening_denial(status, code, reopen);
        }
    }
}

fn opening_denial(status: &str, code: &str, reopen: bool) {
    let mut responses = vec![accept_response()];
    if reopen {
        responses.push(events_response(&[snapshot("queued", "queued", 0)]));
    }
    let body = serde_json::json!({"status": status[..3].parse::<u16>().expect("status"), "code": code, "instance": "req-denial", "detail": "Denied.", "terms_url": "https://app.githits.com/terms", "acceptance_url": "https://app.githits.com/accept"});
    responses.push(response(
        status,
        &[
            ("Content-Type", "application/problem+json"),
            ("Retry-After", "17"),
        ],
        &serde_json::to_vec(&body).expect("json"),
    ));
    let server = ScriptedServer::respond_with(responses);
    let error = generate(&server, OutputFormat::CycloneDx).expect_err("denied opening");
    assert!(
        matches!(&error, ApiError::Problem { problem, retry_after } if problem.code.as_str() == code && retry_after.as_deref() == Some("17"))
    );
    let text = error.to_string();
    assert!(
        text.contains("req-denial")
            && text.contains("retry after: 17")
            && text.contains("terms: https://app.githits.com/terms")
    );
    assert_eq!(server.requests().len(), if reopen { 3 } else { 2 });
}

#[test]
fn pending_and_failed_downloads_preserve_distinct_problem_codes() {
    for (code, expected) in [
        ("ANALYSIS_PENDING", Code::AnalysisPending),
        ("ANALYSIS_FAILED", Code::AnalysisFailed),
    ] {
        let mut body = serde_json::json!({"status": 409, "code": code, "instance": "req-result"});
        if code == "ANALYSIS_FAILED" {
            body["failure_code"] = "output_too_large".into();
        }
        let server = ScriptedServer::respond_with(vec![
            accept_response(),
            events_response(&[snapshot("succeeded", "succeeded", 1)]),
            response(
                "409 Conflict",
                &[("Content-Type", "application/problem+json")],
                &serde_json::to_vec(&body).expect("json"),
            ),
        ]);
        let error = generate(&server, OutputFormat::CycloneDx).expect_err("not a document");
        assert!(matches!(&error, ApiError::Problem { problem, .. } if problem.code == expected));
        if code == "ANALYSIS_FAILED" {
            assert!(error.to_string().contains("failure: output_too_large"));
        }
        assert_eq!(server.requests().len(), 3);
    }
}

#[test]
fn all_result_formats_accept_gateway_utf8_charset_and_preserve_exact_bytes() {
    for (wire, format, bytes) in [
        ("cyclonedx", OutputFormat::CycloneDx, b"{}".as_slice()),
        (
            "spdx",
            OutputFormat::Spdx,
            b"SPDXVersion: SPDX-2.3\n".as_slice(),
        ),
        ("text", OutputFormat::Text, "inventory: é\n".as_bytes()),
    ] {
        let server = ScriptedServer::success(wire, bytes);
        assert_eq!(generate(&server, format).expect("format").bytes, bytes);
        assert_eq!(server.requests().len(), 3);
    }
}

#[test]
fn wrong_media_or_charset_is_never_a_document() {
    for media in [
        "text/plain",
        "application/vnd.cyclonedx+json; charset=latin1",
        "application/vnd.cyclonedx+json; broken",
    ] {
        let server = ScriptedServer::respond_with(vec![
            accept_response(),
            events_response(&[snapshot("succeeded", "succeeded", 1)]),
            response(
                "200 OK",
                &[("Content-Type", media), ("X-Request-ID", "req-media")],
                b"document",
            ),
        ]);
        let error = generate(&server, OutputFormat::CycloneDx).expect_err("media mismatch");
        assert!(
            matches!(error, ApiError::Protocol { request_id: Some(id), .. } if id == "req-media")
        );
        assert_eq!(server.requests().len(), 3);
    }
}

#[test]
fn acceptance_at_body_limit_is_accepted_and_one_more_byte_stops_before_open() {
    for extra in [0, 1] {
        let mut body = serde_json::to_vec(&accepted()).expect("json");
        body.resize(MAX_EVENT_BYTES + extra, b' ');
        let mut responses = vec![response(
            "202 Accepted",
            &[("Content-Type", "application/json")],
            &body,
        )];
        if extra == 0 {
            responses.extend([
                events_response(&[snapshot("succeeded", "succeeded", 1)]),
                result(b"{}"),
            ]);
        }
        let server = ScriptedServer::respond_with(responses);
        let result = generate(&server, OutputFormat::CycloneDx);
        if extra == 0 {
            assert_eq!(result.expect("at cap").bytes, b"{}");
        } else {
            assert!(matches!(
                result,
                Err(ApiError::Protocol {
                    reason: "analysis response exceeds the body limit",
                    ..
                })
            ));
        }
        assert_eq!(server.requests().len(), if extra == 0 { 3 } else { 1 });
    }
}

#[test]
fn oversized_problem_body_is_not_parsed_as_a_complete_problem() {
    for extra in [0, 1] {
        let mut body = br#"{"status":429,"code":"RATE_LIMITED","instance":"req-body"}"#.to_vec();
        body.resize(MAX_PROBLEM_BYTES + extra, b' ');
        let server = ScriptedServer::respond_with(vec![response(
            "429 Too Many Requests",
            &[("X-Request-ID", "req-body")],
            &body,
        )]);
        let error = generate(&server, OutputFormat::CycloneDx).expect_err("error response");
        if extra == 0 {
            assert!(matches!(error, ApiError::Problem { .. }));
        } else {
            assert!(
                matches!(error, ApiError::Unexpected { status: 429, request_id: Some(id) } if id == "req-body")
            );
        }
        assert_eq!(server.requests().len(), 1);
    }
}

#[test]
fn malformed_snapshot_is_not_recovered_or_exposed() {
    let mut invalid = snapshot("running", "resolving", 0);
    invalid["error"] = serde_json::json!({"diagnostic": "fake-private-marker"});
    let server = ScriptedServer::respond_with(vec![accept_response(), events_response(&[invalid])]);
    let error = generate(&server, OutputFormat::CycloneDx).expect_err("malformed");
    assert!(matches!(error, ApiError::Protocol { .. }));
    assert!(!error.to_string().contains("fake-private-marker"));
    assert_eq!(server.requests().len(), 2);
}
