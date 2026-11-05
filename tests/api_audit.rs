//! Audit uses the same authenticated, single-submit job transport.
#![expect(clippy::expect_used, reason = "test helpers fail loudly")]
mod support;

use githits_scan::{
    api::http::HttpSbomApi,
    api::jobs::{FailureCode, Phase},
    api::{ApiError, AuditApi, MAX_RESPONSE_BYTES, ProgressEvent, UploadFile, UploadSet},
    env,
};
use std::ffi::OsString;
use support::jobs::{ScriptedServer, accept_response, events_response, snapshot};
use support::{head, response};

const REPORT: &[u8] = include_bytes!("fixtures/audit/findings.json");
fn audit_snapshot(state: &str, phase: &str, revision: u64) -> serde_json::Value {
    let mut s = snapshot(state, phase, revision);
    s["kind"] = "audit".into();
    s["format"] = "json".into();
    s
}
fn result(bytes: &[u8]) -> Vec<u8> {
    response(
        "200 OK",
        &[
            ("Content-Type", "application/json"),
            ("X-Request-ID", "req-audit-result"),
        ],
        bytes,
    )
}
fn client(s: &ScriptedServer) -> HttpSbomApi {
    HttpSbomApi::new(
        env::from_source(|name| match name {
            "GITHITS_API_TOKEN" => Some(OsString::from("test-token")),
            "GITHITS_API_URL" => Some(OsString::from(s.origin())),
            _ => None,
        })
        .expect("environment"),
    )
    .expect("client")
}
fn upload() -> UploadSet {
    UploadSet::try_new(vec![UploadFile {
        path: "package-lock.json".into(),
        contents: "{}".into(),
    }])
    .expect("upload")
}
fn audit(s: &ScriptedServer) -> Result<githits_scan::api::audit::Report, ApiError> {
    client(s).audit(upload(), &mut |_| Ok(()))
}
fn success(result: Vec<u8>) -> ScriptedServer {
    ScriptedServer::respond_with(vec![
        accept_response(),
        events_response(&[audit_snapshot("succeeded", "succeeded", 1)]),
        result,
    ])
}

#[test]
fn audit_reconnect_replaces_equal_revision_assessments_and_never_resubmits() {
    let mut first = audit_snapshot("running", "assessing", 0);
    first["counts"] = serde_json::json!({"assessments_done":0,"assessments_total":2});
    let mut next = audit_snapshot("running", "future_phase", 0);
    next["attempt"] = 2.into();
    next["counts"] = serde_json::json!({});
    let s = ScriptedServer::respond_with(vec![
        accept_response(),
        events_response(&[first]),
        events_response(&[next, audit_snapshot("succeeded", "succeeded", 0)]),
        result(REPORT),
    ]);
    let mut progress = Vec::new();
    let r = client(&s)
        .audit(upload(), &mut |e| {
            progress.push(e.clone());
            Ok(())
        })
        .expect("audit");
    assert_eq!(r.version(), 1);
    assert_eq!(progress.len(), 5);
    assert_eq!(progress[1], ProgressEvent::Reconnecting);
    let first = match &progress[0] {
        ProgressEvent::Snapshot(s) => Some(s),
        _ => None,
    }
    .expect("snapshot");
    assert_eq!(first.phase, Phase::Assessing);
    assert_eq!(first.counts.assessments_done, Some(0));
    let next = match &progress[2] {
        ProgressEvent::Snapshot(s) => Some(s),
        _ => None,
    }
    .expect("snapshot");
    assert_eq!(next.phase, Phase::Unknown);
    assert_eq!(next.attempt, 2);
    assert_eq!(next.counts.assessments_done, None);
    let requests = s.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests
            .iter()
            .filter(|r| head(r).starts_with("post "))
            .count(),
        1
    );
    assert!(head(&requests[0]).contains("kind=audit&format=json"));
    for r in requests {
        assert!(
            head(&r)
                .to_ascii_lowercase()
                .contains("authorization: bearer test-token")
        );
    }
}

#[test]
fn audit_admission_and_result_errors_have_no_fallback_or_second_submission() {
    for status in [
        "401 Unauthorized",
        "429 Too Many Requests",
        "422 Unprocessable Entity",
    ] {
        let s = ScriptedServer::respond_with(vec![response(
            status,
            &[("Content-Type", "text/plain")],
            b"untrusted",
        )]);
        assert!(audit(&s).is_err());
        assert_eq!(s.requests().len(), 1);
    }
    for status in ["409 Conflict", "404 Not Found", "302 Found"] {
        let s = success(response(status,&[("Content-Type","application/problem+json")], br#"{"code":"ANALYSIS_PENDING","status":409,"instance":"req","type":"about:blank","title":"pending"}"#));
        assert!(audit(&s).is_err());
        assert_eq!(s.requests().len(), 3);
    }
}

#[test]
fn audit_terminal_failure_and_unfamiliar_state_stop_before_result() {
    let mut failed = audit_snapshot("failed", "failed", 1);
    failed["error"] = "future executor secret diagnostic".into();
    let s = ScriptedServer::respond_with(vec![accept_response(), events_response(&[failed])]);
    let e = audit(&s).expect_err("failed");
    assert!(matches!(
        e,
        ApiError::JobFailed {
            code: FailureCode::Unknown,
            ..
        }
    ));
    assert!(!e.to_string().contains("secret"));
    assert_eq!(s.requests().len(), 2);
    let s = ScriptedServer::respond_with(vec![
        accept_response(),
        events_response(&[audit_snapshot("future_terminal", "future_phase", 1)]),
    ]);
    assert!(matches!(audit(&s), Err(ApiError::Protocol { .. })));
    assert_eq!(s.requests().len(), 2);
}

#[test]
fn audit_result_media_structure_and_size_fail_closed() {
    for r in [
        response("200 OK", &[("Content-Type", "text/plain")], REPORT),
        result(b"{}"),
        result(br#"{"schema_version":1}"#),
    ] {
        let s = success(r);
        let error = audit(&s).expect_err("invalid result");
        assert!(matches!(error, ApiError::Protocol { .. }));
        if error.to_string().contains("report") {
            assert!(error.to_string().contains("req-audit-result"));
        }
        assert_eq!(s.requests().len(), 3);
    }
    let s = success(result(&vec![b' '; MAX_RESPONSE_BYTES + 1]));
    assert!(matches!(audit(&s), Err(ApiError::ResponseTooLarge)));
    assert_eq!(s.requests().len(), 3);
}
