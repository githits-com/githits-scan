//! The licenses view reuses analysis ownership and progress, without another result download.
#![expect(clippy::expect_used, reason = "test helpers fail loudly")]
mod support;

use std::ffi::OsString;
use std::io;

use githits_scan::api::http::HttpSbomApi;
use githits_scan::api::{ApiError, Code, LicensesApi, ProgressEvent, UploadFile, UploadSet};
use githits_scan::env;
use support::jobs::{ID, ScriptedServer, accept_response, accepted, events_response, snapshot};
use support::{head, response};

const REPORT: &[u8] = include_bytes!("fixtures/licenses/report-v1.json");
const REPORT_V2: &[u8] = include_bytes!("fixtures/licenses/report-v2.json");

fn client(server: &ScriptedServer) -> HttpSbomApi {
    HttpSbomApi::new(
        env::from_source(|name| match name {
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
        path: "package-lock.json".into(),
        contents: "{}".into(),
    }])
    .expect("upload")
}

fn result(bytes: &[u8]) -> Vec<u8> {
    response(
        "200 OK",
        &[
            ("Content-Type", "application/json; charset=utf-8"),
            ("X-Request-ID", "req-licenses"),
        ],
        bytes,
    )
}

fn success(download: Vec<u8>) -> ScriptedServer {
    ScriptedServer::respond_with(vec![
        accept_response(),
        events_response(&[snapshot("succeeded", "succeeded", 1)]),
        download,
    ])
}

#[test]
fn license_report_downloads_only_the_view_after_success_and_reconnect() {
    let server = ScriptedServer::respond_with(vec![
        accept_response(),
        events_response(&[snapshot("running", "enriching", 0)]),
        events_response(&[snapshot("succeeded", "succeeded", 1)]),
        result(REPORT_V2),
    ]);
    let mut progress = Vec::new();
    let report = client(&server)
        .report(upload(), &mut |event| {
            progress.push(event.clone());
            Ok(())
        })
        .expect("report");
    assert_eq!(report.bytes(), REPORT_V2);
    let value: serde_json::Value = serde_json::from_slice(report.bytes()).expect("report JSON");
    assert_eq!(value["schema_version"], 2);
    assert!(progress.contains(&ProgressEvent::Reconnecting));
    assert_eq!(progress.last(), Some(&ProgressEvent::Downloading));
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert!(
        head(&requests[0])
            .starts_with("post /v1/experimental/lockfile-jobs?kind=sbom&format=cyclonedx ")
    );
    assert!(
        head(&requests[1]).starts_with(&format!("get /v1/experimental/lockfile-jobs/{ID}/events "))
    );
    assert!(
        head(&requests[2]).starts_with(&format!("get /v1/experimental/lockfile-jobs/{ID}/events "))
    );
    assert!(head(&requests[3]).starts_with(&format!("get /v1/experimental/license-reports/{ID} ")));
    for request in &requests {
        assert!(head(request).contains("authorization: bearer test-token"));
    }
}

#[test]
fn license_report_failures_keep_request_identity_and_do_not_resubmit() {
    for (status, code, expected) in [
        (409, "INCOMPATIBLE_ANALYSIS", Code::IncompatibleAnalysis),
        (422, "LICENSE_REPORT_TOO_LARGE", Code::LicenseReportTooLarge),
        (429, "RATE_LIMITED", Code::RateLimited),
    ] {
        let body = format!(r#"{{"status":{status},"code":"{code}","instance":"req-failure"}}"#);
        let server = success(response(
            &format!("{status} Error"),
            &[
                ("Content-Type", "application/problem+json"),
                ("Retry-After", "301"),
            ],
            body.as_bytes(),
        ));
        let error = client(&server)
            .report(upload(), &mut |_| Ok(()))
            .map(|_| ())
            .expect_err("expected failure");
        assert!(matches!(error, ApiError::Problem { ref problem, .. }
            if problem.code == expected && problem.instance == "req-failure"));
        assert_eq!(server.requests().len(), 3);
    }
}

#[test]
fn license_report_invalid_data_and_media_fail_without_payload_excerpts() {
    for download in [
        result(b"untrusted-payload"),
        response(
            "200 OK",
            &[
                ("Content-Type", "text/plain"),
                ("X-Request-ID", "req-licenses"),
            ],
            REPORT,
        ),
    ] {
        let server = success(download);
        let error = client(&server)
            .report(upload(), &mut |_| Ok(()))
            .map(|_| ())
            .expect_err("expected failure");
        assert!(error.to_string().contains("req-licenses"));
        assert!(!error.to_string().contains("untrusted-payload"));
        assert_eq!(server.requests().len(), 3);
    }
}

#[test]
fn license_report_callback_failure_stops_before_download() {
    let server = ScriptedServer::respond_with(vec![
        accept_response(),
        events_response(&[snapshot("succeeded", "succeeded", 1)]),
    ]);
    let error = client(&server).report(upload(), &mut |_| Err(io::Error::other("closed progress")));
    assert!(matches!(error, Err(ApiError::Progress(_))));
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn license_report_still_rejects_foreign_job_links() {
    let mut job = accepted();
    job["result_url"] = "https://example.invalid/result".into();
    let server = ScriptedServer::respond_with(vec![response(
        "202 Accepted",
        &[("Content-Type", "application/json")],
        &serde_json::to_vec(&job).expect("json"),
    )]);
    assert!(matches!(
        client(&server).report(upload(), &mut |_| Ok(())),
        Err(ApiError::Protocol { .. })
    ));
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn rate_limit_license_result_retries_only_the_existing_report_view() {
    let server = ScriptedServer::respond_with(vec![
        accept_response(),
        events_response(&[snapshot("succeeded", "succeeded", 1)]),
        support::jobs::rate_limited("0"),
        result(REPORT_V2),
    ]);
    let report = client(&server)
        .report(upload(), &mut |_| Ok(()))
        .expect("recovered view");
    assert_eq!(report.bytes(), REPORT_V2);
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    for request in &requests[2..] {
        assert!(head(request).starts_with(&format!("get /v1/experimental/license-reports/{ID} ")));
    }
    assert_eq!(
        requests
            .iter()
            .filter(|r| head(r).starts_with("post "))
            .count(),
        1
    );
}
