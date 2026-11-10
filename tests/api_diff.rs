//! Paired request shape, exact full-wire accounting and shared transport security.
#![expect(clippy::expect_used, reason = "fixture helpers fail loudly")]
mod support;
use githits_scan::{
    api::{
        self, UploadFile, UploadSet,
        diff::{DiffApi, Input, UnlockedManifests},
        http::HttpSbomApi,
    },
    env,
};
use std::ffi::OsString;
use support::{body, diff as fixture, head, jobs::ScriptedServer, response};

fn set(path: &str, contents: &str) -> UploadSet {
    UploadSet::try_new(vec![UploadFile {
        path: path.into(),
        contents: contents.into(),
    }])
    .expect("set")
}
fn client(origin: &str) -> HttpSbomApi {
    HttpSbomApi::new(
        env::from_source(|key| match key {
            "GITHITS_API_TOKEN" => Some(OsString::from("test-token")),
            "GITHITS_API_URL" => Some(OsString::from(origin)),
            _ => None,
        })
        .expect("environment"),
    )
    .expect("client")
}
fn input() -> Input {
    Input::try_new(
        Some(set("résumé/package.json", "{\"name\":\"a\"}")),
        Some(set("résumé/package.json", "{\"name\":\"b\"}")),
        UnlockedManifests::RecordedOnly,
    )
    .expect("input")
}

#[test]
fn diff_http_sends_literal_paired_fields_and_exact_required_controls() {
    let bytes = serde_json::to_vec_pretty(&fixture::report()).expect("json");
    let server = ScriptedServer::respond_with(fixture::exchanges(&bytes));
    let report = client(&server.origin())
        .diff(input(), &mut |_| Ok(()))
        .expect("report");
    assert_eq!(report.bytes(), bytes);
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(head(&requests[0]).starts_with("post /v1/experimental/dependency-diffs http/1.1"));
    assert!(head(&requests[0]).contains("authorization: bearer test-token"));
    let wire = body(&requests[0]);
    for field in ["base_files[]", "head_files[]"] {
        assert!(wire.contains(&format!(
            "name=\"{field}\"; filename=\"résumé/package.json\""
        )));
    }
    assert!(wire.contains("name=\"request\"\r\n\r\n"));
    assert!(!wire.contains("r%C3%A9"));
    let json = wire
        .split("name=\"request\"\r\n\r\n")
        .nth(1)
        .expect("request")
        .split("\r\n")
        .next()
        .expect("JSON");
    let value: serde_json::Value = serde_json::from_str(json).expect("controls");
    assert_eq!(
        value,
        serde_json::json!({"schema_version":1,"base":{"state":"supplied"},"head":{"state":"supplied"},
        "selection":{"groups":["all"],"unlocked_manifests":"recorded_only"},"analysis":{"advisories":true,"direct_reviews":true}})
    );
    let expected = paired_bytes(
        &[
            ("base_files[]", "résumé/package.json", 12),
            ("head_files[]", "résumé/package.json", 12),
        ],
        json.len(),
    );
    assert_eq!(wire.len(), expected);
    let length = head(&requests[0])
        .lines()
        .find_map(|s| s.strip_prefix("content-length: ").map(str::to_owned))
        .expect("length");
    assert_eq!(length.parse::<usize>().expect("number"), expected);
}

// Independent literal wire oracle, rather than using the production estimator.
fn paired_bytes(files: &[(&str, &str, usize)], request: usize) -> usize {
    let boundary = 67;
    let files:usize=files.iter().map(|(field,path,n)|2+boundary+2+
        format!("Content-Disposition: form-data; name=\"{field}\"; filename=\"{path}\"\r\nContent-Type: application/octet-stream\r\n\r\n").len()+n+2).sum();
    files
        + 2
        + boundary
        + 2
        + "Content-Disposition: form-data; name=\"request\"\r\n\r\n".len()
        + request
        + 2
        + 2
        + boundary
        + 4
}

#[test]
fn diff_http_accepts_the_exact_eight_million_byte_wire_body() {
    let controls=serde_json::json!({"schema_version":1,"base":{"state":"supplied"},"head":{"state":"supplied"},
        "selection":{"groups":["all"],"unlocked_manifests":"resolve"},"analysis":{"advisories":true,"direct_reviews":true}}).to_string();
    let room = usize::try_from(api::MAX_BODY_BYTES).expect("size")
        - paired_bytes(
            &[("base_files[]", "x", 0), ("head_files[]", "y", 0)],
            controls.len(),
        );
    let input = Input::try_new(
        Some(set("x", &"a".repeat(room / 2))),
        Some(set("y", &"b".repeat(room - room / 2))),
        UnlockedManifests::Resolve,
    )
    .expect("exact input");
    let server = ScriptedServer::respond_with(fixture::exchanges(
        &serde_json::to_vec(&fixture::report()).expect("json"),
    ));
    client(&server.origin())
        .diff(input, &mut |_| Ok(()))
        .expect("report");
    let requests = server.requests();
    assert_eq!(body(&requests[0]).len(), 8_000_000);
}

#[test]
fn diff_http_does_not_retry_admission_or_follow_redirects() {
    for status in ["429 Too Many Requests", "307 Temporary Redirect"] {
        let server = ScriptedServer::respond_with(vec![response(
            status,
            &[("Location", "https://example.invalid/steal")],
            b"",
        )]);
        let error = client(&server.origin())
            .diff(input(), &mut |_| Ok(()))
            .err()
            .expect("error");
        assert!(!error.to_string().contains("test-token"));
        assert_eq!(server.requests().len(), 1);
    }
}

#[test]
fn diff_http_rejects_wrong_sse_kind_without_a_result_request() {
    let server = ScriptedServer::respond_with(vec![
        support::jobs::accept_response(),
        support::jobs::events_response(&[support::jobs::snapshot("succeeded", "succeeded", 1)]),
    ]);
    assert!(
        client(&server.origin())
            .diff(input(), &mut |_| Ok(()))
            .is_err()
    );
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn rate_limit_diff_rebuilds_paired_upload_and_recovers_without_a_second_job() {
    let bytes = serde_json::to_vec(&fixture::report()).expect("JSON");
    let mut replies = vec![support::jobs::rate_limited("0")];
    replies.extend(fixture::exchanges(&bytes));
    let server = ScriptedServer::respond_with(replies);
    let report = client(&server.origin())
        .diff(input(), &mut |_| Ok(()))
        .expect("recovered");
    assert_eq!(report.bytes(), bytes);
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    for request in &requests[..2] {
        let wire = body(request);
        for (field, name) in [("base_files[]", "a"), ("head_files[]", "b")] {
            assert!(wire.contains(&format!(
                "name=\"{field}\"; filename=\"résumé/package.json\""
            )));
            assert!(wire.contains(&format!("{{\"name\":\"{name}\"}}")));
        }
        assert!(wire.contains("name=\"request\"\r\n\r\n"));
    }
    let controls = |request: &[u8]| {
        body(request)
            .split("name=\"request\"\r\n\r\n")
            .nth(1)
            .expect("controls")
            .split("\r\n")
            .next()
            .expect("JSON")
            .to_owned()
    };
    assert_eq!(controls(&requests[0]), controls(&requests[1]));
}

#[test]
fn rate_limit_diff_shares_submission_budget_with_result_download() {
    let mut replies = vec![support::jobs::rate_limited("0"); 5];
    let bytes = serde_json::to_vec(&fixture::report()).expect("JSON");
    let mut accepted = fixture::exchanges(&bytes);
    accepted[2] = support::jobs::rate_limited("0");
    replies.extend(accepted);
    let server = ScriptedServer::respond_with(replies);
    let error = client(&server.origin())
        .diff(input(), &mut |_| Ok(()))
        .map(|_| ())
        .expect_err("shared budget");
    assert!(
        matches!(error, api::ApiError::Problem { problem, .. } if problem.code == api::Code::RateLimited)
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 8);
    assert_eq!(
        requests
            .iter()
            .filter(|r| head(r).starts_with("post "))
            .count(),
        6
    );
    assert!(head(&requests[7]).contains("/result "));
}
