//! The HTTP client against a loopback server: exact request shape, every
//! response class, and the bounded reads.

#![expect(
    clippy::expect_used,
    reason = "test helpers fail loudly like the tests they serve"
)]

mod support;

use std::ffi::OsString;
use std::net::TcpListener;

use githits_scan::api::http::HttpSbomApi;
use githits_scan::api::{
    ApiError, Code, FileStatus, MAX_RESPONSE_BYTES, OutputFormat, Problem, SbomApi, UploadFile,
    UploadSet, upload,
};
use githits_scan::env;
use support::jobs::ScriptedServer;
use support::{MockServer, body, head, response};

fn api(server: &MockServer) -> HttpSbomApi {
    api_at(&server.origin())
}

fn api_at(origin: &str) -> HttpSbomApi {
    let environment = env::from_source(|name| match name {
        "GITHITS_API_TOKEN" => Some(OsString::from("test-token")),
        "GITHITS_API_URL" => Some(OsString::from(origin)),
        _ => None,
    })
    .expect("environment");
    HttpSbomApi::new(environment).expect("client")
}

fn problem_of(error: ApiError) -> Option<(Box<Problem>, Option<String>)> {
    match error {
        ApiError::Problem {
            problem,
            retry_after,
        } => Some((problem, retry_after)),
        _ => None,
    }
}

fn upload(files: &[(&str, &str)]) -> UploadSet {
    UploadSet::try_new(
        files
            .iter()
            .map(|(path, contents)| UploadFile {
                path: (*path).to_owned(),
                contents: (*contents).to_owned(),
            })
            .collect(),
    )
    .expect("upload set")
}

#[test]
fn sends_the_documented_request_shape() {
    let server = ScriptedServer::success("spdx", b"SPDXVersion: SPDX-2.3\n");
    let files = [
        ("web/package.json", "{\"name\":\"x\"}"),
        ("web/package-lock.json", "{}"),
        ("r\u{e9}sum\u{e9}/Cargo.lock", "# lock\n"),
    ];

    let document = api_at(&server.origin())
        .generate(upload(&files), OutputFormat::Spdx, &mut |_| Ok(()))
        .expect("document");
    let requests = server.requests();
    let request = &requests[0];

    assert_eq!(document.bytes, b"SPDXVersion: SPDX-2.3\n");
    let head = head(request);
    assert!(
        head.starts_with("post /v1/experimental/lockfile-jobs?kind=sbom&format=spdx http/1.1\r\n"),
        "{head}"
    );
    assert!(
        head.contains("\r\nauthorization: bearer test-token\r\n"),
        "{head}"
    );
    assert!(
        head.contains("\r\nx-githits-client-name: githits-scan\r\n"),
        "{head}"
    );
    assert!(
        head.contains(&format!(
            "\r\nx-githits-client-version: {}\r\n",
            env!("CARGO_PKG_VERSION")
        )),
        "{head}"
    );
    assert!(
        head.contains(&format!(
            "\r\nuser-agent: githits-scan/{}\r\n",
            env!("CARGO_PKG_VERSION")
        )),
        "{head}"
    );
    assert!(
        head.contains("content-type: multipart/form-data; boundary="),
        "{head}"
    );

    let body = body(request);
    for (path, contents) in files {
        let part = format!(
            "Content-Disposition: form-data; name=\"files[]\"; filename=\"{path}\"\r\nContent-Type: application/octet-stream\r\n\r\n{contents}\r\n"
        );
        assert!(body.contains(&part), "missing part for {path} in:\n{body}");
    }
    assert!(
        !body.contains("r%C3%A9"),
        "non-ASCII paths are sent raw:\n{body}"
    );
    assert_eq!(body.matches("name=\"files[]\"").count(), 3);
    assert!(
        !body.contains("name=\"format\""),
        "format travels in the query only"
    );
}

#[test]
fn the_body_estimate_matches_the_real_content_length() {
    let server = ScriptedServer::success("cyclonedx", b"{}");
    let files = [
        ("Cargo.lock", "abc"),
        ("deep/dir/Cargo.toml", "[package]\n"),
    ];

    api_at(&server.origin())
        .generate(upload(&files), OutputFormat::CycloneDx, &mut |_| Ok(()))
        .expect("document");
    let requests = server.requests();
    let request = &requests[0];

    let head = head(request);
    let content_length: u64 = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .expect("content-length header")
        .trim()
        .parse()
        .expect("number");
    let estimate = upload::estimate_body(
        files
            .iter()
            .map(|(path, contents)| (*path, contents.len() as u64)),
    );
    assert_eq!(content_length, estimate);
}

#[test]
fn a_problem_document_becomes_a_typed_error_with_files_and_retry_after() {
    let server = MockServer::respond_with(response(
        "422 Unprocessable Content",
        &[
            ("Content-Type", "application/problem+json"),
            ("X-Request-ID", "req-42"),
            ("Retry-After", "17"),
        ],
        br#"{"type":"about:blank","title":"Unusable manifest","status":422,"detail":"One file could not be used.","instance":"req-42","code":"UNUSABLE_MANIFEST","files":[{"path":"Cargo.lock","status":"unparsed"}]}"#,
    ));

    let error = api(&server)
        .generate(
            upload(&[("Cargo.lock", "")]),
            OutputFormat::CycloneDx,
            &mut |_| Ok(()),
        )
        .expect_err("problem");

    let (problem, retry_after) = problem_of(error).expect("a problem document");
    assert_eq!(problem.code, Code::UnusableManifest);
    assert_eq!(problem.status, 422);
    assert_eq!(problem.instance, "req-42");
    assert_eq!(problem.files[0].status, FileStatus::Unparsed);
    assert_eq!(retry_after.as_deref(), Some("17"));
}

#[test]
fn a_non_problem_error_body_reports_the_status_and_request_id() {
    let server = MockServer::respond_with(response(
        "502 Bad Gateway",
        &[("Content-Type", "text/html"), ("X-Request-ID", "req-7")],
        b"<html>bad gateway</html>",
    ));

    let error = api(&server)
        .generate(
            upload(&[("Cargo.lock", "")]),
            OutputFormat::CycloneDx,
            &mut |_| Ok(()),
        )
        .expect_err("unexpected");

    assert!(
        matches!(&error, ApiError::Unexpected { status: 502, request_id: Some(id) } if id == "req-7"),
        "{error}"
    );
}

#[test]
fn the_documented_empty_500_has_no_request_id() {
    let server = MockServer::respond_with(response("500 Internal Server Error", &[], b""));

    let error = api(&server)
        .generate(
            upload(&[("Cargo.lock", "")]),
            OutputFormat::CycloneDx,
            &mut |_| Ok(()),
        )
        .expect_err("unexpected");

    assert!(
        matches!(
            error,
            ApiError::Unexpected {
                status: 500,
                request_id: None
            }
        ),
        "{error}"
    );
}

#[test]
fn redirects_are_not_followed() {
    let server = MockServer::respond_with(response(
        "307 Temporary Redirect",
        &[("Location", "http://127.0.0.1:9/elsewhere")],
        b"",
    ));

    let error = api(&server)
        .generate(
            upload(&[("Cargo.lock", "")]),
            OutputFormat::CycloneDx,
            &mut |_| Ok(()),
        )
        .expect_err("redirect");

    assert!(
        matches!(error, ApiError::Unexpected { status: 307, .. }),
        "{error}"
    );
}

#[test]
fn a_document_at_the_response_limit_is_accepted_and_one_byte_more_is_rejected() {
    let at_limit = vec![b'x'; MAX_RESPONSE_BYTES];
    let server = ScriptedServer::success("text", &at_limit);
    let document = api_at(&server.origin())
        .generate(
            upload(&[("Cargo.lock", "")]),
            OutputFormat::Text,
            &mut |_| Ok(()),
        )
        .expect("document at limit");
    assert_eq!(document.bytes.len(), MAX_RESPONSE_BYTES);
    assert_eq!(server.requests().len(), 3);

    let over = vec![b'x'; MAX_RESPONSE_BYTES + 1];
    let server = ScriptedServer::success("text", &over);
    let error = api_at(&server.origin())
        .generate(
            upload(&[("Cargo.lock", "")]),
            OutputFormat::Text,
            &mut |_| Ok(()),
        )
        .expect_err("over limit");
    assert!(matches!(error, ApiError::ResponseTooLarge), "{error}");
    assert_eq!(server.requests().len(), 3);
}

#[test]
fn a_connection_failure_is_a_transport_error_without_the_token() {
    // Bind and release a port so the connection is refused deterministically.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    drop(listener);

    let error = api_at(&origin)
        .generate(
            upload(&[("Cargo.lock", "")]),
            OutputFormat::CycloneDx,
            &mut |_| Ok(()),
        )
        .expect_err("refused");

    assert!(matches!(error, ApiError::Transport(_)), "{error}");
    let text = format!("{error} {:?}", std::error::Error::source(&error));
    assert!(!text.contains("test-token"), "{text}");
}

#[test]
fn a_gateway_timeout_remains_a_typed_problem() {
    let server = MockServer::respond_with(response(
        "504 Gateway Timeout",
        &[("Content-Type", "application/problem+json")],
        br#"{"status":504,"code":"TIMEOUT","detail":"Generation timed out.","instance":"req-timeout"}"#,
    ));

    let error = api(&server)
        .generate(
            upload(&[("Cargo.lock", "")]),
            OutputFormat::CycloneDx,
            &mut |_| Ok(()),
        )
        .expect_err("gateway timeout");

    let (problem, retry_after) = problem_of(error).expect("typed problem");
    assert_eq!(problem.code, Code::Timeout);
    assert_eq!(problem.status, 504);
    assert_eq!(problem.instance, "req-timeout");
    assert_eq!(retry_after, None);
    assert!(!server.request().is_empty(), "expected a non-empty value");
}
