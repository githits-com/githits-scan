//! Throttling is visible on stderr while result bytes and exit behavior survive.
use super::*;
use crate::support::jobs::{accept_response, events_response, rate_limited, snapshot};

const SBOM: &[u8] = br#"{"bomFormat":"CycloneDX","specVersion":"1.7","components":[]}"#;
const NOTICE: &str = "warning: rate limited while submitting analysis; retry 1 of up to 5 now (request id: req-limit)\n";

fn recovering(bytes: &[u8], audit: bool) -> ScriptedServer {
    let mut terminal = snapshot("succeeded", "succeeded", 1);
    if audit {
        terminal["kind"] = "audit".into();
        terminal["format"] = "json".into();
    }
    let media = if audit {
        "application/json"
    } else {
        "application/vnd.cyclonedx+json"
    };
    ScriptedServer::respond_with(vec![
        rate_limited("0"),
        accept_response(),
        events_response(&[terminal]),
        response("200 OK", &[("Content-Type", media)], bytes),
    ])
}

#[test]
fn rate_limit_sbom_recovers_with_exact_document_in_normal_and_quiet_modes() {
    let repo = repository(&[("Cargo.lock", "")]);
    for flags in [&[][..], &["--quiet"][..]] {
        let server = recovering(SBOM, false);
        let output = generate(
            repo.path(),
            Some("test-token"),
            Some(&server.origin()),
            flags,
        );
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(output.stdout, SBOM);
        assert!(stderr(&output).contains(NOTICE), "{}", stderr(&output));
        if !flags.is_empty() {
            assert_eq!(stderr(&output), NOTICE);
        }
        assert_eq!(server.requests().len(), 4);
    }
}

#[test]
fn rate_limit_audit_and_license_json_keep_warnings_and_valid_json() {
    let repo = repository(&[
        ("Cargo.lock", ""),
        (
            "githits-scan.toml",
            "version=1\n[lockfiles]\ninclude=[\"Cargo.lock\"]\n[licenses]\nallow=[]\n",
        ),
    ]);
    let audit = serde_json::to_vec(&crate::support::audit::clean()).expect("audit JSON");
    let licenses = include_bytes!("../fixtures/licenses/report-v2.json");
    for (command, bytes, is_audit) in [
        (&["audit"][..], audit.as_slice(), true),
        (&["license", "check"][..], SBOM, false),
        (&["license", "report"][..], licenses.as_slice(), false),
    ] {
        let mut terminal = snapshot("succeeded", "succeeded", 1);
        if is_audit {
            terminal["kind"] = "audit".into();
            terminal["format"] = "json".into();
        }
        let media = if is_audit || command == ["license", "report"] {
            "application/json"
        } else {
            "application/vnd.cyclonedx+json"
        };
        let server = ScriptedServer::respond_with(vec![
            rate_limited("0"),
            accept_response(),
            events_response(&[terminal]),
            response("200 OK", &[("Content-Type", media)], bytes),
        ]);
        let output = githits_scan()
            .args(command)
            .arg(repo.path())
            .args(["--json", "--quiet"])
            .env("GITHITS_API_TOKEN", "test-token")
            .env("GITHITS_API_URL", server.origin())
            .output()
            .expect("binary");
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let _: serde_json::Value = serde_json::from_slice(&output.stdout).expect("result JSON");
        assert!(stderr(&output).contains(NOTICE), "{}", stderr(&output));
        assert!(!stderr(&output).contains("test-token"));
        assert_eq!(server.requests().len(), 4);
    }
}

#[test]
fn rate_limit_exhaustion_preserves_existing_output_and_exit_three() {
    let repo = repository(&[("Cargo.lock", ""), ("bom.json", "keep existing bytes")]);
    let target = repo.path().join("bom.json");
    let server = ScriptedServer::respond_with(vec![rate_limited("0"); 6]);
    let output = generate(
        repo.path(),
        Some("test-token"),
        Some(&server.origin()),
        &["--quiet", "--output", target.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(
        fs::read(target).expect("existing output"),
        b"keep existing bytes"
    );
    let text = stderr(&output);
    assert_eq!(text.matches("warning: rate limited").count(), 5);
    for attempt in 1..=5 {
        assert!(text.contains(&format!("retry {attempt} of up to 5")));
    }
    assert!(text.contains("warning: automatic rate-limit recovery stopped after 5 retries"));
    assert!(text.contains("error: RATE_LIMITED (HTTP 429)"));
    assert!(text.contains("request id: req-limit"));
    assert!(!text.contains("test-token"));
    assert_eq!(server.requests().len(), 6);
}

#[test]
fn rate_limit_missing_delay_says_the_service_supplied_none() {
    let repo = repository(&[("Cargo.lock", "")]);
    let server = ScriptedServer::respond_with(vec![response("429 Too Many Requests", &[("Content-Type", "application/problem+json")], br#"{"status":429,"code":"RATE_LIMITED","detail":"Too many requests.","instance":"req-no-delay"}"#)]);
    let output = generate(
        repo.path(),
        Some("test-token"),
        Some(&server.origin()),
        &["--quiet"],
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(
        stderr(&output),
        "error: RATE_LIMITED (HTTP 429): Too many requests.\n  request id: req-no-delay\n  action: the service supplied no retry delay; reduce request frequency and try again later\n"
    );
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn rate_limit_wait_budget_names_requested_and_remaining_wait() {
    let repo = repository(&[("Cargo.lock", "")]);
    let server = ScriptedServer::respond_with(vec![rate_limited("301")]);
    let output = generate(
        repo.path(),
        Some("test-token"),
        Some(&server.origin()),
        &["--quiet"],
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(stderr(&output).starts_with("warning: automatic rate-limit recovery stopped: the server requested 301s but only 300s of waiting remain\n"));
    assert!(stderr(&output).contains("error: RATE_LIMITED (HTTP 429)"));
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn rate_limit_raw_response_has_a_useful_action_without_exposing_its_body() {
    let repo = repository(&[("Cargo.lock", "")]);
    let server = ScriptedServer::respond_with(vec![response(
        "429 Too Many Requests",
        &[("X-Request-ID", "req-proxy")],
        b"untrusted-proxy-text",
    )]);
    let output = generate(
        repo.path(),
        Some("test-token"),
        Some(&server.origin()),
        &["--quiet"],
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stdout, [] as [u8; 0]);
    let text = stderr(&output);
    assert!(text.contains("req-proxy"));
    assert!(text.contains(
        "the service rate limited this request; reduce request frequency and try again later"
    ));
    assert!(!text.contains("untrusted-proxy-text"));
    assert_eq!(server.requests().len(), 1);
}
