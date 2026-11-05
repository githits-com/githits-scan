//! Quiet mode preserves documents, failures and exit codes at the actual CLI.
use super::*;

const DOCUMENT: &[u8] = br#"{"bomFormat":"CycloneDX","specVersion":"1.7","components":[]}"#;

#[test]
fn quiet_sbom_preserves_document_and_file_with_both_flag_spellings() {
    for flag in ["-q", "--quiet"] {
        let repo = repository(&[("Cargo.lock", "")]);
        let server = ScriptedServer::success("cyclonedx", DOCUMENT);
        let output = generate(
            repo.path(),
            Some("test-token"),
            Some(&server.origin()),
            &[flag],
        );
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, DOCUMENT);
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
        assert_eq!(server.requests().len(), 3);
        let file = repo.path().join("sbom.json");
        let server = ScriptedServer::success("cyclonedx", DOCUMENT);
        let output = generate(
            repo.path(),
            Some("test-token"),
            Some(&server.origin()),
            &[flag, "-o", file.to_str().expect("path")],
        );
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        assert_eq!(fs::read(file).expect("file"), DOCUMENT);
        assert_eq!(server.requests().len(), 3);
    }
}

fn quiet_command(command: &[&str], root: &Path, origin: Option<&str>) -> Output {
    let mut child = githits_scan();
    child
        .args(command)
        .arg(root)
        .arg("--quiet")
        .env_remove("GITHITS_API_TOKEN")
        .env_remove("GITHITS_API_URL");
    if let Some(origin) = origin {
        child
            .env("GITHITS_API_TOKEN", "test-token")
            .env("GITHITS_API_URL", origin);
    }
    child.output().expect("binary")
}

#[test]
fn quiet_keeps_missing_token_api_failure_and_blocked_scan_diagnostics() {
    for command in [&["audit"][..], &["sbom", "generate"][..]] {
        let repo = repository(&[("Cargo.lock", "")]);
        let output = quiet_command(command, repo.path(), None);
        assert_eq!(output.status.code(), Some(2));
        assert!(stderr(&output).contains("GITHITS_API_TOKEN"));
        assert!(output.stdout.is_empty(), "{:?}", output.stdout);
        let server = MockServer::respond_with(response("429 Too Many Requests", &[("Content-Type", "application/problem+json"), ("Retry-After", "60")], br#"{"type":"about:blank","title":"Rate limited","status":429,"detail":"Too many requests.","instance":"req-quiet","code":"RATE_LIMITED"}"#));
        let output = quiet_command(command, repo.path(), Some(&server.origin()));
        drop(server.request());
        assert_eq!(output.status.code(), Some(3));
        assert!(stderr(&output).starts_with("error: RATE_LIMITED"));
        assert!(
            stderr(&output).contains("req-quiet") && stderr(&output).contains("retry after: 60")
        );
        assert!(output.stdout.is_empty(), "{:?}", output.stdout);
        let empty = repository(&[]);
        let output = quiet_command(command, empty.path(), Some("http://127.0.0.1:1"));
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains("no lockfiles"));
        assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    }
}

#[test]
fn quiet_and_exclude_help_is_consistent_across_commands() {
    for command in [
        &["detect"][..],
        &["audit"][..],
        &["sbom", "generate"][..],
        &["license", "check"][..],
        &["license", "report"][..],
    ] {
        let output = githits_scan()
            .args(command)
            .arg("--help")
            .output()
            .expect("help");
        assert_eq!(output.status.code(), Some(0));
        assert!(stdout(&output).contains("-q, --quiet"));
        assert!(stdout(&output).contains("Omit matching package files"));
    }
}

#[test]
fn quiet_sbom_keeps_partial_resolution_warning_without_changing_document_or_exit() {
    let document = br#"{"bomFormat":"CycloneDX","properties":[{"name":"githits:completeness","value":"partial_manifest_inventory"}],"components":[]}"#;
    for flag in ["-q", "--quiet"] {
        let repo = repository(&[("Cargo.lock", "")]);
        let server = ScriptedServer::success("cyclonedx", document);
        let output = generate(
            repo.path(),
            Some("test-token"),
            Some(&server.origin()),
            &[flag],
        );
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, document);
        assert_eq!(
            stderr(&output),
            "warning: SBOM dependency resolution is incomplete (partial_manifest_inventory)\n"
        );
        assert_eq!(server.requests().len(), 3);
    }
}

#[test]
fn unusable_inputs_suggest_excluding_unrelated_projects_for_audit_and_sbom() {
    for command in [&["audit"][..], &["sbom", "generate"][..]] {
        let repo = repository(&[("Cargo.lock", "")]);
        let server = ScriptedServer::respond_with(vec![response("422 Unprocessable Entity", &[("Content-Type", "application/problem+json")], br#"{"status":422,"code":"UNUSABLE_MANIFEST","title":"Unusable input","detail":"A selected file could not be parsed.","instance":"req-fixture","files":[{"path":"tests/fixtures/Cargo.lock","status":"unparsed"}]}"#)]);
        let output = quiet_command(command, repo.path(), Some(&server.origin()));
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty(), "{:?}", output.stdout);
        let text = stderr(&output);
        for expected in [
            "req-fixture",
            "tests/fixtures/Cargo.lock: unparsed",
            "exclude unrelated projects with --exclude <glob>",
            "fix the listed files",
        ] {
            assert!(text.contains(expected), "{expected}: {text}");
        }
        assert_eq!(server.requests().len(), 1);
    }
}
