//! Binary compatibility coverage for including manifest-only projects by
//! default, and for `detect` agreeing with what `sbom generate` would upload.

use super::*;

const LISTED: &str = "version = 1\n\n[lockfiles]\ninclude = []\nmanifests = [\"app/package.json\"]\n\n[licenses]\nallow = [\"MIT\"]\n";

#[test]
fn sbom_uploads_configured_workspace_evidence_and_honors_member_exclusion() {
    let repo = repository(&[
        ("githits-scan.toml", include_str!("../../githits-scan.toml")),
        ("Cargo.lock", "# shared workspace lock\n"),
        ("Cargo.toml", "[workspace]\nmembers = [\"xtask\"]\n"),
        (
            "xtask/Cargo.toml",
            "[package]\nname = \"xtask\"\nversion = \"0.0.0\"\n",
        ),
        ("unrelated/Cargo.toml", "[package]\nname = \"unrelated\"\n"),
    ]);
    let document = br#"{"properties":[{"name":"githits:completeness","value":"recorded_lockfile_inventory"}]}"#;
    for exclude_member in [false, true] {
        let server = ScriptedServer::success("cyclonedx", document);
        let extra = if exclude_member {
            &["--exclude", "xtask/**"][..]
        } else {
            &[]
        };
        let output = generate(
            repo.path(),
            Some("test-token"),
            Some(&server.origin()),
            extra,
        );
        let requests = server.requests();

        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(output.stdout, document);
        assert_eq!(requests.len(), 3, "one job, events and result");
        let request = String::from_utf8_lossy(&requests[0]);
        for path in ["Cargo.lock", "Cargo.toml"] {
            assert_eq!(request.matches(&format!("filename=\"{path}\"")).count(), 1);
        }
        assert_eq!(
            request.contains("filename=\"xtask/Cargo.toml\""),
            !exclude_member
        );
        assert!(!request.contains("filename=\"xtask/Cargo.lock\""));
        assert!(!request.contains("filename=\"unrelated/Cargo.toml\""));
        assert_eq!(
            request.matches("filename=").count(),
            if exclude_member { 2 } else { 3 }
        );
        let summary = if exclude_member {
            "uploaded 1 lockfile and 1 manifest (Cargo.toml)\n"
        } else {
            "uploaded 1 lockfile and 2 manifests (Cargo.toml, xtask/Cargo.toml)\n"
        };
        assert!(stderr(&output).contains(summary), "{}", stderr(&output));
        assert!(!stderr(&output).contains("resolved without"));
    }
}

#[test]
fn license_check_uploads_a_manifest_only_project_by_default() {
    let repo = repository(&[("githits-scan.toml", LISTED), ("app/package.json", "{}")]);
    let server = ScriptedServer::success("cyclonedx", CYCLONEDX.as_bytes());

    let output = githits_scan()
        .args(["license", "check", "--json"])
        .arg(repo.path())
        .env("GITHITS_API_TOKEN", "test-token")
        .env("GITHITS_API_URL", server.origin())
        .output()
        .expect("run githits-scan license check");
    let requests = server.requests();

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(
        stderr(&output),
        "uploaded 0 lockfiles and 1 manifest (app/package.json)\n"
    );
    let request = String::from_utf8_lossy(&requests[0]);
    assert_eq!(request.matches("filename=").count(), 1, "{request}");
    assert!(
        request.contains("filename=\"app/package.json\""),
        "{request}"
    );
}

#[test]
fn detect_lockfiles_only_still_counts_a_listed_manifest_only_project() {
    let repo = repository(&[
        ("githits-scan.toml", LISTED),
        ("app/package.json", "{}"),
        ("tools/package.json", "{}"),
    ]);

    let output = detect(repo.path(), &["--lockfiles-only"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report = stdout(&output);
    let (inventory, skipped) = report
        .split_once("Manifest-only projects (not uploaded with --lockfiles-only):")
        .expect("skipped section");
    assert!(
        inventory.contains("app/package.json") && inventory.contains("included"),
        "{report}"
    );
    assert!(!inventory.contains("tools/package.json"), "{report}");
    assert!(skipped.contains("tools/package.json"), "{report}");
    assert!(!skipped.contains("app/package.json"), "{report}");
}

#[test]
fn detect_reports_findings_when_every_lockfile_is_excluded() {
    let repo = repository(&[("Cargo.lock", "")]);

    let output = detect(repo.path(), &["--exclude", "Cargo.lock"]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
}

#[test]
fn an_empty_upload_names_unlisted_manifest_only_projects() {
    let repo = repository(&[
        (
            "githits-scan.toml",
            "version = 1\n\n[lockfiles]\ninclude = []\n",
        ),
        ("app/package.json", "{}"),
    ]);

    let output = generate(
        repo.path(),
        Some("test-token"),
        Some("http://127.0.0.1:9"),
        &["--no-check"],
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(
        stderr(&output).contains(
            "1 manifest-only project not uploaded (not listed in the configuration): app/package.json\n"
        ),
        "{}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains("submitting"));
}

#[test]
fn an_empty_upload_with_excluded_lockfiles_names_skipped_projects() {
    let repo = repository(&[("Cargo.lock", ""), ("app/package.json", "{}")]);

    let output = generate(
        repo.path(),
        Some("test-token"),
        Some("http://127.0.0.1:9"),
        &["--lockfiles-only", "--exclude", "Cargo.lock"],
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let stderr = stderr(&output);
    assert!(stderr.contains("every lockfile is excluded"), "{stderr}");
    assert!(
        stderr.contains(
            "1 manifest-only project not uploaded (--lockfiles-only): app/package.json\n"
        ),
        "{stderr}"
    );
    assert!(!stderr.contains("submitting"));
}

#[test]
fn detect_succeeds_when_only_a_listed_nested_manifest_would_be_uploaded() {
    let repo = repository(&[
        (
            "githits-scan.toml",
            "version = 1\n\n[lockfiles]\ninclude = []\nexclude = [\"Cargo.lock\"]\nmanifests = [\"crates/core/Cargo.toml\"]\n",
        ),
        ("Cargo.lock", ""),
        ("crates/core/Cargo.toml", ""),
    ]);

    let output = detect(repo.path(), &[]);

    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
    let report = stdout(&output);
    let row = report
        .lines()
        .find(|line| line.trim_start().starts_with("crates/core/Cargo.toml"))
        .expect("nested row");
    assert!(row.trim_end().ends_with("included"), "{report}");
    assert!(
        report.starts_with("no lockfiles, 1 lockfile excluded, 1 additional manifest included"),
        "{report}"
    );
    assert!(
        report.contains("Manifests included by configuration:"),
        "{report}"
    );
}
