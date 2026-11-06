//! Experimental diff argument and immutable-input contract.
use std::fs;
use std::path::Path;
use std::process::Command;

use super::{githits_scan, stderr, stdout};

fn git_output(root: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env_remove("GITHITS_API_TOKEN")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .expect("git")
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = git_output(root, args);
    assert!(output.status.success(), "git failed");
    String::from_utf8(output.stdout).expect("Git UTF-8")
}

fn committed(root: &Path) {
    git(root, &["init", "--quiet"]);
    git(root, &["config", "user.name", "Fixture"]);
    git(root, &["config", "user.email", "fixture@example.invalid"]);
    git(root, &["config", "core.autocrlf", "false"]);
    git(root, &["add", "."]);
    git(root, &["commit", "--quiet", "-m", "fixture"]);
}

#[test]
fn diff_help_marks_experimental_and_documents_working_tree() {
    let output = githits_scan()
        .args(["diff", "--help"])
        .output()
        .expect("help");
    assert!(output.status.success());
    for text in [
        "experimental",
        "--base",
        "--head",
        "working tree",
        "--format",
        "--lockfiles-only",
    ] {
        assert!(stdout(&output).contains(text), "missing {text}");
    }
}

#[test]
fn diff_identical_inputs_need_no_token_and_preserve_checkout() {
    let repo = tempfile::tempdir().expect("repository");
    fs::write(repo.path().join("Cargo.lock"), "version = 4\n").expect("lockfile");
    committed(repo.path());
    let before = git(repo.path(), &["status", "--porcelain=v1"]);
    let output = githits_scan()
        .arg("diff")
        .arg(repo.path())
        .args(["--base", "HEAD", "--head", "HEAD", "--format", "json"])
        .env_remove("GITHITS_API_TOKEN")
        .env_remove("GITHITS_API_URL")
        .output()
        .expect("diff");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("report");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["analysis_performed"], false);
    assert_eq!(report["changes"], serde_json::json!([]));
    assert_eq!(git(repo.path(), &["status", "--porcelain=v1"]), before);
}

#[test]
fn diff_bad_ref_is_usage_error_without_ref_echo_or_network() {
    let repo = tempfile::tempdir().expect("repository");
    fs::write(repo.path().join("Cargo.lock"), "version = 4\n").expect("lockfile");
    committed(repo.path());
    let output = githits_scan()
        .arg("diff")
        .arg(repo.path())
        .args(["--base=--output=private-sentinel", "--format", "json"])
        .env_remove("GITHITS_API_TOKEN")
        .output()
        .expect("diff");
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert_eq!(stdout(&output), "");
    assert!(!stderr(&output).contains("private-sentinel"));
    assert!(stderr(&output).contains("revision"));
}

fn pair() -> tempfile::TempDir {
    let (manifest, lock) = super::support::diff::files(false);
    let repo =
        super::support::repository(&[("package.json", manifest), ("package-lock.json", lock)]);
    committed(repo.path());
    let (manifest, lock) = super::support::diff::files(true);
    fs::write(repo.path().join("package.json"), manifest).expect("head manifest");
    fs::write(repo.path().join("package-lock.json"), lock).expect("head lock");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "--quiet", "-m", "head fixture"]);
    repo
}

fn online(root: &Path, origin: &str) -> std::process::Output {
    githits_scan()
        .arg("diff")
        .arg(root)
        .args(["--base", "HEAD~1", "--head", "HEAD", "--format", "json"])
        .env("GITHITS_API_TOKEN", "test-token")
        .env("GITHITS_API_URL", origin)
        .output()
        .expect("online diff")
}

fn upgrade_response() -> Vec<u8> {
    super::support::response("200 OK", &[("Content-Type","application/json")],
        &serde_json::to_vec(&serde_json::json!({"total":1,"reviews":[super::support::diff::review("minimist","1.2.5","1.2.8")]})).expect("JSON"))
}

#[test]
fn diff_binary_uploads_base_head_and_reviews_only_the_direct_upgrade() {
    use super::support::{diff as fixture, jobs::ScriptedServer};
    let repo = pair();
    let before = git(repo.path(), &["status", "--porcelain=v1"]);
    let server = ScriptedServer::respond_with(
        [
            fixture::exchanges(false, false),
            fixture::exchanges(true, false),
            fixture::exchanges(false, true),
            fixture::exchanges(true, true),
            vec![upgrade_response()],
        ]
        .concat(),
    );
    let output = online(repo.path(), &server.origin());
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("report");
    assert_eq!(report["changes"].as_array().expect("changes").len(), 4);
    assert_eq!(report["changes"][1]["head_scope"], "transitive");
    assert_eq!(report["changes"][2]["head_scope"], "direct");
    assert_eq!(
        report["changes"][1]["vulnerabilities"]["introduced"],
        serde_json::json!(["GHSA-introduced"])
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 13);
    for (index, head) in [(0, false), (3, true), (6, false), (9, true)] {
        let body = String::from_utf8_lossy(&requests[index]);
        assert!(body.contains(fixture::files(head).1));
    }
    let upgrade = String::from_utf8_lossy(&requests[12]);
    assert!(
        upgrade.starts_with("POST /v1/package-upgrade-reviews?fields=security.direct,changelog ")
    );
    let body: serde_json::Value =
        serde_json::from_str(upgrade.split("\r\n\r\n").nth(1).expect("body"))
            .expect("upgrade request");
    assert_eq!(body["packages"].as_array().expect("packages").len(), 1);
    assert_eq!(body["packages"][0]["name"], "minimist");
    assert_eq!(git(repo.path(), &["status", "--porcelain=v1"]), before);
}

#[test]
fn diff_audit_rate_limit_retains_inventory_and_unknown_security_without_retry() {
    use super::support::{diff as fixture, jobs::ScriptedServer, response};
    let repo = pair();
    let limited = response("429 Too Many Requests", &[("Content-Type","application/problem+json"),("Retry-After","65")],
        br#"{"status":429,"code":"RATE_LIMITED","detail":"Slow down.","instance":"fixture-request"}"#);
    let server = ScriptedServer::respond_with(
        [
            fixture::exchanges(false, false),
            fixture::exchanges(true, false),
            vec![limited, upgrade_response()],
        ]
        .concat(),
    );
    let output = online(repo.path(), &server.origin());
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("report");
    assert_eq!(report["incomplete"], true);
    assert_eq!(
        report["changes"][2]["vulnerabilities"]["fixed"],
        serde_json::Value::Null
    );
    assert!(stderr(&output).contains("retry after: 65s"));
    assert_eq!(server.requests().len(), 8);
}

#[test]
fn diff_empty_base_and_working_tree_edits_are_compared_without_checkout_changes() {
    use super::support::{diff as fixture, jobs::ScriptedServer};
    let repo = super::support::repository(&[("README.md", "fixture")]);
    committed(repo.path());
    let (manifest, lock) = fixture::files(true);
    fs::write(repo.path().join("package.json"), manifest).expect("manifest");
    fs::write(repo.path().join("package-lock.json"), lock).expect("lock");
    let before = git(repo.path(), &["status", "--porcelain=v1"]);
    let server = ScriptedServer::respond_with(
        [
            fixture::exchanges(true, false),
            fixture::exchanges(true, true),
        ]
        .concat(),
    );
    let output = githits_scan()
        .arg("diff")
        .arg(repo.path())
        .args(["--base", "HEAD", "--format", "json"])
        .env("GITHITS_API_TOKEN", "test-token")
        .env("GITHITS_API_URL", server.origin())
        .output()
        .expect("diff");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("report");
    assert_eq!(report["head"], "working-tree");
    assert!(
        report["changes"]
            .as_array()
            .expect("changes")
            .iter()
            .all(|c| c["kind"] == "added")
    );
    assert_eq!(server.requests().len(), 6);
    assert_eq!(git(repo.path(), &["status", "--porcelain=v1"]), before);
}

#[test]
fn diff_omitted_evidence_remains_in_json_on_the_identical_input_path() {
    let repo = super::support::repository(&[
        ("pom.xml", "<project/>"),
        ("githits-scan.toml", "version=1"),
    ]);
    committed(repo.path());
    let output = githits_scan()
        .arg("diff")
        .arg(repo.path())
        .args(["--base", "HEAD", "--head", "HEAD", "--format", "json"])
        .env_remove("GITHITS_API_TOKEN")
        .output()
        .expect("diff");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("report");
    assert_eq!(report["incomplete"], true);
    assert!(report["notices"].to_string().contains("pom.xml"));
    assert!(
        report["notices"]
            .to_string()
            .contains("ignores githits-scan.toml")
    );
}

#[test]
fn diff_large_selected_blob_fails_before_reading_credentials() {
    let repo = tempfile::tempdir().expect("repo");
    fs::File::create(repo.path().join("Cargo.lock"))
        .expect("file")
        .set_len(githits_scan::api::MAX_FILE_BYTES + 1)
        .expect("length");
    committed(repo.path());
    let output = githits_scan()
        .arg("diff")
        .arg(repo.path())
        .args(["--base", "HEAD", "--head", "HEAD"])
        .env_remove("GITHITS_API_TOKEN")
        .output()
        .expect("diff");
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("limit per file"));
    assert_eq!(stdout(&output), "");
}

#[test]
fn diff_rejects_sparse_working_tree_and_accepts_explicit_committed_head() {
    let repo = super::support::repository(&[
        ("README.md", "fixture"),
        ("sub/Cargo.lock", "version = 4\n"),
    ]);
    committed(repo.path());
    git(
        repo.path(),
        &["sparse-checkout", "set", "--no-cone", "README.md"],
    );
    let output = githits_scan()
        .arg("diff")
        .arg(repo.path())
        .args(["--base", "HEAD"])
        .env_remove("GITHITS_API_TOKEN")
        .output()
        .expect("diff");
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("sparse working tree"));
    let output = githits_scan()
        .arg("diff")
        .arg(repo.path())
        .args(["--base", "HEAD", "--head", "HEAD", "--format", "json"])
        .env_remove("GITHITS_API_TOKEN")
        .output()
        .expect("committed diff");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn diff_missing_partial_clone_blob_fails_without_hydrating() {
    let repo = super::support::repository(&[("Cargo.lock", "version = 4\n")]);
    committed(repo.path());
    let oid = git(repo.path(), &["rev-parse", "HEAD:Cargo.lock"]);
    let oid = oid.trim();
    let object = repo
        .path()
        .join(".git/objects")
        .join(&oid[..2])
        .join(&oid[2..]);
    assert!(object.is_file());
    git(
        repo.path(),
        &[
            "config",
            "remote.origin.url",
            "https://127.0.0.1:9/unavailable",
        ],
    );
    git(repo.path(), &["config", "remote.origin.promisor", "true"]);
    git(
        repo.path(),
        &["config", "extensions.partialClone", "origin"],
    );
    fs::remove_file(&object).expect("simulate missing promisor blob");
    let output = githits_scan()
        .arg("diff")
        .arg(repo.path())
        .args(["--base", "HEAD", "--head", "HEAD"])
        .env_remove("GITHITS_API_TOKEN")
        .env("GIT_NO_LAZY_FETCH", "0")
        .output()
        .expect("diff");
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("object unavailable locally"));
    assert!(!object.exists());
}

#[test]
fn diff_file_count_limit_has_a_diff_specific_selection_hint() {
    let repo = tempfile::tempdir().expect("repo");
    for i in 0..257 {
        let dir = repo.path().join(format!("project-{i}"));
        fs::create_dir(&dir).expect("dir");
        fs::write(dir.join("Cargo.lock"), "version = 4\n").expect("lock");
    }
    committed(repo.path());
    let output = githits_scan()
        .arg("diff")
        .arg(repo.path())
        .args(["--base", "HEAD", "--head", "HEAD"])
        .env_remove("GITHITS_API_TOKEN")
        .output()
        .expect("diff");
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("257 files"));
    assert!(stderr(&output).contains("narrow both diff inputs"));
    assert!(!stderr(&output).contains("detect --save"));
}

#[cfg(unix)]
#[test]
fn diff_does_not_follow_working_tree_symlink_directories() {
    use std::os::unix::fs::symlink;
    let repo = super::support::repository(&[("sub/Cargo.lock", "version = 4\n")]);
    committed(repo.path());
    let outside = super::support::repository(&[("Cargo.lock", "private-sentinel")]);
    fs::remove_dir_all(repo.path().join("sub")).expect("replace fixture directory");
    symlink(outside.path(), repo.path().join("sub")).expect("symlink");
    let output = githits_scan()
        .arg("diff")
        .arg(repo.path())
        .args(["--base", "HEAD", "--format", "json"])
        .env_remove("GITHITS_API_TOKEN")
        .output()
        .expect("diff");
    // Only the historical side remains selected; credentials are requested before any upload.
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("GITHITS_API_TOKEN"));
    assert!(!stderr(&output).contains("private-sentinel"));
}

#[test]
fn diff_unmerged_working_tree_fails_before_any_analysis() {
    let repo = super::support::repository(&[("Cargo.lock", "base\n")]);
    committed(repo.path());
    git(repo.path(), &["checkout", "-q", "-b", "theirs"]);
    fs::write(repo.path().join("Cargo.lock"), "theirs\n").expect("theirs");
    git(repo.path(), &["commit", "-qam", "theirs"]);
    git(repo.path(), &["checkout", "-q", "-b", "ours", "HEAD~1"]);
    fs::write(repo.path().join("Cargo.lock"), "ours\n").expect("ours");
    git(repo.path(), &["commit", "-qam", "ours"]);
    assert!(
        !git_output(repo.path(), &["merge", "theirs"])
            .status
            .success()
    );
    let output = githits_scan()
        .arg("diff")
        .arg(repo.path())
        .args(["--base", "HEAD"])
        .env_remove("GITHITS_API_TOKEN")
        .output()
        .expect("diff");
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("unmerged Git paths"));
}

// APFS rejects these names; Git record decoding is tested independently on every platform.
#[cfg(target_os = "linux")]
#[test]
fn diff_ignores_non_utf8_unrelated_names_but_rejects_non_utf8_package_paths() {
    use std::os::unix::ffi::OsStringExt;
    for package in [false, true] {
        let repo = super::support::repository(&[("Cargo.lock", "version = 4\n")]);
        let name = std::ffi::OsString::from_vec(b"odd\xff".to_vec());
        let path = repo.path().join(name);
        if package {
            fs::create_dir(&path).expect("directory");
            fs::write(path.join("Cargo.lock"), "version = 4\n").expect("lock");
        } else {
            fs::write(path, "unrelated").expect("unrelated file");
        }
        committed(repo.path());
        let output = githits_scan()
            .arg("diff")
            .arg(repo.path())
            .args(["--base", "HEAD", "--head", "HEAD", "--format", "json"])
            .env_remove("GITHITS_API_TOKEN")
            .output()
            .expect("diff");
        assert_eq!(
            output.status.code(),
            Some(if package { 2 } else { 0 }),
            "{}",
            stderr(&output)
        );
    }
}
