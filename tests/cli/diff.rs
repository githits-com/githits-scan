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
        "--output-json",
        "--output-markdown",
        "--lockfiles-only",
    ] {
        assert!(stdout(&output).contains(text), "missing {text}");
    }
}

#[test]
fn diff_identical_inputs_require_a_real_assessment_and_credentials() {
    let repo = super::support::repository(&[("Cargo.lock", "version = 4\n")]);
    committed(repo.path());
    let before = git(repo.path(), &["status", "--porcelain=v1"]);
    let output = githits_scan()
        .arg("diff")
        .arg(repo.path())
        .args(["--base", "HEAD", "--head", "HEAD", "--format", "json"])
        .env_remove("GITHITS_API_TOKEN")
        .output()
        .expect("diff");
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("GITHITS_API_TOKEN"));
    assert_eq!(output.stdout, [] as [u8; 0]);
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

#[test]
fn diff_binary_uses_one_paired_job_and_preserves_original_json() {
    use super::support::{diff as fixture, jobs::ScriptedServer};
    let repo = pair();
    let before = git(repo.path(), &["status", "--porcelain=v1"]);
    let bytes = serde_json::to_vec_pretty(&fixture::report()).expect("report");
    let server = ScriptedServer::respond_with(fixture::exchanges(&bytes));
    let output = online(repo.path(), &server.origin());
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, bytes);
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    let body = String::from_utf8_lossy(&requests[0]);
    assert!(body.starts_with("POST /v1/experimental/dependency-diffs HTTP/1.1"));
    for field in ["base_files[]", "head_files[]", "request"] {
        assert!(body.contains(&format!("name=\"{field}\"")));
    }
    for side in [false, true] {
        let (manifest, lock) = fixture::files(side);
        assert!(body.contains(manifest));
        assert!(body.contains(lock));
    }
    assert!(body.contains("\"unlocked_manifests\":\"resolve\""));
    assert_eq!(git(repo.path(), &["status", "--porcelain=v1"]), before);
}

#[test]
fn diff_binary_uploads_bun_workspace_members_once_per_side_in_both_modes() {
    use super::support::{diff as fixture, jobs::ScriptedServer};
    let repo = super::support::repository(&[
        ("bun.lock", "{}"),
        (
            "package.json",
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        ),
        (
            "packages/a/package.json",
            r#"{"name":"a","version":"1.0.0"}"#,
        ),
        (
            "packages/b/package.json",
            r#"{"name":"b","version":"1.0.0"}"#,
        ),
    ]);
    committed(repo.path());
    let bytes = serde_json::to_vec(&fixture::report()).expect("report");
    for lockfiles_only in [false, true] {
        let server = ScriptedServer::respond_with(fixture::exchanges(&bytes));
        let mut command = githits_scan();
        command
            .arg("diff")
            .arg(repo.path())
            .args(["--base", "HEAD", "--head", "HEAD", "--format", "json"])
            .env("GITHITS_API_TOKEN", "test-token")
            .env("GITHITS_API_URL", server.origin());
        if lockfiles_only {
            command.arg("--lockfiles-only");
        }
        let output = command.output().expect("diff");
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(output.stdout, bytes);
        let requests = server.requests();
        assert_eq!(requests.len(), 3, "one paired job");
        assert_bun_workspace_parts(&requests[0]);
    }
}

fn assert_bun_workspace_parts(request: &[u8]) {
    let body = String::from_utf8_lossy(request);
    for path in [
        "bun.lock",
        "package.json",
        "packages/a/package.json",
        "packages/b/package.json",
    ] {
        assert_eq!(
            body.matches(&format!("filename=\"{path}\"")).count(),
            2,
            "one copy per revision: {path}"
        );
    }
}

#[test]
fn diff_binary_retains_partial_and_future_reports_without_a_safe_claim() {
    use super::support::{diff as fixture, jobs::ScriptedServer};
    for future in [false, true] {
        let repo = pair();
        let mut value = fixture::report();
        value["outcome"] = "partial".into();
        value["advisories"] =
            serde_json::json!({"status":"unavailable","reason":"provider_unavailable"});
        if future {
            value = serde_json::json!({"schema_version":99,"kind":"diff","new_shape":true});
        }
        let bytes = serde_json::to_vec(&value).expect("report");
        let server = ScriptedServer::respond_with(fixture::exchanges(&bytes));
        let output = online(repo.path(), &server.origin());
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(output.stdout, bytes);
        assert_eq!(server.requests().len(), 3);
    }
}

#[test]
fn diff_binary_side_qualified_admission_failure_writes_no_document_or_retry() {
    use super::support::{jobs::ScriptedServer, response};
    let repo = pair();
    let server=ScriptedServer::respond_with(vec![response("422 Unprocessable Content",&[("Content-Type","application/problem+json")],
        br#"{"status":422,"code":"UNUSABLE_MANIFEST","side":"head","instance":"request-fixture","files":[{"path":"package.json","status":"unparsed"}]}"#)]);
    let output = online(repo.path(), &server.origin());
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert_eq!(output.stdout, [] as [u8; 0]);
    for expected in ["head", "package.json", "unparsed", "request-fixture"] {
        assert!(stderr(&output).contains(expected));
    }
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn diff_empty_base_and_working_tree_bytes_are_sent_with_explicit_states() {
    use super::support::{diff as fixture, jobs::ScriptedServer};
    let repo = super::support::repository(&[("README.md", "empty base")]);
    committed(repo.path());
    fs::write(repo.path().join("package.json"), fixture::files(true).0).expect("working manifest");
    fs::write(
        repo.path().join("package-lock.json"),
        fixture::files(true).1,
    )
    .expect("working lock");
    let server = ScriptedServer::respond_with(fixture::exchanges(
        &serde_json::to_vec(&fixture::report()).expect("json"),
    ));
    let output = githits_scan()
        .arg("diff")
        .arg(repo.path())
        .args(["--base", "HEAD", "--format", "json"])
        .env("GITHITS_API_TOKEN", "test-token")
        .env("GITHITS_API_URL", server.origin())
        .output()
        .expect("diff");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    let body = String::from_utf8_lossy(&requests[0]);
    assert!(body.contains("\"base\":{\"state\":\"empty\"}"));
    assert!(!body.contains("name=\"base_files[]\""));
    assert!(body.contains(fixture::files(true).1));
}

#[test]
fn diff_local_selection_notices_stay_on_stderr_and_json_stays_exact() {
    use super::support::{diff as fixture, jobs::ScriptedServer};
    let repo = pair();
    fs::write(
        repo.path().join("githits-scan.toml"),
        "unread configuration",
    )
    .expect("config");
    let bytes = serde_json::to_vec(&fixture::report()).expect("json");
    let server = ScriptedServer::respond_with(fixture::exchanges(&bytes));
    let output = githits_scan()
        .arg("diff")
        .arg(repo.path())
        .args(["--base", "HEAD", "--format", "json", "--quiet"])
        .env("GITHITS_API_TOKEN", "test-token")
        .env("GITHITS_API_URL", server.origin())
        .output()
        .expect("diff");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, bytes);
    assert!(stderr(&output).contains("ignores githits-scan.toml"));
    assert_eq!(server.requests().len(), 3);
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
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("GITHITS_API_TOKEN"));
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
        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    }
}

#[test]
fn diff_pair_aggregate_count_fails_before_credentials() {
    let repo = tempfile::tempdir().expect("repo");
    for i in 0..129 {
        let dir = repo.path().join(format!("p{i}"));
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
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("258 files"));
    assert!(!stderr(&output).contains("GITHITS_API_TOKEN"));
}

#[test]
fn diff_lockfiles_only_retains_companions_and_sets_recorded_only() {
    use super::support::{diff as fixture, jobs::ScriptedServer};
    let repo = pair();
    fs::create_dir(repo.path().join("other")).expect("directory");
    fs::write(
        repo.path().join("other/package.json"),
        r#"{"name":"manifest-only","version":"1.0.0"}"#,
    )
    .expect("manifest");
    let server = ScriptedServer::respond_with(fixture::exchanges(
        &serde_json::to_vec(&fixture::report()).expect("json"),
    ));
    let output = githits_scan()
        .arg("diff")
        .arg(repo.path())
        .args(["--base", "HEAD", "--lockfiles-only", "--format", "json"])
        .env("GITHITS_API_TOKEN", "test-token")
        .env("GITHITS_API_URL", server.origin())
        .output()
        .expect("diff");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let requests = server.requests();
    let body = String::from_utf8_lossy(&requests[0]);
    assert!(body.contains("\"unlocked_manifests\":\"recorded_only\""));
    assert!(!body.contains("filename=\"other/package.json\""));
    assert_eq!(body.matches("filename=\"package.json\"").count(), 2);
}

#[path = "diff/dual_output.rs"]
mod dual_output;
