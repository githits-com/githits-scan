//! Compatibility tests for the `githits-scan` binary.
//!
//! These run the real executable so that exit codes and output streams, which
//! automation depends on, are verified end to end.

#![expect(
    clippy::expect_used,
    reason = "test helpers fail loudly like the tests they serve"
)]

mod support;

#[path = "cli/polish.rs"]
mod polish;

#[path = "cli/release_fixes.rs"]
mod release_fixes;

#[path = "cli/license_groups.rs"]
mod license_groups;
#[path = "cli/license_readiness.rs"]
mod license_readiness;
#[path = "cli/license_report.rs"]
mod license_report;
#[path = "cli/license_report_flags.rs"]
mod license_report_flags;
#[path = "cli/license_report_v2.rs"]
mod license_report_v2;

#[path = "cli/audit.rs"]
mod audit;
#[path = "cli/bun.rs"]
mod bun;
#[path = "cli/manifest_defaults.rs"]
mod manifest_defaults;
#[path = "cli/manifest_ecosystems.rs"]
mod manifest_ecosystems;
#[path = "cli/pairing.rs"]
mod pairing;
#[path = "cli/quiet.rs"]
mod quiet;

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use support::jobs::ScriptedServer;
use support::{MockServer, repository, response};

fn githits_scan() -> Command {
    Command::new(env!("CARGO_BIN_EXE_githits-scan"))
}

/// `sbom generate` with a controlled environment: the token variable and the
/// origin override come only from `token` and `origin`.
fn generate(root: &Path, token: Option<&str>, origin: Option<&str>, extra: &[&str]) -> Output {
    let mut command = githits_scan();
    command
        .args(["sbom", "generate"])
        .arg(root)
        .args(extra)
        .env_remove("GITHITS_API_TOKEN")
        .env_remove("GITHITS_API_URL");
    if let Some(token) = token {
        command.env("GITHITS_API_TOKEN", token);
    }
    if let Some(origin) = origin {
        command.env("GITHITS_API_URL", origin);
    }
    command.output().expect("run githits-scan sbom generate")
}

fn detect(root: &Path, extra: &[&str]) -> Output {
    githits_scan()
        .arg("detect")
        .arg(root)
        .args(extra)
        .output()
        .expect("run githits-scan detect")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("utf-8 stdout")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf-8 stderr")
}

#[test]
fn version_prints_the_crate_version_on_stdout() {
    let output = githits_scan()
        .arg("--version")
        .output()
        .expect("run githits-scan --version");
    assert!(output.status.success(), "status: {}", output.status);
    assert_eq!(
        stdout(&output).trim(),
        format!("githits-scan {}", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
}

#[test]
fn running_without_a_command_prints_usage_and_exits_with_usage_error() {
    let output = githits_scan().output().expect("run githits-scan");
    assert_eq!(output.status.code(), Some(2), "status: {}", output.status);
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    let stderr = stderr(&output);
    assert!(stderr.contains("Usage: githits-scan"), "stderr: {stderr}");
    assert!(stderr.contains("detect"), "stderr: {stderr}");
}

#[test]
fn unknown_arguments_fail_with_usage_error_on_stderr() {
    let output = githits_scan()
        .arg("--definitely-unknown")
        .output()
        .expect("run githits-scan");
    assert_eq!(
        output.status.code(),
        Some(2),
        "clap usage errors exit with 2"
    );
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(
        stderr(&output).contains("--definitely-unknown"),
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn detect_help_documents_every_flag() {
    let output = githits_scan()
        .args(["detect", "--help"])
        .output()
        .expect("run githits-scan detect --help");
    assert!(output.status.success(), "status: {}", output.status);
    let help = stdout(&output);
    for flag in [
        "[PATH]",
        "--lockfiles-only",
        "--exclude",
        "--json",
        "--no-color",
    ] {
        assert!(help.contains(flag), "missing {flag} in help:\n{help}");
    }
}

#[test]
fn detect_lists_lockfiles_on_stdout_and_exits_zero() {
    let repo = repository(&[
        ("Cargo.lock", "# lock\n"),
        ("Cargo.toml", "[package]\n"),
        ("web/package-lock.json", "{}"),
        ("web/package.json", "{}"),
    ]);

    let output = detect(repo.path(), &[]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(output.stderr.is_empty(), "stderr: {}", stderr(&output));
    let report = stdout(&output);
    assert!(
        report.starts_with("2 lockfiles in 2 ecosystems\n"),
        "{report}"
    );
    assert!(report.contains("Cargo.lock"), "{report}");
    assert!(report.contains("web/package-lock.json"), "{report}");
    assert!(
        !report.contains("\x1b["),
        "no escape codes when piped: {report}"
    );
}

#[test]
fn detect_exclude_is_a_usage_error_for_an_invalid_glob() {
    let repo = repository(&[("Cargo.lock", "")]);

    let output = detect(repo.path(), &["--exclude", "["]);

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let stderr = stderr(&output);
    assert!(stderr.contains("--exclude"), "stderr: {stderr}");
    assert!(stderr.contains("invalid"), "stderr: {stderr}");
}

#[test]
fn detect_exclude_and_save_writes_the_patterns() {
    let repo = repository(&[("Cargo.lock", ""), ("web/yarn.lock", "")]);

    let output = detect(repo.path(), &["--exclude", "web/**", "--save"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let config = fs::read_to_string(repo.path().join("githits-scan.toml")).expect("config");
    assert!(config.contains("\"web/**\""), "{config}");
    assert!(config.contains("\"Cargo.lock\""), "{config}");
    assert!(!config.contains("yarn.lock"), "{config}");
}

#[test]
fn detect_without_lockfiles_is_a_finding() {
    let repo = repository(&[("README.md", "")]);

    let output = detect(repo.path(), &[]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).starts_with("no lockfiles found in"));
}

#[test]
fn detect_json_is_parseable_and_versioned() {
    let repo = repository(&[("Cargo.lock", "abc"), ("legacy/package.json", "")]);

    let output = detect(repo.path(), &["--json"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["lockfiles"][0]["path"], "Cargo.lock");
    assert_eq!(value["lockfiles"][0]["ecosystem"], "rust");
    assert_eq!(value["lockfiles"][0]["bytes"], 3);
    assert_eq!(value["manifest_only"][0]["path"], "legacy/package.json");
}

#[test]
fn detect_counts_manifest_only_projects_unless_lockfiles_only() {
    let repo = repository(&[("package.json", "{}")]);

    let default = detect(repo.path(), &["--json"]);
    let lockfiles_only = detect(repo.path(), &["--json", "--lockfiles-only"]);

    assert_eq!(default.status.code(), Some(0), "{}", stderr(&default));
    assert_eq!(lockfiles_only.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&default.stdout).expect("json stdout");
    assert_eq!(value["lockfiles_only"], false);
    let value: serde_json::Value =
        serde_json::from_slice(&lockfiles_only.stdout).expect("json stdout");
    assert_eq!(value["lockfiles_only"], true);
}

#[test]
fn detect_on_a_missing_directory_is_a_usage_error_on_stderr() {
    let repo = repository(&[("Cargo.lock", "")]);

    for root in [
        repo.path().join("missing"),
        repo.path().join("Cargo.lock/child"),
    ] {
        let output = detect(&root, &[]);

        assert_eq!(output.status.code(), Some(2), "{}", root.display());
        assert!(output.stdout.is_empty(), "{:?}", output.stdout);
        let stderr = stderr(&output);
        assert!(
            stderr.starts_with("error: ") && stderr.contains("is not a directory"),
            "stderr: {stderr}"
        );
    }
}

#[cfg(unix)]
#[test]
fn detect_on_an_unreadable_tree_is_an_execution_error() {
    use std::os::unix::fs::PermissionsExt;

    let repo = repository(&[("Cargo.lock", ""), ("locked/Cargo.lock", "")]);
    let locked = repo.path().join("locked");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("chmod");

    let output = detect(repo.path(), &[]);

    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).expect("restore");
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    let stderr = stderr(&output);
    assert!(
        stderr.starts_with("error: cannot read the directory tree;")
            && stderr.contains("--exclude")
            && stderr.contains("\n  caused by: "),
        "stderr: {stderr}"
    );
}

#[test]
fn detect_defaults_to_the_current_directory() {
    let repo = repository(&[("Gemfile.lock", ""), ("Gemfile", "")]);

    let output = githits_scan()
        .arg("detect")
        .current_dir(repo.path())
        .output()
        .expect("run githits-scan detect");

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains("Gemfile.lock"));
}

#[test]
fn sbom_generate_help_documents_every_flag() {
    let output = githits_scan()
        .args(["sbom", "generate", "--help"])
        .output()
        .expect("run githits-scan sbom generate --help");
    assert!(output.status.success(), "status: {}", output.status);
    let help = stdout(&output);
    for text in [
        "[PATH]",
        "--format",
        "cyclonedx",
        "spdx",
        "text",
        "-o, --output",
        "--lockfiles-only",
        "--exclude",
        "--no-color",
        "GITHITS_API_TOKEN",
        "Submits one job and reports progress on stderr",
    ] {
        assert!(help.contains(text), "missing {text} in help:\n{help}");
    }
}

#[test]
fn sbom_generate_without_a_token_is_a_usage_error_that_never_echoes_secrets() {
    let repo = repository(&[("Cargo.lock", "")]);

    let output = generate(repo.path(), None, None, &[]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    let stderr = stderr(&output);
    assert!(
        stderr.starts_with("error: GITHITS_API_TOKEN is not set;"),
        "stderr: {stderr}"
    );
}

#[test]
fn sbom_generate_rejects_an_insecure_origin_before_any_request() {
    let repo = repository(&[("Cargo.lock", "")]);

    let output = generate(
        repo.path(),
        Some("secret-token-value"),
        Some("http://api.githits.dev"),
        &[],
    );

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr(&output);
    assert!(
        stderr.contains("GITHITS_API_URL must use https"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("secret-token-value"), "stderr: {stderr}");
}

#[test]
fn sbom_generate_without_lockfiles_is_a_finding_without_a_request() {
    let repo = repository(&[("README.md", "")]);

    // The origin points at a closed port: any request would fail with exit 3.
    let output = generate(repo.path(), Some("t"), Some("http://127.0.0.1:9"), &[]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(stderr(&output).starts_with("scanning repository...\nno lockfiles found in "));
}

#[test]
fn sbom_generate_writes_the_document_to_stdout_and_the_summary_to_stderr() {
    let repo = repository(&[("Cargo.lock", "# lock\n"), ("Cargo.toml", "[package]\n")]);
    let document = br#"{"bomFormat":"CycloneDX","specVersion":"1.7","properties":[{"name":"githits:completeness","value":"recorded_lockfile_inventory"}]}"#;
    let server = ScriptedServer::success("cyclonedx", document);

    let output = generate(repo.path(), Some("test-token"), Some(&server.origin()), &[]);
    let requests = server.requests();
    assert_eq!(requests.len(), 3, "submission, events and result exchanges");
    let request = String::from_utf8_lossy(&requests[0]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, document);
    assert_eq!(
        stderr(&output),
        format!(
            "scanning repository...\npreparing upload...\nsubmitting 1 lockfile and 1 manifest...\nSBOM ready; downloading...\nuploaded 1 lockfile and 1 manifest (Cargo.toml)\ninventory: recorded_lockfile_inventory; wrote {} bytes to stdout\n",
            document.len()
        )
    );
    assert!(
        request.starts_with(
            "POST /v1/experimental/lockfile-jobs?kind=sbom&format=cyclonedx HTTP/1.1\r\n"
        ),
        "{request}"
    );
    assert!(request.contains("filename=\"Cargo.lock\""), "{request}");
    assert!(request.contains("filename=\"Cargo.toml\""), "{request}");
    assert!(request.contains("format=cyclonedx"), "{request}");
}

#[test]
fn sbom_generate_writes_the_output_file_only_on_success() {
    let repo = repository(&[("Cargo.lock", "")]);
    let target = repo.path().join("bom.spdx");
    let server = MockServer::respond_with(response(
        "429 Too Many Requests",
        &[
            ("Content-Type", "application/problem+json"),
            ("X-Request-ID", "req-9"),
            ("Retry-After", "30"),
        ],
        br#"{"type":"about:blank","title":"Rate limited","status":429,"detail":"Too many requests.","instance":"req-9","code":"RATE_LIMITED"}"#,
    ));

    let failed = generate(
        repo.path(),
        Some("test-token"),
        Some(&server.origin()),
        &[
            "--format",
            "spdx",
            "--output",
            target.to_str().expect("utf-8 path"),
        ],
    );
    drop(server.request());

    assert_eq!(failed.status.code(), Some(3), "{}", stderr(&failed));
    assert!(!target.exists(), "no output file on failure");
    let stderr_text = stderr(&failed);
    assert_eq!(
        stderr_text,
        "scanning repository...\npreparing upload...\nsubmitting 1 lockfile and 0 manifests...\nerror: RATE_LIMITED (HTTP 429): Too many requests.\n  request id: req-9\n  retry after: 30s\n  action: wait for the retry-after period and run again\n"
    );

    let document = b"SPDXVersion: SPDX-2.3\n";
    let server = ScriptedServer::success("spdx", document);
    let succeeded = generate(
        repo.path(),
        Some("test-token"),
        Some(&server.origin()),
        &[
            "--format",
            "spdx",
            "-o",
            target.to_str().expect("utf-8 path"),
        ],
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 3, "submission, events and result exchanges");
    let request = String::from_utf8_lossy(&requests[0]).into_owned();

    assert_eq!(succeeded.status.code(), Some(0), "{}", stderr(&succeeded));
    assert!(succeeded.stdout.is_empty(), "{:?}", succeeded.stdout);
    assert_eq!(fs::read(&target).expect("output"), document);
    assert_eq!(
        stderr(&succeeded),
        format!(
            "scanning repository...\npreparing upload...\nsubmitting 1 lockfile and 0 manifests...\nSBOM ready; downloading...\nuploaded 1 lockfile and 0 manifests\nsaved {} (22 bytes)\n",
            target.display()
        )
    );
    assert!(request.contains("format=spdx"), "{request}");
}

const DRIFT_CONFIG: &str = "version = 1\n\n[lockfiles]\ninclude = [\"Cargo.lock\", \"gone/Cargo.lock\"]\nexclude = [\"examples/**\"]\n";

#[test]
fn detect_with_a_config_reports_statuses_and_fails_on_drift() {
    let repo = repository(&[
        ("githits-scan.toml", DRIFT_CONFIG),
        ("Cargo.lock", ""),
        ("examples/demo/Cargo.lock", ""),
        ("web/yarn.lock", ""),
    ]);

    let output = detect(repo.path(), &[]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let report = stdout(&output);
    assert!(report.contains("drift against"), "{report}");
    assert!(report.contains("  STATUS\n"), "{report}");
    assert!(report.contains("unlisted"), "{report}");
    assert!(report.contains("gone/Cargo.lock"), "{report}");

    let relaxed = detect(repo.path(), &["--no-check"]);
    assert_eq!(relaxed.status.code(), Some(0), "{}", stderr(&relaxed));
}

#[test]
fn detect_save_accepts_the_inventory_and_conflicts_with_no_check() {
    let repo = repository(&[
        ("githits-scan.toml", DRIFT_CONFIG),
        ("Cargo.lock", ""),
        ("examples/demo/Cargo.lock", ""),
        ("web/yarn.lock", ""),
    ]);

    let conflict = detect(repo.path(), &["--save", "--no-check"]);
    assert_eq!(conflict.status.code(), Some(2));
    assert!(
        stderr(&conflict).contains("--no-check"),
        "{}",
        stderr(&conflict)
    );

    let saved = detect(repo.path(), &["--save"]);
    assert_eq!(saved.status.code(), Some(0), "{}", stderr(&saved));
    assert!(
        stdout(&saved).contains("added 1, removed 1"),
        "{}",
        stdout(&saved)
    );
    let text = fs::read_to_string(repo.path().join("githits-scan.toml")).expect("config");
    assert!(text.contains("exclude = [\"examples/**\"]"), "{text}");
    assert!(text.contains("\"web/yarn.lock\""), "{text}");
    assert!(!text.contains("gone/Cargo.lock"), "{text}");

    let clean = detect(repo.path(), &[]);
    assert_eq!(clean.status.code(), Some(0), "{}", stderr(&clean));
}

#[test]
fn a_config_override_is_read_from_the_given_file() {
    let repo = repository(&[("Cargo.lock", "")]);
    let config = repo.path().join("ci").join("scan.toml");
    fs::create_dir_all(config.parent().expect("parent")).expect("mkdir");
    fs::write(
        &config,
        "version = 1\n[lockfiles]\ninclude = [\"Cargo.lock\"]\n",
    )
    .expect("write");

    let output = detect(
        repo.path(),
        &["--config", config.to_str().expect("utf-8 path"), "--json"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["config"], config.to_str().expect("utf-8 path"));
    assert_eq!(value["lockfiles"][0]["status"], "included");
}

#[test]
fn an_invalid_config_is_a_usage_error_for_every_command() {
    let repo = repository(&[
        (
            "githits-scan.toml",
            "version = 1\n[lockfiles]\ninclud = []\n",
        ),
        ("Cargo.lock", ""),
    ]);

    let detect_run = detect(repo.path(), &[]);
    assert_eq!(detect_run.status.code(), Some(2), "{}", stderr(&detect_run));
    assert!(
        stderr(&detect_run).contains("includ"),
        "{}",
        stderr(&detect_run)
    );

    let generate_run = generate(repo.path(), Some("t"), Some("http://127.0.0.1:9"), &[]);
    assert_eq!(
        generate_run.status.code(),
        Some(2),
        "{}",
        stderr(&generate_run)
    );
}

#[test]
fn sbom_generate_fails_on_drift_before_any_request() {
    let repo = repository(&[
        ("githits-scan.toml", DRIFT_CONFIG),
        ("Cargo.lock", ""),
        ("web/yarn.lock", ""),
    ]);

    // A closed port: any request would fail with exit 3 instead of 1.
    let output = generate(repo.path(), Some("t"), Some("http://127.0.0.1:9"), &[]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    let stderr = stderr(&output);
    assert!(
        stderr.starts_with("scanning repository...\ninventory drift against "),
        "{stderr}"
    );
    assert!(stderr.contains("unlisted: web/yarn.lock"), "{stderr}");
    assert!(stderr.contains("missing: gone/Cargo.lock"), "{stderr}");
}

#[test]
fn sbom_generate_reads_the_config_override_and_names_it_on_drift() {
    let repo = repository(&[("Cargo.lock", ""), ("web/yarn.lock", "")]);
    let elsewhere = tempfile::tempdir().expect("tempdir");
    let config = elsewhere.path().join("scan.toml");
    fs::write(
        &config,
        "version = 1\n[lockfiles]\ninclude = [\"Cargo.lock\"]\n",
    )
    .expect("write");

    let output = generate(
        repo.path(),
        Some("t"),
        Some("http://127.0.0.1:9"),
        &["--config", config.to_str().expect("utf-8 path")],
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let stderr = stderr(&output);
    assert!(
        stderr.starts_with(&format!(
            "scanning repository...\ninventory drift against {} ",
            config.display()
        )),
        "{stderr}"
    );
    assert!(stderr.contains("unlisted: web/yarn.lock"), "{stderr}");
}

const LICENSE_CONFIG: &str = "version = 1\n\n[lockfiles]\ninclude = [\"Cargo.lock\"]\n\n[licenses]\nallow = [\"MIT\"]\n\n[[licenses.exceptions]]\npurl = \"pkg:cargo/ring\"\nreason = \"reviewed\"\n";
const CYCLONEDX: &str = r#"{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"bom-ref":"1","name":"serde","version":"1","purl":"pkg:cargo/serde@1","licenses":[{"expression":"MIT OR Apache-2.0"}]},{"bom-ref":"2","name":"ring","version":"0.17.8","purl":"pkg:cargo/ring@0.17.8","licenses":[{"expression":"OpenSSL"}]},{"bom-ref":"3","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0","licenses":[{"expression":"WTFPL"}]}]}"#;

fn check(root: &Path, extra: &[&str]) -> Output {
    githits_scan()
        .args(["license", "check"])
        .arg(root)
        .args(extra)
        .env_remove("GITHITS_API_TOKEN")
        .env_remove("GITHITS_API_URL")
        .output()
        .expect("run githits-scan license check")
}

#[test]
fn license_check_help_documents_every_flag() {
    let output = githits_scan()
        .args(["license", "check", "--help"])
        .output()
        .expect("run githits-scan license check --help");
    assert!(output.status.success(), "status: {}", output.status);
    let help = stdout(&output);
    for text in [
        "[PATH]",
        "--sbom",
        "--config",
        "--no-check",
        "--lockfiles-only",
        "--exclude",
        "--json",
        "--no-color",
    ] {
        assert!(help.contains(text), "missing {text} in help:\n{help}");
    }
}

#[test]
fn license_check_on_a_file_needs_no_token_and_exits_one_on_violations() {
    let repo = repository(&[
        ("githits-scan.toml", LICENSE_CONFIG),
        ("bom.cdx.json", CYCLONEDX),
    ]);
    let file = repo.path().join("bom.cdx.json");

    let output = check(repo.path(), &["--sbom", file.to_str().expect("utf-8 path")]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(
        stderr(&output),
        "checking licenses...\nwarning: SBOM has no githits:completeness property; inventory completeness is unknown\n"
    );
    let report = stdout(&output);
    assert!(
        report.starts_with("1 violation in 3 components\n"),
        "{report}"
    );
    assert!(report.contains("left-pad 1.3.0"), "{report}");
    assert!(
        report.contains("pkg:cargo/ring: reviewed (ring 0.17.8)"),
        "{report}"
    );

    let json = check(
        repo.path(),
        &["--sbom", file.to_str().expect("utf-8 path"), "--json"],
    );
    assert_eq!(json.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["violations"][0]["purl"], "pkg:npm/left-pad@1.3.0");
    assert_eq!(value["violations"][0]["reason"], "not_allowed");
}

#[test]
fn license_check_without_a_config_names_the_missing_file() {
    for (override_config, json) in [(false, false), (false, true), (true, false), (true, true)] {
        let repo = repository(&[("bom.cdx.json", CYCLONEDX)]);
        let file = repo.path().join("bom.cdx.json");
        let config = repo.path().join(if override_config {
            "policy.toml"
        } else {
            "githits-scan.toml"
        });
        if override_config {
            fs::write(repo.path().join("githits-scan.toml"), LICENSE_CONFIG)
                .expect("default config");
        }
        let mut extra = vec!["--sbom", file.to_str().expect("utf-8 path")];
        if override_config {
            extra.extend(["--config", config.to_str().expect("utf-8 path")]);
        }
        if json {
            extra.push("--json");
        }

        let output = check(repo.path(), &extra);

        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
        assert!(output.stdout.is_empty(), "{:?}", output.stdout);
        assert_eq!(
            stderr(&output),
            format!(
                "error: configuration file {} not found; run `githits-scan detect --save` with the same PATH, then enable [licenses], or select an existing file with --config\n",
                config.display()
            )
        );
    }
}

#[test]
fn license_check_without_a_policy_names_the_missing_table() {
    for (override_config, json) in [(false, false), (false, true), (true, false), (true, true)] {
        let repo = repository(&[("bom.cdx.json", CYCLONEDX)]);
        let file = repo.path().join("bom.cdx.json");
        let config = repo.path().join(if override_config {
            "policy.toml"
        } else {
            "githits-scan.toml"
        });
        fs::write(&config, "version = 1\n").expect("config without policy");
        if override_config {
            fs::write(repo.path().join("githits-scan.toml"), LICENSE_CONFIG)
                .expect("default config");
        }
        let mut extra = vec!["--sbom", file.to_str().expect("utf-8 path")];
        if override_config {
            extra.extend(["--config", config.to_str().expect("utf-8 path")]);
        }
        if json {
            extra.push("--json");
        }

        let output = check(repo.path(), &extra);

        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
        assert!(output.stdout.is_empty(), "{:?}", output.stdout);
        assert_eq!(
            stderr(&output),
            format!(
                "error: {} has no [licenses] table; add one with `allow = [...]` (see the README) to enable license check\n",
                config.display()
            )
        );
    }
}

#[test]
fn license_check_generates_through_the_api_when_no_file_is_given() {
    let repo = repository(&[("githits-scan.toml", LICENSE_CONFIG), ("Cargo.lock", "")]);
    for json in [false, true] {
        let server = ScriptedServer::success("cyclonedx", CYCLONEDX.as_bytes());
        let mut command = githits_scan();
        command.args(["license", "check"]).arg(repo.path());
        if json {
            command.arg("--json");
        }
        let output = command
            .env("GITHITS_API_TOKEN", "test-token")
            .env("GITHITS_API_URL", server.origin())
            .output()
            .expect("run githits-scan license check");
        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        let request = String::from_utf8_lossy(&requests[0]);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(request.contains("kind=sbom&format=cyclonedx"), "{request}");
        if json {
            assert_eq!(stderr(&output), "uploaded 1 lockfile and 0 manifests\n");
            let report: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("JSON report");
            assert_eq!(report["schema_version"], 1);
            assert_eq!(report["components"], 3);
            assert_eq!(
                report["violations"].as_array().expect("violations").len(),
                1
            );
            assert_eq!(report["violations"][0]["purl"], "pkg:npm/left-pad@1.3.0");
        } else {
            assert_eq!(
                stderr(&output),
                "scanning repository...\npreparing upload...\nsubmitting 1 lockfile and 0 manifests...\nSBOM ready; downloading...\nuploaded 1 lockfile and 0 manifests\nchecking licenses...\n"
            );
            assert!(
                stdout(&output).starts_with("1 violation in 3 components\n"),
                "{}",
                stdout(&output)
            );
        }
    }
    let without_token = check(repo.path(), &[]);
    assert_eq!(without_token.status.code(), Some(2));
    assert!(stderr(&without_token).contains("GITHITS_API_TOKEN"));
}

#[test]
fn job_and_result_failures_preserve_an_existing_output_file() {
    use support::jobs::{accept_response, events_response, snapshot};
    let repo = repository(&[("Cargo.lock", "")]);
    let target = repo.path().join("bom.json");
    for case in ["failed", "pending", "media"] {
        fs::write(&target, "previous document").expect("existing output");
        let mut terminal = snapshot("succeeded", "succeeded", 1);
        let mut responses = vec![accept_response()];
        if case == "failed" {
            terminal["state"] = "failed".into();
            terminal["phase"] = "failed".into();
            terminal["error"] = "resolution_failed".into();
        }
        responses.push(events_response(&[terminal]));
        if case == "pending" {
            responses.push(response("409 Conflict", &[("Content-Type", "application/problem+json")], br#"{"code":"ANALYSIS_PENDING","status":409,"detail":"pending","instance":"req-result"}"#));
        } else if case == "media" {
            responses.push(response(
                "200 OK",
                &[("Content-Type", "text/plain")],
                b"wrong format",
            ));
        }
        let expected_requests = responses.len();
        let server = ScriptedServer::respond_with(responses);
        let output = generate(
            repo.path(),
            Some("test-token"),
            Some(&server.origin()),
            &["--output", target.to_str().expect("path")],
        );
        assert_eq!(server.requests().len(), expected_requests);
        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        assert!(output.stdout.is_empty(), "{:?}", output.stdout);
        assert_eq!(fs::read(&target).expect("output"), b"previous document");
        let diagnostic = stderr(&output);
        let expected = match case {
            "failed" => "resolution_failed",
            "pending" => "ANALYSIS_PENDING",
            _ => "unexpected response media type",
        };
        assert!(diagnostic.contains(expected), "{diagnostic}");
        assert!(!diagnostic.contains("test-token"));
        assert!(!diagnostic.contains("succeeded") && !diagnostic.contains("saved "));
        assert_eq!(
            diagnostic.contains("SBOM ready; downloading..."),
            case != "failed"
        );
    }
}

#[test]
fn sbom_generate_text_preserves_exact_stdout_bytes() {
    let repo = repository(&[("Cargo.lock", "")]);
    let document = b"package inventory\n";
    let server = ScriptedServer::success("text", document);
    let output = generate(
        repo.path(),
        Some("test-token"),
        Some(&server.origin()),
        &["--format", "text"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, document);
    assert_eq!(
        stderr(&output),
        format!(
            "scanning repository...\npreparing upload...\nsubmitting 1 lockfile and 0 manifests...\nSBOM ready; downloading...\nuploaded 1 lockfile and 0 manifests\nwrote {} bytes to stdout\n",
            document.len()
        )
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(String::from_utf8_lossy(&requests[0]).contains("kind=sbom&format=text"));
}

#[test]
fn human_progress_is_flushed_before_admission_and_explains_recovery() {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Duration;
    use support::jobs::{accept_response, events_response, response_handler, snapshot};

    let repo = repository(&[("Cargo.lock", "")]);
    let (arrived_tx, arrived_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let mut resolving = snapshot("running", "resolving", 0);
    resolving["counts"] = serde_json::json!({"manifests_done": 0, "manifests_total": 1});
    let mut enriching = snapshot("running", "enriching", 0);
    enriching["attempt"] = 2.into();
    enriching["counts"] = serde_json::json!({"coordinates_done": 20, "coordinates_total": 20, "cached": 20, "fetched": 0, "fetch_failed": 0});
    let server = ScriptedServer::with_handlers(vec![
        Box::new(move |mut stream| {
            arrived_tx.send(()).expect("submission arrived");
            release_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("release admission");
            stream.write_all(&accept_response()).expect("accept");
        }),
        response_handler(events_response(&[
            snapshot("queued", "queued", 0),
            resolving,
        ])),
        response_handler(events_response(&[
            enriching,
            snapshot("running", "rendering", 1),
            snapshot("succeeded", "succeeded", 2),
        ])),
        response_handler(response(
            "200 OK",
            &[("Content-Type", "application/vnd.cyclonedx+json")],
            b"{}",
        )),
    ]);
    let mut child = githits_scan()
        .args(["sbom", "generate"])
        .arg(repo.path())
        .env("GITHITS_API_TOKEN", "test-token")
        .env("GITHITS_API_URL", server.origin())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary");
    let stderr_pipe = child.stderr.take().expect("stderr");
    let (line_tx, line_rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let lines: Vec<String> = BufReader::new(stderr_pipe)
            .lines()
            .map(|line| {
                let line = line.expect("stderr line");
                line_tx.send(line.clone()).expect("line delivery");
                line
            })
            .collect();
        lines.join("\n") + "\n"
    });
    arrived_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("held submission");
    for expected in [
        "scanning repository...",
        "preparing upload...",
        "submitting 1 lockfile and 0 manifests...",
    ] {
        assert_eq!(
            line_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("flushed before acceptance"),
            expected
        );
    }
    release_tx.send(()).expect("release");
    let output = child.wait_with_output().expect("completion");
    let diagnostic = reader.join().expect("reader");
    assert_eq!(output.status.code(), Some(0), "{diagnostic}");
    assert_eq!(output.stdout, b"{}");
    assert_eq!(
        diagnostic,
        "scanning repository...\npreparing upload...\nsubmitting 1 lockfile and 0 manifests...\nwaiting for analysis...\nresolving dependencies: 0 / 1 manifests\nprogress connection lost; reconnecting...\nenriching package metadata: 20 / 20 packages (attempt 2)\nrendering SBOM...\nSBOM ready; downloading...\nuploaded 1 lockfile and 0 manifests\nwrote 2 bytes to stdout\n"
    );
    assert_eq!(server.requests().len(), 4);
}

#[test]
fn terminal_job_failures_give_actionable_guidance_without_success() {
    use support::jobs::{accept_response, events_response, snapshot};
    let repo = repository(&[("Cargo.lock", "")]);
    for (code, action, format) in [
        (
            "output_too_large",
            "scan a smaller tree or exclude unneeded lockfiles with --exclude",
            "cyclonedx",
        ),
        (
            "unrepresentable_spdx",
            "run again with --format cyclonedx",
            "spdx",
        ),
    ] {
        let mut failed = snapshot("failed", "failed", 1);
        failed["error"] = code.into();
        failed["format"] = format.into();
        let server =
            ScriptedServer::respond_with(vec![accept_response(), events_response(&[failed])]);
        let output = generate(
            repo.path(),
            Some("test-token"),
            Some(&server.origin()),
            &["--format", format],
        );
        let diagnostic = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{diagnostic}");
        assert!(output.stdout.is_empty(), "{:?}", output.stdout);
        assert!(
            diagnostic.contains(&format!(
                "error: analysis failed: {code} (request id req-events)\n  action: {action}\n"
            )),
            "{diagnostic}"
        );
        assert!(
            !diagnostic.contains("SBOM ready")
                && !diagnostic.contains("wrote ")
                && !diagnostic.contains("saved ")
        );
        assert_eq!(server.requests().len(), 2);
    }
}

#[test]
fn output_write_failure_does_not_claim_command_completion() {
    let repo = repository(&[("Cargo.lock", "")]);
    let server = ScriptedServer::success("cyclonedx", b"{}");
    let output = generate(
        repo.path(),
        Some("test-token"),
        Some(&server.origin()),
        &["--output", repo.path().to_str().expect("path")],
    );
    let diagnostic = stderr(&output);
    assert_eq!(output.status.code(), Some(3), "{diagnostic}");
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(
        diagnostic.contains("SBOM ready; downloading...\nerror: cannot write"),
        "{diagnostic}"
    );
    assert!(!diagnostic.contains("saved ") && !diagnostic.contains("succeeded"));
    assert_eq!(server.requests().len(), 3);
}

#[path = "cli/consistency.rs"]
mod consistency;
