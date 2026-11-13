//! Real binary audit contract: streams, findings, evidence gaps and compact output.
#[path = "audit_applicability.rs"]
mod audit_applicability;
#[path = "audit_compact_replay.rs"]
mod audit_compact_replay;
#[path = "audit_details.rs"]
mod audit_details;
#[path = "audit_git_coverage.rs"]
mod audit_git_coverage;
#[path = "audit_native_diagnostics.rs"]
mod audit_native_diagnostics;
#[path = "audit_native_inputs.rs"]
mod audit_native_inputs;
#[path = "audit_native_lifecycle.rs"]
mod audit_native_lifecycle;
#[path = "audit_native_rendering.rs"]
mod audit_native_rendering;
#[path = "audit_non_registry.rs"]
mod audit_non_registry;
#[path = "audit_presentation.rs"]
mod audit_presentation;
#[path = "audit_presentation_json.rs"]
mod audit_presentation_json;
#[path = "audit_remediation.rs"]
mod audit_remediation;
#[path = "audit_report.rs"]
mod audit_report;
#[path = "audit_saved_flags.rs"]
mod audit_saved_flags;
#[path = "npm_workspace.rs"]
mod npm_workspace;

#[path = "audit_explanation_ux.rs"]
mod audit_explanation_ux;
#[path = "audit_saved.rs"]
mod audit_saved;

#[path = "config_policy.rs"]
mod config_policy;

use super::*;
use crate::support::audit::{clean, findings as fixture};
use crate::support::jobs::{accept_response, events_response, snapshot};

const REPORT: &[u8] = include_bytes!("../fixtures/audit/native-findings.json");

fn run(root: &Path, origin: Option<&str>, extra: &[&str]) -> Output {
    let mut command = githits_scan();
    command
        .arg("audit")
        .arg(root)
        .args(extra)
        .env_remove("GITHITS_API_TOKEN")
        .env_remove("GITHITS_API_URL");
    if let Some(origin) = origin {
        command
            .env("GITHITS_API_TOKEN", "test-token")
            .env("GITHITS_API_URL", origin);
    }
    command.output().expect("audit binary")
}
fn offline(file: &Path, extra: &[&str]) -> Output {
    githits_scan()
        .args(["audit", "--from-analysis"])
        .arg(file)
        .args(extra)
        .current_dir(file.parent().expect("analysis parent"))
        .env_remove("GITHITS_API_TOKEN")
        .env("GITHITS_API_URL", "not-an-origin")
        .output()
        .expect("offline audit")
}

fn server(bytes: &[u8]) -> ScriptedServer {
    let mut terminal = snapshot("succeeded", "succeeded", 1);
    terminal["kind"] = "audit".into();
    terminal["format"] = "json".into();
    let mut progress = snapshot("running", "assessing", 0);
    progress["kind"] = "audit".into();
    progress["format"] = "json".into();
    progress["counts"] = serde_json::json!({"assessments_done":0,"assessments_total":2});
    ScriptedServer::respond_with(vec![
        accept_response(),
        events_response(&[progress, terminal]),
        response("200 OK", &[("Content-Type", "application/json")], bytes),
    ])
}
fn repo() -> tempfile::TempDir {
    repository(&[("package-lock.json", "{}"), ("package.json", "{}")])
}

#[test]
fn audit_submits_configured_workspace_evidence_and_honors_member_exclusion() {
    let r = repository(&[
        ("githits-scan.toml", include_str!("../../githits-scan.toml")),
        ("Cargo.lock", "# shared workspace lock\n"),
        ("Cargo.toml", "[workspace]\nmembers = [\"xtask\"]\n"),
        (
            "xtask/Cargo.toml",
            "[package]\nname = \"xtask\"\nversion = \"0.0.0\"\n",
        ),
        ("unrelated/Cargo.toml", "[package]\nname = \"unrelated\"\n"),
    ]);
    for exclude_member in [false, true] {
        // The fixture supplies findings; this verifies file submission and
        // preserves exit policy, not backend workspace assessment.
        let s = server(REPORT);
        let extra = if exclude_member {
            &["--json", "--exclude", "xtask/**"][..]
        } else {
            &["--json"][..]
        };
        let output = run(r.path(), Some(&s.origin()), extra);
        let requests = s.requests();
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("JSON report");
        assert_eq!(report["schema_version"], 2);
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
    }
}

#[test]
fn audit_binary_help_documents_all_options_and_attention_exit_policy() {
    let output = githits_scan()
        .args(["audit", "--help"])
        .output()
        .expect("help");
    assert_eq!(output.status.code(), Some(0));
    let help = stdout(&output)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for word in [
        "--config",
        "--no-check",
        "--lockfiles-only",
        "--exclude",
        "--json",
        "--details",
        "--output",
        "--no-color",
        "--quiet",
        "Exit 1",
        "outdated",
        "duplicate",
        "manifest/lock disagreement",
        "constraint",
    ] {
        assert!(help.contains(word), "{word}: {}", stdout(&output));
    }
    assert!(!help.contains("--report-version"));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    let output = run(repo().path(), None, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
}

#[test]
fn audit_binary_human_report_preserves_all_categories_attribution_and_progress() {
    let r = repo();
    let s = server(REPORT);
    let output = run(r.path(), Some(&s.origin()), &["--no-color", "--details"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    for text in [
        "Vulnerabilities (1)",
        "Package warnings (1)",
        "Outdated versions (1)",
        "Duplicate versions (1)",
        "GHSA-demo",
        "CVE-demo",
        "web/package-lock.json",
        "advisory range could not be evaluated",
        "GHSA-context",
        "advisory-reported fix versions: 1.1.0",
    ] {
        assert!(
            stdout(&output).contains(text),
            "{text}: {}",
            stdout(&output)
        );
    }
    let err = stderr(&output);
    assert!(
        err.contains("assessing audit evidence: 0 / 2 assessments"),
        "{err}"
    );
    assert!(err.contains("audit report ready; downloading..."));
    assert!(!err.contains("SBOM ready"));
    assert!(!output.stdout.contains(&0x1b));
    assert_eq!(s.requests().len(), 3);
}

#[test]
fn audit_binary_clean_report_and_compact_json_have_correct_streams_and_exits() {
    let r = repo();
    let bytes = serde_json::to_vec_pretty(&clean()).expect("json");
    for extra in [&["--json"][..], &["--json", "--output", "-"][..], &[][..]] {
        let s = server(&bytes);
        let output = run(r.path(), Some(&s.origin()), extra);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        if extra.contains(&"--json") {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
            assert_eq!(result["summary"]["dependencies"], 2);
            assert_eq!(result["incomplete"], false);
            assert!(result.get("inputs").is_none() && result.get("occurrences").is_none());
            assert!(!stderr(&output).contains("assessing"));
        } else {
            assert!(stdout(&output).starts_with("No audit findings in available evidence"));
        }
        assert_eq!(s.requests().len(), 3);
    }
}

#[test]
fn audit_binary_each_finding_category_is_attention() {
    for category in ["vulnerabilities", "lifecycle", "outdated", "duplicates"] {
        let mut value = clean();
        let original = fixture();
        if category == "lifecycle" {
            value["lifecycle"]["findings"] = original["lifecycle"]["findings"].clone();
        } else {
            value["findings"][category] = original["findings"][category].clone();
        }
        value["summary"][category] = 1.into();
        let bytes = serde_json::to_vec(&value).expect("json");
        let r = repo();
        let s = server(&bytes);
        let output = run(r.path(), Some(&s.origin()), &["--json"]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{category}: {}",
            stderr(&output)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
        assert_eq!(result["summary"][category], 1);
        assert!(result.get("inputs").is_none());
        assert!(!stderr(&output).contains("unverified"));
        assert_eq!(s.requests().len(), 3);
    }
}

#[test]
fn audit_binary_semantic_discrepancy_is_incomplete_without_dumping_raw_evidence() {
    let mut value = clean();
    value["coverage"]["vulnerabilities"]["candidates_count"] = 0.into();
    let bytes = serde_json::to_vec(&value).expect("json");
    let r = repo();
    let s = server(&bytes);
    let output = run(r.path(), Some(&s.origin()), &["--json"]);
    assert_eq!(output.status.code(), Some(1));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(result["incomplete"], true);
    assert!(result.get("occurrences").is_none());
    assert!(stdout(&output).contains("unverified"));
    assert_eq!(s.requests().len(), 3);
}

#[test]
fn audit_binary_unsupported_reports_fail_without_emitting_or_resubmitting() {
    for version in [1, 2, 4, u64::MAX] {
        let bytes = serde_json::to_vec(
            &serde_json::json!({"schema_version":version,"private_field":"opaque"}),
        )
        .expect("JSON");
        for args in [&["--json"][..], &[][..]] {
            let r = repo();
            let s = server(&bytes);
            let output = run(r.path(), Some(&s.origin()), args);
            assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
            assert_eq!(output.stdout, [] as [u8; 0]);
            assert!(stderr(&output).contains("requires version 3"));
            assert!(!stderr(&output).contains("opaque"));
            assert_eq!(s.requests().len(), 3, "no automatic resubmission");
        }
    }
}

#[test]
fn audit_binary_compact_file_and_structural_failure_keep_existing_output() {
    let r = repo();
    let path = r.path().join("audit.json");
    let p = path.to_str().expect("path");
    let s = server(REPORT);
    let output = run(r.path(), Some(&s.origin()), &["--json", "-o", p]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    let saved = fs::read(&path).expect("report");
    let result: serde_json::Value = serde_json::from_slice(&saved).expect("JSON");
    assert_eq!(result["summary"]["vulnerabilities"], 1);
    assert!(result.get("inputs").is_none());
    assert!(stderr(&output).contains("saved"));
    assert_eq!(s.requests().len(), 3);
    let s = server(br#"{"schema_version":1}"#);
    let output = run(r.path(), Some(&s.origin()), &["--json", "-o", p]);
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert_eq!(fs::read(&path).expect("unchanged"), saved);
    assert!(!stderr(&output).contains("saved"));
    assert_eq!(s.requests().len(), 3);
    let s = server(REPORT);
    let output = run(
        r.path(),
        Some(&s.origin()),
        &["--json", "-o", r.path().to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(!stderr(&output).contains("saved"));
    assert_eq!(s.requests().len(), 3);
}

#[test]
fn audit_binary_preflight_empty_drift_and_missing_token_stop_before_network() {
    let r = repository(&[]);
    let output = run(r.path(), Some("http://127.0.0.1:1"), &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(stderr(&output).contains("no lockfiles"));
    let r = repo();
    fs::write(
        r.path().join("githits-scan.toml"),
        "version = 1\n[lockfiles]\ninclude = []\n",
    )
    .expect("config");
    let output = run(r.path(), Some("http://127.0.0.1:1"), &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("inventory drift"));
    let output = run(r.path(), None, &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(stderr(&output).contains("GITHITS_API_TOKEN"));
}

#[test]
fn audit_binary_human_file_is_plain_and_omits_declaration_inventory() {
    let mut value = clean();
    value["private_inventory"] = serde_json::json!({"scope":"dev","optional":true});
    let r = repo();
    let path = r.path().join("audit.txt");
    let s = server(&serde_json::to_vec(&value).expect("json"));
    let output = run(
        r.path(),
        Some(&s.origin()),
        &["--output", path.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    let report = fs::read_to_string(path).expect("human file");
    assert!(
        !report.contains("scope:")
            && !report.contains("optional:")
            && !report.contains("Input evidence")
    );
    assert!(!report.contains('\u{001b}'));
    assert_eq!(s.requests().len(), 3);
}

#[test]
fn audit_binary_compact_formats_deduplicate_files_and_drop_internal_fields() {
    let mut value = fixture();
    value["findings"]["vulnerabilities"][0]["paths"] =
        serde_json::json!(["package-lock.json", "package-lock.json"]);
    value["findings"]["vulnerabilities"][0]["severity_type"] = serde_json::Value::Null;
    value["findings"]["vulnerabilities"][0]["severity_score"] = serde_json::Value::Null;
    value["findings"]["vulnerabilities"][0]["verified_remedies"] = serde_json::json!(["1.0.2"]);
    value["findings"]["vulnerabilities"][0]["internal_future_field"] = "private-extra-value".into();
    for json in [false, true] {
        let r = repo();
        let s = server(&serde_json::to_vec(&value).expect("json"));
        let output = run(
            r.path(),
            Some(&s.origin()),
            if json { &["--json"] } else { &["--details"] },
        );
        assert_eq!(output.status.code(), Some(1));
        let text = stdout(&output);
        for noise in [
            "occurrence",
            "Input evidence",
            "private-repeat-id",
            "private-extra-value",
            "node_modules/demo",
            "audit-synthetic",
        ] {
            assert!(!text.contains(noise), "{noise}: {text}");
        }
        if json {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
            assert_eq!(
                result["vulnerabilities"][0]["files"],
                serde_json::json!(["package-lock.json"])
            );
            assert!(result["vulnerabilities"][0].get("severity").is_none());
            assert_eq!(
                result["vulnerabilities"][0]["proposed_fixes"],
                serde_json::json!(["1.1.0"])
            );
            assert_eq!(
                result["vulnerabilities"][0]["verified_advisory_fixes"],
                serde_json::json!(["1.0.2"])
            );
            assert_eq!(
                result["duplicates"][0]["versions"][1]["files"],
                serde_json::json!(["web/package-lock.json"])
            );
            assert!(result.get("inputs").is_none() && result.get("coverage").is_none());
        } else {
            let line = text
                .lines()
                .find(|l| l.contains("GHSA-demo"))
                .expect("finding");
            assert!(line.ends_with("[package-lock.json]"), "{line}");
            assert!(
                !line.contains("unavailable"),
                "missing severity must not add a placeholder: {line}"
            );
            assert_eq!(line.matches("package-lock.json").count(), 1);
        }
        assert_eq!(s.requests().len(), 3);
    }
}

#[test]
fn audit_binary_multiple_reason_codes_are_readable_and_order_independent() {
    let mut value = fixture();
    value["unknowns"]["vulnerabilities"][0]["reasons"] =
        serde_json::json!(["metadata_unavailable", "invalid_range"]);
    let mut reversed = value["unknowns"]["vulnerabilities"][0].clone();
    reversed["reasons"] = serde_json::json!(["invalid_range", "metadata_unavailable"]);
    value["unknowns"]["vulnerabilities"]
        .as_array_mut()
        .expect("unknowns")
        .push(reversed);
    for json in [false, true] {
        let r = repo();
        let s = server(&serde_json::to_vec(&value).expect("json"));
        let output = run(
            r.path(),
            Some(&s.origin()),
            if json { &["--json"] } else { &[] },
        );
        assert_eq!(output.status.code(), Some(1));
        let text = if json {
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
            serde_json::to_string(&value["issues"]).expect("friendly common issues")
        } else {
            stdout(&output)
        };
        assert!(!text.contains("invalid_range") && !text.contains("metadata_unavailable"));
        assert_eq!(
            text.matches("advisory range could not be evaluated, package metadata missing")
                .count(),
            1
        );
        assert_eq!(s.requests().len(), 3);
    }
}

#[test]
fn audit_binary_quiet_preserves_reports_and_suppresses_routine_stderr() {
    for extra in [&["-q"][..], &["--quiet", "--json"][..]] {
        let r = repo();
        let s = server(REPORT);
        let output = run(r.path(), Some(&s.origin()), extra);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
        assert!(!output.stdout.is_empty(), "expected a non-empty value");
        assert!(!stdout(&output).contains("Not scanned:"));
        assert_eq!(s.requests().len(), 3);
    }
    let r = repo();
    let file = r.path().join("audit.json");
    let s = server(REPORT);
    let output = run(
        r.path(),
        Some(&s.origin()),
        &["--quiet", "--json", "-o", file.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let result: serde_json::Value =
        serde_json::from_slice(&fs::read(file).expect("file")).expect("JSON");
    assert_eq!(result["summary"]["vulnerabilities"], 1);
    assert_eq!(result["manifests"], serde_json::json!(["package.json"]));
    assert_eq!(s.requests().len(), 3);
}

#[test]
fn audit_binary_used_manifests_replace_excluded_file_and_stdout_completion_lists() {
    let r = repo();
    fs::create_dir(r.path().join("fixtures")).expect("mkdir");
    fs::write(r.path().join("fixtures/Cargo.lock"), "").expect("lockfile");
    fs::write(r.path().join("fixtures/Cargo.toml"), "").expect("manifest");
    for json in [false, true] {
        let s = server(REPORT);
        let output = run(
            r.path(),
            Some(&s.origin()),
            if json {
                &["--exclude", "fixtures/**", "--json"]
            } else {
                &["--exclude", "fixtures/**"]
            },
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(
            !stdout(&output).contains("fixtures/") && !stdout(&output).contains("Not scanned:")
        );
        assert!(!stderr(&output).contains("wrote audit report to stdout"));
        if json {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
            assert_eq!(result["manifests"], serde_json::json!(["package.json"]));
            assert!(result.get("skipped_files").is_none());
        } else {
            assert_eq!(
                stdout(&output).matches("Manifests: package.json").count(),
                1
            );
        }
        assert_eq!(s.requests().len(), 3);
    }
}
