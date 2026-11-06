//! Real binary audit contract: streams, findings, evidence gaps and compact output.
#[path = "audit_compact_replay.rs"]
mod audit_compact_replay;
#[path = "audit_details.rs"]
mod audit_details;
#[path = "audit_native_diagnostics.rs"]
mod audit_native_diagnostics;
#[path = "audit_native_inputs.rs"]
mod audit_native_inputs;
#[path = "audit_presentation.rs"]
mod audit_presentation;
#[path = "audit_remediation.rs"]
mod audit_remediation;
#[path = "audit_saved_flags.rs"]
mod audit_saved_flags;
#[path = "audit_v2.rs"]
mod audit_v2;
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

const REPORT: &[u8] = include_bytes!("../fixtures/audit/findings.json");

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
        assert_eq!(report["schema_version"], 1);
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
        "Deprecated releases (1)",
        "Outdated versions (1)",
        "Duplicate versions (1)",
        "GHSA-demo",
        "CVE-demo",
        "web/package-lock.json",
        "advisory range could not be evaluated",
        "GHSA-context",
        "proposed fixes: 1.0.1",
        "Required ranges and requesting dependencies are not provided",
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
            assert_eq!(result["summary"]["dependencies"], 1);
            assert_eq!(result["incomplete"], false);
            assert!(result.get("inputs").is_none() && result.get("occurrences").is_none());
            assert!(!stderr(&output).contains("assessing"));
        } else {
            assert!(stdout(&output).starts_with("No audit findings in checked dependencies"));
        }
        assert_eq!(s.requests().len(), 3);
    }
}

#[test]
fn audit_binary_each_finding_category_is_attention() {
    for category in ["vulnerabilities", "deprecated", "outdated", "duplicates"] {
        let mut value = clean();
        let original = fixture();
        value["findings"][category] = original["findings"][category].clone();
        value["summary"][category] = 1.into();
        if category == "duplicates" {
            value["occurrences"][1] = original["occurrences"][1].clone();
            value["summary"]["dependencies"] = 2.into();
            set_checked_candidates(&mut value, 2);
            value["coverage"]["duplicates"]["candidates_count"] = 2.into();
        }
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
fn audit_binary_resolution_only_gaps_and_unknown_strings_are_not_clean() {
    for status in [
        "partial",
        "timeout",
        "max_iterations",
        "future_status",
        "complete",
    ] {
        let mut value = clean();
        let diagnostics = if status == "complete" {
            serde_json::json!([{"name":"skipped","reason":"non_registry_source"}])
        } else {
            serde_json::json!([])
        };
        value["inputs"]["resolutions"] =
            serde_json::json!([{"path":"package.json","status":status,"diagnostics":diagnostics}]);
        let r = repo();
        let s = server(&serde_json::to_vec(&value).expect("json"));
        let output = run(r.path(), Some(&s.origin()), &[]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{status}: {}",
            stderr(&output)
        );
        assert!(
            stdout(&output).contains(&format!("resolution {status}"))
                && stdout(&output).contains("[package.json]")
        );
        if status == "complete" {
            assert!(
                stdout(&output).contains("skipped")
                    && stdout(&output).contains("non-registry dependency")
            );
        }
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
    let bytes = include_bytes!("../fixtures/audit/openapi-example.json");
    let s = server(bytes);
    let output = run(r.path(), Some(&s.origin()), &["--json"]);
    assert_eq!(output.status.code(), Some(1));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(result["incomplete"], true);
    assert!(result.get("occurrences").is_none());
    assert_eq!(s.requests().len(), 3);
}

#[test]
fn audit_binary_future_report_is_incomplete_without_forwarding_unknown_fields() {
    let bytes = br#"{ "schema_version":3, "summary":{"future":true}, "private_field":"opaque" }"#;
    for json in [true, false] {
        let r = repo();
        let s = server(bytes);
        let output = run(
            r.path(),
            Some(&s.origin()),
            if json { &["--json"] } else { &[] },
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(stdout(&output).contains("schema version 3 is not supported"));
        assert!(!stdout(&output).contains("private_field") && !stdout(&output).contains("opaque"));
        if json {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
            assert_eq!(result["schema_version"], 1);
            assert_eq!(result["incomplete"], true);
            assert!(result.get("summary").is_none() && result.get("manifests").is_none());
        } else {
            assert!(!stdout(&output).contains("dependencies"));
        }
        assert_eq!(s.requests().len(), 3);
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
fn audit_binary_gap_only_reports_are_attention_with_attributed_open_evidence() {
    for gap in [
        "unsupported",
        "not_collected",
        "source",
        "excluded",
        "future_check",
    ] {
        let mut value = clean();
        let coordinate = value["occurrences"][0]["coordinate"].clone();
        match gap {
            "unsupported" => {
                value["coverage"]["vulnerabilities"]["checked_count"] = 0.into();
                value["coverage"]["vulnerabilities"]["unsupported_count"] = 1.into();
                value["coverage"]["vulnerabilities"]["unsupported_registries"] =
                    serde_json::json!(["npm"]);
                value["unknowns"]["vulnerabilities"] = serde_json::json!([{"coordinate":coordinate,"occurrence_ids":["one","two"],"check":"vulnerabilities","status":"unsupported","reasons":["unsupported_registry"],"advisory_ids":[]}]);
                value["summary"]["incomplete_checks"] = 1.into();
            }
            "not_collected" => {
                value["coverage"]["deprecation"]["checked_count"] = 0.into();
                value["coverage"]["deprecation"]["not_collected_count"] = 1.into();
                value["coverage"]["deprecation"]["not_collected_registries"] =
                    serde_json::json!(["npm"]);
                value["unknowns"]["metadata"] = serde_json::json!([{"coordinate":coordinate,"occurrence_ids":["one","two"],"check":"deprecation","status":"not_collected","reason":null}]);
                value["summary"]["incomplete_checks"] = 1.into();
            }
            "source" => {
                value["coverage"]["sources"][1]["state"] = "future_state".into();
                value["coverage"]["sources"][1]["reasons"] = serde_json::json!(["future_reason"]);
                value["unknowns"]["sources"] =
                    serde_json::json!([value["coverage"]["sources"][1].clone()]);
                value["summary"]["incomplete_sources"] = 1.into();
            }
            "excluded" => {
                value["occurrences"][0]["coordinate"] = serde_json::Value::Null;
                value["occurrences"][0]["eligibility_reason"] = "non_registry_source".into();
                value["unknowns"]["excluded_occurrences"] =
                    serde_json::json!([{"occurrence_id":"one","reason":"non_registry_source"}]);
                value["coverage"]["duplicates"]["excluded_occurrences_count"] = 1.into();
                value["summary"]["excluded_occurrences"] = 1.into();
            }
            _ => {
                value["unknowns"]["metadata"] = serde_json::json!([{"coordinate":coordinate,"occurrence_ids":["one","two"],"check":"future_check","status":"future_outcome","reason":"future_reason\u{001b}[2J"}]);
                value["summary"]["incomplete_checks"] = 1.into();
            }
        }
        let r = repo();
        let s = server(&serde_json::to_vec(&value).expect("json"));
        let output = run(r.path(), Some(&s.origin()), &["--no-color"]);
        assert_eq!(output.status.code(), Some(1), "{gap}: {}", stderr(&output));
        assert!(!stdout(&output).contains("No audit findings"));
        assert!(
            !stdout(&output).contains("unverified"),
            "{gap}: {}",
            stdout(&output)
        );
        assert!(!output.stdout.contains(&0x1b));
        assert!(stdout(&output).contains("package-lock.json"));
        if gap == "source" {
            assert!(stdout(&output).contains("future_state"));
        }
        if gap == "future_check" {
            assert!(stdout(&output).contains("future_outcome"));
        }
        assert_eq!(s.requests().len(), 3);
    }
}

#[test]
fn audit_binary_human_file_is_plain_and_omits_declaration_inventory() {
    let mut value = clean();
    value["inputs"]["declarations"] = serde_json::json!([
        {"id":"false","name":"demo","manifest_path":"package.json","scope":"dev","optional":"false"},
        {"id":"true","name":"demo","manifest_path":"package.json","scope":"","optional":"true"}
    ]);
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

fn set_checked_candidates(value: &mut serde_json::Value, count: u64) {
    for check in ["vulnerabilities", "deprecation", "outdated"] {
        value["coverage"][check]["candidates_count"] = count.into();
        value["coverage"][check]["checked_count"] = count.into();
    }
}

#[test]
fn audit_binary_quotes_are_readable_and_manifest_subject_source_owners_have_paths() {
    let mut value = clean();
    value["inputs"]["subjects"] = serde_json::json!([{"id":"subject","name":"workspace-root","version":null,"lockfile_path":"package-lock.json","native_package_id":"root-native","role":"workspace"}]);
    value["coverage"]["sources"][0]["state"] = "incomplete".into();
    value["coverage"]["sources"][0]["reasons"] =
        serde_json::json!(["isn't complete: \"quoted reason\"\n\u{001b}[2J\u{202e}"]);
    let manifest = value["coverage"]["sources"][0].clone();
    let subject =
        serde_json::json!({"owner_id":"subject","state":"incomplete","reasons":["subject_gap"]});
    value["coverage"]["sources"]
        .as_array_mut()
        .expect("sources")
        .push(subject.clone());
    value["unknowns"]["sources"] = serde_json::json!([manifest, subject]);
    value["summary"]["incomplete_sources"] = 2.into();
    value["notices"] = serde_json::json!(["don't escape \"ordinary quotes\""]);
    let r = repo();
    let s = server(&serde_json::to_vec(&value).expect("json"));
    let output = run(r.path(), Some(&s.origin()), &["--no-color"]);
    assert_eq!(output.status.code(), Some(1));
    let report = stdout(&output);
    assert!(report.contains("[package.json]"), "{report}");
    assert!(
        report.contains("workspace-root") && report.contains("[package-lock.json]"),
        "{report}"
    );
    assert!(report.contains("isn't complete: \"quoted reason\""));
    assert!(!report.contains("don't escape \"ordinary quotes\""));
    assert!(!report.contains("attribution unavailable") && !report.contains("unverified"));
    assert!(!report.contains('\u{001b}') && !report.contains('\u{202e}'));
    assert_eq!(s.requests().len(), 3);
}

#[test]
fn audit_binary_compact_formats_deduplicate_files_and_drop_internal_fields() {
    let mut value = fixture();
    let mut repeated = value["occurrences"][0].clone();
    repeated["id"] = "private-repeat-id".into();
    value["occurrences"]
        .as_array_mut()
        .expect("packages")
        .push(repeated);
    value["coverage"]["sources"]
        .as_array_mut()
        .expect("sources")
        .push(serde_json::json!({"owner_id":"private-repeat-id","state":"complete","reasons":[]}));
    value["summary"]["occurrences"] = 3.into();
    value["findings"]["vulnerabilities"][0]["occurrence_ids"] =
        serde_json::json!(["one", "private-repeat-id"]);
    value["findings"]["duplicates"][0]["versions"][0]["occurrence_ids"] =
        serde_json::json!(["one", "private-repeat-id"]);
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
            "native",
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
                serde_json::json!(["1.0.1"])
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
            assert_eq!(
                text.matches("Mitigation planning unavailable in this report.")
                    .count(),
                1
            );
            assert_eq!(line.matches("package-lock.json").count(), 1);
            assert_eq!(
                text.matches("Required ranges and requesting dependencies")
                    .count(),
                1
            );
        }
        assert_eq!(s.requests().len(), 3);
    }
}

#[test]
fn audit_binary_manifest_resolved_packages_use_manifest_paths_without_missing_placeholders() {
    let mut value = clean();
    for o in value["occurrences"].as_array_mut().expect("packages") {
        o["lockfile_path"] = serde_json::Value::Null;
        o["native_package_id"] = serde_json::Value::Null;
        o["resolution_manifest_paths"] = serde_json::json!(["package.json"]);
    }
    for json in [false, true] {
        let r = repo();
        let s = server(&serde_json::to_vec(&value).expect("json"));
        let output = run(
            r.path(),
            Some(&s.origin()),
            if json { &["--json"] } else { &[] },
        );
        assert_eq!(output.status.code(), Some(0));
        assert!(!stderr(&output).contains("projects resolved"));
        if json {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
            assert_eq!(
                result["resolved_from_manifests"],
                serde_json::json!(["package.json"])
            );
            assert_eq!(result["incomplete"], false);
        } else {
            assert!(stdout(&output).starts_with("No audit findings"));
            assert_eq!(
                stdout(&output)
                    .matches("Resolved from manifest constraints: package.json")
                    .count(),
                1
            );
            assert!(
                !stdout(&output).contains("unavailable")
                    && !stdout(&output).contains("Incomplete checks")
            );
        }
        assert_eq!(s.requests().len(), 3);
    }
}

#[test]
fn audit_binary_manifest_resolved_findings_name_their_manifest_in_both_formats() {
    let mut value = clean();
    for o in value["occurrences"].as_array_mut().expect("packages") {
        o["lockfile_path"] = serde_json::Value::Null;
        o["resolution_manifest_paths"] = serde_json::json!(["package.json"]);
    }
    value["findings"]["vulnerabilities"] = fixture()["findings"]["vulnerabilities"].clone();
    value["summary"]["vulnerabilities"] = 1.into();
    for json in [false, true] {
        let r = repo();
        let s = server(&serde_json::to_vec(&value).expect("json"));
        let output = run(
            r.path(),
            Some(&s.origin()),
            if json { &["--json"] } else { &[] },
        );
        assert_eq!(output.status.code(), Some(1));
        if json {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
            assert_eq!(
                result["vulnerabilities"][0]["files"],
                serde_json::json!(["package.json"])
            );
        } else {
            assert!(
                stdout(&output)
                    .lines()
                    .any(|line| line.contains("GHSA-") && line.ends_with("[package.json]"))
            );
        }
        assert_eq!(s.requests().len(), 3);
    }
}

#[test]
fn audit_binary_partial_resolution_groups_duplicate_diagnostics_in_both_formats() {
    let mut value = clean();
    value["inputs"]["resolutions"] = serde_json::json!([{"path":"package.json","status":"partial","diagnostics":[{"name":"tool","reason":"skipped_requirement"},{"name":"tool","reason":"skipped_requirement"}]}]);
    for json in [false, true] {
        let r = repo();
        let s = server(&serde_json::to_vec(&value).expect("json"));
        let output = run(
            r.path(),
            Some(&s.origin()),
            if json { &["--json"] } else { &[] },
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(!stderr(&output).contains("projects resolved"));
        if json {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
            assert_eq!(result["incomplete"], true);
            assert_eq!(result["issues"].as_array().expect("issues").len(), 1);
            assert_eq!(result["issues"][0]["packages"], serde_json::json!(["tool"]));
        } else {
            assert_eq!(
                stdout(&output)
                    .matches("dependency requirement skipped")
                    .count(),
                1
            );
        }
        assert_eq!(s.requests().len(), 3);
    }
}

#[test]
fn audit_binary_registry_wide_uncollected_checks_are_counts_not_package_dumps() {
    let mut value = clean();
    let mut third = value["occurrences"][0].clone();
    third["id"] = "three".into();
    value["occurrences"]
        .as_array_mut()
        .expect("packages")
        .push(third);
    let mut unknowns = Vec::new();
    for (i, o) in value["occurrences"]
        .as_array_mut()
        .expect("packages")
        .iter_mut()
        .enumerate()
    {
        let name = format!("not-for-package-dump-{i}");
        o["name"] = name.clone().into();
        o["coordinate"]["name"] = name.into();
        o["lockfile_path"] = "package-lock.json".into();
        unknowns.push(serde_json::json!({"coordinate":o["coordinate"],"occurrence_ids":[o["id"]],"check":"deprecation","status":"not_collected","reason":null}));
    }
    value["unknowns"]["metadata"] = unknowns.into();
    value["coverage"]["sources"]
        .as_array_mut()
        .expect("sources")
        .push(serde_json::json!({"owner_id":"three","state":"complete","reasons":[]}));
    set_checked_candidates(&mut value, 3);
    value["coverage"]["deprecation"]["checked_count"] = 0.into();
    value["coverage"]["deprecation"]["not_collected_count"] = 3.into();
    value["coverage"]["deprecation"]["not_collected_registries"] = serde_json::json!(["npm"]);
    value["coverage"]["duplicates"]["candidates_count"] = 3.into();
    value["summary"]["dependencies"] = 3.into();
    value["summary"]["occurrences"] = 3.into();
    value["summary"]["incomplete_checks"] = 3.into();
    for json in [false, true] {
        let r = repo();
        let s = server(&serde_json::to_vec(&value).expect("json"));
        let output = run(
            r.path(),
            Some(&s.origin()),
            if json { &["--json"] } else { &[] },
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(
            !stdout(&output).contains("not-for-package-dump")
                && !stdout(&output).contains("unverified")
        );
        if json {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
            let issue = result["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .find(|i| i["status"] == "not_collected")
                .expect("uncollected issue");
            assert_eq!(issue["package_count"], 3);
            assert_eq!(issue["registries"], serde_json::json!(["npm"]));
            assert!(issue.get("packages").is_none());
        } else {
            assert!(stdout(&output).contains("3 packages (npm)"));
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
        let text = stdout(&output);
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

#[test]
fn audit_binary_non_registry_packages_are_separate_from_failed_checks() {
    let mut value = clean();
    value["occurrences"][0]["coordinate"] = serde_json::Value::Null;
    value["occurrences"][0]["name"] = "xtask".into();
    value["occurrences"][0]["version"] = "0.0.0".into();
    value["occurrences"][0]["eligibility_reason"] = "non_registry_source".into();
    value["unknowns"]["excluded_occurrences"] =
        serde_json::json!([{"occurrence_id":"one","reason":"non_registry_source"}]);
    value["coverage"]["duplicates"]["excluded_occurrences_count"] = 1.into();
    value["summary"]["excluded_occurrences"] = 1.into();
    for json in [false, true] {
        let r = repo();
        let s = server(&serde_json::to_vec(&value).expect("JSON"));
        let output = run(
            r.path(),
            Some(&s.origin()),
            if json { &["--json"] } else { &[] },
        );
        assert_eq!(output.status.code(), Some(1));
        if json {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
            assert_eq!(result["incomplete"], true);
            assert_eq!(result["issues"][0]["status"], "excluded");
            assert_eq!(
                result["issues"][0]["packages"],
                serde_json::json!(["xtask@0.0.0"])
            );
        } else {
            let text = stdout(&output);
            assert!(text.starts_with("Audit results\n"));
            assert!(text.contains(
                "Packages not checked\n  xtask@0.0.0 — non-registry dependency [package-lock.json]"
            ));
            assert!(
                !text.contains("Audit incomplete")
                    && !text.contains("Incomplete checks")
                    && !text.contains("unverified")
            );
        }
        assert_eq!(s.requests().len(), 3);
    }
}

#[test]
fn audit_binary_per_check_exclusions_keep_their_check_context() {
    let mut value = clean();
    let coordinate = value["occurrences"][0]["coordinate"].clone();
    value["unknowns"]["metadata"] = serde_json::json!([{"coordinate":coordinate,"occurrence_ids":["one","two"],"check":"future_check","status":"excluded","reason":"future_reason"}]);
    value["summary"]["incomplete_checks"] = 1.into();
    let r = repo();
    let s = server(&serde_json::to_vec(&value).expect("JSON"));
    let output = run(r.path(), Some(&s.origin()), &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains("Incomplete checks\n  future_check excluded: future_reason"));
    assert!(!stdout(&output).contains("Packages not checked"));
    assert_eq!(s.requests().len(), 3);
}
