//! Informational reports preserve occurrences and evidence without a policy.

use super::*;
use crate::support::jobs::{accept_response, events_response, snapshot};

const REPORT: &[u8] = include_bytes!("../fixtures/licenses/report-v1.json");
const REPORT_V2: &[u8] = include_bytes!("../fixtures/licenses/report-v2.json");

fn offline(file: &Path, extra: &[&str]) -> Output {
    githits_scan()
        .args(["license", "report", "--from-report"])
        .arg(file)
        .args(extra)
        .current_dir(file.parent().expect("report parent"))
        .env_remove("GITHITS_API_TOKEN")
        .env("GITHITS_API_URL", "invalid-origin")
        .output()
        .expect("offline report")
}

fn online(root: &Path, origin: &str, extra: &[&str]) -> Output {
    githits_scan()
        .args(["license", "report"])
        .arg(root)
        .args(extra)
        .env("GITHITS_API_TOKEN", "test-token")
        .env("GITHITS_API_URL", origin)
        .output()
        .expect("online report")
}

fn server(download: Vec<u8>) -> ScriptedServer {
    ScriptedServer::respond_with(vec![
        accept_response(),
        events_response(&[snapshot("succeeded", "succeeded", 1)]),
        download,
    ])
}

#[test]
fn license_report_default_is_package_and_license_rows() {
    let repo = repository(&[("report.json", std::str::from_utf8(REPORT).expect("fixture"))]);
    let file = repo.path().join("report.json");
    let output = offline(&file, &["--quiet", "--no-color"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "Package                       License\nfixture-root 1.0.0 [project]  MIT\nsame-package 1.2.3            MIT OR Apache-2.0; Additional notice\n  input file: web/package-lock.json\nsame-package 1.2.3            not reported\n  input file: tools/package-lock.json\n"
    );
    assert_eq!(
        stderr(&output),
        "warning: dependency resolution is incomplete\n"
    );
}

#[test]
fn license_report_details_show_inspection_targets_without_debug_metadata() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    let mut component = value["components"][1].clone();
    component["licenses"] = serde_json::json!([{"expression":"MIT", "acknowledgement":"declared"}]);
    component["publisher_evidence"]["observations"] = serde_json::json!([
        {"relationship":"controlling", "observation":{"source":"registry_metadata", "scope":"release", "field":"license", "version":"1.2.3", "statements":["MIT"]}, "interpretation":{"status":"expression"}},
        {"relationship":"context", "observation":{"source":"repository_manifest", "scope":"repository", "field":"license", "statements":["MIT"]}, "interpretation":{"status":"expression"}}
    ]);
    component["external_references"] = serde_json::json!([
        {"type":"vcs", "url":"https://example.invalid/repo", "comment":"{\"basis\":\"package_metadata\"}"},
        {"type":"other", "url":"https://example.invalid/registry-index"},
        {"type":"website", "url":"https://example.invalid/homepage"}
    ]);
    value["components"] = serde_json::json!([component]);
    let repo = repository(&[("report.json", &serde_json::to_string(&value).expect("JSON"))]);
    let output = offline(&repo.path().join("report.json"), &["--details", "--quiet"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.contains(concat!(
            "same-package 1.2.3  MIT\n",
            "  input file: web/package-lock.json\n",
            "  publisher context (scope: repository): matches reported license text\n",
            "  repository: https://example.invalid/repo\n"
        )),
        "{text}"
    );
    for debug in [
        "occurrence:",
        "package URL:",
        "capture:",
        "statement coverage:",
        "acknowledgement: declared",
        "statement: MIT",
        "registry_metadata",
        "registry-index",
        "homepage",
        "package_metadata",
        "interpretation: expression",
    ] {
        assert!(!text.contains(debug), "debug metadata {debug}: {text}");
    }
}

#[test]
fn license_report_details_keep_complete_mixed_publisher_statements() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    value["components"][0]["publisher_evidence"] = serde_json::json!({
        "observations":[{
            "relationship":"context",
            "observation":{"scope":"repository", "statements":["MIT", "Apache-2.0"]}
        }]
    });
    let repo = repository(&[("report.json", &serde_json::to_string(&value).expect("JSON"))]);
    let output = offline(&repo.path().join("report.json"), &["--details", "--quiet"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains(concat!(
        "fixture-root 1.0.0 [project]  MIT\n",
        "  input file: package.json\n",
        "  kind: manifest; type: application\n",
        "  publisher context (scope: repository)\n",
        "    statement: MIT\n",
        "    statement: Apache-2.0\n",
    )));
}

#[test]
fn license_report_details_keep_unknown_applicability_and_scoped_gaps() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    let observation = &mut value["components"][1]["publisher_evidence"]["observations"][0];
    observation["relationship"] = "future_relationship".into();
    observation["observation"]["scope"] = "future_scope".into();
    observation["observation"]["field"] = "future_field".into();
    value["inventory"]["compositions"] = serde_json::json!([
        {"aggregate":"incomplete", "assemblies":["root"]},
        {"aggregate":"complete", "dependencies":["root"]},
        {"aggregate":"incomplete", "dependencies":["a"]},
        {"aggregate":"unknown", "assemblies":[], "dependencies":[]},
        {"aggregate":"complete", "future_scope":true}
    ]);
    let repo = repository(&[("report.json", &serde_json::to_string(&value).expect("JSON"))]);
    let output = offline(&repo.path().join("report.json"), &["--details", "--quiet"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    for expected in [
        "publisher statement (relationship: future_relationship; scope: future_scope; version: 1.2.3\n    field: future_field): matches reported license text",
        "component inventory: incomplete",
        "dependency relationships: incomplete",
        "component inventory: unknown",
        "dependency relationships: unknown",
        "inventory coverage: unrecognized scope (retained in JSON)",
        "dependency coverage: fixture-root 1.0.0 [project] (inputs: package.json): incomplete\n    reason: required input was not supplied",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert!(!text.contains(": complete\n"));
}

#[test]
fn license_report_compact_choices_preserve_boundaries_and_missing_versions() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    value["components"]
        .as_array_mut()
        .expect("components")
        .truncate(1);
    value["components"][0]["version"] = serde_json::Value::Null;
    value["components"][0]["licenses"] = serde_json::json!([
        {"license":{"id":"BSD-3-Clause", "name":"BSD license"}},
        {"license":{"name":"Custom; \"terms\""}},
        {"future_choice":true},
        {"expression":"MIT", "license":{"id":"Apache-2.0", "name":"Apache License"}},
        {"license":{"name":"\"Quoted terms"}}
    ]);
    let repo = repository(&[("report.json", &serde_json::to_string(&value).expect("JSON"))]);
    let output = offline(&repo.path().join("report.json"), &["--quiet", "--no-color"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let compact = stdout(&output);
    let row = compact.lines().nth(1).expect("package row");
    let (package, choices) = row.split_once("  ").expect("column separator");
    assert_eq!(package, "fixture-root [project]");
    assert!(
        choices.starts_with(
            "BSD-3-Clause (BSD license); \"Custom; \\\"terms\\\"\"; unrecognized choice"
        ),
        "{choices}"
    );
    assert!(choices.ends_with("..."));
    assert!(choices.chars().count() <= 80);
    assert!(compact.contains("use --json"));
    assert_eq!(
        offline(&repo.path().join("report.json"), &["--json", "--quiet"]).stdout,
        serde_json::to_vec(&value).expect("exact bytes")
    );
    let details = offline(&repo.path().join("report.json"), &["--details", "--quiet"]);
    assert_eq!(details.status.code(), Some(0));
    assert!(
        stdout(&details)
            .contains("reported license: MIT\n    id: Apache-2.0; name: Apache License")
    );
}

#[test]
fn license_report_empty_inventory_has_only_the_column_header() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    value["components"] = serde_json::json!([]);
    let repo = repository(&[("report.json", &serde_json::to_string(&value).expect("JSON"))]);
    let output = offline(&repo.path().join("report.json"), &["--quiet", "--no-color"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stdout(&output), "Package  License\n");
}

#[test]
fn license_report_compact_hint_is_routine_stderr_only() {
    let repo = repository(&[("report.json", std::str::from_utf8(REPORT).expect("fixture"))]);
    let file = repo.path().join("report.json");
    let hint = "Use --details for evidence and coverage; --json for the complete report.";
    let compact = offline(&file, &["--no-color"]);
    assert_eq!(compact.status.code(), Some(0));
    assert!(!stdout(&compact).contains(hint));
    assert_eq!(stderr(&compact).matches(hint).count(), 1);
    for args in [&["--quiet"][..], &["--details"][..], &["--json"][..]] {
        let output = offline(&file, args);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert!(!stderr(&output).contains(hint));
        assert!(stderr(&output).contains("dependency resolution is incomplete"));
    }
}

#[test]
fn license_report_online_json_needs_no_policy_and_preserves_bytes() {
    let repo = repository(&[("package-lock.json", "{}")]);
    let api = server(response(
        "200 OK",
        &[("Content-Type", "application/json")],
        REPORT_V2,
    ));
    let output = online(repo.path(), &api.origin(), &["--json", "--quiet"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, REPORT_V2);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report JSON");
    assert_eq!(value["schema_version"], 2);
    assert_eq!(stderr(&output), "");
    let requests = api.requests();
    assert_eq!(requests.len(), 3);
    assert!(support::head(&requests[2]).contains("/v1/experimental/license-reports/"));
}

#[test]
fn license_report_offline_preserves_actionable_evidence_and_occurrences() {
    let repo = repository(&[
        ("report.json", std::str::from_utf8(REPORT).expect("fixture")),
        ("githits-scan.toml", "invalid config"),
    ]);
    let file = repo.path().join("report.json");
    let raw = offline(&file, &["--json", "--quiet"]);
    assert_eq!(raw.status.code(), Some(0), "{}", stderr(&raw));
    assert_eq!(raw.stdout, REPORT);
    assert!(stderr(&raw).contains("dependency resolution is incomplete"));
    let human = offline(&file, &["--details", "--no-color"]);
    assert_eq!(human.status.code(), Some(0), "{}", stderr(&human));
    let text = stdout(&human);
    assert!(text.starts_with("3 reported occurrences (inventory: incomplete dependency resolution); informational, not a policy check\n"));
    assert_eq!(text.matches("same-package 1.2.3").count(), 2);
    assert_eq!(text.matches("input file: package.json").count(), 1);
    assert_eq!(text.matches("input file: web/package-lock.json").count(), 1);
    for expected in [
        "fixture-root 1.0.0",
        "web/package-lock.json",
        "tools/package-lock.json",
        "same-package 1.2.3  not reported",
        "observed licenses: Custom terms",
        "publisher context (scope: repository)",
        "scope: repository",
        "statement: Custom terms",
        "scope: excluded",
        "same-package 1.2.3  MIT OR Apache-2.0; Additional notice",
        "Additional notice",
        "interpretation: ambiguous license evidence",
        "issue: unrecognized text in license expression at position 9",
        "issue: unrecognized issue (retained in JSON)",
        "unrecognized evidence (retained in JSON)",
        "latest check: failed",
        "observed file: vendor/COPYING",
        "detected: Custom terms",
        "distribution: https://example.invalid/package.tgz",
        "resolution: web/package.json: partial",
        "dependency coverage: fixture-root 1.0.0 [project] (inputs: package.json): incomplete",
        "reason: required input was not supplied",
        "notice: Available evidence is incomplete",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert!(!text.contains("MIT AND"));
    for diagnostic in [
        "occurrence:",
        "package URL:",
        "capture:",
        "statement coverage:",
        "attribution:",
    ] {
        assert!(
            !text.contains(diagnostic),
            "inactionable metadata: {diagnostic}"
        );
    }
    assert!(
        text.lines().count() < 64,
        "details must be shorter than the old 64-line fixture"
    );
    for absent in [
        "publisher evidence: not reported",
        "source observations: not reported",
        "observed licenses: not reported",
        "input files: not reported",
    ] {
        assert!(
            !text.contains(absent),
            "absent metadata should be omitted: {absent}"
        );
    }
    let detailed_json = offline(&file, &["--details", "--json", "--quiet"]);
    assert_eq!(detailed_json.status.code(), Some(0));
    assert_eq!(detailed_json.stdout, REPORT);
    assert!(
        !text.contains("aaaaaaa"),
        "reference hashes must not become subject hashes"
    );
}

#[test]
fn license_report_details_keep_publisher_and_source_ownership() {
    let repo = repository(&[("report.json", std::str::from_utf8(REPORT).expect("fixture"))]);
    let file = repo.path().join("report.json");
    let output = offline(&file, &["--details", "--quiet"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).contains(concat!(
        "  publisher: status: ambiguous license evidence; reason: context only; no release license statement\n",
        "  publisher context (scope: repository)\n",
        "    statement: MIT\n",
        "    statement: Custom terms\n",
        "    interpretation: ambiguous license evidence\n",
        "    issue: unrecognized text in license expression at position 9\n",
        "    issue: unrecognized issue (retained in JSON)\n",
        "  source observations: status: unrecognized evidence (retained in JSON)\n    module: example.invalid/observed-module; version: v0.9.0\n    URL: https://example.invalid/observed-module/licenses; latest check: failed\n",
        "    observed file: vendor/COPYING; detected: Custom terms; detected: MIT\n",
    )));
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    value["components"][0]["publisher_evidence"] = serde_json::json!({});
    value["components"][0]["source_evidence"] = serde_json::json!({});
    value["components"][2]["publisher_evidence"]["observations"][0]["interpretation"]["issues"][0]
        .as_object_mut()
        .expect("structured issue")
        .remove("offset");
    value["components"][2]["publisher_evidence"]["status"] = serde_json::Value::Null;
    value["components"][2]["source_evidence"]["provider"] = serde_json::Value::Null;
    value["components"][2]["publisher_evidence"]["observations"]
        .as_array_mut()
        .expect("observations")
        .push(serde_json::json!({"interpretation":{"status":"future_status"}}));
    fs::write(&file, serde_json::to_vec(&value).expect("JSON")).expect("write");
    let partial = offline(&file, &["--details", "--quiet"]);
    assert_eq!(partial.status.code(), Some(0));
    let text = stdout(&partial);
    assert!(!text.contains("  publisher:\n"));
    assert!(!text.contains("  source observations:\n"));
    assert!(text.contains("  publisher: reason: context only; no release license statement\n"));
    assert!(text.contains("    issue: unrecognized text in license expression\n"));
    assert!(text.contains("  publisher statement (relationship: not reported; scope: not reported)\n    interpretation: unrecognized evidence (retained in JSON)\n"));
    assert!(text.contains(
        "  source observations: status: unrecognized evidence (retained in JSON)\n    module:"
    ));
}

#[test]
fn license_report_escapes_controls_and_labels_unknown_evidence() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    value["components"][0]["name"] = "quoted\"name\n\u{1b}[31m".into();
    value["components"][0]["licenses"] = serde_json::json!([{"future_choice":true}]);
    value["components"][0]["external_references"] =
        serde_json::json!([{ "url":"https://example.invalid/untyped", "future_reference":true }]);
    value["inventory"]["completeness"] = "future_inventory".into();
    value["inventory"]["properties"][1]["value"] = "unknown structure".into();
    let repo = repository(&[("report.json", &serde_json::to_string(&value).expect("json"))]);
    let output = offline(&repo.path().join("report.json"), &["--details", "--quiet"]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(text.contains("quoted\"name\\n\\u{1b}[31m"), "{text}");
    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("unrecognized choice (retained in JSON)"));
    assert!(!text.contains("https://example.invalid/untyped"));
    assert!(!text.contains("source reference: https://example.invalid/untyped"));
    assert!(text.contains("resolution evidence: unrecognized (retained in JSON)"));
    assert!(text.contains("inventory: unrecognized inventory evidence (retained in JSON)"));
    assert_eq!(output.stderr, Vec::<u8>::new());
}

#[test]
fn license_report_saved_invalid_or_missing_input_is_usage() {
    let repo = repository(&[("report.json", "{\"schema_version\":1}")]);
    let file = repo.path().join("report.json");
    let invalid = offline(&file, &[]);
    assert_eq!(invalid.status.code(), Some(2));
    assert_eq!(invalid.stdout, Vec::<u8>::new());
    assert!(stderr(&invalid).contains("invalid dependency-license report"));
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    value["schema_version"] = 3.into();
    fs::write(&file, serde_json::to_vec(&value).expect("json")).expect("write");
    let future = offline(&file, &[]);
    assert_eq!(future.status.code(), Some(2));
    assert!(stderr(&future).contains("unsupported dependency-license report version"));
    assert_eq!(future.stdout, Vec::<u8>::new());
    let missing = offline(&repo.path().join("absent.json"), &[]);
    assert_eq!(missing.status.code(), Some(2));
    assert_eq!(missing.stdout, Vec::<u8>::new());
}

#[test]
fn license_report_human_file_is_plain_and_failure_preserves_destination() {
    let repo = repository(&[("package-lock.json", "{}"), ("output.txt", "original")]);
    let destination = repo.path().join("output.txt");
    let api = server(response(
        "200 OK",
        &[("Content-Type", "application/json")],
        b"invalid report",
    ));
    let failed = online(
        repo.path(),
        &api.origin(),
        &["--details", "--output", destination.to_str().expect("path")],
    );
    assert_eq!(failed.status.code(), Some(3));
    assert_eq!(failed.stdout, Vec::<u8>::new());
    assert_eq!(fs::read_to_string(&destination).expect("read"), "original");
    let api = server(response(
        "200 OK",
        &[("Content-Type", "application/json")],
        REPORT,
    ));
    let output = online(
        repo.path(),
        &api.origin(),
        &["--details", "--output", destination.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, Vec::<u8>::new());
    let text = fs::read_to_string(&destination).expect("read");
    assert!(text.starts_with("3 reported occurrences"));
    assert!(!text.contains('\u{1b}'));
    let diagnostics = stderr(&output);
    assert!(diagnostics.contains("license report ready; downloading..."));
    assert!(!diagnostics.contains("SBOM ready"));
    assert!(diagnostics.contains("saved "));
}

#[test]
fn license_report_help_documents_flags_and_informational_exit() {
    let output = githits_scan()
        .args(["license", "report", "--help"])
        .output()
        .expect("help");
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    for flag in [
        "--from-report",
        "--config",
        "--no-check",
        "--lockfiles-only",
        "--exclude",
        "--json",
        "--details",
        "--output",
        "--quiet",
        "--no-color",
    ] {
        assert!(text.contains(flag), "missing {flag}");
    }
    assert!(text.contains("informational"));
    assert!(text.contains("Exit 0"));
}

#[test]
fn license_report_reuses_inventory_gates_and_inventory_only_configuration() {
    let empty = repository(&[]);
    let output = online(empty.path(), "http://127.0.0.1:1", &["--quiet"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(output.stdout, Vec::<u8>::new());
    let repo = repository(&[
        ("package-lock.json", "{}"),
        (
            "githits-scan.toml",
            "version = 1\n[lockfiles]\ninclude = []\n",
        ),
    ]);
    let drift = online(repo.path(), "http://127.0.0.1:1", &["--quiet"]);
    assert_eq!(drift.status.code(), Some(1), "{}", stderr(&drift));
    assert_eq!(drift.stdout, Vec::<u8>::new());
    fs::write(
        repo.path().join("githits-scan.toml"),
        "version = 1\n[lockfiles]\ninclude = [\"package-lock.json\"]\n",
    )
    .expect("config");
    let api = server(response(
        "200 OK",
        &[("Content-Type", "application/json")],
        REPORT,
    ));
    let configured = online(repo.path(), &api.origin(), &["--json", "--quiet"]);
    assert_eq!(configured.status.code(), Some(0), "{}", stderr(&configured));
    assert_eq!(configured.stdout, REPORT);
    assert_eq!(api.requests().len(), 3);
}

#[test]
fn license_report_keeps_local_file_and_unfamiliar_subjects() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    value["components"][0]["type"] = "file".into();
    value["components"][0]["record_kind"] = serde_json::Value::Null;
    value["components"][1]["properties"].as_array_mut().expect("properties").push(serde_json::json!({"name":"githits:source_kind", "value":"LOCKED_PACKAGE_SOURCE_KIND_LOCAL"}));
    value["components"][2]["type"] = "future_subject".into();
    value["components"][2]["record_kind"] = "future_kind".into();
    let repo = repository(&[("report.json", &serde_json::to_string(&value).expect("json"))]);
    let output = offline(&repo.path().join("report.json"), &["--details", "--quiet"]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(text.starts_with("3 reported occurrences"));
    assert!(text.contains("type: file"));
    assert!(!text.contains("kind: not reported"));
    assert!(text.contains("kind: future_kind; type: future_subject"));
    assert_eq!(text.matches("same-package 1.2.3").count(), 2);
}

#[test]
fn license_report_versions_remain_with_their_evidence() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    value["components"][1]["publisher_evidence"]["observations"][0]["observation"]["version"] =
        "0.9.0".into();
    let repo = repository(&[("report.json", &serde_json::to_string(&value).expect("JSON"))]);
    let output = offline(&repo.path().join("report.json"), &["--details", "--quiet"]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(text.contains("same-package 1.2.3"));
    assert!(text.contains(
        "publisher statement (scope: release; version: 0.9.0): matches reported license text"
    ));
    assert!(text.contains("module: example.invalid/observed-module; version: v0.9.0"));
    assert!(!text.contains("module: example.invalid/observed-module\n    version: 1.2.3"));
    assert!(text.contains("Inventory completeness is not license coverage"));
}

#[test]
fn license_report_unfamiliar_coverage_preserves_known_siblings_and_raw_json() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    value["inventory"]["compositions"] =
        serde_json::json!([{ "future_aggregate":"unknown" }, { "aggregate":"incomplete" }]);
    value["inventory"]["properties"][1]["value"] = serde_json::json!([
        {"future_input":"unknown", "future_status":"queued"},
        {"path":"future/package.json", "future_status":"queued"},
        {"path":"known/package.json", "status":"partial"}
    ])
    .to_string()
    .into();
    value["inventory"]["properties"][2]["value"] = serde_json::json!({
        "unknown-owner":{"future_state":"unknown"},
        "reason-only-owner":{"reasons":["future_reason"]},
        "known-owner":{"state":"incomplete", "reasons":["missing_input"]}
    })
    .to_string()
    .into();
    let bytes = serde_json::to_string(&value).expect("json");
    let repo = repository(&[("report.json", &bytes)]);
    let file = repo.path().join("report.json");
    let output = offline(&file, &["--details", "--quiet"]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    for expected in [
        "inventory coverage: unrecognized (retained in JSON)",
        "inventory coverage: incomplete",
        "resolution: input not reported: unrecognized evidence (retained in JSON)",
        "resolution: future/package.json: unrecognized evidence (retained in JSON)",
        "resolution: known/package.json: partially resolved",
        "dependency coverage: unresolved reference unknown-owner: unrecognized evidence (retained in JSON)",
        "dependency coverage: unresolved reference reason-only-owner: unrecognized evidence (retained in JSON)",
        "dependency coverage: unresolved reference known-owner: incomplete",
        "reason: unrecognized evidence (retained in JSON)",
        "reason: required input was not supplied",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert!(!text.contains("status not reported"));
    assert!(!text.contains("unknown-owner: not reported"));
    let raw = offline(&file, &["--json", "--quiet"]);
    assert_eq!(raw.status.code(), Some(0));
    assert_eq!(raw.stdout, bytes.as_bytes());
}

#[test]
fn license_report_single_occurrence_uses_singular_lead() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    value["components"]
        .as_array_mut()
        .expect("components")
        .truncate(1);
    let bytes = serde_json::to_string(&value).expect("JSON");
    let repo = repository(&[("report.json", &bytes)]);
    let output = offline(&repo.path().join("report.json"), &["--details", "--quiet"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).starts_with("1 reported occurrence (inventory:"));
    assert!(!stdout(&output).contains("1 reported occurrences"));
}

#[test]
fn license_report_output_file_io_failure_exits_three() {
    let repo = repository(&[("package-lock.json", "{}")]);
    let destination = repo.path().join("missing/dir/report.txt");
    let api = server(response(
        "200 OK",
        &[("Content-Type", "application/json")],
        REPORT,
    ));
    let output = online(
        repo.path(),
        &api.origin(),
        &["--output", destination.to_str().expect("path"), "--quiet"],
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stdout, Vec::<u8>::new());
    assert!(
        stderr(&output).contains("cannot write"),
        "{}",
        stderr(&output)
    );
    assert!(!destination.exists());
    assert_eq!(api.requests().len(), 3);
}

#[test]
fn license_report_replay_output_preserves_json_and_single_readable_warning() {
    let repo = repository(&[("report.json", std::str::from_utf8(REPORT).expect("fixture"))]);
    let input = repo.path().join("report.json");
    let target = repo.path().join("copy.json");
    let output = offline(&input, &["--json", "-o", target.to_str().expect("path")]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, Vec::<u8>::new());
    assert_eq!(fs::read(&target).expect("copy"), REPORT);
    let diagnostic = stderr(&output);
    assert_eq!(
        diagnostic
            .matches("dependency resolution is incomplete")
            .count(),
        1
    );
    assert!(!diagnostic.contains("partial_manifest_inventory"));
    let stdout_report = offline(&input, &["--json", "-o", "-"]);
    assert_eq!(stdout_report.stdout, REPORT);
}
