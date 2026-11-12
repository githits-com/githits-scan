//! Real binary acceptance of compact reports and recorded requirement origins.
use super::*;
use crate::support::audit::{clean, findings, unsupported};
use serde_json::{Value, json};

fn repo() -> tempfile::TempDir {
    repository(&[
        ("package-lock.json", "{}"),
        ("package.json", "{}"),
        ("web/package-lock.json", "{}"),
        ("web/package.json", "{}"),
    ])
}

fn execute(value: &Value, extra: &[&str]) -> (Output, Vec<Vec<u8>>) {
    let r = repo();
    let s = server(&serde_json::to_vec(value).expect("report"));
    // These cases qualify full recorded maintenance context; compact visibility has
    // dedicated flag regressions.
    let mut args = extra.to_vec();
    args.push("--details");
    let output = run(r.path(), Some(&s.origin()), &args);
    (output, s.requests())
}

#[test]
fn audit_report_binary_names_selected_manifests_and_useful_origins_without_a_dump() {
    let mut v = findings();
    v["private_inventory"] = json!({"native_id":"not-a-user-result"});
    let (output, requests) = execute(&v, &["--json"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    let result: Value = serde_json::from_slice(&output.stdout).expect("compact report");
    assert_eq!(result["schema_version"], 2);
    assert_eq!(
        result["manifests"],
        json!(["package.json", "web/package.json"])
    );
    assert_eq!(
        result["duplicates"][0]["versions"][0]["origins"][0]["requested_requirement"],
        "^1.0.0"
    );
    assert_eq!(
        result["duplicates"][0]["versions"][1]["origins"][0]["requester"],
        "tool@3.0.0"
    );
    assert_eq!(
        result["duplicates"][0]["unattributed_requirements"][0]["target_status"],
        "untargeted"
    );
    assert!(result.get("resolved_from_manifests").is_none());
    for field in [
        "private_inventory",
        "native_id",
        "generated_at",
        "notices",
        "occurrences",
        "inputs",
        "unverified",
    ] {
        assert!(!stdout(&output).contains(field), "{field}");
    }
    assert_eq!(requests.len(), 3);
}

#[test]
fn audit_report_binary_human_origins_distinguish_unattributed_and_missing_information() {
    let (output, requests) = execute(&findings(), &["--no-color"]);
    assert_eq!(output.status.code(), Some(1));
    let out = stdout(&output);
    for text in [
        "app requests ^1.0.0",
        "tool@3.0.0 — requirement not recorded",
        "Declarations without a recorded dependency link",
        "app requests ^1.0.0 [package.json]",
        "Vulnerabilities (1)",
        "Package warnings (1)",
        "Outdated versions (1)",
        "Duplicate versions (1)",
        "Incomplete checks",
        "Coverage notes",
        "external-path",
        "GHSA-context",
    ] {
        assert!(out.contains(text), "{text}: {out}");
    }
    assert!(!out.contains("Required ranges and requesting dependencies are not provided"));
    assert!(!out.contains("unavailable package"));
    assert_eq!(requests.len(), 3);
}

#[test]
fn audit_report_binary_clean_unsupported_and_unverified_outcomes_have_truthful_exits() {
    let mut invalid = clean();
    invalid["coverage"]["vulnerabilities"]["checked_count"] = 0.into();
    for (value, code, incomplete, unverified) in [
        (clean(), 0, false, false),
        (unsupported(), 1, true, false),
        (invalid, 1, true, true),
    ] {
        let (output, requests) = execute(&value, &["--json", "-q"]);
        assert_eq!(output.status.code(), Some(code), "{}", stderr(&output));
        assert!(output.stderr.is_empty(), "{:?}", output.stderr);
        let result: Value = serde_json::from_slice(&output.stdout).expect("report");
        assert_eq!(result["incomplete"], incomplete);
        assert_eq!(stdout(&output).contains("unverified"), unverified);
        assert_eq!(requests.len(), 3);
    }
}

#[test]
fn audit_report_binary_missing_withheld_ambiguous_and_future_origins_remain_visible() {
    for (status, expected) in [
        ("requirement_withheld", "requirement withheld"),
        ("requirement_ambiguous", "requirement ambiguous"),
        ("parent_not_recorded", "requesting dependency not recorded"),
        (
            "provider_requirement",
            "requirement bound to a provider package",
        ),
        ("future_origin", "future_origin"),
    ] {
        let mut value = findings();
        let o = &mut value["findings"]["duplicates"][0]["versions"][0]["origins"][0];
        o["status"] = status.into();
        o["requested_requirement"] = Value::Null;
        if status == "parent_not_recorded" {
            o["requester"] = Value::Null;
        }
        let (output, _) = execute(&value, &["--json"]);
        assert_eq!(output.status.code(), Some(1));
        let result: Value = serde_json::from_slice(&output.stdout).expect("report");
        assert_eq!(
            result["duplicates"][0]["versions"][0]["origins"][0]["status"],
            status
        );
        assert!(!stdout(&output).contains("unverified"));
        let (output, _) = execute(&value, &["--no-color"]);
        assert!(
            stdout(&output).contains(expected),
            "{status}: {}",
            stdout(&output)
        );
    }
}

#[test]
fn audit_report_binary_file_output_is_preserved_on_malformed_known_reports() {
    let r = repo();
    let path = r.path().join("audit.json");
    let p = path.to_str().expect("path");
    let s = server(&serde_json::to_vec(&findings()).expect("json"));
    let output = run(r.path(), Some(&s.origin()), &["--json", "-q", "-o", p]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let saved = fs::read(&path).expect("saved");
    assert_eq!(s.requests().len(), 3);
    let s = server(br#"{"schema_version":2,"findings":{}}"#);
    let output = run(r.path(), Some(&s.origin()), &["--json", "-o", p]);
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert_eq!(fs::read(&path).expect("preserved"), saved);
    assert_eq!(s.requests().len(), 3);
    let mut value = findings();
    value["findings"]["duplicates"][0]["versions"][0]["origins"][0]["attribution_basis"] = 7.into();
    let s = server(&serde_json::to_vec(&value).expect("json"));
    let output = run(r.path(), Some(&s.origin()), &["--json", "-o", p]);
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert_eq!(fs::read(&path).expect("preserved"), saved);
    assert_eq!(s.requests().len(), 3);
    let mut value = clean();
    value["unknowns"]["resolution"] = json!([{"path":"Cargo.toml","name":null,"reason":"required_input_not_supplied","required_path":7}]);
    let s = server(&serde_json::to_vec(&value).expect("json"));
    let output = run(r.path(), Some(&s.origin()), &["--json", "-o", p]);
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert_eq!(fs::read(&path).expect("preserved"), saved);
    assert_eq!(s.requests().len(), 3);
}

fn published_requests() -> Value {
    let mut value = findings();
    let group = &mut value["findings"]["duplicates"][0];
    for (version, requirement) in group["versions"]
        .as_array_mut()
        .expect("versions")
        .iter_mut()
        .zip(["^1.0.0", "^2.0.0"])
    {
        version["paths"] = json!(["package-lock.json"]);
        let origin = &mut version["origins"][0];
        origin["path"] = "package-lock.json".into();
        origin["status"] = "parent_release_declared".into();
        origin["requested_requirement"] = requirement.into();
    }
    group["unattributed_requirements"][0]["path"] = "package-lock.json".into();
    group["unattributed_requirements"][0]["requirement_status"] = "parent_release_declared".into();
    value
}

fn duplicate_section(output: &Output) -> String {
    stdout(output)
        .split_once("Duplicate versions")
        .expect("duplicates")
        .1
        .split("\nIncomplete checks")
        .next()
        .expect("section")
        .to_owned()
}

#[test]
fn audit_report_human_metadata_requests_need_no_banner_with_one_shared_file() {
    let value = published_requests();
    let (output, _) = execute(&value, &["--no-color", "-q"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    let text = duplicate_section(&output);
    assert!(!text.contains("Published package metadata"));
    assert!(text.starts_with(" (1)\n  npm:demo [package-lock.json]\n"));
    assert_eq!(text.matches("[package-lock.json]").count(), 1);
    assert!(text.contains("npm:demo [package-lock.json]"));
    assert!(text.contains("app requests ^1.0.0"));
    assert!(text.contains("tool@3.0.0 requests ^2.0.0"));
    assert!(text.contains("Declarations without a recorded dependency link"));
    assert!(!text.contains("parent_release_declared") && !text.contains("target not identified"));
    let (output, _) = execute(&value, &["--json", "-q"]);
    let result: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(
        result["duplicates"][0]["versions"][0]["origins"][0]["status"],
        "parent_release_declared"
    );
    assert_eq!(
        result["duplicates"][0]["unattributed_requirements"][0]["target_status"],
        "untargeted"
    );
    let mut value = published_requests();
    value["findings"]["duplicates"][0]["versions"][0]["origins"][0]["requested_requirement"] =
        Value::Null;
    let (output, _) = execute(&value, &["--no-color"]);
    assert!(stdout(&output).contains("app — published requirement unavailable"));
}

#[test]
fn audit_report_human_candidate_only_metadata_and_link_gaps_are_plain() {
    let mut value = findings();
    value["findings"]["duplicates"][0]["unattributed_requirements"][0]["requirement_status"] =
        "parent_release_declared".into();
    value["unknowns"]["sources"][0]["reasons"] = json!(["untargeted_requirement"]);
    let (output, _) = execute(&value, &["--no-color"]);
    let text = stdout(&output);
    assert!(!text.contains("Published package metadata"));
    assert!(text.contains("dependency requirement without a recorded link"));
    assert!(!text.contains("target not identified") && !text.contains("parent_release_declared"));
}

#[test]
fn audit_report_human_mixed_and_foreign_origin_files_remain_visible() {
    let mut value = published_requests();
    let version = &mut value["findings"]["duplicates"][0]["versions"][1];
    version["paths"] = json!(["web/package-lock.json"]);
    version["origins"][0]["path"] = "web/package-lock.json".into();
    let (output, _) = execute(&value, &["--no-color"]);
    let text = duplicate_section(&output);
    assert!(text.contains("1.0.0 [package-lock.json]"));
    assert!(text.contains("2.0.0 [web/package-lock.json]"));
    let mut value = published_requests();
    value["findings"]["duplicates"][0]["unattributed_requirements"][0]["path"] =
        "package.json".into();
    let (output, _) = execute(&value, &["--no-color"]);
    let text = duplicate_section(&output);
    assert!(!text.contains("npm:demo [package-lock.json]"));
    assert!(text.contains("app requests ^1.0.0 [package.json]"));
    let mut value = published_requests();
    value["findings"]["duplicates"][0]["versions"][0]["origins"][0]["path"] = "foreign.lock".into();
    let (output, _) = execute(&value, &["--no-color"]);
    let text = stdout(&output);
    assert!(text.contains("app requests ^1.0.0 [foreign.lock]"));
    assert!(text.contains("unverified"));
}

#[test]
fn audit_report_human_absent_and_future_links_keep_distinct_meanings() {
    for (status, expected) in [
        ("absent", "dependency absent from recorded graph"),
        ("future_target", "unrecognized link status: future_target"),
    ] {
        let mut value = published_requests();
        value["findings"]["duplicates"][0]["unattributed_requirements"][0]["target_status"] =
            status.into();
        let (output, _) = execute(&value, &["--no-color"]);
        assert_eq!(output.status.code(), Some(1));
        assert!(
            stdout(&output).contains(expected),
            "{status}: {}",
            stdout(&output)
        );
    }
}

fn compatible_requests() -> Value {
    let mut value = published_requests();
    let group = &mut value["findings"]["duplicates"][0];
    group["unattributed_requirements"] = json!([]);
    for version in group["versions"].as_array_mut().expect("versions") {
        let mut origin = version["origins"][0].clone();
        origin["status"] = "parent_release_compatible".into();
        origin["attribution_basis"] = "published_requirement_compatibility".into();
        origin["requester"] = json!({"name":"requests","version":"2.32.3"});
        origin["requested_requirement"] = "<4,>=2".into();
        version["origins"] = json!([
            origin,
            {"path":"package-lock.json","requester":null,
             "requested_requirement":null,"status":"parent_not_recorded"}
        ]);
    }
    value
}

#[test]
fn audit_report_possible_requesters_preserve_basis_absence_and_gaps() {
    let value = compatible_requests();
    let (output, requests) = execute(&value, &["--json", "-q"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    assert_eq!(requests.len(), 3);
    let result: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(result["schema_version"], 2);
    assert_eq!(result["incomplete"], true);
    assert!(!stdout(&output).contains("unverified"));
    for version in result["duplicates"][0]["versions"]
        .as_array()
        .expect("versions")
    {
        let origins = version["origins"].as_array().expect("origins");
        assert_eq!(origins.len(), 2);
        let possible = origins
            .iter()
            .find(|o| o["status"] == "parent_release_compatible")
            .expect("possible");
        assert_eq!(
            possible["attribution_basis"],
            "published_requirement_compatibility"
        );
        assert_eq!(possible["requested_requirement"], "<4,>=2");
        let absent = origins
            .iter()
            .find(|o| o["status"] == "parent_not_recorded")
            .expect("absence");
        assert!(absent.get("requester").is_none() && absent.get("attribution_basis").is_none());
    }
    let (output, _) = execute(&value, &["--no-color", "-q"]);
    let text = stdout(&output);
    assert_eq!(
        text.matches("possible requester: requests@2.32.3 (requires <4,>=2)")
            .count(),
        2
    );
    assert_eq!(
        text.matches("requesting dependency not recorded").count(),
        2
    );
    assert!(!text.contains("Published package metadata"));
    assert!(text.contains("Incomplete checks"));
    assert!(
        !text.contains("parent_release_compatible")
            && !text.contains("published_requirement_compatibility")
    );
    let mut value = value;
    value["findings"]["duplicates"][0]["versions"][0]["origins"][0]["requested_requirement"] =
        Value::Null;
    let (output, _) = execute(&value, &["--no-color"]);
    assert!(
        stdout(&output).contains("possible requester: requests@2.32.3 — requirement unavailable")
    );
}

#[test]
fn audit_report_possible_requester_basis_is_optional_and_future_values_survive() {
    for basis in [Value::Null, json!("future_basis")] {
        let mut value = compatible_requests();
        let origin = &mut value["findings"]["duplicates"][0]["versions"][0]["origins"][0];
        origin["attribution_basis"] = basis.clone();
        origin["status"] = "future_origin\u{1b}".into();
        let (output, _) = execute(&value, &["--json"]);
        let result: Value = serde_json::from_slice(&output.stdout).expect("json");
        let origins = result["duplicates"][0]["versions"][0]["origins"]
            .as_array()
            .expect("origins");
        let origin = origins
            .iter()
            .find(|o| o["status"] == "future_origin\u{1b}")
            .expect("future");
        if basis.is_null() {
            assert!(origin.get("attribution_basis").is_none());
        } else {
            assert_eq!(origin["attribution_basis"], basis);
        }
        let (output, _) = execute(&value, &["--no-color"]);
        assert!(stdout(&output).contains("future_origin\\u{1b}"));
        assert!(!stdout(&output).contains('\u{1b}'));
    }
}

#[test]
fn audit_report_recorded_requesters_keep_text_and_supplied_basis() {
    for basis in ["lockfile_recorded", "manifest_lock_agreement"] {
        let mut value = findings();
        value["findings"]["duplicates"][0]["versions"][0]["origins"][0]["attribution_basis"] =
            basis.into();
        let (output, _) = execute(&value, &["--json"]);
        let result: Value = serde_json::from_slice(&output.stdout).expect("json");
        assert_eq!(
            result["duplicates"][0]["versions"][0]["origins"][0]["attribution_basis"],
            basis
        );
        let (output, _) = execute(&value, &["--no-color"]);
        assert!(stdout(&output).contains("app requests ^1.0.0"));
        assert!(!stdout(&output).contains("possible requester:"));
    }
}

fn required_input_gaps() -> Value {
    let mut value = clean();
    value["summary"]["incomplete_sources"] = 1.into();
    value["unknowns"]["sources"] = json!([{"path":"package.json","reasons":["not_expanded","incomplete_native_declarations","required_input_not_supplied"]}]);
    value["unknowns"]["resolution"] = json!([
        {"path":"package.json","name":null,"reason":"required_input_not_supplied","required_path":"packages/b/package.json"},
        {"path":"package.json","name":null,"reason":"required_input_not_supplied","required_path":"packages/a/package.json"},
        {"path":"package.json","name":null,"reason":"incomplete_native_declarations"}
    ]);
    value
}

#[test]
fn audit_report_required_files_coalesce_repeated_source_diagnostics() {
    let value = required_input_gaps();
    let (output, requests) = execute(&value, &["--json", "-q"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    assert_eq!(requests.len(), 3);
    let result: Value = serde_json::from_slice(&output.stdout).expect("report");
    assert_eq!(result["incomplete"], true);
    let issues = result["issues"].as_array().expect("issues");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0]["check"], "dependency information");
    assert_eq!(
        issues[0]["required_files"],
        json!(["packages/a/package.json", "packages/b/package.json"])
    );
    assert!(!stdout(&output).contains("required_input_not_supplied"));
    let (output, _) = execute(&value, &["--no-color", "-q"]);
    let text = stdout(&output);
    assert_eq!(
        text.matches("dependency information incomplete:").count(),
        1
    );
    for expected in [
        "transitive dependencies were not included",
        "dependency declarations are incomplete",
        "required project files were not uploaded",
        "required files: packages/a/package.json, packages/b/package.json",
        "[lockfiles].manifests in githits-scan.toml",
        "githits-scan detect",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
}

#[test]
fn audit_report_required_files_keep_named_unmatched_and_future_diagnostics() {
    let mut value = required_input_gaps();
    value["unknowns"]["resolution"] = json!([
        {"path":"package.json","name":"named","reason":"required_input_not_supplied","required_path":"packages/named/package.json"},
        {"path":"package.json","name":null,"reason":"future_gap\u{001b}","required_path":"packages/future\u{001b}/package.json"},
        {"path":"other.json","name":null,"reason":"required_input_not_supplied","required_path":null}
    ]);
    let (output, _) = execute(&value, &["--json", "-q"]);
    let result: Value = serde_json::from_slice(&output.stdout).expect("report");
    let issues = result["issues"].as_array().expect("issues");
    assert_eq!(issues.len(), 4);
    assert!(issues.iter().any(|i| i["packages"] == json!(["named"])
        && i["required_files"] == json!(["packages/named/package.json"])));
    assert!(issues.iter().any(|i| i["reason"] == "future_gap\u{001b}"
        && i["required_files"] == json!(["packages/future\u{001b}/package.json"])));
    assert!(
        issues
            .iter()
            .any(|i| i["files"] == json!(["other.json"]) && i.get("required_files").is_none())
    );
    let (output, _) = execute(&value, &["--no-color", "-q"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!output.stdout.contains(&0x1b));
    assert!(stdout(&output).contains("future_gap\\u{1b}"));
    assert_eq!(stdout(&output).matches("action:").count(), 1);
    assert!(stdout(&output).contains("[lockfiles].manifests in githits-scan.toml"));
}

#[test]
fn audit_report_known_gap_reasons_are_plain_and_future_reasons_survive() {
    for (code, expected) in [
        (
            "missing_requirement",
            "dependency requirement could not be determined",
        ),
        (
            "unsupported_dependency",
            "dependency not supported by this check",
        ),
        (
            "unsupported_dependency_facets",
            "dependency attributes not supported by this check",
        ),
        (
            "unsupported_ecosystem",
            "ecosystem not supported by this check",
        ),
        ("unmet_dependency", "unresolved dependency"),
        (
            "unknown_relationship",
            "dependency relationships could not be determined",
        ),
        (
            "unsupported_registry_context",
            "package registry configuration not supported",
        ),
        (
            "manifest_lock_target_ambiguous",
            "manifest requirement matches multiple locked packages",
        ),
        (
            "manifest_lock_target_not_recorded",
            "manifest requirement has no recorded locked package",
        ),
        (
            "incomplete_dependency_groups",
            "dependency groups are incomplete",
        ),
        (
            "unsupported_manifest_lock_requirement",
            "manifest requirement cannot be compared with the lockfile",
        ),
        (
            "missing_ranges",
            "advisory affected-version ranges unavailable",
        ),
        ("dependency_list_unavailable", "dependency list unavailable"),
        ("unresolved_dependency", "unresolved dependency"),
        (
            "unresolved_manifest_activation",
            "dependency activation could not be determined",
        ),
        (
            "incomplete_dependency_list",
            "dependency list is incomplete",
        ),
        ("invalid_version", "package version could not be evaluated"),
        ("future_reason", "future_reason"),
    ] {
        let mut value = clean();
        value["summary"]["incomplete_sources"] = 1.into();
        value["unknowns"]["sources"] = json!([{"path":"package.json","reasons":[code]}]);
        let (output, _) = execute(&value, &["--no-color", "-q"]);
        assert_eq!(output.status.code(), Some(1));
        assert!(stdout(&output).contains(expected));
        let (output, _) = execute(&value, &["--json", "-q"]);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty(), "{:?}", output.stderr);
        let result: Value = serde_json::from_slice(&output.stdout).expect("report");
        assert_eq!(result["incomplete"], true);
        assert_eq!(result["issues"][0]["reason"], expected);
        assert_eq!(result["issues"][0]["files"], json!(["package.json"]));
        assert_eq!(
            result["summary"],
            json!({"dependencies":2,"vulnerabilities":0,"lifecycle":0,"retained_lifecycle_warnings":0,"outdated":0,"duplicates":0})
        );
    }
}

#[test]
fn audit_report_missing_advisory_ranges_keep_context() {
    let mut value = findings();
    value["unknowns"]["vulnerabilities"][0]["reasons"] = json!(["missing_ranges"]);
    let (output, requests) = execute(&value, &["--no-color", "-q"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    assert_eq!(requests.len(), 3);
    for expected in [
        "advisory affected-version ranges unavailable",
        "npm:demo@2.0.0",
        "web/package-lock.json",
        "GHSA-context",
    ] {
        assert!(stdout(&output).contains(expected), "{expected}");
    }
    let (output, requests) = execute(&value, &["--json", "-q"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    assert_eq!(requests.len(), 3);
    let result: Value = serde_json::from_slice(&output.stdout).expect("report");
    assert_eq!(result["incomplete"], true);
    let issue = result["issues"]
        .as_array()
        .expect("issues")
        .iter()
        .find(|issue| issue["advisories"] == json!(["GHSA-context"]))
        .expect("advisory gap");
    assert_eq!(issue["check"], "vulnerabilities");
    assert_eq!(
        issue["reason"],
        "advisory affected-version ranges unavailable"
    );
    assert_eq!(issue["status"], "unknown");
    assert_eq!(issue["packages"], json!(["npm:demo@2.0.0"]));
    assert_eq!(issue["files"], json!(["web/package-lock.json"]));
    assert_eq!(issue["advisories"], json!(["GHSA-context"]));
    assert!(!stdout(&output).contains("unverified"));
}

#[test]
fn audit_report_reason_aliases_and_future_reasons() {
    let mut value = findings();
    value["unknowns"]["sources"][0]["reasons"] =
        json!(["unmet_dependency", "unresolved_dependency", "future_reason"]);
    let (output, requests) = execute(&value, &["--no-color", "-q"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    assert_eq!(requests.len(), 3);
    let text = stdout(&output);
    assert_eq!(text.matches("unresolved dependency").count(), 1);
    assert_eq!(text.matches("future_reason").count(), 1);
    assert!(text.contains("[package-lock.json]"));
    let (output, requests) = execute(&value, &["--json", "-q"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    assert_eq!(requests.len(), 3);
    let result: Value = serde_json::from_slice(&output.stdout).expect("report");
    assert_eq!(result["incomplete"], true);
    assert_eq!(
        result["summary"],
        json!({"dependencies":2,"vulnerabilities":1,"lifecycle":1,"retained_lifecycle_warnings":0,"outdated":1,"duplicates":1})
    );
    let issue = result["issues"]
        .as_array()
        .expect("issues")
        .iter()
        .find(|issue| issue["check"] == "dependency information")
        .expect("source gap");
    assert_eq!(issue["reason"], "future_reason, unresolved dependency");
    assert_eq!(issue["status"], "incomplete");
    assert_eq!(issue["files"], json!(["package-lock.json"]));
    assert!(!stdout(&output).contains("unverified"));
}

#[test]
fn audit_report_file_lists_wrap_after_one_hundred_rendered_characters() {
    for length in [76, 77] {
        let path = format!("{}/package.json", "a".repeat(length));
        let repo = repository(&[(&path, "{}")]);
        let s = server(&serde_json::to_vec(&clean()).expect("report"));
        let output = run(repo.path(), Some(&s.origin()), &["--no-color", "-q"]);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty(), "{:?}", output.stderr);
        let expected = if length == 76 {
            format!("Manifests: {path}\n")
        } else {
            format!("Manifests (1):\n  {path}\n")
        };
        assert!(stdout(&output).contains(&expected));
        assert_eq!(s.requests().len(), 3);
    }
}
