//! Binary acceptance for complete joint mitigation action sets.
#[path = "audit_blocker_identity.rs"]
mod audit_blocker_identity;

#[path = "audit_remediation_ux.rs"]
mod audit_remediation_ux;

#[path = "audit_remediation_grouping.rs"]
mod audit_remediation_grouping;

#[path = "audit_change_reasons.rs"]
mod audit_change_reasons;

use super::*;
use crate::support::audit::findings;
use serde_json::{Value, json};

fn remediation_report() -> Value {
    let mut value = findings();
    value["remediation"] =
        serde_json::from_slice(include_bytes!("../fixtures/audit/remediation.json"))
            .expect("remediation fixture");
    value
}

fn execute_report(value: &Value, extra: &[&str]) -> Output {
    let root = repo();
    let mock = server(&serde_json::to_vec(value).expect("report"));
    let output = run(root.path(), Some(&mock.origin()), extra);
    assert_eq!(mock.requests().len(), 3, "one submit/events/result");
    output
}

fn json_report(value: &Value) -> Value {
    let output = execute_report(value, &["--json", "--quiet"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).is_empty(), "{:?}", stderr(&output));
    serde_json::from_slice(&output.stdout).expect("compact JSON")
}

fn human_report(value: &Value) -> String {
    let output = execute_report(value, &["--no-color", "--quiet", "--details"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    stdout(&output)
}

#[test]
fn audit_remediation_normal_output_establishes_problem_before_guidance() {
    let mut input = remediation_report();
    input["remediation"]["recommendations"][0]["checks"]["parent_search"] = "not_assessed".into();
    input["remediation"]["recommendations"][0]["limitations"] = json!(["withdrawal_not_observed"]);
    let text = human_report(&input);
    let section = text
        .split_once("Fix guidance")
        .expect("mitigation section")
        .1
        .split_once("Package warnings")
        .expect("next section")
        .0;
    assert_eq!(
        section.trim(),
        concat!(
            "npm:demo@1.0.0 — vulnerable\n",
            "    GHSA-demo / CVE-demo (CVSS 7.5): Authored example advisory\n",
            "      advisory-reported fix versions: 1.1.0\n",
            "      verified advisory fixes: 1.1.1\n",
            "    Found in: package-lock.json\n\n",
            "    Suggested fix:\n",
            "      Upgrade npm:demo 1.0.0 -> 1.1.1"
        )
    );
    let result = json_report(&input);
    assert_eq!(
        result["remediation"]["recommendations"][0]["checks"],
        input["remediation"]["recommendations"][0]["checks"]
    );
    assert_eq!(
        result["remediation"]["recommendations"][0]["limitations"],
        json!(["withdrawal_not_observed"])
    );
    assert_eq!(
        result["remediation"]["recommendations"][0]["findings"][0],
        json!({"package":"npm:demo@1.0.0","advisory":"GHSA-demo","files":["package-lock.json"]})
    );
}

#[test]
fn audit_remediation_problem_context_handles_missing_and_untrusted_metadata() {
    let mut input = remediation_report();
    input["findings"]["vulnerabilities"][0]["summary"] = Value::Null;
    input["findings"]["vulnerabilities"][0]["severity_score"] = Value::Null;
    input["remediation"]["recommendations"][0]["changes"][0]["paths"] =
        json!(["web/package-lock.json"]);
    let text = human_report(&input);
    let section = text.split_once("Fix guidance").expect("section").1;
    assert!(section.contains("    GHSA-demo / CVE-demo\n"));
    assert!(!section.contains("(CVSS") && !section.contains("Authored example"));
    assert!(section.contains("Found in: package-lock.json"));
    assert!(section.contains("Change in: web/package-lock.json"));
    input["findings"]["vulnerabilities"][0]["summary"] = "unsafe\n\u{1b}[2J".into();
    input["findings"]["vulnerabilities"][0]["malicious"] = true.into();
    let text = human_report(&input);
    let section = text.split_once("Fix guidance").expect("section").1;
    assert!(section.contains("GHSA-demo / CVE-demo MALICIOUS: unsafe\\n\\u{1b}[2J"));
    assert!(!section.contains('\u{1b}'));
    for field in [
        "finding_refs",
        "addressed_finding_refs",
        "remaining_finding_refs",
    ] {
        input["remediation"]["recommendations"][0][field] = json!([]);
    }
    let text = human_report(&input);
    let section = text.split_once("Fix guidance").expect("section").1;
    assert!(section.contains("  npm:demo@1.0.0\n"));
    assert!(!section.contains("— vulnerable"));
    assert!(section.contains("Candidate changes:"));
    assert!(!section.contains("Suggested fix") && !section.contains("      Upgrade npm:"));
    input["remediation"]["recommendations"][0]["finding_refs"] = json!([0]);
    input["remediation"]["recommendations"][0]["remaining_finding_refs"] = json!([0]);
    let text = human_report(&input);
    let section = text.split_once("Fix guidance").expect("section").1;
    assert!(section.contains("— vulnerable") && section.contains("still unresolved: GHSA-demo"));
    assert!(section.contains("Candidate changes:"));
    assert!(!section.contains("Suggested fix") && !section.contains("      Upgrade npm:"));
}

#[test]
fn audit_remediation_full_report_keeps_each_covered_problem_once() {
    let mut input = remediation_report();
    let text = human_report(&input);
    assert_eq!(text.matches("Authored example advisory").count(), 1);
    assert_eq!(text.matches("CVE-demo").count(), 1);
    assert_eq!(
        text.matches("advisory-reported fix versions: 1.1.0")
            .count(),
        1
    );
    assert_eq!(text.matches("verified advisory fixes: 1.1.1").count(), 1);
    assert!(!text.contains("Vulnerabilities (1)"));
    let mut uncovered = input["findings"]["vulnerabilities"][0].clone();
    uncovered["advisory_id"] = "GHSA-uncovered".into();
    uncovered["aliases"] = json!(["CVE-uncovered"]);
    uncovered["summary"] = "Uncovered advisory".into();
    input["findings"]["vulnerabilities"]
        .as_array_mut()
        .expect("findings")
        .push(uncovered);
    input["summary"]["vulnerabilities"] = 2.into();
    let text = human_report(&input);
    assert!(text.contains("Vulnerabilities (1)"));
    assert_eq!(text.matches("Authored example advisory").count(), 1);
    assert_eq!(text.matches("Uncovered advisory").count(), 1);
    let result = json_report(&input);
    assert!(
        !serde_json::to_string(&result)
            .expect("JSON")
            .contains("problem_indices")
    );
    assert_eq!(
        result["vulnerabilities"]
            .as_array()
            .expect("inventory")
            .len(),
        2
    );
    input.as_object_mut().expect("report").remove("remediation");
    let text = human_report(&input);
    assert!(text.contains("Vulnerabilities (2)"));
    assert!(text.contains("verified advisory fixes"));
}

#[test]
fn audit_remediation_summary_uses_singular_nouns() {
    let input = remediation_report();
    assert!(human_report(&input).contains(
        "2 dependencies; 1 vulnerability, 1 package warning, 1 outdated version, 1 duplicate package"
    ));
    let output = execute_report(&crate::support::audit::clean(), &["--quiet", "--no-color"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output).lines().nth(1), Some("2 dependencies"));
}

fn shape_case(name: &str) -> Value {
    let mut input = remediation_report();
    if name == "joint-two-parents" {
        return serde_json::from_slice(&joint_action_report()).expect("joint");
    }
    if name == "partial-with-blockers" {
        let record = &mut input["remediation"]["recommendations"][0];
        record["outcome"] = "partial".into();
        record["remaining_finding_refs"] = json!([0]);
        record["blockers"] = json!([blocker()]);
        record["checks"]["requirements"] = "blocked".into();
    }
    if name == "shared-limits-large-unused-trace" {
        let trace_row = json!({"path":"package-lock.json","name":"demo","version":"1.0.0","kind":"package","coordinate":{"registry":"npm","name":"demo","version":"1.0.0"},"project_root":false,"dependency_coverage":null});
        input["remediation"]["trace"]["occurrences"] = Value::Array(vec![trace_row; 1000]);
        let record = input["remediation"]["recommendations"][0].clone();
        input["remediation"]["recommendations"] = json!([record, record]);
    }
    input
}

#[test]
fn audit_remediation_output_shape_keeps_actions_without_trace_dump() {
    for case in [
        "leaf",
        "joint-two-parents",
        "partial-with-blockers",
        "shared-limits-large-unused-trace",
    ] {
        let input = shape_case(case);
        let raw = serde_json::to_string_pretty(&input["remediation"]).expect("raw");
        let result = json_report(&input);
        let projected = serde_json::to_string_pretty(&result["remediation"]).expect("projected");
        let text = human_report(&input);
        let human = text
            .split_once("Fix guidance")
            .expect("section")
            .1
            .split_once("Package warnings")
            .expect("next section")
            .0;
        assert_shape_records(&input, &result);
        for forbidden in [
            "\"occurrences\"",
            "\"relations\"",
            "\"finding_refs\"",
            "\"memberships_checked\"",
        ] {
            assert!(!projected.contains(forbidden));
        }
        for noise in [
            "native resolution:",
            "catalog freshness:",
            "withdrawal:",
            "trace:",
        ] {
            assert!(!human.contains(noise));
        }
        assert!(!human.contains("Verify changes with your package manager and tests."));
        println!(
            "{case}: producer={}/{} human={}/{} compact_json={}/{} bytes/lines",
            raw.len(),
            raw.lines().count(),
            human.len(),
            human.lines().count(),
            projected.len(),
            projected.lines().count()
        );
    }
}

fn assert_shape_records(input: &Value, result: &Value) {
    let records = result["remediation"]["recommendations"]
        .as_array()
        .expect("records");
    assert_eq!(
        records.len(),
        input["remediation"]["recommendations"]
            .as_array()
            .expect("input records")
            .len()
    );
    for (record, original) in records.iter().zip(
        input["remediation"]["recommendations"]
            .as_array()
            .expect("input"),
    ) {
        assert_eq!(
            record["changes"].as_array().expect("changes").len(),
            original["changes"]
                .as_array()
                .expect("original changes")
                .len()
        );
        assert_eq!(
            record["blockers"].as_array().expect("blockers").len(),
            original["blockers"]
                .as_array()
                .expect("original blockers")
                .len()
        );
    }
}

fn blocker() -> Value {
    json!({"owner":{"name":"parent","version":"2.0.0"},"owner_role":"third_party",
        "path":"package.json","kind":"runtime","requested_requirement":"<1.1",
        "requirement_status":"recorded","basis":"exact_parent","context":{},
        "declaration_ref":{"path":"package.json","kind":"native","index":123},
        "reason":"third_party_request_excludes_target","other_target_versions":["1.2.0"]})
}

#[test]
fn audit_remediation_optional_change_flags_preserve_absence() {
    let mut input = remediation_report();
    input["remediation"]["recommendations"][0]["checks"]["prerelease_target"] = true.into();
    input["remediation"]["recommendations"][0]["checks"]["deprecated_target"] = true.into();
    let change = &mut input["remediation"]["recommendations"][0]["changes"][0];
    change["prerelease_target"] = true.into();
    change
        .as_object_mut()
        .expect("change")
        .remove("deprecated_target");
    let result = json_report(&input);
    assert!(
        result["remediation"]["recommendations"][0]["changes"][0]
            .get("deprecated_target")
            .is_none()
    );
    let text = human_report(&input);
    assert!(text.contains("target is prerelease"));
    assert_eq!(text.matches("prerelease").count(), 1);
    assert!(text.contains("action includes a deprecated target"));
    assert!(!text.contains("target: prerelease=true, deprecated=false"));
}

#[test]
fn audit_remediation_material_warnings_remain_visible() {
    for (check, value, warning) in [
        (
            "advisories",
            "unknown",
            "target advisories: not determined from the supplied evidence",
        ),
        (
            "advisories",
            "affected",
            "still affected by known advisories",
        ),
        (
            "release_availability",
            "unverified",
            "release availability: not verified",
        ),
        ("requirements", "unchecked", "requirements: not checked"),
        (
            "requirements",
            "blocked",
            "blocked by dependency requirements",
        ),
        (
            "parent_search",
            "limited",
            "Upgrades to packages using this dependency were not fully checked.",
        ),
    ] {
        let mut input = remediation_report();
        input["remediation"]["recommendations"][0]["checks"][check] = value.into();
        let text = human_report(&input);
        assert!(text.contains(warning), "{check}: {value}");
        if check != "parent_search" {
            let section = text.split_once("Fix guidance").expect("section").1;
            assert!(section.contains("Candidate changes:"));
            assert!(!section.contains("Suggested fix"));
            assert!(!section.contains("      Upgrade npm:"));
        }
    }
}

#[test]
fn audit_remediation_partial_candidates_keep_qualifiers_with_weak_evidence() {
    for evidence in ["blocked", "future_value"] {
        let mut input = remediation_report();
        let r = &mut input["remediation"]["recommendations"][0];
        r["outcome"] = "partial".into();
        r["remaining_finding_refs"] = json!([0]);
        r["checks"]["requirements"] = evidence.into();
        let text = human_report(&input);
        let section = text.split_once("Fix guidance").expect("section").1;
        assert!(section.contains("Candidate changes (partial):"));
        assert!(section.contains("still unresolved: GHSA-demo"));
        assert!(!section.contains("Suggested fix"));
        assert!(!section.contains("      Upgrade npm:"));
        if evidence == "blocked" {
            assert!(section.contains("Upgrade candidate: npm:demo"));
        }
    }
}

#[test]
fn audit_remediation_file_output_is_plain_quiet_and_complete() {
    let input = remediation_report();
    let root = repo();
    let path = root.path().join("audit.txt");
    let mock = server(&serde_json::to_vec(&input).expect("report"));
    let output = run(
        root.path(),
        Some(&mock.origin()),
        &["--quiet", "--output", path.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let text = fs::read_to_string(path).expect("file");
    assert!(text.contains("Fix guidance"));
    assert!(text.contains("Upgrade npm:demo 1.0.0 -> 1.1.1"));
    assert!(!text.contains('\u{1b}'));
}

#[test]
fn audit_remediation_partial_records_and_conflicts_keep_scopes() {
    let mut input = remediation_report();
    let r = &mut input["remediation"]["recommendations"][0];
    r["outcome"] = "partial".into();
    r["remaining_finding_refs"] = json!([0]);
    r["changes"][0]["strategy"] = "override".into();
    r["changes"][0]["conflicting_target_versions"] = json!(["1.2.0"]);
    r["blockers"] = json!([blocker()]);
    r["checks"]["requirements"] = "blocked".into();
    r["limitations"] = json!(["incompatible_recommendations"]);
    let mut other = r.clone();
    other["changes"][0]["target_version"] = "1.2.0".into();
    other["changes"][0]["paths"] = json!(["web/package-lock.json"]);
    other["limitations"] = json!(["checked_occurrence_changed_by_other_recommendation"]);
    input["remediation"]["recommendations"]
        .as_array_mut()
        .expect("records")
        .push(other);
    let result = json_report(&input);
    let records = result["remediation"]["recommendations"]
        .as_array()
        .expect("records");
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[0]["addressed_findings"],
        records[0]["remaining_findings"]
    );
    assert_eq!(
        records[1]["changes"][0]["paths"],
        json!(["web/package-lock.json"])
    );
    assert_eq!(
        records[0]["blockers"][0]["other_target_versions"],
        json!(["1.2.0"])
    );
    let text = human_report(&input);
    for fact in [
        "partial",
        "still unresolved:",
        "Override candidate",
        "parent@2.0.0",
        "<1.1",
        "web/package-lock.json",
        "do not combine",
        "recheck combined changes",
    ] {
        assert!(text.contains(fact), "missing {fact}");
    }
}

#[test]
fn audit_remediation_blocker_context_stays_structured_in_json() {
    let mut input = remediation_report();
    let mut b = blocker();
    b["owner_role"] = "project".into();
    b["owner"]["name"] = "parent\n\u{1b}[2J".into();
    b["reason"] = "project_request_change".into();
    b["requirement_status"] = "future_requirement_status".into();
    let context = json!({"future":{"platform":"\u{1b}[2J\u{202e}"},"groups":["custom"]});
    b["context"] = context.clone();
    input["remediation"]["recommendations"][0]["blockers"] = json!([b]);
    let result = json_report(&input);
    let result_blocker = &result["remediation"]["recommendations"][0]["blockers"][0];
    assert_eq!(result_blocker["context"], context);
    assert!(result_blocker.get("declaration_ref").is_none());
    let text = prose(&human_report(&input));
    assert!(!text.contains('\u{1b}') && !text.contains('\u{202e}'));
    assert!(!text.contains("context:"));
    assert!(text.contains("parent\\n\\u{1b}[2J@2.0.0"));
    assert!(text.contains("applying this change requires updating the project requirement"));
    assert!(text.contains("the service returned an unfamiliar status"));
    assert!(!text.contains("future_requirement_status"));
}

#[test]
fn audit_remediation_advisory_lists_avoid_repeating_covered_findings() {
    let mut base = remediation_report();
    let mut second = base["findings"]["vulnerabilities"][0].clone();
    second["advisory_id"] = "GHSA-other".into();
    base["findings"]["vulnerabilities"]
        .as_array_mut()
        .expect("findings")
        .push(second);
    base["summary"]["vulnerabilities"] = 2.into();
    for (addressed, remaining) in [
        (json!([0]), json!([1])),
        (json!([1, 0]), json!([])),
        (json!([0]), json!([])),
    ] {
        let mut input = base.clone();
        let r = &mut input["remediation"]["recommendations"][0];
        r["finding_refs"] = json!([0, 1]);
        r["outcome"] = "partial".into();
        r["addressed_finding_refs"] = addressed;
        r["remaining_finding_refs"] = remaining;
        r["checks"]["advisories"] = "unknown".into();
        let text = human_report(&input);
        let section = text
            .split_once("Fix guidance")
            .expect("section")
            .1
            .split_once("Package warnings")
            .expect("next section")
            .0;
        assert!(!section.contains("    advisories: "));
        assert!(section.contains("target advisories: not determined from the supplied evidence"));
        assert!(section.contains("GHSA-demo") && section.contains("GHSA-other"));
    }
}

#[test]
fn audit_remediation_future_vocabulary_never_looks_like_known_action() {
    for path in [
        "/status",
        "/recommendations/0/outcome",
        "/recommendations/0/changes/0/strategy",
        "/recommendations/0/checks/advisories",
        "/recommendations/0/checks/native_resolution",
        "/recommendations/0/checks/parent_search",
        "/recommendations/0/checks/catalog_freshness",
        "/recommendations/0/checks/withdrawal",
        "/recommendations/0/checks/parent_search",
    ] {
        let mut input = remediation_report();
        *input["remediation"].pointer_mut(path).expect("field") = "future_value".into();
        let result = json_report(&input);
        assert!(
            serde_json::to_string(&result["remediation"])
                .expect("JSON")
                .contains("future_value")
        );
        let text = human_report(&input);
        let warning = if path == "/status" {
            "unfamiliar fix-planning status"
        } else if path == "/recommendations/0/checks/parent_search" {
            "unfamiliar result for upgrades"
        } else if path == "/recommendations/0/outcome" {
            "unfamiliar mitigation outcome"
        } else if path == "/recommendations/0/changes/0/strategy" {
            "unfamiliar change strategy"
        } else {
            "unfamiliar check result"
        };
        assert!(text.contains(warning), "{path}: {text}");
        assert!(!text.contains("      Upgrade "), "{path}");
        assert!(!text.contains("Suggested fix"), "{path}");
        assert!(!text.contains("No upgrade path found"), "{path}");
    }
}

#[test]
fn audit_remediation_unavailable_planning_does_not_change_clean_base() {
    for planning in ["completed", "not_assessed", "limited"] {
        let mut input = crate::support::audit::clean();
        input["remediation"] = remediation_report()["remediation"].clone();
        input["remediation"]["status"] = planning.into();
        input["remediation"]["recommendations"] = json!([]);
        input["remediation"]["limits"]["reasons"] = json!(["planning_deadline"]);
        let output = execute_report(&input, &["--json"]);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let result: Value = serde_json::from_slice(&output.stdout).expect("JSON");
        assert_eq!(result["incomplete"], false);
        assert_eq!(result["remediation"]["status"], planning);
    }
    let without_guidance = findings();
    assert!(json_report(&without_guidance).get("remediation").is_none());
    assert_eq!(
        human_report(&without_guidance)
            .matches("Fix guidance is unavailable")
            .count(),
        1
    );
}

fn assert_unverified(input: &Value) {
    let result = json_report(input);
    assert_eq!(result["incomplete"], true);
    assert!(result.get("remediation").is_none());
    assert_eq!(
        result["issues"]
            .as_array()
            .expect("issues")
            .iter()
            .filter(|i| i["status"] == "unverified")
            .count(),
        1
    );
    let text = human_report(input);
    assert!(text.contains("mitigation recommendation references or search domain are unverified"));
    assert!(!text.contains("Fix guidance is unavailable"));
    assert!(!text.contains("Fix guidance"));
}

#[test]
fn audit_remediation_invalid_references_suppress_only_action_section() {
    for field in [
        "finding_refs",
        "addressed_finding_refs",
        "remaining_finding_refs",
    ] {
        let mut input = remediation_report();
        input["remediation"]["recommendations"][0][field] = json!([999]);
        assert_unverified(&input);
    }
    let mut clean = crate::support::audit::clean();
    clean["remediation"] = remediation_report()["remediation"].clone();
    assert_unverified(&clean);
}

#[test]
fn audit_remediation_negative_outcome_needs_domain_and_stays_scoped() {
    let mut input = remediation_report();
    let record = &mut input["remediation"]["recommendations"][0];
    record["outcome"] = "no_upgrade_path".into();
    record["changes"] = json!([]);
    record["checks"]["release_availability"] = "unverified".into();
    record["checks"]["advisories"] = "not_assessed".into();
    record["checks"]["requirements"] = "not_assessed".into();
    assert_unverified(&input);
    input["remediation"]["recommendations"][0]["search_domain"] = json!({"constraint_scope":"represented_requests","release_scope":"observed_catalog_upgrades","packages":[{"coordinate":{"registry":"npm","name":"demo","version":"1.0.0"},"versions":["1.0.0"]}]});
    assert!(
        prose(&human_report(&input)).contains(
            "No upgrade path found among releases known to the service, under the dependency requirements considered"
        )
    );
    let text = prose(&human_report(&input));
    let section = text.split_once("Fix guidance").expect("section").1;
    for absent in [
        "release availability:",
        "target advisories:",
        "requirements:",
    ] {
        assert!(!section.contains(absent));
    }
    assert!(json_report(&input)["remediation"]["recommendations"][0]["search_domain"].is_object());
    input["remediation"]["recommendations"][0]["search_domain"]["release_scope"] =
        "future_scope".into();
    let text = prose(&human_report(&input));
    assert!(text.contains("The upgrade search scope is unfamiliar, so no conclusion about an upgrade path can be drawn."));
    assert!(!text.contains("No upgrade path found"));
}

#[test]
fn audit_remediation_future_checks_cannot_produce_negative() {
    let mut base = remediation_report();
    let r = &mut base["remediation"]["recommendations"][0];
    r["outcome"] = "no_upgrade_path".into();
    r["changes"] = json!([]);
    r["search_domain"] = json!({"constraint_scope":"represented_requests","release_scope":"observed_catalog_upgrades","packages":[{"coordinate":{"registry":"npm","name":"demo","version":"1.0.0"},"versions":["1.0.0"]}]});
    for path in [
        "/remediation/status",
        "/remediation/recommendations/0/checks/advisories",
        "/remediation/recommendations/0/checks/requirements",
    ] {
        let mut input = base.clone();
        *input.pointer_mut(path).expect("field") = "future_value".into();
        let text = prose(&human_report(&input));
        assert!(!text.contains("No upgrade path found"), "{path}");
        assert!(text.contains("The planning or check evidence is unfamiliar, so no conclusion about an upgrade path can be drawn."));
        let result = json_report(&input);
        assert!(
            serde_json::to_string(&result["remediation"])
                .expect("JSON")
                .contains("future_value")
        );
    }
}

#[test]
fn audit_remediation_type_failure_preserves_existing_output() {
    let mut input = remediation_report();
    input["remediation"]["recommendations"][0]["changes"] = Value::Null;
    let root = repo();
    let path = root.path().join("audit.txt");
    fs::write(&path, "keep existing").expect("existing");
    let mock = server(&serde_json::to_vec(&input).expect("report"));
    let output = run(
        root.path(),
        Some(&mock.origin()),
        &["--output", path.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert_eq!(fs::read_to_string(path).expect("output"), "keep existing");
}

#[test]
fn audit_remediation_trace_omission_keeps_inline_facts_and_counts() {
    let mut input = remediation_report();
    let before = json_report(&input);
    input["remediation"]["trace"] =
        json!({"status":"not_retained","occurrences":[],"relations":[]});
    input["remediation"]["recommendations"][0]["detail_status"] = "not_retained".into();
    input["remediation"]["recommendations"][0]["occurrence_refs"] = json!([]);
    input["remediation"]["recommendations"][0]["changes"][0]["occurrence_refs"] = json!([]);
    input["remediation"]["limits"] = json!({"reasons":["output_limit"],"omitted_recommendations":1,"omitted_occurrences":3,"omitted_relations":2});
    let after = json_report(&input);
    assert_eq!(
        before["remediation"]["recommendations"][0]["changes"],
        after["remediation"]["recommendations"][0]["changes"]
    );
    assert_eq!(after["remediation"]["limits"]["omitted_recommendations"], 1);
    let text = human_report(&input);
    assert!(text.contains("omitted recommendations: 1"));
    assert!(!text.contains("omitted: 1 recommendations, 3 occurrences, 2 relations"));
    assert!(!text.contains("detail: not retained"));
    assert_eq!(after["remediation"]["limits"]["omitted_occurrences"], 3);
    assert_eq!(after["remediation"]["limits"]["omitted_relations"], 2);
    assert_eq!(
        after["remediation"]["recommendations"][0]["detail_status"],
        "not_retained"
    );
    assert!(text.contains("npm:demo 1.0.0 -> 1.1.1"));
}

#[test]
fn audit_remediation_joint_action_set_keeps_every_change() {
    let bytes = joint_action_report();
    assert_json_joint_action_set(&bytes);
    assert_human_joint_action_set(&bytes);
}

#[test]
fn audit_remediation_parent_upgrade_names_the_vulnerable_dependency() {
    let mut input = remediation_report();
    let change = &mut input["remediation"]["recommendations"][0]["changes"][0];
    change["name"] = "parent-a".into();
    change["from_version"] = "2.0.0".into();
    change["target_version"] = "2.1.0".into();
    let text = human_report(&input);
    let section = text
        .split_once("Fix guidance")
        .expect("section")
        .1
        .split_once("Package warnings")
        .expect("next section")
        .0;
    assert_eq!(
        section.trim(),
        concat!(
            "npm:demo@1.0.0 — vulnerable\n",
            "    GHSA-demo / CVE-demo (CVSS 7.5): Authored example advisory\n",
            "      advisory-reported fix versions: 1.1.0\n",
            "      verified advisory fixes: 1.1.1\n",
            "    Found in: package-lock.json\n\n",
            "    Suggested fix:\n",
            "      Upgrade npm:parent-a 2.0.0 -> 2.1.0"
        )
    );
}

fn joint_action_report() -> Vec<u8> {
    let mut report = findings();
    let mut remediation: Value =
        serde_json::from_slice(include_bytes!("../fixtures/audit/remediation.json"))
            .expect("remediation fixture");
    let original = remediation["recommendations"][0]["changes"][0].clone();

    let mut parent_a = original.clone();
    parent_a["name"] = "parent-a".into();
    parent_a["from_version"] = "2.0.0".into();
    parent_a["target_version"] = "2.1.0".into();

    let mut parent_b = original.clone();
    parent_b["name"] = "parent-b".into();
    parent_b["from_version"] = "3.0.0".into();
    parent_b["target_version"] = "3.1.0".into();

    remediation["recommendations"][0]["changes"] = json!([parent_a, parent_b, original]);
    report["remediation"] = remediation;
    serde_json::to_vec(&report).expect("report")
}

fn assert_json_joint_action_set(bytes: &[u8]) {
    let r = repo();
    let s = server(bytes);
    let output = run(r.path(), Some(&s.origin()), &["--json", "-q"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let serialized = stdout(&output);
    let result: Value = serde_json::from_str(&serialized).expect("compact report");
    let recommendations = result["remediation"]["recommendations"]
        .as_array()
        .expect("recommendations");
    assert_eq!(recommendations.len(), 1);
    let recommendation = &recommendations[0];
    let changes = recommendation["changes"].as_array().expect("changes");
    assert_eq!(changes.len(), 3);
    for (change, (name, from, target)) in changes.iter().zip([
        ("parent-a", "2.0.0", "2.1.0"),
        ("parent-b", "3.0.0", "3.1.0"),
        ("demo", "1.0.0", "1.1.1"),
    ]) {
        assert_eq!(change["name"], name);
        assert_eq!(change["from_version"], from);
        assert_eq!(change["target_version"], target);
    }
    assert_eq!(
        recommendation["addressed_findings"][0]["advisory"],
        "GHSA-demo"
    );
    assert_eq!(result["summary"]["vulnerabilities"], 1);
    assert_eq!(result["incomplete"], true);
    for field in [
        "\"finding_refs\"",
        "\"occurrence_refs\"",
        "\"occurrences\"",
        "\"memberships_checked\"",
    ] {
        assert!(!serialized.contains(field), "unexpected raw field {field}");
    }
}

fn assert_human_joint_action_set(bytes: &[u8]) {
    let r = repo();
    let s = server(bytes);
    let output = run(
        r.path(),
        Some(&s.origin()),
        &["--no-color", "-q", "--details"],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let human = stdout(&output);
    assert_eq!(human.matches("Fix guidance").count(), 1);
    let mitigation = human
        .split_once("Fix guidance")
        .expect("mitigation section")
        .1
        .split_once("Package warnings")
        .expect("deprecated section")
        .0;
    assert!(mitigation.contains("change together:"));
    let action_lines = [
        "Upgrade npm:parent-a 2.0.0 -> 2.1.0",
        "Upgrade npm:parent-b 3.0.0 -> 3.1.0",
        "Upgrade npm:demo 1.0.0 -> 1.1.1",
    ];
    let positions: Vec<_> = action_lines
        .iter()
        .map(|line| mitigation.find(line).expect("joint action line"))
        .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(mitigation.matches("package-lock.json").count(), 1);
}

#[test]
fn audit_remediation_native_disagreement_keeps_the_candidate_qualified() {
    let mut input = remediation_report();
    input["remediation"]["recommendations"][0]["checks"]["requirements"] = "unchecked".into();
    input["remediation"]["recommendations"][0]["limitations"] =
        json!(["manifest_lock_disagreement"]);
    let text = human_report(&input);
    assert!(text.contains("Candidate changes:"), "{text}");
    assert!(text.contains("requirements: not checked"), "{text}");
    assert!(
        text.contains("limit: manifest and lockfile disagree"),
        "{text}"
    );
    assert!(!text.contains("Suggested fix:"), "{text}");
    assert!(!text.contains("manifest_lock_disagreement"), "{text}");
}
