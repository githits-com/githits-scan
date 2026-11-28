//! New evidence travels with the same completed audit through every output path.
use super::audit_remediation::{execute_report, human_report, json_report};
use super::*;
use serde_json::{Value, json};

fn input() -> Value {
    let mut value = fixture();
    value["remediation"] =
        serde_json::from_slice(include_bytes!("../fixtures/audit/remediation.json"))
            .expect("remediation");
    let r = &mut value["remediation"]["recommendations"][0];
    r["search_detail_status"] = "retained".into();
    r["search_details"] = json!([{
        "kind":"unavailable","operation":"release","reasons":["lookup_failed"],
        "witness":{"coordinate":{"registry":"npm","name":"example-parent","version":"3.0.0"},"acquisition":"lookup_failed","private_unused_id":"omit"}
    }]);
    value["remediation"]["limits"]["omitted_search_details"] = 1.into();
    value
}
fn json_output(output: &Output) -> Value {
    assert_eq!(output.status.code(), Some(1), "{}", stderr(output));
    serde_json::from_slice(&output.stdout).expect("document")
}
#[test]
fn audit_search_binary_one_result_preserves_evidence_through_archive_and_outputs() {
    let root = repo();
    let archive = root.path().join("analysis.json");
    let mock = server(&serde_json::to_vec(&input()).expect("report"));
    let online = run(
        root.path(),
        Some(&mock.origin()),
        &[
            "--presentation-json",
            "--save-analysis",
            archive.to_str().expect("path"),
        ],
    );
    let online = json_output(&online);
    let replay = json_output(&offline(&archive, &["--presentation-json"]));
    let facts = json_output(&offline(&archive, &["--json"]));
    assert_eq!(online["remediation"], replay["remediation"]);
    assert_eq!(replay["audit"], facts);
    let record = &facts["remediation"]["recommendations"][0];
    assert_eq!(record["search_detail_status"], "retained");
    assert_eq!(
        record["search_details"][0]["witness"]["coordinate"]["name"],
        "example-parent"
    );
    assert_eq!(facts["remediation"]["limits"]["omitted_search_details"], 1);
    let explanation = &replay["remediation"]["recommendations"][0]["search_explanations"][0];
    assert_eq!(explanation["search_detail_index"], 0);
    let summary = explanation["summary"].as_str().expect("summary");
    for flags in [
        vec!["--details", "--no-color"],
        vec!["--explain", "npm:demo@1.0.0", "--no-color"],
    ] {
        let output = offline(&archive, &flags);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(
            prose(&stdout(&output)).contains(&prose(summary)),
            "{}",
            stdout(&output)
        );
        assert_eq!(
            stdout(&output).matches("\n    Upgrade search:\n").count(),
            1
        );
        assert!(stdout(&output).contains("\n      Release metadata for "));
        assert!(!stdout(&output).contains("lookup_failed"));
    }
    let stored = fs::read_to_string(&archive).expect("saved analysis");
    assert!(stored.contains("search_details") && stored.contains("lookup_failed"));
    assert!(!stored.contains("private_unused_id"));
    assert_eq!(
        mock.requests().len(),
        3,
        "offline paths do not submit another job"
    );
}

fn unbound_input() -> Value {
    let mut value = input();
    let record = &mut value["remediation"]["recommendations"][0];
    record["checks"]["requirements"] = "unchecked".into();
    record["changes"][0]["strategy"] = "unknown".into();
    record["limitations"] = json!(["unbound_request", "parent_evidence_incomplete"]);
    record["search_details"] = json!([{
        "kind": "unavailable",
        "operation": "source",
        "reasons": ["unbound_request"],
        "witness": {
            "coordinate": record["subject"].clone(),
            "observation": {
                "name": "demo",
                "path": "package-lock.json",
                "status": "unbound_request",
                "requested_requirement": "^1.0",
                "requirement_status": "recorded"
            }
        }
    }]);
    value
}

#[test]
fn audit_search_links_no_copy_to_the_recorded_requirement_in_both_text_modes() {
    let value = unbound_input();
    let compact = execute_report(&value, &["--quiet", "--no-color"]);
    assert_eq!(compact.status.code(), Some(1), "{}", stderr(&compact));
    let compact = prose(&stdout(&compact));
    assert!(compact.contains("A declaration in package-lock.json requires demo ^1.0. The report could not link it to a locked copy."), "{compact}");
    assert_eq!(compact.matches("to a locked copy").count(), 1, "{compact}");
    assert!(
        !compact.contains("Upgrade search") && !compact.contains("unbound_request"),
        "{compact}"
    );
    let detailed = human_report(&value);
    assert!(
        detailed.contains("Upgrade search:")
            && detailed.contains("demo requires ^1.0 [package-lock.json]"),
        "{detailed}"
    );
    assert!(
        !detailed.contains("unbound_request") && !detailed.contains("unfamiliar reason"),
        "{detailed}"
    );
    let facts = json_report(&value);
    assert_eq!(
        facts["remediation"]["recommendations"][0]["search_details"][0]["reasons"],
        json!(["unbound_request"])
    );
}

#[test]
fn audit_search_default_combines_metadata_with_the_declaration_and_keeps_a_distinct_cap() {
    let mut value = unbound_input();
    value["remediation"]["recommendations"][0]["checks"]["parent_search"] = "limited".into();
    for cap in [false, true] {
        if cap {
            let record = &mut value["remediation"]["recommendations"][0];
            record["limitations"]
                .as_array_mut()
                .expect("limitations")
                .push("parent_candidate_limit".into());
            let coordinate = record["subject"].clone();
            record["search_details"]
                .as_array_mut()
                .expect("search details")
                .push(json!({
                    "kind": "stopped",
                    "stage": "domain_sampling",
                    "reason": "parent_candidate_limit",
                    "witness": {"coordinate": coordinate, "budget_scope": "local"}
                }));
        }
        let output = execute_report(&value, &["--quiet", "--no-color"]);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        let report = prose(&stdout(&output));
        assert!(
            report.contains("Missing dependency information limited the upgrade search, including a declaration in package-lock.json that requires demo ^1.0 and could not be linked to a locked copy."),
            "{report}"
        );
        assert_eq!(
            report.matches("linked to a locked copy").count(),
            1,
            "{report}"
        );
        assert!(!report.contains("metadata needed to check"), "{report}");
        assert!(!report.contains("could not finish checking"), "{report}");
        assert_eq!(
            report.contains("reached its limit for checking upgrades"),
            cap,
            "{report}"
        );
    }
}

#[test]
fn audit_search_default_keeps_the_generic_metadata_limit_without_a_concrete_declaration() {
    let mut value = unbound_input();
    let record = &mut value["remediation"]["recommendations"][0];
    record["checks"]["parent_search"] = "limited".into();
    record["search_detail_status"] = "not_retained".into();
    record["search_details"] = json!([]);
    record["limitations"] = json!([
        "unbound_request",
        "parent_evidence_incomplete",
        "parent_candidate_limit"
    ]);
    let other = record.clone();
    value["remediation"]["recommendations"]
        .as_array_mut()
        .expect("recommendations")
        .push(other);
    let output = execute_report(&value, &["--quiet", "--no-color"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let report = prose(&stdout(&output));
    assert_eq!(report.matches("Metadata needed to check upgrades of packages that depend on this dependency was unavailable").count(), 1, "{report}");
    assert_eq!(
        report
            .matches("reached its limit for checking upgrades")
            .count(),
        1,
        "{report}"
    );
    assert!(!report.contains("including a declaration"), "{report}");
}

#[test]
fn audit_search_binary_explains_unchecked_new_dependency() {
    let root = repo();
    let archive = root.path().join("analysis.json");
    let mut saved: Value =
        serde_json::from_slice(include_bytes!("../fixtures/audit/analysis.json")).expect("archive");
    let record = &mut saved["producer_report"]["remediation"]["recommendations"][0];
    record["search_detail_status"] = "retained".into();
    let detail = json!({
        "kind": "unavailable",
        "operation": "boundary",
        "reasons": ["new_dependency_not_checked"],
        "witness": {}
    });
    record["search_details"] = json!([detail]);
    fs::write(&archive, serde_json::to_vec(&saved).expect("JSON")).expect("archive");

    let summary = "Dependency relationship: a new dependency was not checked.";
    let output = offline(&archive, &["--explain", "npm:demo@1.0.0", "--no-color"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(prose(&text).contains(summary), "{text}");
    assert!(!text.contains("new_dependency_not_checked"), "{text}");

    let view = json_output(&offline(&archive, &["--presentation-json"]));
    assert_eq!(
        view["remediation"]["recommendations"][0]["search_explanations"][0]["summary"],
        summary
    );
    assert_eq!(
        view["audit"]["remediation"]["recommendations"][0]["search_details"][0],
        detail
    );
}
#[test]
fn audit_search_binary_malformed_evidence_preserves_existing_output() {
    let root = repo();
    let path = root.path().join("keep.json");
    fs::write(&path, "keep existing output").expect("output");
    let mut value = input();
    value["remediation"]["recommendations"][0]["search_details"][0]["reasons"] = json!([]);
    let mock = server(&serde_json::to_vec(&value).expect("report"));
    let output = run(
        root.path(),
        Some(&mock.origin()),
        &[
            "--presentation-json",
            "--output",
            path.to_str().expect("path"),
        ],
    );
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(
        fs::read_to_string(&path).expect("output"),
        "keep existing output"
    );
    assert_eq!(mock.requests().len(), 3);
    let archive = root.path().join("invalid-analysis.json");
    let mut saved: Value =
        serde_json::from_slice(include_bytes!("../fixtures/audit/analysis.json")).expect("archive");
    saved["producer_report"]["remediation"]["recommendations"][0]["search_detail_status"] =
        "retained".into();
    fs::write(&archive, serde_json::to_vec(&saved).expect("bytes")).expect("archive");
    let output = offline(
        &archive,
        &[
            "--presentation-json",
            "--output",
            path.to_str().expect("path"),
        ],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(
        fs::read_to_string(path).expect("output"),
        "keep existing output"
    );
}
