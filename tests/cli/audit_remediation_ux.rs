//! Truthful human action guidance using existing service facts.
use super::*;

fn graph_report() -> Value {
    serde_json::from_slice(include_bytes!("../fixtures/audit/graph.json")).expect("graph fixture")
}

fn named_constraint() -> Value {
    serde_json::from_slice(include_bytes!("../fixtures/audit/blocker.json"))
        .expect("blocker fixture")
}

#[test]
fn audit_ux_advisory_hints_are_not_presented_as_recommendations() {
    for remediated in [false, true] {
        let mut value = remediation_report();
        if !remediated {
            value.as_object_mut().expect("report").remove("remediation");
        }
        let text = human_report(&value);
        assert!(
            text.contains("advisory-reported fix versions: 1.1.0"),
            "{text}"
        );
        assert!(!text.contains("proposed fixes:"), "{text}");
        assert!(text.contains("verified advisory fixes: 1.1.1"), "{text}");
        let result = json_report(&value);
        assert_eq!(
            result["vulnerabilities"][0]["proposed_fixes"],
            json!(["1.1.0"])
        );
    }
}

#[test]
fn audit_ux_constraint_labels_distinguish_exclusion_from_uncertainty() {
    for (reason, label, explanation) in [
        (
            "third_party_request_excludes_target",
            "requirement conflict:",
            None,
        ),
        (
            "required_request_excludes_target",
            "requirement conflict:",
            None,
        ),
        (
            "project_request_change",
            "constraint:",
            Some("project requirement must change"),
        ),
        (
            "unsupported_selector",
            "constraint:",
            Some("dependency requirement could not be evaluated"),
        ),
        (
            "future_reason\n\u{1b}[2J",
            "constraint:",
            Some("future_reason\\n\\u{1b}[2J"),
        ),
    ] {
        let mut value = remediation_report();
        let mut blocker = named_constraint();
        blocker["reason"] = reason.into();
        value["remediation"]["recommendations"][0]["blockers"] = json!([blocker]);
        let text = human_report(&value);
        assert!(
            text.contains(&format!("{label} express@5.1.0 requires cookie ^0.7.1")),
            "{text}"
        );
        assert_constraint_explanation(&text, explanation);
        assert_eq!(
            json_report(&value)["remediation"]["recommendations"][0]["blockers"][0],
            blocker
        );
    }
}

fn assert_constraint_explanation(text: &str, explanation: Option<&str>) {
    if let Some(expected) = explanation {
        assert!(text.contains(expected), "{text}");
    } else {
        assert!(!text.contains("excludes the target"), "{text}");
    }
    assert!(!text.contains('\u{1b}'));
    assert!(!text.contains("Blocked by"), "{text}");
}

#[test]
fn audit_ux_override_shows_benefit_and_one_truthful_verification_note() {
    let mut value = remediation_report();
    let record = &mut value["remediation"]["recommendations"][0];
    record["changes"][0]["strategy"] = "override".into();
    record["checks"]["requirements"] = "blocked".into();
    record["blockers"] = json!([named_constraint()]);
    let mut second = record["changes"][0].clone();
    second["name"] = "other".into();
    record["changes"]
        .as_array_mut()
        .expect("changes")
        .push(second);
    let text = human_report(&value);
    assert!(text.contains("would address: GHSA-demo"), "{text}");
    assert_eq!(text.matches("override not verified:").count(), 1, "{text}");
    assert!(
        text.contains("package-manager support and build not checked"),
        "{text}"
    );
    assert!(text.contains("requirement conflict:"), "{text}");
    assert!(!text.contains("Suggested fix"), "{text}");
    value["remediation"]["recommendations"][0]["checks"]["native_resolution"] =
        "future_check".into();
    let text = human_report(&value);
    assert!(
        !text.contains("package-manager support and build not checked"),
        "{text}"
    );
    assert!(text.contains("native resolution: future_check"), "{text}");
}

#[test]
fn audit_ux_partial_results_preserve_overlap_and_missing_impact() {
    for addressed in [json!([0]), json!([])] {
        let mut value = remediation_report();
        let record = &mut value["remediation"]["recommendations"][0];
        record["outcome"] = "partial".into();
        record["addressed_finding_refs"] = addressed.clone();
        record["remaining_finding_refs"] = json!([0]);
        let text = human_report(&value);
        if addressed == json!([0]) {
            assert!(text.contains("would address: GHSA-demo (partly)"), "{text}");
            assert!(
                text.contains("still unresolved: GHSA-demo (partly)"),
                "{text}"
            );
        } else {
            assert!(text.contains("would address: none reported"), "{text}");
            assert!(text.contains("still unresolved: GHSA-demo"), "{text}");
            assert!(!text.contains("(partly)"), "{text}");
        }
        assert!(!text.contains("some copies"), "{text}");
        assert_eq!(
            json_report(&value)["remediation"]["recommendations"][0]["remaining_findings"][0]["advisory"],
            "GHSA-demo"
        );
    }
}

#[test]
fn audit_ux_negative_conclusion_is_separated_and_keeps_its_scope() {
    let mut value = remediation_report();
    let r = &mut value["remediation"]["recommendations"][0];
    r["outcome"] = "no_upgrade_path".into();
    r["changes"] = json!([]);
    r["addressed_finding_refs"] = json!([]);
    r["remaining_finding_refs"] = json!([0]);
    r["search_domain"] = json!({"constraint_scope":"represented_requests","release_scope":"observed_catalog_upgrades","packages":[]});
    let text = human_report(&value);
    assert!(
        text.contains(
            "\n\n    No upgrade path found within observed releases and represented requests.\n"
        ),
        "{text}"
    );
    assert!(text.contains("still unresolved: GHSA-demo"), "{text}");
    assert!(!text.contains("would address:"), "{text}");
    assert_eq!(
        json_report(&value)["remediation"]["recommendations"][0]["outcome"],
        "no_upgrade_path"
    );
}

#[test]
fn audit_ux_joint_request_context_is_shared_by_online_and_saved_explanation() {
    let value = graph_report();
    let root = repo();
    let archive = root.path().join("analysis.json");
    let mock = server(&serde_json::to_vec(&value).expect("report"));
    let output = run(
        root.path(),
        Some(&mock.origin()),
        &[
            "--quiet",
            "--save-analysis",
            archive.to_str().expect("path"),
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let expected =
        "recorded request for npm:demo@1.0.0: <1.1.0; owner parent@2.0.0 [package-lock.json]";
    assert_eq!(
        stdout(&output).matches(expected).count(),
        1,
        "{}",
        stdout(&output)
    );
    let replay = offline(&archive, &["--explain", "npm:demo@1.0.0", "--no-color"]);
    assert_eq!(replay.status.code(), Some(1), "{}", stderr(&replay));
    assert_eq!(
        stdout(&replay).matches(expected).count(),
        1,
        "{}",
        stdout(&replay)
    );
    assert_eq!(mock.requests().len(), 3);
    let compact = json_report(&value);
    assert!(
        compact["remediation"]["recommendations"][0]
            .get("recorded_requests")
            .is_none()
    );
    let saved: Value = serde_json::from_slice(&fs::read(&archive).expect("archive")).expect("JSON");
    assert!(
        saved["producer_report"]["remediation"]["recommendations"][0]
            .get("recorded_requests")
            .is_none()
    );
}

#[test]
fn audit_ux_joint_request_preserves_distinct_owner_and_escapes_evidence() {
    let mut value = graph_report();
    let request = &mut value["remediation"]["trace"]["relations"][1]["requests"][0];
    request["owner"]["name"] = "another\n\u{1b}[2J".into();
    request["requested_requirement"] = "<1.1\n".into();
    request["path"] = "manifest\n.json".into();
    let text = human_report(&value);
    assert!(text.contains("recorded request for npm:demo@1.0.0: <1.1\\n; owner another\\n\\u{1b}[2J@2.0.0 [manifest\\n.json]"), "{text}");
    assert!(!text.contains('\u{1b}'));
    assert!(!text.contains("another ->"), "{text}");
}

#[test]
fn audit_ux_joint_context_omits_unproven_or_unavailable_requests() {
    for (path, invalid) in [
        ("/remediation/trace/status", json!("not_retained")),
        (
            "/remediation/recommendations/0/detail_status",
            json!("future_detail"),
        ),
        (
            "/remediation/recommendations/0/changes/1/occurrence_refs",
            json!([]),
        ),
        (
            "/remediation/recommendations/0/changes/0/from_version",
            json!("different"),
        ),
        (
            "/remediation/trace/relations/1/path",
            json!("other/package-lock.json"),
        ),
        ("/remediation/trace/relations/1/from_ref", json!(99)),
        ("/remediation/trace/relations/1/to_ref", Value::Null),
        (
            "/remediation/trace/relations/1/disposition",
            json!("unverified_target"),
        ),
        (
            "/remediation/trace/relations/1/requests/0/requirement_status",
            json!("provider_requirement"),
        ),
        (
            "/remediation/trace/relations/1/requests/0/requested_requirement",
            Value::Null,
        ),
        ("/remediation/trace/occurrences/0/coordinate", Value::Null),
    ] {
        let mut value = graph_report();
        *value.pointer_mut(path).expect("fixture field") = invalid;
        let text = human_report(&value);
        assert!(!text.contains("recorded request for"), "{path}: {text}");
        assert!(text.contains("Upgrade npm:"), "{path}: {text}");
    }
}

#[test]
fn audit_ux_joint_context_deduplicates_facts_without_joining_package_names() {
    let mut value = graph_report();
    let relation = value["remediation"]["trace"]["relations"][1].clone();
    value["remediation"]["trace"]["relations"]
        .as_array_mut()
        .expect("relations")
        .push(relation);
    let text = human_report(&value);
    assert_eq!(
        text.matches("recorded request for npm:demo@1.0.0:").count(),
        1,
        "{text}"
    );
    let mut distinct = value["remediation"]["trace"]["relations"][1].clone();
    distinct["requests"][0]["path"] = "other/package.json".into();
    value["remediation"]["trace"]["relations"]
        .as_array_mut()
        .expect("relations")
        .push(distinct);
    let text = human_report(&value);
    assert_eq!(
        text.matches("recorded request for npm:demo@1.0.0:").count(),
        2,
        "{text}"
    );
    assert!(text.contains("[other/package.json]"), "{text}");
    let node = value["remediation"]["trace"]["occurrences"][0].clone();
    value["remediation"]["trace"]["occurrences"]
        .as_array_mut()
        .expect("nodes")
        .push(node);
    value["remediation"]["recommendations"][0]["changes"][0]["occurrence_refs"] = json!([3]);
    let text = human_report(&value);
    assert!(!text.contains("recorded request for"), "{text}");
}

#[test]
fn audit_ux_mixed_impact_marks_only_the_overlapping_advisory() {
    let mut value = remediation_report();
    let mut second = value["findings"]["vulnerabilities"][0].clone();
    second["advisory_id"] = "GHSA-second".into();
    value["findings"]["vulnerabilities"]
        .as_array_mut()
        .expect("findings")
        .push(second);
    value["summary"]["vulnerabilities"] = 2.into();
    let record = &mut value["remediation"]["recommendations"][0];
    record["outcome"] = "partial".into();
    record["finding_refs"] = json!([0, 1]);
    record["addressed_finding_refs"] = json!([0, 1]);
    record["remaining_finding_refs"] = json!([0]);
    let text = human_report(&value);
    assert!(
        text.contains("would address: GHSA-demo (partly), GHSA-second"),
        "{text}"
    );
    assert!(
        text.contains("still unresolved: GHSA-demo (partly)"),
        "{text}"
    );
    assert!(!text.contains("GHSA-second (partly)"), "{text}");
}
