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
    assert!(text.contains("would address the listed advisory"), "{text}");
    assert_eq!(text.matches("override not verified:").count(), 1, "{text}");
    assert!(
        text.contains("package-manager support and build not checked"),
        "{text}"
    );
    assert!(
        text.contains("Dependency requirements conflict with this candidate."),
        "{text}"
    );
    assert!(!text.contains("Suggested fix"), "{text}");
    value["remediation"]["recommendations"][0]["checks"]["native_resolution"] =
        "future_check".into();
    let text = human_report(&value);
    assert!(
        !text.contains("package-manager support and build not checked"),
        "{text}"
    );
    assert!(
        text.contains("native resolution: the service returned an unfamiliar check result"),
        "{text}"
    );
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
            "\n\n    No upgrade path found among releases known to the service, under the dependency requirements\n      considered.\n"
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
fn audit_ux_candidate_compresses_only_the_complete_displayed_advisory_set() {
    let mut value = remediation_report();
    let mut second = value["findings"]["vulnerabilities"][0].clone();
    second["advisory_id"] = "GHSA-second".into();
    value["findings"]["vulnerabilities"]
        .as_array_mut()
        .expect("findings")
        .push(second);
    value["summary"]["vulnerabilities"] = 2.into();
    let record = &mut value["remediation"]["recommendations"][0];
    record["finding_refs"] = json!([0, 1]);
    record["addressed_finding_refs"] = json!([0, 1]);
    record["checks"]["requirements"] = "blocked".into();
    record["blockers"] = json!([named_constraint()]);
    let text = human_report(&value);
    assert!(
        text.contains("would address all listed advisories"),
        "{text}"
    );
    assert!(
        text.contains("GHSA-demo") && text.contains("GHSA-second"),
        "{text}"
    );
    assert!(
        text.contains("Dependency requirements conflict with this candidate.")
            && text.contains("Candidate changes"),
        "{text}"
    );
    assert!(
        !text.contains("Suggested fix") && !text.contains("would address: GHSA"),
        "{text}"
    );
    value["remediation"]["recommendations"][0]["addressed_finding_refs"] = json!([0]);
    value["remediation"]["recommendations"][0]["remaining_finding_refs"] = json!([1]);
    value["remediation"]["recommendations"][0]["outcome"] = "partial".into();
    let partial = human_report(&value);
    assert!(
        partial.contains("would address: GHSA-demo")
            && partial.contains("still unresolved: GHSA-second"),
        "{partial}"
    );
    assert!(
        !partial.contains("would address all listed advisories"),
        "{partial}"
    );
}

#[test]
fn audit_ux_shared_search_limits_preserve_the_requiring_package_scope() {
    for (cause, detail) in [
        ("parent_candidate_limit", "service limit"),
        ("assignment_limit", "combinations"),
        ("parent_evidence_incomplete", "information"),
        ("parent_exact_lookup_limit", "metadata checks"),
    ] {
        let mut value = remediation_report();
        value["remediation"]["status"] = "limited".into();
        value["remediation"]["limits"]["reasons"] = json!([cause]);
        let text = human_report(&value);
        let shared = prose(text.split_once("planning limit:").expect("shared limit").1);
        assert!(
            shared.contains("packages requiring vulnerable dependencies"),
            "{cause}: {shared}"
        );
        assert!(
            shared.contains(detail) && !shared.contains(cause),
            "{cause}: {shared}"
        );
    }
}
