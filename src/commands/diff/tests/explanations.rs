//! Authored presentation projections, not captured production reports.
use super::*;

fn cause(message: &str, declaration: Option<&str>) -> serde_json::Value {
    let mut row = json!({"code":"producer_cause","message":message,
        "source_key":"package-lock.json","manifest_path":"package.json",
        "dependency_name":"helper","coverage_state":"incomplete",
        "coverage_reasons":["untargeted_requirement"]});
    if let Some(id) = declaration {
        row["declaration_id"] = id.into();
    }
    row
}

fn explained() -> serde_json::Value {
    let mut v = fixture::report();
    v["changes"][0]["directness"]["base"] = "unknown".into();
    v["changes"][0]["before_ids"] = json!(["shared-occurrence"]);
    v["snapshots"]["base"]["occurrences"] = json!([{"id":"shared-occurrence",
        "directness":"unknown","directness_reasons":[cause("A dependency entry could not be matched.", None)],
        "directness_proof_ids":["shared-proof"]}]);
    v["snapshots"]["base"]["reachability"] = json!([
        {"id":"shared-proof","reasons":[cause("The dependency declaration could not be matched.", Some("base:d1"))]},
        {"id":"unrelated-proof","reasons":[cause("UNRELATED ENTRY.", None)]}
    ]);
    v["snapshots"]["head"]["occurrences"] = json!([{"id":"shared-occurrence",
        "directness":"unknown","directness_proof_ids":["shared-proof"]}]);
    v["snapshots"]["head"]["reachability"] = json!([{"id":"shared-proof",
        "reasons":[cause("LATER REVISION ONLY.", Some("head:d1"))]}]);
    v
}

#[test]
fn diff_explanations_follow_same_side_proofs() {
    let v = explained();
    let text = rendered(&v, Format::Human);
    assert!(
        text.contains("The dependency declaration could not be matched."),
        "{text}"
    );
    assert!(text.contains("A dependency entry could not be matched."));
    assert!(text.contains("helper in package.json"));
    assert!(text.contains("package.json"));
    assert!(!text.contains("untargeted_requirement"));
    assert!(!text.contains("LATER REVISION ONLY"));
    assert!(!text.contains("UNRELATED"));
    let mut v = v;
    v["changes"][0]["directness"]["head"] = "unknown".into();
    v["changes"][0]["after_ids"] = json!(["shared-occurrence"]);
    let text = rendered(&v, Format::Human);
    assert!(text.contains("LATER REVISION ONLY."));
    let later = text
        .find("in the later revision")
        .expect("later explanation");
    assert!(!text[..later].contains("LATER REVISION ONLY"));
}

#[test]
fn diff_explanations_keep_local_and_shared_causes() {
    let mut v = explained();
    let mut second = v["snapshots"]["base"]["occurrences"][0].clone();
    second["id"] = "second".into();
    second["directness_reasons"] = json!([cause("A second local cause.", None)]);
    v["snapshots"]["base"]["occurrences"]
        .as_array_mut()
        .expect("occurrences")
        .extend([second, json!({"id":"known","directness":"transitive"})]);
    v["changes"][0]["before_ids"] = json!(["shared-occurrence", "second", "known"]);
    let text = rendered(&v, Format::Human);
    assert_eq!(
        text.matches("The dependency declaration could not be matched.")
            .count(),
        1
    );
    assert!(text.contains("A second local cause."));
    assert!(!text.contains("The service did not return its explanation"));
    v["snapshots"]["base"]["occurrences"]
        .as_array_mut()
        .expect("occurrences")
        .push(json!({"id":"legacy","directness":"unknown"}));
    v["changes"][0]["before_ids"]
        .as_array_mut()
        .expect("IDs")
        .push("legacy".into());
    let text = rendered(&v, Format::Human);
    assert_eq!(
        text.matches("The service did not return its explanation")
            .count(),
        1
    );
    let mut change = v["changes"][0].clone();
    change["id"] = "change:2".into();
    change["package"]["name"] = "second-package".into();
    change["before_ids"] = json!(["second"]);
    v["changes"].as_array_mut().expect("changes").push(change);
    let text = rendered(&v, Format::Human);
    assert_eq!(
        text.matches("The dependency declaration could not be matched.")
            .count(),
        1
    );
    assert!(text.contains("minimist, second-package are used directly"));
}

#[test]
fn diff_explanations_keep_distinct_root_owners() {
    let mut v = explained();
    let mut other = cause(
        "The dependency declaration could not be matched.",
        Some("base:d2"),
    );
    other["manifest_path"] = "tools/package.json".into();
    v["snapshots"]["base"]["reachability"]
        .as_array_mut()
        .expect("proofs")
        .push(json!({"id":"other-owner","reasons":[other]}));
    v["snapshots"]["base"]["occurrences"][0]["directness_proof_ids"]
        .as_array_mut()
        .expect("IDs")
        .push("other-owner".into());
    v["snapshots"]["base"]["declarations"].as_array_mut().expect("declarations")
        .push(json!({"id":"base:d2","declared_name":"helper","declaring_manifest":"tools/package.json"}));
    let text = rendered(&v, Format::Human);
    assert_eq!(
        text.matches("The dependency declaration could not be matched.")
            .count(),
        2
    );
    assert!(text.contains("helper in tools/package.json"));
}

#[test]
fn diff_explanations_distinguish_known_absent_and_legacy() {
    for kind in ["added", "removed"] {
        let mut v = explained();
        v["changes"][0]["kind"] = kind.into();
        v["changes"][0]["directness"] = if kind == "added" {
            json!({"base":"unknown","head":"transitive"})
        } else {
            json!({"base":"transitive","head":"unknown"})
        };
        let text = rendered(&v, Format::Human);
        assert!(!text.contains("Scan could not tell whether"), "{text}");
    }
    for ids in [json!([]), json!(["declaration-only"]), json!(["known"])] {
        let mut v = explained();
        v["snapshots"]["base"]["occurrences"] = json!([{"id":"known","directness":"transitive"}]);
        v["changes"][0]["before_ids"] = ids;
        let text = rendered(&v, Format::Human);
        assert!(
            text.contains("The service did not return its explanation"),
            "{text}"
        );
        assert!(!text.contains("malformed"));
    }
    let mut v = explained();
    v["snapshots"]["base"]["reachability"] = json!([]);
    let text = rendered(&v, Format::Human);
    assert!(text.contains("Part of the service's explanation was missing"));
    v["changes"][0]["directness"]["base"] = "future_type".into();
    let text = rendered(&v, Format::Human);
    assert!(!text.contains("future_type"));
    assert!(text.contains("classification that this version of Scan cannot explain"));
    assert!(text.contains("Scan could not tell whether"));
}

#[test]
fn diff_explanations_show_binding_causes_without_occurrence_changes() {
    let mut v = explained();
    v["changes"] = json!([]);
    v["snapshots"]["base"]["bindings"] = json!([
        {"declaration_id":"base:d1","source_key":"package-lock.json",
         "reasons":[cause("The declared dependency could not be matched to a package entry.", Some("base:d1"))]},
        {"declaration_id":"base:d1","source_key":"other.lock",
         "reasons":[cause("WRONG SOURCE binding.", None)]},
        {"declaration_id":"unrelated","source_key":"package-lock.json",
         "reasons":[cause("WRONG DECLARATION binding.", None)]}
    ]);
    let text = rendered(&v, Format::Human);
    assert!(
        text.contains("In the earlier revision: The declared dependency could not be matched to a package entry."),
        "{text}"
    );
    assert!(!text.contains("WRONG SOURCE"));
    assert!(!text.contains("WRONG DECLARATION"));
    assert!(text.contains("helper in package.json"));
    // Open status vocabulary must not suppress an explicitly joined cause.
    v["declaration_changes"][0]["binding_transitions"][0]["review_eligibility"] =
        json!({"status":"future_eligibility"});
    assert!(rendered(&v, Format::Human).contains("In the earlier revision:"));
}

#[test]
fn diff_explanations_use_same_side_declaration_labels() {
    let mut v = fixture::report();
    v["declaration_changes"][0]["after_id"] = "shared-declaration".into();
    v["snapshots"]["head"]["declarations"][0] = json!({"id":"shared-declaration",
        "declared_name":"correct-head","declaring_manifest":"head/package.json"});
    v["snapshots"]["base"]["declarations"].as_array_mut().expect("declarations").insert(0,
        json!({"id":"shared-declaration","declared_name":"WRONG-BASE","declaring_manifest":"wrong/package.json"}));
    v["direct_reviews"]["status"] = "partial".into();
    v["direct_reviews"]["data"][0]["status"] = "unavailable".into();
    let text = rendered(&v, Format::Human);
    assert!(
        text.contains("Changed correct-head in head/package.json"),
        "{text}"
    );
    assert!(text.contains("Declared as correct-head in head/package.json"));
    assert!(!text.contains("WRONG-BASE"));
}

#[test]
fn diff_explanations_preserve_review_failure_scope() {
    for (scope, label) in [
        ("batch", "preparing the combined report failed"),
        ("review", "upgrade review failed in the service"),
        (
            "future_scope",
            "did not identify whether this package's review",
        ),
    ] {
        let mut v = fixture::report();
        v["changes"] = json!([]);
        v["direct_reviews"]["status"] = "partial".into();
        let row = &mut v["direct_reviews"]["data"][0];
        row["status"] = "unavailable".into();
        row["reason"] = "review_failed".into();
        row["failure"] = json!({"scope":scope,"code":"future_error","message":"The producer could not collect review evidence."});
        let text = rendered(&v, Format::Human);
        assert!(text.contains(label), "{text}");
        assert!(text.contains("The producer could not collect review evidence."));
        assert!(!text.contains("future_error"));
        assert!(!text.contains("review_failed"));
        assert!(text.contains("Declared as helper in package.json"));
        assert!(!text.contains("Review detail not interpreted"));
        v["direct_reviews"]["data"][0]["status"] = "partial".into();
        let text = rendered(&v, Format::Human);
        assert!(text.contains(label));
        assert!(text.contains("The earlier version is affected by security advisories"));
        assert!(text.contains("Illustrative migration note"));
        if scope == "batch" {
            assert!(text.contains("its complete result could not be returned"));
            assert!(!text.contains("its result was not returned"));
        }
        assert!(!text.contains("Review detail not interpreted"));
    }
}

#[test]
fn diff_explanations_keep_unstarted_omitted_and_legacy_failures_distinct() {
    for (status, reason, explanation) in [
        (
            "not_assessed",
            "deadline",
            "The upgrade review was not completed before the comparison's time limit.",
        ),
        (
            "omitted",
            "result_size_limit",
            "The upgrade was assessed, but its review could not fit within the report's size limit.",
        ),
        (
            "unavailable",
            "review_failed",
            "The upgrade review could not be returned. The service did not supply a failure explanation.",
        ),
        (
            "not_assessed",
            "evidence_unavailable",
            "The information required to review this upgrade was unavailable.",
        ),
    ] {
        let mut v = fixture::report();
        v["direct_reviews"]["status"] = "partial".into();
        v["direct_reviews"]["data"][0]["status"] = status.into();
        v["direct_reviews"]["data"][0]["reason"] = reason.into();
        v["direct_reviews"]["data"][0]
            .as_object_mut()
            .expect("review")
            .remove("data");
        let text = rendered(&v, Format::Human);
        assert!(!text.contains(reason), "{text}");
        assert!(text.contains(explanation), "{text}");
        assert!(!text.contains("Review detail not interpreted"));
    }
}

#[test]
fn diff_explanations_cover_reachability_proof_causes() {
    let mut v = explained();
    v["changes"] = json!([]);
    let summary = json!({"complete":false,"manifest_path":"package.json",
        "source_key":"package-lock.json","basis":"declaration_and_root_graph",
        "reachability_id":"shared-proof"});
    v["snapshots"]["base"]["coverage"]["reachability"] = json!([summary]);
    v["coverage"]["reachability"] = json!([summary]);
    let text = rendered(&v, Format::Human);
    assert_eq!(
        text.matches("The dependency declaration could not be matched.")
            .count(),
        1,
        "{text}"
    );
    assert!(
        text.contains("In the earlier revision: The dependency declaration could not be matched.")
    );
    assert!(!text.contains("Report reachability:"));
    assert!(!text.contains("LATER REVISION ONLY"));
    v["snapshots"]["base"]["coverage"]["reachability"][0]
        .as_object_mut()
        .expect("summary")
        .remove("reachability_id");
    let text = rendered(&v, Format::Human);
    assert!(text.contains("the service did not explain why it could not connect"));
    assert!(!text.contains("The dependency declaration could not be matched."));
}
