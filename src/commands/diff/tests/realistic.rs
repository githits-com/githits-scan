//! Small authored regressions for defects found in genuine full-report verification.
use super::*;

fn assessment(status: &str) -> serde_json::Value {
    json!({"status":status,"reasons":if status == "unknown" {vec!["source_scope_incomplete"]} else {vec![]}})
}
fn delta(id: &str, kind: &str, base: &str, head: &str) -> serde_json::Value {
    json!({"finding_id":id,"kind":kind,"base":assessment(base),"head":assessment(head)})
}
fn finding(id: &str) -> serde_json::Value {
    json!({"id":id,"osv_id":id,"package":{"registry":"npm","name":"fixture-package"},"summary":"An authored security finding"})
}
fn uncertain_project() -> serde_json::Value {
    let mut v = fixture::report();
    v["outcome"] = "partial".into();
    v["advisories"]["status"] = "partial".into();
    let data = &mut v["advisories"]["data"];
    data["exposures"][1]["deltas"] =
        json!([delta("finding:1", "indeterminate", "affected", "unknown")]);
    for index in 0..50 {
        let id = format!("WHOLLY-UNCONFIRMED-{index}");
        data["findings"]
            .as_array_mut()
            .expect("findings")
            .push(finding(&id));
        data["exposures"][1]["deltas"]
            .as_array_mut()
            .expect("deltas")
            .push(delta(&id, "indeterminate", "unknown", "unknown"));
    }
    for (id, kind, base, head) in [
        ("EXAMPLE-PAST", "indeterminate", "affected", "unknown"),
        ("EXAMPLE-NOW", "indeterminate", "unknown", "affected"),
        ("EXAMPLE-REMAINS", "unchanged", "affected", "affected"),
    ] {
        data["findings"]
            .as_array_mut()
            .expect("findings")
            .push(finding(id));
        data["exposures"][1]["deltas"]
            .as_array_mut()
            .expect("deltas")
            .push(delta(id, kind, base, head));
    }
    v
}

#[test]
fn diff_repeated_project_uncertainty_is_grouped_without_hiding_positive_facts() {
    let v = uncertain_project();
    let text = rendered(&v, Format::Human);
    for id in [
        "EXAMPLE-1",
        "EXAMPLE-PAST",
        "EXAMPLE-NOW",
        "EXAMPLE-REMAINS",
    ] {
        assert!(text.contains(id), "{id}: {text}");
    }
    assert_eq!(
        text.matches("EXAMPLE-1").count(),
        1,
        "local fix must carry its project qualification: {text}"
    );
    assert!(text.contains("no longer affected"));
    assert!(text.contains("could not confirm"));
    assert!(text.contains("package information"));
    assert!(
        !text.contains("WHOLLY-UNCONFIRMED-"),
        "not a list of unestablished vulnerabilities"
    );
    assert!(!text.contains("service supplied no explanation"));
    assert!(
        text.lines().count() < 80,
        "repeated uncertainty grew the report"
    );
    let report = Report::from_bytes(serde_json::to_vec(&v).expect("json")).expect("report");
    assert!(String::from_utf8_lossy(report.bytes()).contains("WHOLLY-UNCONFIRMED-49"));
}

#[test]
fn diff_identical_missing_files_are_grouped_but_report_scope_stays_separate() {
    let mut v = fixture::report();
    let problem = json!({"path":"bun.lock","required_path":"packages/a/package.json","reason":"required_input_not_supplied"});
    for side in ["base", "head"] {
        v["snapshots"][side]["coverage"]["resolution"] = json!([problem]);
    }
    let text = rendered(&v, Format::Human);
    assert_eq!(text.matches("packages/a/package.json").count(), 1, "{text}");
    assert!(text.contains("both revisions"));
    assert!(text.contains("Files that need attention"));
    assert!(
        text.find("Files that need attention").expect("files")
            > text.find("Upgrade review").expect("review")
    );
    v["coverage"]["resolution"] = json!([problem]);
    let text = rendered(&v, Format::Human);
    assert_eq!(text.matches("packages/a/package.json").count(), 2);
    assert!(text.contains("in this comparison"));
}

#[test]
fn diff_complete_no_change_report_omits_empty_security_sections() {
    let mut v = fixture::report();
    v["changes"] = json!([]);
    v["declaration_changes"] = json!([]);
    v["direct_reviews"]["data"] = json!([]);
    v["notices"] = json!([]);
    v["advisories"]["data"]["coordinate_transitions"] = json!([]);
    for exposure in v["advisories"]["data"]["exposures"]
        .as_array_mut()
        .expect("exposures")
    {
        exposure["deltas"] = json!([delta(
            "finding:1",
            "non_affecting",
            "non_affecting",
            "non_affecting"
        )]);
    }
    let text = rendered(&v, Format::Human);
    assert!(text.contains("No package version changes were reported"));
    assert!(!text.contains("Security advisories"));
    assert!(!text.contains("today's security information"));
    assert!(!text.contains("Upgrade review"));
}

#[test]
fn diff_unexplained_partial_file_information_keeps_its_revision_scope() {
    for (base, head, report, phase) in [
        (true, false, false, "in the earlier revision"),
        (false, true, false, "in the later revision"),
        (true, true, true, "in both revisions"),
        (false, false, true, "in this comparison"),
    ] {
        let mut v = fixture::report();
        v["snapshots"]["base"]["coverage"]["partial"] = base.into();
        v["snapshots"]["head"]["coverage"]["partial"] = head.into();
        v["coverage"]["partial"] = report.into();
        let text = rendered(&v, Format::Human);
        assert!(text.contains(&format!(
            "Some dependency information was unavailable {phase}"
        )));
        assert!(text.contains("the service did not supply specific file details"));
    }
}

#[test]
fn diff_independent_security_coverage_problems_all_remain_visible() {
    for inventory in ["complete", "partial"] {
        let mut v = fixture::report();
        v["advisories"]["data"]["exposures"][0]["coverage"] = json!({"base":{
            "inventory":inventory,"assessment":"partial","checked":1,"coordinates":2,
            "unqualified_occurrences":1}});
        let text = rendered(&v, Format::Human);
        assert!(text.contains("some package entries could not be identified for security checks"));
        assert!(text.contains("could not finish checking every relevant package version"));
        if inventory == "partial" {
            assert!(text.contains("package information was incomplete"));
        }
    }
}

#[test]
fn diff_section_unconfirmed_results_survive_unrelated_inventory_qualification() {
    let mut v = fixture::report();
    v["advisories"]["status"] = "partial".into();
    v["advisories"]["coverage"] = json!({"checked":1,"coordinates":2,"unknown":1});
    v["advisories"]["data"]["exposures"][0]["coverage"] = json!({"base":{
        "inventory":"partial","assessment":"complete","checked":1,"coordinates":1}});
    let text = rendered(&v, Format::Human);
    assert!(text.contains("package information was incomplete"));
    assert!(text.contains("Some advisory results could not be confirmed"));
    assert!(!text.contains("service supplied no explanation"));
}
