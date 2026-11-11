//! Expected Git limits must not become generic manual-review instructions.
use super::*;

fn git_report() -> serde_json::Value {
    let mut v = fixture::report();
    v["outcome"] = "partial".into();
    v["changes"] = json!([]);
    v["declaration_changes"] = json!([]);
    v["coverage"]["partial"] = true.into();
    v["advisories"]["status"] = "partial".into();
    v["advisories"]["coverage"]["reasons"] = json!([
        "git_dependency_graph_unavailable",
        "git_registry_checks_not_supported"
    ]);
    v["advisories"]["data"]["coordinate_transitions"] = json!([]);
    v["direct_reviews"] = json!({"status":"complete", "data":[], "coverage":{"eligible":0,"completed":0,"returned":0,"not_assessed":0,"unavailable":0,"omitted":0}});
    for side in ["base", "head"] {
        v["snapshots"][side]["coverage"]["sources"] =
            json!([{"path":"package-lock.json","reasons":["git_dependency_graph_unavailable"]}]);
        v["snapshots"][side]["coverage"]["excluded_dependencies"] = json!([{"name":"git-demo","version":null,"paths":["package-lock.json"],"reason":"git_registry_checks_not_supported"}]);
        for exposure in v["advisories"]["data"]["exposures"]
            .as_array_mut()
            .expect("exposures")
        {
            exposure["coverage"][side] = json!({"inventory":"partial","assessment":"partial","coordinates":2,"checked":2,"unqualified_occurrences":1,"reasons":["git_dependency_graph_unavailable", "git_registry_checks_not_supported"]});
        }
    }
    v
}

#[test]
fn diff_git_coverage_is_a_note_in_human_and_markdown_without_losing_advisories() {
    let v = git_report();
    for format in [Format::Human, Format::Markdown] {
        let text = rendered(&v, format)
            .replace("&#45;", "-")
            .replace("&#46;", ".");
        assert!(text.contains("Coverage notes"), "{text}");
        assert!(
            text.contains("Registry checks do not cover Git-based dependencies"),
            "{text}"
        );
        assert!(
            text.contains("Git dependency relationships are not recorded"),
            "{text}"
        );
        let notes = text.split("Coverage notes").nth(1).expect("notes");
        for line in notes
            .lines()
            .filter(|line| line.contains("Git") || line.contains("Registry checks"))
        {
            assert!(line.contains("package-lock.json"), "{line}");
        }
        assert!(text.contains("still affected"), "{text}");
        for warning in [
            "Files that need attention",
            "Check security advisories manually",
            "Some checks could not be completed",
            "version of Scan cannot explain",
            "could not finish checking every",
        ] {
            assert!(!text.contains(warning), "{warning}: {text}");
        }
    }
    let bytes = serde_json::to_vec_pretty(&v).expect("JSON");
    let report = Report::from_bytes(bytes.clone()).expect("report");
    let mut out = Vec::new();
    render::write(&report, Format::Json, ("base", "head"), &mut out).expect("render");
    assert_eq!(out, bytes);
}

#[test]
fn diff_git_coverage_does_not_hide_unexplained_or_mixed_deficits() {
    for pointer in [
        "/advisories/coverage/reasons",
        "/advisories/data/exposures/0/coverage/base/reasons",
    ] {
        for reasons in [
            json!([]),
            json!(["future_cause"]),
            json!(["git_dependency_graph_unavailable", "metadata_unavailable"]),
        ] {
            let mut v = git_report();
            *v.pointer_mut(pointer).expect("reasons") = reasons;
            let text = rendered(&v, Format::Human);
            assert!(
                text.contains("Some checks could not be completed"),
                "{pointer}: {text}"
            );
        }
    }
    for (pointer, value) in [
        ("/direct_reviews/status", json!("partial")),
        ("/direct_reviews/status", json!("not_requested")),
        ("/advisories/status", json!("not_requested")),
        ("/advisories/coverage/unknown", json!(1)),
        ("/snapshots/base/side", json!("future")),
    ] {
        let mut v = git_report();
        *v.pointer_mut(pointer).expect("path") = value;
        assert!(
            rendered(&v, Format::Human).contains("Some checks could not be completed"),
            "{pointer}"
        );
    }
    for (side, revision) in [("base", "earlier"), ("head", "later")] {
        let mut v = git_report();
        v["snapshots"][side]["coverage"] = json!({"partial":true});
        for format in [Format::Human, Format::Markdown] {
            let text = rendered(&v, format);
            assert!(
                text.contains("Some checks could not be completed"),
                "{text}"
            );
            assert!(text.contains("Files that need attention"), "{text}");
            assert!(
                text.contains(&format!("unavailable in the {revision} revision")),
                "{text}"
            );
        }
    }
    let mut v = git_report();
    v["snapshots"]["head"]["coverage"]["sources"][0]["reasons"] = json!([
        "git_dependency_graph_unavailable",
        "required_input_not_supplied"
    ]);
    v["snapshots"]["head"]["coverage"]["sources"][0]["required_path"] =
        "member/package.json".into();
    let text = rendered(&v, Format::Human);
    assert!(text.contains("Files that need attention"), "{text}");
    assert!(text.contains("member/package.json"), "{text}");
    assert!(text.contains("Coverage notes"), "{text}");
}

#[test]
fn diff_git_coverage_requires_local_proof_for_derived_delta_limits() {
    let mut v = git_report();
    for side in ["base", "head"] {
        v["advisories"]["data"]["exposures"][1]["deltas"][0][side]["reasons"] =
            json!(["source_scope_incomplete"]);
    }
    let text = rendered(&v, Format::Human);
    assert!(
        !text.contains("Check security advisories manually"),
        "{text}"
    );
    v["advisories"]["data"]["exposures"][1]["deltas"][0]["head"]["reasons"] =
        json!(["coordinate_assessment_incomplete"]);
    let text = rendered(&v, Format::Human);
    assert!(
        text.contains("Check security advisories manually"),
        "{text}"
    );
}

#[test]
fn diff_git_coverage_binding_limit_joins_only_its_own_root_proof() {
    let mut v = git_report();
    v["snapshots"]["head"]["coverage"]["resolution"] =
        json!([{"path":"package-lock.json", "reason":"git_source_binding_unavailable"}]);
    v["snapshots"]["head"]["coverage"]["reachability"] = json!([{"complete":false,"manifest_path":"package.json","source_key":"package-lock.json","basis":"declaration_and_root_graph","reachability_id":"head:root"}]);
    v["snapshots"]["head"]["reachability"] = json!([{"id":"head:root","manifest_path":"package.json","source_key":"package-lock.json","complete":false,"reasons":[{"code":"root_dependency_coverage_incomplete","message":"Unavailable source binding","source_key":"package-lock.json","coverage_reasons":["git_source_binding_unavailable"]}]}]);
    let text = rendered(&v, Format::Human);
    assert!(!text.contains("Files that need attention"), "{text}");
    assert!(
        !text.contains("Some checks could not be completed"),
        "{text}"
    );
    assert!(
        text.contains("Some Git source bindings cannot be established"),
        "{text}"
    );
    v["snapshots"]["head"]["reachability"][0]["manifest_path"] = "other/package.json".into();
    let text = rendered(&v, Format::Human);
    assert!(text.contains("Files that need attention"), "{text}");
}

#[test]
fn diff_git_coverage_unexplained_indeterminate_results_keep_caution() {
    let mut v = git_report();
    let row = &mut v["advisories"]["data"]["exposures"][1]["deltas"][0];
    row["kind"] = "indeterminate".into();
    row["head"]["status"] = "unknown".into();
    let text = rendered(&v, Format::Human);
    assert!(
        text.contains("Some checks could not be completed"),
        "{text}"
    );
    assert!(text.contains("could not be confirmed"), "{text}");
}

#[test]
fn diff_git_coverage_changed_binding_and_occurrence_keep_neutral_causes() {
    let mut v = fixture::report();
    v["declaration_changes"][0]["binding_transitions"][0]["base_status"] =
        "source_unavailable".into();
    let cause = json!({"code":"git_source_binding_unavailable","message":"An expected captured-source limit","source_key":"package-lock.json","manifest_path":"package.json","dependency_name":"helper","declaration_id":"base:d1"});
    v["snapshots"]["base"]["bindings"] =
        json!([{"declaration_id":"base:d1","source_key":"package-lock.json","reasons":[cause]}]);
    v["changes"][0]["directness"]["base"] = "unknown".into();
    v["changes"][0]["before_ids"] = json!(["base:git"]);
    v["snapshots"]["base"]["occurrences"] = json!([{"id":"base:git","directness":"unknown","directness_reasons":[{"code":"git_dependency_graph_unavailable","message":"EXPECTED GRAPH LIMIT","source_key":"package-lock.json"}],"directness_proof_ids":[]}]);
    let text = rendered(&v, Format::Human);
    assert!(
        text.contains("Some Git source bindings cannot be established"),
        "{text}"
    );
    assert!(
        text.contains("Git dependency relationships are not recorded"),
        "{text}"
    );
    assert!(
        !text.contains("Review the declaration and package-lock.json"),
        "{text}"
    );
    assert!(!text.contains("EXPECTED GRAPH LIMIT"), "{text}");
    v["snapshots"]["base"]["bindings"][0]["reasons"] = json!([]);
    assert!(rendered(&v, Format::Human).contains("Review the declaration and package-lock.json"));
}
