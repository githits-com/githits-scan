//! Registry exclusions qualify assessments without excusing missing graph evidence.
use super::*;

fn excluded() -> serde_json::Value {
    let mut v = fixture::report();
    v["outcome"] = "partial".into();
    v["changes"] = json!([]);
    v["declaration_changes"] = json!([]);
    v["coverage"] = json!({"partial":true});
    v["advisories"]["status"] = "partial".into();
    v["advisories"]["reason"] = serde_json::Value::Null;
    v["advisories"]["coverage"]["reasons"] = json!(["non_registry_source"]);
    v["advisories"]["data"]["coordinate_transitions"] = json!([]);
    v["direct_reviews"] = json!({"status":"complete","data":[],"coverage":{"eligible":0,"completed":0,"returned":0,"not_assessed":0,"unavailable":0,"omitted":0}});
    for side in ["base", "head"] {
        v["snapshots"][side]["coverage"] = json!({"partial":true,"excluded_dependencies":[{"name":"workspace-helper","version":"0.1.0","paths":["Cargo.lock","tools/Cargo.lock"],"reason":"non_registry_source"}]});
        for e in v["advisories"]["data"]["exposures"]
            .as_array_mut()
            .expect("exposures")
        {
            e["coverage"][side] = json!({"inventory":"complete","assessment":"partial","coordinates":2,"checked":2,"unqualified_occurrences":1,"reasons":["non_registry_source"]});
        }
    }
    v
}

#[test]
fn diff_non_registry_exclusions_are_notes_and_keep_advisories_and_exact_json() {
    let v = excluded();
    for format in [Format::Human, Format::Markdown] {
        let text = rendered(&v, format)
            .replace("&#45;", "-")
            .replace("&#46;", ".");
        for expected in [
            "Coverage notes",
            "workspace-helper 0.1.0",
            "Cargo.lock, tools/Cargo.lock",
            "excluded from registry vulnerability and update checks",
            "still affected",
        ] {
            assert!(text.contains(expected), "{expected}: {text}");
        }
        assert_eq!(
            text.matches("excluded from registry vulnerability and update checks")
                .count(),
            1,
            "{text}"
        );
        for warning in [
            "Files that need attention",
            "manually",
            "Some checks could not be completed",
            "could not finish checking",
            "non_registry_source",
            "local workspace",
            "checked safe",
        ] {
            assert!(!text.contains(warning), "{warning}: {text}");
        }
    }
    let bytes = serde_json::to_vec_pretty(&v).expect("JSON");
    let report = Report::from_bytes(bytes.clone()).expect("report");
    let mut output = Vec::new();
    render::write(&report, Format::Json, ("base", "head"), &mut output).expect("render");
    assert_eq!(output, bytes);
}

#[test]
fn diff_non_registry_reason_does_not_excuse_other_gap_contexts() {
    for family in [
        "sources",
        "resolution",
        "mismatches",
        "excluded_dependencies",
    ] {
        let mut v = excluded();
        let reason = if family == "excluded_dependencies" {
            "future_reason"
        } else {
            "non_registry_source"
        };
        v["snapshots"]["head"]["coverage"][family] =
            json!([{"path":"Cargo.lock","name":"helper","reason":reason}]);
        for format in [Format::Human, Format::Markdown] {
            let text = rendered(&v, format).replace("&#45;", "-");
            assert!(
                text.contains("Files that need attention"),
                "{family}: {text}"
            );
            assert!(
                text.contains("Some checks could not be completed"),
                "{family}: {text}"
            );
            assert!(
                text.contains("Review these files manually"),
                "{family}: {text}"
            );
            assert!(
                family == "excluded_dependencies"
                    || text.contains("The service reported a non-registry source"),
                "{family}: {text}"
            );
            assert!(
                family == "excluded_dependencies" || !text.contains("did not supply a reason"),
                "{family}: {text}"
            );
        }
    }
}

#[test]
fn diff_non_registry_scoped_assessment_requires_complete_inventory_and_checks() {
    for (pointer, value) in [
        (
            "/advisories/data/exposures/0/coverage/base/inventory",
            json!("partial"),
        ),
        (
            "/advisories/data/exposures/0/coverage/base/checked",
            json!(1),
        ),
        (
            "/advisories/data/exposures/0/coverage/base/reasons",
            json!(["non_registry_source", "dependency_list_unavailable"]),
        ),
        (
            "/advisories/data/exposures/0/coverage/base/reasons",
            json!([]),
        ),
        (
            "/advisories/data/exposures/0/coverage/base/assessment",
            json!("future"),
        ),
        ("/advisories/coverage/unknown", json!(1)),
        ("/advisories/coverage/unsupported", json!(1)),
        ("/advisories/reason", json!("provider_unavailable")),
        ("/direct_reviews/coverage/omitted", json!(1)),
    ] {
        let mut v = excluded();
        *v.pointer_mut(pointer).expect("pointer") = value;
        let text = rendered(&v, Format::Human);
        assert!(
            text.contains("Some checks could not be completed"),
            "{pointer}: {text}"
        );
    }
}

#[test]
fn diff_non_registry_exclusion_does_not_hide_missing_files_or_graphs() {
    for family in ["sources", "resolution", "reachability"] {
        let mut v = excluded();
        v["snapshots"]["head"]["coverage"][family] = match family {
            "sources" => {
                json!([{"path":"tools/Cargo.lock","reasons":["dependency_list_unavailable"]}])
            }
            "resolution" => {
                json!([{"path":"Cargo.lock","reason":"required_input_not_supplied","required_path":"member/Cargo.toml"}])
            }
            _ => {
                json!([{"manifest_path":"Cargo.toml","source_key":"Cargo.lock","complete":false,"basis":"declaration_and_root_graph"}])
            }
        };
        let text = rendered(&v, Format::Human);
        assert!(
            text.contains("Files that need attention"),
            "{family}: {text}"
        );
        assert!(
            text.contains("Some checks could not be completed"),
            "{family}: {text}"
        );
        assert!(text.contains("Coverage notes"), "{family}: {text}");
    }
}

#[test]
fn diff_non_registry_derived_delta_limits_use_only_their_own_scope() {
    let mut v = excluded();
    for side in ["base", "head"] {
        v["advisories"]["data"]["exposures"][1]["deltas"][0][side]["reasons"] =
            json!(["source_scope_incomplete"]);
    }
    assert!(!rendered(&v, Format::Human).contains("manually"));
    for reason in [
        "coordinate_assessment_incomplete",
        "non_registry_source",
        "future_reason",
    ] {
        let mut broken = v.clone();
        broken["advisories"]["data"]["exposures"][1]["deltas"][0]["head"]["reasons"] =
            json!([reason]);
        assert!(
            rendered(&broken, Format::Human).contains("Check security advisories manually"),
            "{reason}"
        );
    }
    v["advisories"]["data"]["exposures"][1]["coverage"]["head"]["inventory"] = "partial".into();
    assert!(rendered(&v, Format::Human).contains("Check security advisories manually"));
}

#[test]
fn diff_non_registry_exclusion_with_expected_git_graph_loss_stays_neutral() {
    for (causes, caution) in [
        (
            json!(["non_registry_source", "git_dependency_graph_unavailable"]),
            false,
        ),
        (
            json!(["non_registry_source", "git_registry_checks_not_supported"]),
            true,
        ),
        (
            json!([
                "non_registry_source",
                "git_dependency_graph_unavailable",
                "future_reason"
            ]),
            true,
        ),
    ] {
        let mut v = excluded();
        for side in ["base", "head"] {
            v["advisories"]["data"]["exposures"][0]["coverage"][side]["inventory"] =
                "partial".into();
            v["advisories"]["data"]["exposures"][0]["coverage"][side]["reasons"] = causes.clone();
        }
        let text = rendered(&v, Format::Human);
        assert_eq!(
            text.contains("Some checks could not be completed"),
            caution,
            "{causes}: {text}"
        );
    }
}

#[test]
fn diff_non_registry_aggregate_only_note_remains_visible() {
    let mut v = excluded();
    for side in ["base", "head"] {
        v["snapshots"][side]["coverage"]["excluded_dependencies"] = json!([]);
    }
    let text = rendered(&v, Format::Human);
    assert_eq!(
        text.matches(crate::coverage::NON_REGISTRY_NOTE).count(),
        1,
        "{text}"
    );
    assert!(
        text.contains("Some checks could not be completed"),
        "{text}"
    );
}
