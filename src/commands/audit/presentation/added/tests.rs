//! Issue-specific inputs stay beside the versions that were checked.
use super::*;
use serde_json::{Value, json};

fn branch(registry: &str, issue: &Value) -> Branch {
    let mut value = json!({
        "registry": registry,
        "name": "added-root",
        "authored_name": "added-root",
        "requested_requirement": "^1",
        "requirement_status": "recorded",
        "scope": "runtime",
        "selection_basis": "registry_resolution",
        "selected_version": "1.0.0",
        "coordinates": [{
            "registry": registry,
            "name": "added-root",
            "version": "1.0.0",
            "advisory_status": "non_affecting",
            "advisory_ids": []
        }],
        "issues": [issue]
    });
    if value["issues"][0]["operation"] == "catalog" {
        value["selected_version"] = Value::Null;
        value["coordinates"] = json!([]);
    }
    serde_json::from_value(value).expect("branch")
}

#[test]
fn audit_added_dependencies_explains_cargo_activation_inputs() {
    for (reason, context, expected) in [
        (
            "cargo_feature_graph_missing",
            json!({"feature":"std"}),
            vec![
                "Cargo feature graph was unavailable",
                "Cargo feature group std",
            ],
        ),
        (
            "cargo_feature_graph_lookup_failed",
            json!({"feature":"tools"}),
            vec![
                "Cargo feature graph lookup failed",
                "Cargo feature group tools",
            ],
        ),
        (
            "cargo_feature_graph_lookup_deadline",
            json!({}),
            vec!["Cargo feature graph was not retrieved before the time limit"],
        ),
        (
            "cargo_feature_name_filtered",
            json!({"feature":"tools"}),
            vec![
                "manifest capture omitted a requested Cargo feature name",
                "Cargo feature group tools",
            ],
        ),
        (
            "cargo_transitive_features_not_applied",
            json!({"requested_features":["serde","alloc"],"default_features":true}),
            vec![
                "transitive Cargo feature settings were not applied",
                "requested Cargo features serde, alloc",
                "enabled Cargo default features",
            ],
        ),
        (
            "cargo_transitive_features_not_applied",
            json!({"requested_features":[],"default_features":false}),
            vec![
                "requested no explicit Cargo features",
                "disabled Cargo default features",
            ],
        ),
        (
            "cargo_feature_request_unrecorded",
            json!({"feature":"std"}),
            vec![
                "lockfile did not record which Cargo features the incoming request enables",
                "Cargo feature group std",
            ],
        ),
    ] {
        let mut issue = context;
        issue["operation"] = "closure".into();
        issue["reason"] = reason.into();
        issue["owner"] = "declaring-crate@2.0.0".into();
        issue["name"] = "optional-crate".into();
        issue["requested_requirement"] = "^1".into();
        issue["requirement_status"] = "recorded".into();

        let output = lines(&branch("crates", &issue))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(output.contains("No affecting advisories found for crates:added-root@1.0.0."));
        assert!(output.contains("declaring-crate@2.0.0 requesting optional-crate ^1"));
        assert!(
            expected.iter().all(|text| output.contains(text)),
            "{output}"
        );
        assert!(!output.contains(reason), "{output}");
    }
}

#[test]
fn audit_added_dependencies_explains_python_activation_inputs() {
    let marker = r#"extra == "docs" and python_version >= "3.11""#;
    for (reason, context, expected) in [
        (
            "python_transitive_extras_not_applied",
            json!({"requested_extras":["docs","pdf"]}),
            vec![
                "transitive Python extras were not applied",
                "requested Python extras docs, pdf",
            ],
        ),
        (
            "python_extra_name_filtered",
            json!({"marker":marker}),
            vec!["omitted a requested Python extra name", marker],
        ),
        (
            "python_extra_request_unrecorded",
            json!({"marker":marker}),
            vec![
                "lockfile did not record which Python extras the incoming request enables",
                marker,
            ],
        ),
    ] {
        let mut issue = context;
        issue["operation"] = "closure".into();
        issue["reason"] = reason.into();
        issue["owner"] = "declaring-dist@2.0.0".into();
        issue["name"] = "optional-dist".into();
        issue["requested_requirement"] = ">=1".into();
        issue["requirement_status"] = "recorded".into();

        let output = lines(&branch("pypi", &issue))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(output.contains("No affecting advisories found for pypi:added-root@1.0.0."));
        assert!(output.contains("declaring-dist@2.0.0 requesting optional-dist >=1"));
        assert!(
            expected.iter().all(|text| output.contains(text)),
            "{output}"
        );
        assert!(!output.contains(reason), "{output}");
    }
}

#[test]
fn audit_added_dependencies_explains_catalog_conflicts_and_lookup_failures() {
    for (issue, expected) in [
        (
            json!({"operation":"catalog","reason":"catalog_observation_missing"}),
            vec![
                "The registry checks did not select a version for npm:added-root.",
                "Registry version catalog lookup for npm:added-root",
                "no version catalog was available",
            ],
        ),
        (
            json!({"operation":"release","reason":"timeout"}),
            vec![
                "Release metadata lookup for npm:added-root@1.0.0",
                "the registry lookup timed out",
            ],
        ),
        (
            json!({"operation":"catalog","reason":"security_removed"}),
            vec![
                "Registry version catalog lookup for npm:added-root",
                "the registry withdrew the requested package or release",
            ],
        ),
        (
            json!({
                "operation":"release","reason":"registry_http_error","http_status":503,
                "coordinate":{"registry":"npm","name":"deep","version":"1.0.0"}
            }),
            vec![
                "Release metadata lookup for npm:deep@1.0.0",
                "registry returned an HTTP error (HTTP 503)",
            ],
        ),
        (
            json!({
                "operation":"closure","reason":"no_matching_version",
                "owner":"added-root@1.0.0","name":"no-match","requested_requirement":"~9","requirement_status":"recorded"
            }),
            vec![
                "Dependency check for added-root@1.0.0 requesting no-match ~9",
                "no published version matched the requirement",
            ],
        ),
        (
            json!({
                "operation":"selection","reason":"single_version_requirements_conflict",
                "registry":"hex","name":"transitive",
                "selected_versions":["1.0.0"],"represented_versions":["2.0.0"],"requirements":["== 1.0.0"]
            }),
            vec![
                "Registry version selection for hex:transitive",
                "none of the versions retained for the project satisfied all of the requirements",
                "registry branch selected 1.0.0",
                "project assignment retained 2.0.0",
                "conflicting requirements were == 1.0.0",
            ],
        ),
    ] {
        let output = lines(&branch("npm", &issue)).collect::<Vec<_>>().join("\n");
        assert!(
            expected.iter().all(|text| output.contains(text)),
            "{output}"
        );
    }
}

#[test]
fn audit_added_dependencies_keeps_one_explanation_for_each_advisory_gap() {
    let mut branch = branch(
        "npm",
        &json!({
            "operation":"advisories", "reason":"future_reason",
            "coordinate":{"registry":"npm","name":"added-root","version":"1.0.0"}
        }),
    );
    branch.coordinates[0].advisory_status = "unknown".into();
    let mut unsupported = branch.coordinates[0].clone();
    unsupported.coordinate.name = "uncovered".into();
    unsupported.advisory_status = "unsupported".into();
    branch.coordinates.push(unsupported);

    let lines = lines(&branch).collect::<Vec<_>>();
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("Advisory check for npm:added-root@1.0.0"))
            .count(),
        1
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("Scan cannot explain the supplied reason"))
    );
    assert!(lines.iter().any(|line| line.contains("Advisory check for npm:uncovered@1.0.0 could not run because advisory checks do not cover this registry")));
    assert!(!lines.iter().any(|line| line.contains("future_reason")));
}

#[test]
fn audit_added_dependencies_explains_installer_policy_once_per_change() {
    let mut branch = branch("npm", &json!({"operation":"release","reason":"timeout"}));
    branch.issues.clear();
    let mut other = branch.clone();
    other.name = "sibling".into();
    other.authored_name.clone_from(&other.name);
    other.coordinates[0].coordinate.name.clone_from(&other.name);
    let branches = [branch, other];
    assert_eq!(
        compact_changes(branches.iter()).as_deref(),
        Some("One new dependency selected by registry checks is npm:added-root@1.0.0")
    );
    let lines = change_lines(&branches).collect::<Vec<_>>();
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("may select different package copies"))
            .count(),
        1
    );
    let mut unresolved = branches[0].clone();
    unresolved.selected_version = None;
    unresolved.coordinates.clear();
    assert_eq!(
        compact_changes(std::iter::once(&unresolved)).as_deref(),
        Some("The report includes checks for new dependency requests")
    );
}

#[test]
fn audit_added_dependencies_names_conflict_even_when_candidate_release_is_absent() {
    let branch = branch(
        "hex",
        &json!({
            "operation":"selection",
            "reason":"single_version_requirements_conflict",
            "registry":"hex",
            "name":"added-root",
            "selected_versions":["1.0.0"],
            "represented_versions":["2.0.0"],
            "requirements":["^1"]
        }),
    );
    let detail = serde_json::from_value(json!({
        "witness": {
            "coordinate": null,
            "source": {"path":"mix.lock","coordinate":null,"occurrence_refs":[]}
        },
        "added_dependency": branch
    }))
    .expect("search detail");
    let (summary, _) = search(&detail);
    assert_eq!(
        summary,
        concat!(
            "A candidate whose release was not supplied [mix.lock] requires added-root ^1 as a new dependency. ",
            "The checked versions conflict with dependency requirements."
        )
    );
}
