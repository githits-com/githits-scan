use super::*;

fn coordinate(name: &str, version: &str) -> Value {
    json!({"registry":"cargo", "name":name, "version":version})
}
fn with_search(status: &str, details: Value) -> Value {
    let mut value = input();
    let r = &mut value["remediation"]["recommendations"][0];
    r["search_detail_status"] = status.into();
    r["search_details"] = details;
    value
}
fn blocks(value: &Value) -> Value {
    serde_json::to_value(Document::new(&project(value))).expect("presentation")
}

#[test]
fn audit_search_explains_losing_release_without_changing_selected_fix() {
    let value = with_search(
        "retained",
        json!([{
            "kind":"unavailable", "operation":"release", "reasons":["lookup_failed"],
            "witness":{"coordinate":coordinate("example-parent", "3.0.0"),"acquisition":"lookup_failed"}
        }]),
    );
    let doc = blocks(&value);
    let r = &doc["remediation"]["recommendations"][0];
    let detail = &r["search_explanations"][0];
    assert_eq!(detail["search_detail_index"], 0);
    assert_eq!(
        detail["summary"],
        "Release metadata for cargo:example-parent@3.0.0: lookup failed."
    );
    assert_eq!(
        r["checks"],
        blocks(&input())["remediation"]["recommendations"][0]["checks"]
    );
    assert_eq!(
        r["changes"][0]["summary"],
        blocks(&input())["remediation"]["recommendations"][0]["changes"][0]["summary"]
    );
    assert_eq!(
        r["compact_summary"],
        blocks(&input())["remediation"]["recommendations"][0]["compact_summary"]
    );
    assert_eq!(r["details_recommended"], false);
    assert_eq!(
        doc["audit"]["remediation"]["recommendations"][0]["search_details"][0]["witness"]["coordinate"],
        coordinate("example-parent", "3.0.0")
    );
}

#[test]
fn audit_search_limits_for_other_candidates_do_not_qualify_a_supported_bump() {
    let mut value = with_search("retained", json!([]));
    let r = &mut value["remediation"]["recommendations"][0];
    r["checks"]["parent_search"] = "limited".into();
    r["limitations"] = json!(["parent_candidate_limit"]);
    let doc = blocks(&value);
    let r = &doc["remediation"]["recommendations"][0];
    assert_eq!(
        r["compact_summary"],
        "Bump npm:demo 1.0.0 -> 1.1.1 in package-lock.json. Addresses GHSA-demo."
    );
    assert_eq!(r["details_recommended"], false);
    assert_eq!(
        r["checks"],
        json!(["Upgrades to packages using this dependency were not fully checked."])
    );
    assert!(
        r["limitations"][0]
            .as_str()
            .expect("limit")
            .contains("limit for checking")
    );
}

#[test]
fn audit_search_retention_and_legacy_absence_are_not_success_claims() {
    for (status, expected) in [
        ("retained", None),
        ("not_retained", Some("omitted")),
        ("future_status", Some("cannot interpret")),
    ] {
        let value = with_search(status, json!([]));
        let doc = blocks(&value);
        let r = &doc["remediation"]["recommendations"][0];
        assert_eq!(r["search_explanations"], json!([]));
        let limits = serde_json::to_string(&r["limitations"]).expect("limits");
        if let Some(expected) = expected {
            assert!(limits.contains(expected), "{limits}");
        } else {
            assert!(!limits.contains("search explanations"), "{limits}");
        }
        assert!(!limits.contains("safe") && !limits.contains("exhaustive"));
    }
    let mut value = input();
    value["remediation"]["recommendations"][0]["checks"]["parent_search"] = "limited".into();
    let doc = blocks(&value);
    assert!(
        serde_json::to_string(&doc["remediation"]["recommendations"][0]["limitations"])
            .expect("limits")
            .contains("does not include detailed search explanations")
    );
}

#[test]
fn audit_search_keeps_selected_limit_when_losing_alternative_shares_reason() {
    let mut value = with_search(
        "retained",
        json!([{
            "kind":"stopped", "stage":"parent_evaluation", "reason":"parent_candidate_limit",
            "used":1,"allowed":1,
            "witness":{"coordinate":coordinate("other-parent", "2.0.0"),"budget_scope":"shared"}
        }]),
    );
    value["remediation"]["recommendations"][0]["limitations"] = json!(["parent_candidate_limit"]);
    let doc = blocks(&value);
    let r = &doc["remediation"]["recommendations"][0];
    assert_eq!(r["limitations"].as_array().expect("limits").len(), 1);
    assert!(
        r["search_explanations"][0]["summary"]
            .as_str()
            .expect("summary")
            .contains("other-parent")
    );
    assert!(
        !serde_json::to_string(r)
            .expect("blocks")
            .contains("parent_candidate_limit")
    );
}

fn input_with_project_edit() -> Value {
    let mut value = input();
    let mut edit = blocker();
    edit["owner_role"] = "project".into();
    edit["reason"] = "project_request_change".into();
    edit["path"] = "package.json".into();
    edit["dependency_name"] = "demo".into();
    edit["requested_requirement"] = "^1.0".into();
    let r = &mut value["remediation"]["recommendations"][0];
    r["blockers"] = json!([edit]);
    r["checks"]["requirements"] = "blocked".into();
    value
}

#[test]
fn audit_search_copy_keeps_single_candidate_partial_and_required_edit_clear() {
    let mut value = input_with_project_edit();
    let doc = blocks(&value);
    let r = &doc["remediation"]["recommendations"][0];
    assert!(r["heading"].is_null());
    assert!(
        r["changes"][0]["summary"]
            .as_str()
            .expect("candidate")
            .starts_with("Candidate upgrade:")
    );
    assert_eq!(
        r["constraints"][0]["summary"],
        "Applying the candidate requires updating the demo requirement in package.json. Current requirement: ^1.0."
    );
    assert_eq!(r["impact"], json!(["would address the listed advisory"]));
    assert_eq!(r["details_recommended"], false);
    assert_eq!(
        r["compact_summary"],
        concat!(
            "npm:demo 1.0.0 -> 1.1.1. ",
            "Update version constraint for demo in package.json (currently ^1.0). Addresses GHSA-demo."
        )
    );
    value["remediation"]["recommendations"][0]["outcome"] = "partial".into();
    value["remediation"]["recommendations"][0]["remaining_finding_refs"] = json!([0]);
    let doc = blocks(&value);
    let r = &doc["remediation"]["recommendations"][0];
    assert_eq!(r["details_recommended"], true);
    assert!(
        r["changes"][0]["summary"]
            .as_str()
            .expect("candidate")
            .contains("(partial)")
    );
    assert!(
        serde_json::to_string(&r["impact"])
            .expect("impact")
            .contains("still unresolved")
    );
}

#[test]
fn audit_search_keeps_concrete_project_edit_ahead_of_unverified_target() {
    let mut value = input_with_project_edit();
    value["remediation"]["recommendations"][0]["checks"]["release_availability"] =
        "unverified".into();
    let doc = blocks(&value);
    let r = &doc["remediation"]["recommendations"][0];
    assert_eq!(
        r["compact_summary"],
        "npm:demo 1.0.0 -> 1.1.1. Applying the proposal requires updating the version constraint for demo in package.json (currently ^1.0)."
    );
    assert_eq!(r["details_recommended"], true);
    assert_eq!(
        r["constraints"][0]["summary"],
        "Applying the candidate requires updating the demo requirement in package.json. Current requirement: ^1.0."
    );
}

fn addition_evidence() -> Value {
    serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/audit/added-dependencies.json"
    )))
    .expect("added dependency evidence")
}

#[test]
fn audit_search_keeps_reported_blockers_ahead_of_unverified_target() {
    for (requirements, reason, explanation) in [
        (
            "blocked",
            "manifest_lock_disagreement",
            "Manifest and lockfile disagree",
        ),
        (
            "unchecked",
            "manifest_lock_disagreement",
            "Manifest and lockfile disagree",
        ),
        (
            "blocked",
            "project_request_change",
            "Applying this change requires updating the project requirement",
        ),
    ] {
        let mut value = input_with_project_edit();
        let r = &mut value["remediation"]["recommendations"][0];
        r["checks"]["requirements"] = requirements.into();
        r["checks"]["release_availability"] = "unverified".into();
        r["blockers"][0]["reason"] = reason.into();
        r["blockers"][0]["requirement_status"] = "not_recorded".into();
        r["blockers"][0]["requested_requirement"] = Value::Null;
        let doc = blocks(&value);
        let r = &doc["remediation"]["recommendations"][0];
        let summary = r["compact_summary"].as_str().expect("summary");
        assert!(
            summary.starts_with(&format!("npm:demo 1.0.0 -> 1.1.1. {explanation}")),
            "{summary}"
        );
        assert!(
            summary.contains("demo") && summary.contains("package.json"),
            "{summary}"
        );
        assert!(
            !summary.contains("proposed versions are available"),
            "{summary}"
        );
        assert_eq!(r["details_recommended"], true);
        assert_eq!(
            r["checks"][0],
            "The report did not confirm that the proposed versions are available. The release check gives no reason for the missing confirmation."
        );
    }
}

#[test]
fn audit_added_dependencies_compact_preserves_clear_edit() {
    let mut value = input_with_project_edit();
    value["remediation"]["recommendations"][0]["changes"][0]["added_dependencies"] =
        addition_evidence()["added_dependencies"].clone();
    let doc = blocks(&value);
    let r = &doc["remediation"]["recommendations"][0];
    assert_eq!(r["details_recommended"], true);
    assert_eq!(
        r["compact_summary"],
        concat!(
            "npm:demo 1.0.0 -> 1.1.1. ",
            "Update version constraint for demo in package.json (currently ^1.0). Addresses GHSA-demo. ",
            "Registry checks selected npm:added-child@1.0.0 for a new dependency."
        )
    );
}

#[test]
fn audit_added_dependencies_compact_prioritizes_selected_branch_problems() {
    let evidence = addition_evidence();
    let clean = &evidence["added_dependencies"][0];
    let incomplete = &evidence["search_details"][1]["added_dependency"];
    let affected = &evidence["search_details"][0]["added_dependency"];
    for (branches, expected) in [
        (
            json!([clean, incomplete]),
            concat!(
                "npm:demo 1.0.0 -> 1.1.1 in package-lock.json. Addresses GHSA-demo. ",
                "Registry checks selected npm:router@2.3.0 for one of 2 new dependency requests. ",
                "Dependency check for is-promise@4.0.0 — the dependency list was unavailable, ",
                "so its dependencies could not be fully checked."
            ),
        ),
        (
            json!([clean, incomplete, affected]),
            concat!(
                "The registry check found that upgrading npm:demo from 1.0.0 to 1.1.1 in package-lock.json ",
                "introduces a new dependency, npm:affected-descendant@1.0.0, affected by ",
                "AUDIT-ADDED-affected-descendant. Addresses GHSA-demo."
            ),
        ),
    ] {
        let mut value = input();
        value["remediation"]["recommendations"][0]["changes"][0]["added_dependencies"] = branches;
        let doc = blocks(&value);
        let r = &doc["remediation"]["recommendations"][0];
        assert_eq!(r["details_recommended"], true);
        assert_eq!(r["compact_summary"], expected);
    }
}

#[test]
fn audit_added_dependencies_advisory_precedes_unchecked_requirements() {
    let evidence = addition_evidence();
    let mut value = input();
    let r = &mut value["remediation"]["recommendations"][0];
    r["checks"]["requirements"] = "unchecked".into();
    r["changes"][0]["added_dependencies"] =
        json!([evidence["search_details"][0]["added_dependency"]]);
    let doc = blocks(&value);
    let r = &doc["remediation"]["recommendations"][0];
    assert_eq!(r["details_recommended"], true);
    assert_eq!(
        r["compact_summary"],
        concat!(
            "The registry check found that upgrading npm:demo from 1.0.0 to 1.1.1 introduces ",
            "a new dependency, npm:affected-descendant@1.0.0, affected by AUDIT-ADDED-affected-descendant."
        )
    );
    assert_eq!(
        r["checks"],
        json!([
            "The audit did not check whether the project's dependency requirements allow this change. The requirement check gives no reason."
        ])
    );
}

#[test]
fn audit_added_dependencies_failed_checks_precede_unchecked_requirements() {
    let evidence = addition_evidence();
    let incomplete = &evidence["search_details"][1]["added_dependency"];
    let mut unresolved = incomplete.clone();
    unresolved["selected_version"] = Value::Null;
    unresolved["coordinates"] = json!([]);
    unresolved["issues"] = json!([{"operation":"selection","reason":"no_matching_version"}]);
    for (branch, expected) in [
        (
            incomplete,
            concat!(
                "Registry checks selected npm:router@2.3.0 for a new dependency. ",
                "Dependency check for is-promise@4.0.0 — the dependency list was unavailable, ",
                "so its dependencies could not be fully checked."
            ),
        ),
        (
            &unresolved,
            concat!(
                "The release requires router ^2.0.0 as a new dependency. ",
                "Registry version selection for npm:router — no published version matched the requirement."
            ),
        ),
    ] {
        let mut value = input();
        let r = &mut value["remediation"]["recommendations"][0];
        r["checks"]["requirements"] = "unchecked".into();
        r["changes"][0]["added_dependencies"] = json!([branch]);
        let doc = blocks(&value);
        let r = &doc["remediation"]["recommendations"][0];
        assert_eq!(r["details_recommended"], true);
        assert_eq!(
            r["compact_summary"],
            format!("npm:demo 1.0.0 -> 1.1.1. {expected}")
        );
        assert_eq!(
            r["checks"],
            json!([
                "The audit did not check whether the project's dependency requirements allow this change. The requirement check gives no reason."
            ])
        );
    }
}

#[test]
fn audit_added_dependencies_keeps_confirmed_target_problems_inline() {
    let evidence = addition_evidence();
    for (branches, added_problem) in [
        (Value::Null, None),
        (evidence["added_dependencies"].clone(), None),
        (
            json!([evidence["search_details"][0]["added_dependency"]]),
            Some("affected by AUDIT-ADDED-affected-descendant."),
        ),
        (
            json!([evidence["search_details"][1]["added_dependency"]]),
            Some("Dependency check for is-promise@4.0.0"),
        ),
    ] {
        let mut value = input();
        let r = &mut value["remediation"]["recommendations"][0];
        r["checks"]["advisories"] = "affected".into();
        r["checks"]["requirements"] = "blocked".into();
        r["checks"]["release_availability"] = "unverified".into();
        if !branches.is_null() {
            r["changes"][0]["added_dependencies"] = branches;
        }
        let doc = blocks(&value);
        let r = &doc["remediation"]["recommendations"][0];
        let summary = r["compact_summary"].as_str().expect("summary");
        if let Some(added_problem) = added_problem {
            assert!(summary.contains(added_problem), "{summary}");
        }
        assert!(
            summary.ends_with(concat!(
                "A proposed version is still affected by known advisories. ",
                "The upgrade conflicts with dependency requirements."
            )),
            "{summary}"
        );
        assert!(
            !summary.contains("confirm that the proposed versions are available"),
            "{summary}"
        );
        assert_eq!(r["details_recommended"], true);
        assert_eq!(
            r["checks"],
            json!([
                "A proposed version is still affected by known advisories.",
                "The upgrade conflicts with dependency requirements.",
                "The report did not confirm that the proposed versions are available. The release check gives no reason for the missing confirmation."
            ])
        );
    }
}

#[test]
fn audit_added_dependencies_advisory_keeps_concrete_project_edit_conditional() {
    let evidence = addition_evidence();
    let mut value = input_with_project_edit();
    let r = &mut value["remediation"]["recommendations"][0];
    r["changes"][0]["added_dependencies"] =
        json!([evidence["search_details"][0]["added_dependency"]]);
    let doc = blocks(&value);
    let r = &doc["remediation"]["recommendations"][0];
    assert_eq!(r["details_recommended"], true);
    assert_eq!(
        r["compact_summary"],
        concat!(
            "The registry check found that upgrading npm:demo from 1.0.0 to 1.1.1 introduces ",
            "a new dependency, npm:affected-descendant@1.0.0, affected by AUDIT-ADDED-affected-descendant. ",
            "Applying the proposal requires updating the version constraint for demo in package.json (currently ^1.0)."
        )
    );
}

#[test]
fn audit_added_dependencies_compact_names_obstacle_when_no_change_was_selected() {
    let evidence = addition_evidence();
    let details = &evidence["search_details"];
    for (index, expected) in [
        (
            0,
            concat!(
                "Candidate npm:demo@1.2.0 requires added-child ^1 as a new dependency. ",
                "Advisory check for npm:affected-descendant@1.0.0 found applicable advisories ",
                "(AUDIT-ADDED-affected-descendant)."
            ),
        ),
        (
            1,
            concat!(
                "Candidate npm:demo@1.3.0 requires router ^2.0.0 as a new dependency. ",
                "Dependency check for is-promise@4.0.0 — the dependency list was unavailable, ",
                "so its dependencies could not be fully checked."
            ),
        ),
    ] {
        let mut value = with_search("retained", json!([details[2], details[index]]));
        let r = &mut value["remediation"]["recommendations"][0];
        r["outcome"] = "indeterminate".into();
        r["changes"] = json!([]);
        r["addressed_finding_refs"] = json!([]);
        r["remaining_finding_refs"] = json!([0]);
        let doc = blocks(&value);
        let r = &doc["remediation"]["recommendations"][0];
        assert_eq!(r["details_recommended"], true);
        assert_eq!(
            r["compact_summary"],
            format!("The service could not determine a mitigation. {expected}")
        );
        let searches = &r["search_explanations"];
        assert!(
            searches[0]["details"]
                .to_string()
                .contains("The project installer may select")
        );
        assert!(
            !searches[1]["details"]
                .to_string()
                .contains("The project installer may select")
        );
    }
}

#[test]
fn audit_added_dependencies_compact_ignores_obstacles_for_other_candidates() {
    let evidence = addition_evidence();
    let value = with_search("retained", evidence["search_details"].clone());
    let doc = blocks(&value);
    let row = &doc["remediation"]["recommendations"][0];
    assert_eq!(row["details_recommended"], false);
    assert_eq!(
        row["compact_summary"],
        blocks(&input())["remediation"]["recommendations"][0]["compact_summary"]
    );
    assert_eq!(
        row["search_explanations"]
            .as_array()
            .expect("details")
            .len(),
        3
    );
}

#[test]
fn audit_search_operations_and_stages_explain_scope_without_codes_or_counters() {
    for (operation, phrase) in [
        ("source", "Dependency source"),
        ("catalog", "Available package versions"),
        ("release", "Release metadata"),
        ("inventory", "Dependency list"),
        ("boundary", "Dependency relationship"),
        ("request", "Dependency requirement"),
        ("membership", "Requirement comparison"),
        ("advisories", "Advisory applicability"),
        ("ordering", "Version comparison"),
        ("maven_policy", "Maven dependency requirement"),
    ] {
        let value = with_search(
            "retained",
            json!([{"kind":"unavailable","operation":operation,
            "reasons":["lookup_failed"],"witness":{"coordinate":coordinate("example-leaf","3.0.0")}}]),
        );
        let doc = blocks(&value);
        let text = doc["remediation"]["recommendations"][0]["search_explanations"][0]["summary"]
            .as_str()
            .expect("summary");
        assert!(
            text.contains(phrase)
                && text.contains("cargo:example-leaf@3.0.0")
                && text.contains("lookup failed"),
            "{text}"
        );
        assert!(!text.contains(operation) || !text.contains('_'), "{text}");
    }
    for (stage, phrase) in [
        ("leaf_evaluation", "Checking candidate versions"),
        ("domain_construction", "Collecting upgrade versions"),
        ("domain_sampling", "Selecting upgrade versions"),
        ("domain_reservation", "Allocating upgrade checks"),
        ("seed_admission", "Starting upgrade combinations"),
        ("frontier_admission", "Exploring upgrade combinations"),
        ("parent_evaluation", "Checking upgrades"),
    ] {
        let value = with_search(
            "retained",
            json!([{"kind":"stopped","stage":stage,"reason":"phase_deadline",
            "witness":{"coordinate":coordinate("example-parent","2.0.0"),"budget_scope":"shared"}}]),
        );
        let doc = blocks(&value);
        let text = doc["remediation"]["recommendations"][0]["search_explanations"][0]["summary"]
            .as_str()
            .expect("summary");
        assert!(
            text.contains(phrase)
                && text.contains("time limit reached")
                && !text.contains("shared"),
            "{text}"
        );
        assert!(
            !text.contains(stage) && !text.contains("phase_deadline"),
            "{text}"
        );
        assert_eq!(
            doc["audit"]["remediation"]["recommendations"][0]["search_details"][0]["witness"]["budget_scope"],
            "shared"
        );
    }
}
#[test]
fn audit_search_conditions_aliases_and_policy_diagnostics_keep_exact_evidence() {
    let witness: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/audit/search-witness.json"
    ))
    .expect("witness");
    for (state, expected, absent) in [
        (
            "conditional",
            "request is conditional",
            "could not establish whether",
        ),
        (
            "unestablished",
            "could not establish whether",
            "request is conditional",
        ),
    ] {
        let mut witness = witness.clone();
        witness["qualification"]["participation"] = state.into();
        witness["request_checks"] = json!([]);
        witness["request"]["dependency_name"] = "vendor:capability\n\u{1b}[2J".into();
        let value = with_search(
            "retained",
            json!([{"kind":"unavailable","operation":"request","reasons":["request_unavailable"],"witness":witness}]),
        );
        let doc = blocks(&value);
        let explanation = &doc["remediation"]["recommendations"][0]["search_explanations"][0];
        let text = format!(
            "{} {}",
            explanation["summary"].as_str().expect("summary"),
            explanation["details"]
                .as_array()
                .expect("details")
                .iter()
                .map(|v| v.as_str().expect("text"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert!(text.contains(expected) && !text.contains(absent), "{text}");
        assert!(text.contains("vendor:capability\\n\\u{1b}"), "{text}");
        assert!(
            text.contains("example-feature") && text.contains("activation was not established"),
            "{text}"
        );
        assert!(
            text.contains("version: required project files were not uploaded"),
            "{text}"
        );
        assert!(
            !text.contains("required_input_not_supplied")
                && !text.contains('\u{1b}')
                && !text.contains("feature is active"),
            "{text}"
        );
    }
}
#[test]
fn audit_search_unfamiliar_evidence_and_omissions_do_not_invent_causes() {
    let mut value = with_search(
        "retained",
        json!([
            {"kind":"unavailable","operation":"release","reasons":["future_reason"],"witness":{"coordinate":coordinate("example-leaf","3.0.0"),"coverage":{"status":"present","complete":false,"reasons":["future_coverage"]}}},
            {"kind":"future_kind","private_unused_id":"opaque"},
            {"kind":"stopped","stage":"parent_evaluation","reason":"future_reason","witness":{"coordinate":coordinate("example-parent","3.0.0"),"budget_scope":"local"}}
        ]),
    );
    value["remediation"]["limits"]["omitted_search_details"] = 2.into();
    let doc = blocks(&value);
    let entries = &doc["remediation"]["recommendations"][0]["search_explanations"];
    assert!(
        entries[0]["summary"]
            .as_str()
            .expect("summary")
            .contains("cannot explain the supplied reason")
    );
    let detail = entries[0]["details"][0].as_str().expect("coverage detail");
    assert!(
        detail.starts_with("Dependency list:")
            && detail.contains("cannot explain the supplied reason"),
        "{detail}"
    );
    assert!(!detail.contains("check could not be completed"), "{detail}");
    for index in [0, 2] {
        let summary = entries[index]["summary"].as_str().expect("summary");
        assert!(
            summary.contains("check could not be completed")
                && summary.contains("cannot explain the supplied reason"),
            "{summary}"
        );
    }
    assert!(
        entries[1]["summary"]
            .as_str()
            .expect("summary")
            .contains("cannot interpret")
    );
    assert!(
        serde_json::to_string(&doc["remediation"]["limits"])
            .expect("limits")
            .contains("does not identify which recommendations or alternatives")
    );
    assert_eq!(
        doc["audit"]["remediation"]["limits"]["omitted_search_details"],
        2
    );
    let text = serde_json::to_string(&doc["remediation"]).expect("explanations");
    assert!(
        !text.contains("future_reason")
            && !text.contains("future_kind")
            && !text.contains("opaque")
    );
    for detail in [
        json!({"kind":"unavailable","operation":"future_operation","reasons":["lookup_failed"],"witness":{}}),
        json!({"kind":"stopped","stage":"future_stage","reason":"phase_deadline","witness":{"coordinate":null,"budget_scope":"local"}}),
        json!({"kind":"unavailable","operation":"future_operation","reasons":["future_reason"],"witness":{}}),
        json!({"kind":"stopped","stage":"future_stage","reason":"future_reason","witness":{"coordinate":null,"budget_scope":"local"}}),
    ] {
        let doc = blocks(&with_search("retained", json!([detail])));
        let text = doc["remediation"]["recommendations"][0]["search_explanations"][0]["summary"]
            .as_str()
            .expect("summary");
        assert!(
            text.contains("cannot identify")
                && (text.contains("lookup failed")
                    || text.contains("time limit")
                    || text.contains("cannot explain")),
            "{text}"
        );
        assert_eq!(text.matches("JSON").count(), 1, "{text}");
        assert!(
            !text.contains("future_operation") && !text.contains("future_stage"),
            "{text}"
        );
    }
}

#[test]
fn audit_search_indeterminate_result_does_not_deny_supplied_search_evidence() {
    let mut value = with_search(
        "retained",
        json!([{
            "kind":"unavailable","operation":"release","reasons":["lookup_failed"],
            "witness":{"coordinate":coordinate("example-parent","3.0.0"),"acquisition":"lookup_failed"}
        }]),
    );
    let r = &mut value["remediation"]["recommendations"][0];
    r["outcome"] = "indeterminate".into();
    r["addressed_finding_refs"] = json!([]);
    r["remaining_finding_refs"] = json!([0]);
    r["changes"] = json!([]);
    r["blockers"] = json!([]);
    r["limitations"] = json!([]);
    r["checks"]["parent_search"] = "not_assessed".into();
    let doc = blocks(&value);
    let r = &doc["remediation"]["recommendations"][0];
    assert_eq!(
        r["outcome"],
        "The service could not determine a mitigation."
    );
    assert_eq!(r["details_recommended"], true);
    assert_eq!(
        r["compact_summary"],
        concat!(
            "The service could not determine a mitigation. ",
            "Release metadata for cargo:example-parent@3.0.0: lookup failed."
        )
    );
    assert_eq!(
        r["search_explanations"]
            .as_array()
            .expect("explanations")
            .len(),
        1
    );
}

#[test]
fn audit_search_request_clauses_keep_each_result_and_qualification_together() {
    let mut witness: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/audit/search-witness.json"
    ))
    .expect("witness");
    let clause = witness["request_checks"][0]["clauses"][0].clone();
    let mut clauses = Vec::new();
    for (name, status, strength, expected) in [
        ("first", "matched", Some("required"), "requirement matches"),
        (
            "second",
            "mismatched",
            Some("required"),
            "requirement excludes",
        ),
        (
            "third",
            "mismatched",
            Some("preference"),
            "preference differs from",
        ),
        (
            "fourth",
            "unchecked",
            None,
            "requirement was not compared with",
        ),
        (
            "fifth",
            "unchecked",
            None,
            "requirement was not compared with",
        ),
        (
            "sixth",
            "future_status",
            Some("required"),
            "cannot interpret the supplied comparison",
        ),
    ] {
        let mut c = clause.clone();
        c["request"]["dependency_name"] = name.into();
        c["participation"]["status"] = "conditional".into();
        c["effective_membership"] = strength.map_or_else(
            || json!({"status":status,"reason":"unsupported_selector"}),
            |strength| json!({"status":status,"strength":strength}),
        );
        clauses.push((c, name, expected));
    }
    witness["request_checks"][0]["clauses"] =
        Value::Array(clauses.iter().map(|(c, _, _)| c.clone()).collect());
    let doc = blocks(&with_search(
        "retained",
        json!([{"kind":"unavailable","operation":"membership","reasons":["membership_unavailable"],"witness":witness}]),
    ));
    let details = doc["remediation"]["recommendations"][0]["search_explanations"][0]["details"]
        .as_array()
        .expect("details");
    for (_, name, expected) in clauses {
        let line = details
            .iter()
            .filter_map(Value::as_str)
            .find(|line| line.contains(&format!("requires {name} ")))
            .expect("clause");
        assert!(
            line.contains(expected) && line.contains("conditional request"),
            "{line}"
        );
        if name == "fourth" || name == "fifth" {
            assert!(
                line.contains("selector this check cannot evaluate"),
                "{line}"
            );
        }
    }
}

#[test]
fn audit_search_summary_does_not_repeat_its_request_versions_or_relationship() {
    let witness: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/audit/search-witness.json"
    ))
    .expect("witness");
    for operation in ["request", "ordering", "boundary"] {
        let mut w = witness.clone();
        w["requests"] = json!([]);
        if operation == "boundary" {
            remove_summary_subjects(&mut w);
        }
        let doc = blocks(&with_search(
            "retained",
            json!([{"kind":"unavailable","operation":operation,"reasons":["lookup_failed"],"witness":w}]),
        ));
        let details = doc["remediation"]["recommendations"][0]["search_explanations"][0]["details"]
            .as_array()
            .expect("details");
        let text = details
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        match operation {
            "request" => {
                assert!(!details.contains(&json!(
                    "example-parent@2.0.0 requires authored-alias ^1 [Cargo.lock]"
                )));
            }
            "ordering" => assert!(!text.contains("Versions compared:"), "{text}"),
            _ => assert!(!text.contains("Dependency relationship:"), "{text}"),
        }
        assert!(
            !text.contains("dependency list used for this check is incomplete"),
            "{text}"
        );
        assert!(
            text.contains("Dependency list: dependency list is incomplete"),
            "{text}"
        );
    }
}

fn remove_summary_subjects(witness: &mut Value) {
    for field in ["coordinate", "package", "current", "target", "request"] {
        witness.as_object_mut().expect("object").remove(field);
    }
}

#[test]
fn audit_search_budget_scope_stays_in_facts_without_routine_notes() {
    for (scope, unfamiliar) in [("local", false), ("shared", false), ("future_scope", true)] {
        let doc = blocks(&with_search(
            "retained",
            json!([{
                "kind":"stopped", "stage":"parent_evaluation", "reason":"phase_deadline",
                "witness":{"coordinate":coordinate("example-parent","2.0.0"),"budget_scope":scope}
            }]),
        ));
        let summary = doc["remediation"]["recommendations"][0]["search_explanations"][0]["summary"]
            .as_str()
            .expect("summary");
        assert!(summary.contains("time limit reached"), "{summary}");
        assert_eq!(
            summary.contains("cannot interpret which searches"),
            unfamiliar,
            "{summary}"
        );
        assert!(!summary.contains("future_scope"), "{summary}");
        assert_eq!(
            doc["audit"]["remediation"]["recommendations"][0]["search_details"][0]["witness"]["budget_scope"],
            scope
        );
    }
}
