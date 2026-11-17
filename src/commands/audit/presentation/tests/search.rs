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
    let text = detail["summary"].as_str().expect("search summary");
    assert!(text.contains("cargo:example-parent@3.0.0"), "{text}");
    assert!(text.contains("metadata lookup failed"), "{text}");
    assert!(!text.contains("lookup_failed"));
    assert_eq!(
        r["changes"][0]["summary"],
        blocks(&input())["remediation"]["recommendations"][0]["changes"][0]["summary"]
    );
    assert_eq!(
        doc["audit"]["remediation"]["recommendations"][0]["search_details"][0]["witness"]["coordinate"],
        coordinate("example-parent", "3.0.0")
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

#[test]
fn audit_search_copy_keeps_single_candidate_partial_and_required_edit_clear() {
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
        "Update the demo requirement in package.json. Current requirement: ^1.0."
    );
    assert_eq!(r["impact"], json!([]));
    value["remediation"]["recommendations"][0]["outcome"] = "partial".into();
    value["remediation"]["recommendations"][0]["remaining_finding_refs"] = json!([0]);
    let doc = blocks(&value);
    let r = &doc["remediation"]["recommendations"][0];
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
fn audit_search_operations_and_stages_explain_scope_without_codes_or_counters() {
    for (operation, phrase) in [
        ("source", "dependency source"),
        ("catalog", "available package versions"),
        ("release", "release metadata"),
        ("inventory", "dependency list"),
        ("boundary", "dependency relationship"),
        ("request", "dependency requirement"),
        ("membership", "compare dependency requirements"),
        ("advisories", "advisory applicability"),
        ("ordering", "current and candidate versions"),
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
                && text.contains("metadata lookup failed"),
            "{text}"
        );
        assert!(!text.contains(operation) || !text.contains('_'), "{text}");
    }
    for (stage, phrase) in [
        ("leaf_evaluation", "candidate dependency versions"),
        ("domain_construction", "collecting candidate"),
        ("domain_sampling", "selecting candidate"),
        ("domain_reservation", "allocating candidate"),
        ("seed_admission", "starting upgrade combinations"),
        ("frontier_admission", "exploring further"),
        ("parent_evaluation", "packages that depend"),
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
            text.contains(phrase) && text.contains("time limit") && text.contains("shared"),
            "{text}"
        );
        assert!(
            !text.contains(stage) && !text.contains("phase_deadline"),
            "{text}"
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
            {"kind":"unavailable","operation":"release","reasons":["future_reason"],"witness":{"coordinate":coordinate("example-leaf","3.0.0")}},
            {"kind":"future_kind","private_unused_id":"opaque"}
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
    assert!(
        entries[1]["summary"]
            .as_str()
            .expect("summary")
            .contains("cannot interpret")
    );
    assert!(
        serde_json::to_string(&doc["remediation"]["limits"])
            .expect("limits")
            .contains("alternative upgrades")
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
    ] {
        let doc = blocks(&with_search("retained", json!([detail])));
        let text = doc["remediation"]["recommendations"][0]["search_explanations"][0]["summary"]
            .as_str()
            .expect("summary");
        assert!(
            text.contains("cannot identify")
                && (text.contains("lookup failed") || text.contains("time limit")),
            "{text}"
        );
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
    assert_eq!(
        r["search_explanations"]
            .as_array()
            .expect("explanations")
            .len(),
        1
    );
}
