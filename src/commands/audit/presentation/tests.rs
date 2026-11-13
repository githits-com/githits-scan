//! Meaning is verified at its owner; output tests verify transport and layout.
use super::*;
use crate::commands::audit::{self, view};
use serde_json::{Value, json};

fn input() -> Value {
    let mut input: Value = serde_json::from_slice(include_bytes!(
        "../../../../tests/fixtures/audit/native-findings.json"
    ))
    .expect("report");
    input["remediation"] = serde_json::from_slice(include_bytes!(
        "../../../../tests/fixtures/audit/remediation.json"
    ))
    .expect("remediation");
    input
}
fn project(input: &Value) -> View {
    let report = crate::api::audit::Report::from_bytes(&serde_json::to_vec(input).expect("bytes"))
        .expect("report");
    audit::project(&report, Vec::new(), &crate::config::Audit::default()).0
}
fn plan(view: &View) -> Plan {
    let data = match &view.remediation {
        State::Present(data) => Some(data),
        _ => None,
    }
    .expect("verified remediation required");
    Plan::new(
        &data.recommendations[0],
        &data.status,
        &context::Context::record(&data.recommendations[0]),
        ReasonDetail::Evidence,
    )
}
fn blocker() -> Value {
    serde_json::from_slice(include_bytes!(
        "../../../../tests/fixtures/audit/blocker.json"
    ))
    .expect("blocker")
}

#[test]
fn partial_parent_keeps_candidate_identity_checked_benefit_and_unresolved_impact() {
    let bytes = include_str!("../../../../tests/fixtures/audit/graph.json")
        .replace("\"demo\"", "\"example-leaf\"")
        .replace("\"parent\"", "\"example-parent\"")
        .replace("\"npm\"", "\"cargo\"")
        .replace("package-lock.json", "Cargo.lock")
        .replace("package.json", "Cargo.toml");
    let mut input: Value = serde_json::from_str(&bytes).expect("graph");
    let mut reason: Value = serde_json::from_slice::<Vec<Value>>(include_bytes!(
        "../../../../tests/fixtures/audit/change-reasons.json"
    ))
    .expect("reasons")[2]
        .clone();
    reason["dependency"]["name"] = "example-leaf".into();
    reason["dependency"]["registry"] = "cargo".into();
    reason["path"] = "Cargo.lock".into();
    reason["original_requests"][0]["path"] = "Cargo.lock".into();
    reason["original_requests"][0]["owner"]["name"] = "example-parent".into();
    let r = &mut input["remediation"]["recommendations"][0];
    r["outcome"] = "partial".into();
    r["addressed_finding_refs"] = json!([]);
    r["remaining_finding_refs"] = json!([0]);
    let mut parent = r["changes"][1].clone();
    parent["reasons"] = json!([reason]);
    parent["deprecated_target"] = false.into();
    r["checks"]["deprecated_target"] = false.into();
    r["changes"] = json!([parent]);
    let mut edit = blocker();
    edit["owner"] = json!({"name":"application","version":null});
    edit["owner_role"] = "project".into();
    edit["path"] = "Cargo.toml".into();
    edit["dependency_name"] = "example-parent".into();
    edit["reason"] = "project_request_change".into();
    edit["requested_requirement"] = "^2.0".into();
    r["blockers"] = json!([edit]);
    r["checks"]["requirements"] = "blocked".into();
    let view = project(&input);
    let plan = plan(&view);
    assert_eq!(plan.heading.as_deref(), Some("Candidate changes (partial)"));
    assert_eq!(
        plan.changes[0].summary,
        "Upgrade candidate: cargo:example-parent 2.0.0 -> 2.1.0"
    );
    assert_eq!(
        plan.changes[0].reasons[0].summary,
        "why: removes a route to cargo:example-leaf@1.0.0"
    );
    assert_eq!(
        plan.impact,
        [
            "would address: none reported",
            "still unresolved: GHSA-example"
        ]
    );
    assert!(
        plan.constraints[0]
            .summary
            .contains("applying this change requires updating the project requirement")
    );
    assert!(
        plan.context.is_empty(),
        "checked benefit replaces redundant request context"
    );
    let mut text = Vec::new();
    audit::render::write(&view, false, &mut text, crate::style::Palette::PLAIN).expect("text");
    let text = String::from_utf8(text).expect("utf8");
    let document = serde_json::to_value(Document::new(&view)).expect("presentation");
    // Layout/serialization consume the computed blocks without a second phrase map.
    for value in [
        &plan.changes[0].summary,
        &plan.changes[0].reasons[0].summary,
        &plan.impact[0],
        &plan.impact[1],
        &plan.constraints[0].summary,
    ] {
        assert!(text.contains(value), "{text}");
        assert!(
            serde_json::to_string(&document["remediation"])
                .expect("JSON")
                .contains(value)
        );
    }
}

#[test]
fn project_edits_and_preferences_are_distinct_from_requirement_exclusions() {
    for (reason, explanation) in [
        (
            "third_party_request_excludes_target",
            "Dependency requirements conflict with this candidate.",
        ),
        (
            "required_request_excludes_target",
            "Dependency requirements conflict with this candidate.",
        ),
        (
            "project_request_change",
            "applying this change requires updating the project requirement",
        ),
        (
            "project_preference_change",
            "applying this change requires updating the project preference",
        ),
        (
            "future_reason\n\u{1b}[2J",
            "the service supplied an unfamiliar reason; see JSON for the supplied value",
        ),
        (
            "unsupported_selector",
            "dependency requirement could not be evaluated",
        ),
    ] {
        let mut input = input();
        let mut blocker = blocker();
        blocker["reason"] = reason.into();
        input["remediation"]["recommendations"][0]["blockers"] = json!([blocker]);
        input["remediation"]["recommendations"][0]["checks"]["requirements"] = "blocked".into();
        let plan = plan(&project(&input));
        let summary = &plan.constraints[0].summary;
        assert_eq!(summary, explanation);
        assert_eq!(
            plan.constraints[0].details,
            ["express@5.1.0 requires cookie ^0.7.1 [package-lock.json]"]
        );
        assert!(!summary.contains("excludes the target"));
        assert!(
            !plan.checks.iter().any(|s| s.starts_with("requirements:")),
            "blocker already explains the requirement check"
        );
    }
}

#[test]
fn partial_impact_marks_only_overlapping_advisories_and_preserves_missing_benefit() {
    for addressed in [json!([0, 1]), json!([])] {
        let mut input = input();
        let mut second = input["findings"]["vulnerabilities"][0].clone();
        second["advisory_id"] = "GHSA-second".into();
        input["findings"]["vulnerabilities"]
            .as_array_mut()
            .expect("findings")
            .push(second);
        input["summary"]["vulnerabilities"] = 2.into();
        let r = &mut input["remediation"]["recommendations"][0];
        r["outcome"] = "partial".into();
        r["finding_refs"] = json!([0, 1]);
        r["addressed_finding_refs"] = addressed.clone();
        r["remaining_finding_refs"] = json!([0]);
        let plan = plan(&project(&input));
        let expected = if addressed == json!([]) {
            [
                "would address: none reported",
                "still unresolved: GHSA-demo",
            ]
        } else {
            [
                "would address: GHSA-demo (partly), GHSA-second",
                "still unresolved: GHSA-demo (partly)",
            ]
        };
        assert_eq!(plan.impact, expected);
    }
}

#[test]
fn prerelease_qualification_checks_both_flags_and_preserves_complete_proposals() {
    for flag in ["/checks/prerelease_target", "/changes/0/prerelease_target"] {
        for (outcome, remaining, supported) in [
            ("proposed", json!([]), true),
            ("proposed", json!([0]), false),
            ("partial", json!([0]), false),
        ] {
            let mut input = input();
            let r = &mut input["remediation"]["recommendations"][0];
            r["outcome"] = outcome.into();
            r["remaining_finding_refs"] = remaining;
            *r.pointer_mut(flag).expect("flag") = true.into();
            let plan = plan(&project(&input));
            assert_eq!(
                plan.heading
                    .as_deref()
                    .expect("heading")
                    .starts_with("Suggested fix"),
                supported,
                "{flag}, {outcome}"
            );
            assert_eq!(
                plan.changes[0].summary.starts_with("Upgrade npm:"),
                supported
            );
            assert!(
                plan.checks
                    .iter()
                    .chain(&plan.changes[0].details)
                    .any(|s| s.contains("prerelease"))
            );
        }
    }
}

#[test]
fn displayed_context_controls_compression_without_changing_impact_meaning() {
    let view = project(&input());
    let data = match &view.remediation {
        State::Present(data) => Some(data),
        _ => None,
    }
    .expect("verified remediation required");
    let r = &data.recommendations[0];
    let own = Plan::new(
        r,
        &data.status,
        &context::Context::record(r),
        ReasonDetail::Summary,
    );
    let other = view::Finding {
        package: "npm:other@1".into(),
        ..view::Finding::default()
    };
    let selected = context::Context::selected(&[&other]);
    let different = Plan::new(r, &data.status, &selected, ReasonDetail::Summary);
    assert!(own.impact.is_empty() && own.files.is_empty());
    assert_eq!(different.impact, ["would address: GHSA-demo"]);
    assert_eq!(
        different.files,
        r.changes[0].data.paths.iter().cloned().collect()
    );
}

#[test]
fn material_missing_planning_states_have_displayable_messages_without_recommendations() {
    let mut view = project(&input());
    for state in [State::Unavailable, State::Unverified] {
        view.remediation = state;
        let document = Document::new(&view);
        assert_eq!(document.remediation.messages.len(), 1);
        assert!(document.remediation.recommendations.is_empty());
        assert_eq!(document.remediation.limits, [] as [String; 0]);
    }
    view.vulnerabilities.clear();
    view.remediation = State::Unavailable;
    assert_eq!(Document::new(&view).remediation.messages, [] as [String; 0]);
    let mut input = input();
    input["remediation"]["recommendations"] = json!([]);
    let mut view = project(&input);
    assert!(messages(&view)[0].contains("does not establish that no mitigation exists"));
    view.vulnerabilities.clear();
    assert_eq!(messages(&view), [] as [String; 0]);
    if let State::Present(data) = &mut view.remediation {
        data.limits.reasons.push("planning_deadline".into());
    }
    assert_eq!(
        Document::new(&view).remediation.limits,
        ["planning limit: mitigation planning time limit reached"]
    );
}

#[test]
fn outcomes_without_changes_explain_what_was_not_established() {
    for outcome in ["indeterminate", "partial", "proposed"] {
        let mut input = input();
        let r = &mut input["remediation"]["recommendations"][0];
        r["outcome"] = outcome.into();
        r["changes"] = json!([]);
        let plan = plan(&project(&input));
        assert!(plan.heading.is_none());
        let text = plan.outcome.expect("explanation");
        assert_ne!(text, outcome);
        assert!(
            text.contains(if outcome == "indeterminate" {
                "no further reason was supplied"
            } else {
                "without any changes"
            }),
            "{text}"
        );
    }
}

#[test]
fn indeterminate_outcome_never_refers_to_suppressed_detail_blocks() {
    let mut input = input();
    let r = &mut input["remediation"]["recommendations"][0];
    r["outcome"] = "indeterminate".into();
    r["changes"] = json!([]);
    r["limitations"] = json!(["withdrawal_not_observed"]);
    let plan = plan(&project(&input));
    assert!(plan.constraints.is_empty() && plan.limitations.is_empty());
    assert_eq!(
        plan.outcome.as_deref(),
        Some("The service could not determine a mitigation; no further reason was supplied.")
    );
}

#[test]
fn indeterminate_checks_are_retained_without_claiming_no_reason_was_supplied() {
    for (field, value) in [
        ("parent_search", json!("limited")),
        ("withdrawal", json!("future_value")),
        ("native_resolution", json!("future_value")),
        ("catalog_freshness", json!("future_value")),
        ("availability_source", json!("future_value")),
        ("preference_differences", json!(1)),
        ("prerelease_target", json!(true)),
        ("deprecated_target", json!(true)),
    ] {
        let mut input = input();
        let r = &mut input["remediation"]["recommendations"][0];
        r["outcome"] = "indeterminate".into();
        r["changes"] = json!([]);
        r["checks"][field] = value;
        let plan = plan(&project(&input));
        assert!(
            !plan.checks.is_empty(),
            "{field} must have a visible qualification"
        );
        assert_eq!(
            plan.outcome.as_deref(),
            Some("The service could not determine a mitigation.")
        );
    }
}

#[test]
fn explanation_blocks_escape_untrusted_controls_and_omit_opaque_evidence() {
    let mut input = input();
    let mut blocker = blocker();
    blocker["owner"]["name"] = "owner\n\u{1b}[2J <&|>".into();
    blocker["reason"] = "project_request_change".into();
    blocker["context"] = json!({"private":"must not appear"});
    input["remediation"]["recommendations"][0]["blockers"] = json!([blocker]);
    let plan = plan(&project(&input));
    let text = &plan.constraints[0].details[0];
    assert!(text.contains("owner\\n\\u{1b}[2J <&|>"), "{text}");
    assert!(!text.contains(['\n', '\u{1b}']));
    let json = serde_json::to_string(&plan).expect("JSON");
    assert!(!json.contains("must not appear"));
}

#[test]
fn advisory_check_explanations_distinguish_unsupported_missing_and_future_results() {
    for (status, explanation) in [
        (
            "unsupported",
            "advisory checking is not supported for this target",
        ),
        ("unknown", "not determined from the supplied evidence"),
        (
            "future_value",
            "the service returned an unfamiliar check result; see JSON for the supplied value",
        ),
    ] {
        let mut input = input();
        input["remediation"]["recommendations"][0]["checks"]["advisories"] = status.into();
        let view = project(&input);
        let plan = plan(&view);
        assert!(
            plan.checks
                .contains(&format!("target advisories: {explanation}"))
        );
        assert_eq!(plan.heading.as_deref(), Some("Candidate changes"));
        let facts = serde_json::to_value(&view).expect("facts");
        assert_eq!(
            facts["remediation"]["recommendations"][0]["checks"]["advisories"],
            status
        );
    }
}

#[test]
fn unfamiliar_reason_and_strategy_codes_stay_in_facts_instead_of_display_blocks() {
    for field in ["/limitations", "/blockers", "/changes/0/strategy"] {
        let mut input = input();
        let r = &mut input["remediation"]["recommendations"][0];
        let value = match field {
            "/limitations" => json!(["future_code"]),
            "/blockers" => {
                let mut blocker = blocker();
                blocker["reason"] = "future_code".into();
                blocker["requirement_status"] = "future_code".into();
                json!([blocker])
            }
            _ => json!("future_code"),
        };
        *r.pointer_mut(field).expect("field") = value;
        input["remediation"]["limits"]["reasons"] = json!(["future_code"]);
        let view = project(&input);
        let document = serde_json::to_value(Document::new(&view)).expect("presentation");
        let text = serde_json::to_string(&document["remediation"]).expect("blocks");
        assert!(!text.contains("future_code"), "{text}");
        assert!(text.contains("unfamiliar"), "{text}");
        assert!(
            serde_json::to_string(&document["audit"])
                .expect("facts")
                .contains("future_code")
        );
    }
}

#[test]
fn undetermined_strategy_and_applicability_stay_candidates_with_specific_explanations() {
    for strategy in ["unknown", "future_strategy"] {
        let mut input = input();
        let r = &mut input["remediation"]["recommendations"][0];
        r["changes"][0]["strategy"] = strategy.into();
        r["checks"]["requirements"] = "unchecked".into();
        let mut blocker = blocker();
        blocker["reason"] = "native_applicability_not_checked".into();
        r["blockers"] = json!([blocker]);
        r["limitations"] = json!(["native_applicability_not_checked"]);
        let view = project(&input);
        let plan = plan(&view);
        assert_eq!(plan.heading.as_deref(), Some("Candidate changes"));
        let text = serde_json::to_string(&plan).expect("blocks");
        assert!(
            text.contains(
                "whether the dependency requirements apply to this project was not checked"
            ),
            "{text}"
        );
        assert_eq!(
            text.contains("unfamiliar"),
            strategy == "future_strategy",
            "{text}"
        );
        if strategy == "unknown" {
            assert!(
                plan.changes[0].details[0]
                    .contains("How to apply this candidate has not been determined")
            );
        }
        assert_eq!(
            plan.limitations.len(),
            0,
            "constraint already explains applicability"
        );
        assert_eq!(
            serde_json::to_value(&view).expect("facts")["remediation"]["recommendations"][0]["changes"]
                [0]["strategy"],
            strategy
        );
    }
    let mut input = input();
    input["remediation"]["recommendations"][0]["limitations"] =
        json!(["native_applicability_not_checked", "represented_routes_cut"]);
    let plan = plan(&project(&input));
    assert!(
        plan.limitations[0]
            .contains("whether the dependency requirements apply to this project was not checked")
    );
    assert!(plan.limitations[1].contains("dependency routes recorded in this report"));
}

#[test]
fn external_advisory_groups_keep_local_first_and_item_scoped_partial_impact() {
    let mut input = input();
    let original = input["findings"]["vulnerabilities"][0].clone();
    for (package, advisory, file) in [
        ("omega", "GHSA-a", "package-lock.json"),
        ("omega", "GHSA-z", "package-lock.json"),
        ("omega", "GHSA-a", "other/package-lock.json"),
        ("alpha", "GHSA-alpha", "package-lock.json"),
    ] {
        let mut finding = original.clone();
        finding["coordinate"]["name"] = package.into();
        finding["advisory_id"] = advisory.into();
        finding["paths"] = json!([file]);
        input["findings"]["vulnerabilities"]
            .as_array_mut()
            .expect("findings")
            .push(finding);
    }
    input["summary"]["vulnerabilities"] = 5.into();
    let r = &mut input["remediation"]["recommendations"][0];
    r["outcome"] = "partial".into();
    r["finding_refs"] = json!([0, 1, 2, 3, 4]);
    r["addressed_finding_refs"] = json!([0, 1, 2, 3, 4]);
    r["remaining_finding_refs"] = json!([1]);
    let view = project(&input);
    let plan = plan(&view);
    assert_eq!(
        plan.impact,
        [
            "would address: GHSA-demo; npm:alpha@1.0.0 — GHSA-alpha; npm:omega@1.0.0 — GHSA-a (partly), GHSA-z",
            "still unresolved: npm:omega@1.0.0 — GHSA-a (partly)",
        ]
    );
    assert_eq!(plan.impact[0].matches("npm:omega").count(), 1);
    assert!(!plan.impact[0].contains("GHSA-z (partly)"));
    assert!(!plan.impact.iter().any(|s| s.contains('\n')));
    let facts = serde_json::to_value(&view).expect("facts");
    assert_eq!(
        facts["remediation"]["recommendations"][0]["addressed_findings"]
            .as_array()
            .expect("findings")
            .len(),
        5
    );
}

#[test]
fn constraint_groups_keep_inbound_and_outbound_conflicts_and_distinct_causes() {
    let mut input = input();
    let mut inbound = blocker();
    inbound["owner"] = json!({"name":"current-parent", "version":"1.0.0"});
    inbound["dependency_name"] = "example-parent".into();
    inbound["requested_requirement"] = "^1.0".into();
    inbound["reason"] = "required_request_excludes_target".into();
    let mut outbound = inbound.clone();
    outbound["owner"] = json!({"name":"example-parent", "version":"2.0.0"});
    outbound["dependency_name"] = "example-child".into();
    outbound["requested_requirement"] = ">=2.0".into();
    let mut applicability = inbound.clone();
    applicability["reason"] = "native_applicability_not_checked".into();
    let mut coordination = inbound.clone();
    coordination["reason"] = "checked_occurrence_changed_by_other_recommendation".into();
    coordination["other_target_versions"] = json!(["3.0.0"]);
    let mut other_version = coordination.clone();
    other_version["other_target_versions"] = json!(["4.0.0"]);
    let r = &mut input["remediation"]["recommendations"][0];
    r["changes"][0]["name"] = "example-parent".into();
    r["changes"][0]["target_version"] = "2.0.0".into();
    r["checks"]["requirements"] = "blocked".into();
    r["blockers"] = json!([
        inbound,
        outbound,
        applicability,
        coordination,
        other_version
    ]);
    r["limitations"] = json!([
        "native_applicability_not_checked",
        "checked_occurrence_changed_by_other_recommendation",
        "parent_candidate_limit"
    ]);
    input["remediation"]["limits"]["reasons"] = json!(["parent_candidate_limit"]);
    let view = project(&input);
    let plan = plan(&view);
    assert_eq!(
        plan.constraints.len(),
        3,
        "different causes must stay separate"
    );
    assert_eq!(
        plan.constraints[0].summary,
        "Dependency requirements conflict with this candidate."
    );
    assert_eq!(
        plan.constraints[0].details,
        [
            "current-parent@1.0.0 requires example-parent ^1.0 [package-lock.json]",
            "example-parent@2.0.0 requires example-child >=2.0 [package-lock.json]",
        ]
    );
    assert_eq!(plan.constraints[1].details.len(), 1);
    assert_eq!(
        plan.constraints[2].details.len(),
        1,
        "unscoped versions do not duplicate the same visible request"
    );
    assert_eq!(
        plan.limitations.len(),
        1,
        "only matching displayed explanations are suppressed"
    );
    assert!(plan.limitations[0].contains("service limit"));
    let document = serde_json::to_value(Document::new(&view)).expect("presentation");
    assert!(
        !serde_json::to_string(&document["remediation"])
            .expect("blocks")
            .contains("3.0.0")
    );
    assert_eq!(
        document["audit"]["remediation"]["recommendations"][0]["blockers"][3]["other_target_versions"],
        json!(["3.0.0"])
    );
    assert_eq!(
        document["remediation"]["limits"]
            .as_array()
            .expect("shared limits")
            .len(),
        1
    );
}
