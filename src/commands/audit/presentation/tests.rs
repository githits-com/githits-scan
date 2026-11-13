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
    for (reason, prefix, explanation) in [
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
            Some("applying this change requires updating the project requirement"),
        ),
        (
            "project_preference_change",
            "constraint:",
            Some("applying this change requires updating the project preference"),
        ),
        (
            "future_reason\n\u{1b}[2J",
            "constraint:",
            Some("future_reason\\n\\u{1b}[2J"),
        ),
        (
            "unsupported_selector",
            "constraint:",
            Some("dependency requirement could not be evaluated"),
        ),
    ] {
        let mut input = input();
        let mut blocker = blocker();
        blocker["reason"] = reason.into();
        input["remediation"]["recommendations"][0]["blockers"] = json!([blocker]);
        input["remediation"]["recommendations"][0]["checks"]["requirements"] = "blocked".into();
        let plan = plan(&project(&input));
        let summary = &plan.constraints[0].summary;
        assert!(summary.starts_with(prefix), "{summary}");
        assert!(
            summary.contains("express@5.1.0 requires cookie ^0.7.1"),
            "{summary}"
        );
        if let Some(explanation) = explanation {
            assert!(summary.contains(explanation), "{summary}");
        } else {
            assert!(!summary.contains("excludes the target"), "{summary}");
        }
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
fn explanation_blocks_escape_untrusted_controls_and_omit_opaque_evidence() {
    let mut input = input();
    let mut blocker = blocker();
    blocker["owner"]["name"] = "owner\n\u{1b}[2J <&|>".into();
    blocker["reason"] = "project_request_change".into();
    blocker["context"] = json!({"private":"must not appear"});
    input["remediation"]["recommendations"][0]["blockers"] = json!([blocker]);
    let plan = plan(&project(&input));
    let text = &plan.constraints[0].summary;
    assert!(text.contains("owner\\n\\u{1b}[2J <&|>"), "{text}");
    assert!(!text.contains(['\n', '\u{1b}']));
    let json = serde_json::to_string(&plan).expect("JSON");
    assert!(!json.contains("must not appear"));
}
