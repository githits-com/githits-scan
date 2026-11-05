use super::*;
use crate::audit::test_support::{report, value};
use serde_json::{Value, json};

fn edge(from: usize, to: usize, disposition: &str) -> Value {
    let mut r = value()["remediation"]["trace"]["relations"][1].clone();
    r["from_ref"] = from.into();
    r["to_ref"] = to.into();
    r["disposition"] = disposition.into();
    r
}
fn push(value: &mut Value, path: &str, row: Value) {
    value
        .pointer_mut(path)
        .expect("array")
        .as_array_mut()
        .expect("array")
        .push(row);
}

#[test]
fn audit_explain_parent_requests_and_no_recommendation_use_same_seeds() {
    let mut input = value();
    input["remediation"]["recommendations"] = json!([]);
    let report = report(&input);
    let selected = select(&report, "npm:demo@1.0.0").expect("match");
    assert_eq!(selected.finding_indices, BTreeSet::from([0]));
    assert_eq!(selected.sources.len(), 1);
    let source = &selected.sources[0];
    assert_eq!((source.nodes.len(), source.relations.len()), (3, 2));
    assert_eq!(source.relations[0].requests[0].path, "package.json");
    assert_eq!(
        source.relations[1].requests[0]
            .requested_requirement
            .as_deref(),
        Some("<1.1.0")
    );
    assert!(source.issues.is_empty() && !source.has_cycle);
    assert!(select(&report, "npm:demo@2.0.0").is_none());
}

#[test]
fn audit_explain_diamond_cycle_keeps_each_edge_once() {
    let mut input = value();
    let mut extra = input["remediation"]["trace"]["occurrences"][1].clone();
    extra["name"] = "other-parent".into();
    extra["coordinate"]["name"] = "other-parent".into();
    push(&mut input, "/remediation/trace/occurrences", extra);
    for (a, b) in [(2, 3), (3, 0), (1, 3), (3, 1)] {
        push(
            &mut input,
            "/remediation/trace/relations",
            edge(a, b, "standard_dependency"),
        );
    }
    let report = report(&input);
    let selected = select(&report, "npm:demo@1.0.0").expect("match");
    let source = &selected.sources[0];
    assert_eq!((source.nodes.len(), source.relations.len()), (4, 6));
    assert!(source.has_cycle);
}

#[test]
fn audit_explain_unrelated_vulnerability_edges_do_not_follow_shared_root() {
    let mut input = value();
    let mut node = input["remediation"]["trace"]["occurrences"][0].clone();
    node["coordinate"]["name"] = "unrelated".into();
    node["name"] = "unrelated".into();
    push(&mut input, "/remediation/trace/occurrences", node);
    push(
        &mut input,
        "/remediation/trace/relations",
        edge(2, 3, "standard_dependency"),
    );
    let mut other = input["findings"]["vulnerabilities"][0].clone();
    other["coordinate"]["name"] = "unrelated".into();
    push(&mut input, "/findings/vulnerabilities", other);
    let report = report(&input);
    let selected = select(&report, "npm:demo@1.0.0").expect("match");
    assert_eq!(
        (
            selected.sources[0].nodes.len(),
            selected.sources[0].relations.len()
        ),
        (3, 2)
    );
    assert!(
        !selected.sources[0]
            .nodes
            .iter()
            .any(|n| n.package.contains("unrelated"))
    );
}

#[test]
fn audit_explain_same_coordinate_copies_and_other_sources_keep_identity() {
    let mut input = value();
    let copy = input["remediation"]["trace"]["occurrences"][0].clone();
    push(&mut input, "/remediation/trace/occurrences", copy);
    push(
        &mut input,
        "/remediation/trace/relations",
        edge(1, 3, "standard_dependency"),
    );
    for i in 0..3 {
        let mut copy = input["remediation"]["trace"]["occurrences"][i].clone();
        copy["path"] = "other/package-lock.json".into();
        push(&mut input, "/remediation/trace/occurrences", copy);
    }
    for (a, b) in [(6, 5), (5, 4)] {
        let mut r = edge(a, b, "standard_dependency");
        r["path"] = "other/package-lock.json".into();
        push(&mut input, "/remediation/trace/relations", r);
    }
    input["findings"]["vulnerabilities"][0]["paths"] =
        json!(["package-lock.json", "other/package-lock.json"]);
    let report = report(&input);
    let selected = select(&report, "npm:demo@1.0.0").expect("match");
    assert_eq!(selected.sources.len(), 2);
    let primary = selected
        .sources
        .iter()
        .find(|s| s.file == "package-lock.json")
        .expect("source");
    assert_eq!(
        primary
            .nodes
            .iter()
            .filter(|n| n.package == "npm:demo@1.0.0")
            .count(),
        2
    );
    assert_eq!(
        primary
            .nodes
            .iter()
            .map(|n| &n.id)
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    for source in &selected.sources {
        assert!(source.issues.is_empty(), "{:?}", source.issues);
    }
}

#[test]
fn audit_explain_nonpositive_and_activation_observations_are_not_ancestors() {
    let mut input = value();
    for name in ["indirect", "feature"] {
        let mut n = input["remediation"]["trace"]["occurrences"][1].clone();
        n["name"] = name.into();
        n["coordinate"]["name"] = name.into();
        push(&mut input, "/remediation/trace/occurrences", n);
    }
    push(
        &mut input,
        "/remediation/trace/relations",
        edge(3, 0, "indirect_root_seed"),
    );
    let mut activation = edge(1, 4, "activation");
    activation["kind"] = "feature_activation".into();
    push(&mut input, "/remediation/trace/relations", activation);
    let report = report(&input);
    let selected = select(&report, "npm:demo@1.0.0").expect("match");
    let source = &selected.sources[0];
    assert_eq!((source.relations.len(), source.observations.len()), (2, 2));
    assert_eq!(source.nodes.iter().filter(|n| n.ancestry).count(), 3);
    assert!(
        source
            .nodes
            .iter()
            .filter(|n| !n.ancestry)
            .all(|n| n.package.contains("indirect") || n.package.contains("feature"))
    );
    assert!(
        source
            .observations
            .iter()
            .all(|r| r.from.is_some() && r.to.is_some())
    );
}

#[test]
fn audit_explain_bad_references_and_source_associations_are_explicit() {
    let mut input = value();
    input["remediation"]["trace"]["relations"][0]["from_ref"] = 999.into();
    input["remediation"]["recommendations"][0]["occurrence_refs"] = json!([999]);
    let report = report(&input);
    let selected = select(&report, "npm:demo@1.0.0").expect("match");
    assert!(
        selected
            .issues
            .contains("recommendation_occurrence_refs_unverified")
    );
    assert!(
        selected.sources[0]
            .issues
            .contains("relation_refs_unverified")
    );
    assert_eq!(selected.sources[0].relations.len(), 1);
    input["remediation"]["trace"]["occurrences"][1]["path"] = "other.lock".into();
    let report = crate::audit::test_support::report(&input);
    let selected = select(&report, "npm:demo@1.0.0").expect("match");
    assert!(
        selected.sources[0]
            .issues
            .contains("relation_source_unverified")
    );
    assert!(
        selected.sources[0].relations.is_empty(),
        "expected no relations, found {}",
        selected.sources[0].relations.len()
    );
}

#[test]
fn audit_explain_unavailable_trace_does_not_claim_missing_occurrences() {
    for status in ["not_retained", "future_status"] {
        let mut input = value();
        input["remediation"]["trace"]["status"] = status.into();
        input["remediation"]["trace"]["occurrences"] = json!([]);
        input["remediation"]["trace"]["relations"] = json!([]);
        let report = report(&input);
        let selected = select(&report, "npm:demo@1.0.0").expect("match");
        assert!(
            selected.sources.is_empty(),
            "expected no sources, found {}",
            selected.sources.len()
        );
        assert_eq!(selected.issues.len(), 1);
    }
    let mut input = value();
    input["remediation"]["trace"]["occurrences"][0]["coordinate"]["name"] = "different".into();
    let report = report(&input);
    let selected = select(&report, "npm:demo@1.0.0").expect("match");
    assert!(
        selected.sources[0]
            .issues
            .contains("no_recorded_occurrence")
    );
}

#[test]
fn audit_explain_null_endpoint_and_coverage_gaps_remain_observations() {
    let mut input = value();
    input["remediation"]["trace"]["relations"][0]["from_ref"] = Value::Null;
    input["remediation"]["trace"]["relations"][0]["disposition"] = "unexported_endpoint".into();
    input["remediation"]["trace"]["occurrences"][0]["dependency_coverage"] =
        json!({"state":"incomplete","reasons":["outgoing_not_recorded"]});
    input["remediation"]["trace"]["occurrences"][1]["dependency_coverage"] = Value::Null;
    let report = report(&input);
    let result = select(&report, "npm:demo@1.0.0").expect("match");
    let source = &result.sources[0];
    assert_eq!(source.relations.len(), 1);
    assert_eq!(source.observations.len(), 1);
    assert!(source.observations[0].from.is_none());
    assert_eq!(source.observations[0].requests[0].owner.name, "application");
    assert!(
        source.issues.contains("dependency_coverage_incomplete")
            && source.issues.contains("dependency_coverage_unknown")
    );
    assert!(source.nodes.iter().all(|n| !n.project_root));
}

#[test]
fn audit_explain_absent_remediation_retains_problem_without_inventing_routes() {
    let mut input = value();
    input.as_object_mut().expect("report").remove("remediation");
    let report = report(&input);
    let result = select(&report, "npm:demo@1.0.0").expect("match");
    assert_eq!(result.finding_indices, BTreeSet::from([0]));
    assert!(
        result.sources.is_empty(),
        "expected no sources, found {}",
        result.sources.len()
    );
    assert_eq!(result.issues, BTreeSet::from(["remediation_unavailable"]));
}

#[test]
fn audit_explain_partial_copy_scopes_link_changed_and_remaining_routes() {
    let mut input = value();
    let copy = input["remediation"]["trace"]["occurrences"][0].clone();
    push(&mut input, "/remediation/trace/occurrences", copy);
    let mut parent = input["remediation"]["trace"]["occurrences"][1].clone();
    parent["name"] = "other-parent".into();
    parent["coordinate"]["name"] = "other-parent".into();
    parent["version"] = "3.0.0".into();
    parent["coordinate"]["version"] = "3.0.0".into();
    push(&mut input, "/remediation/trace/occurrences", parent);
    let mut root_request = input["remediation"]["trace"]["relations"][0].clone();
    root_request["to_ref"] = 4.into();
    root_request["requests"][0]["requested_requirement"] = "^3.0.0".into();
    push(&mut input, "/remediation/trace/relations", root_request);
    let mut pinned = edge(4, 3, "standard_dependency");
    pinned["requests"][0]["owner"] = json!({"name":"other-parent","version":"3.0.0"});
    pinned["requests"][0]["requested_requirement"] = "1.0.0".into();
    push(&mut input, "/remediation/trace/relations", pinned);
    let rec = &mut input["remediation"]["recommendations"][0];
    rec["outcome"] = "partial".into();
    rec["occurrence_refs"] = json!([0, 3]);
    rec["remaining_occurrence_refs"] = json!([3]);
    rec["remaining_finding_refs"] = json!([0]);
    let report = report(&input);
    let result = select(&report, "npm:demo@1.0.0").expect("match");
    let scope = &result.recommendation_scopes[&0];
    assert_eq!(scope.subject.nodes.len(), 2);
    let changed = &scope.changes[0].as_ref().expect("changed copies").nodes[0];
    let remaining = &scope.remaining.as_ref().expect("remaining copies").nodes[0];
    assert_ne!(changed.node, remaining.node);
    assert_eq!(changed.source, remaining.source);
    let source = result
        .sources
        .iter()
        .find(|s| s.id == remaining.source)
        .expect("source");
    let incoming = source
        .relations
        .iter()
        .find(|r| r.to.as_deref() == Some(remaining.node.as_str()))
        .expect("remaining requester");
    let parent = source
        .nodes
        .iter()
        .find(|n| Some(n.id.as_str()) == incoming.from.as_deref())
        .expect("parent");
    assert_eq!(parent.package, "npm:other-parent@3.0.0");
}

#[test]
fn audit_explain_scope_absence_and_unrepresented_refs_are_not_empty_claims() {
    let mut input = value();
    let rec = &mut input["remediation"]["recommendations"][0];
    rec.as_object_mut()
        .expect("record")
        .remove("remaining_occurrence_refs");
    rec["changes"][0]
        .as_object_mut()
        .expect("change")
        .remove("occurrence_refs");
    rec["occurrence_refs"] = json!([0, 0, 999]);
    let report = report(&input);
    let result = select(&report, "npm:demo@1.0.0").expect("match");
    let scope = &result.recommendation_scopes[&0];
    assert!(scope.remaining.is_none());
    assert!(scope.changes[0].is_none());
    assert_eq!(scope.subject.nodes.len(), 1);
    assert_eq!(scope.subject.not_in_selected_trace, 1);
    assert!(
        result
            .issues
            .contains("recommendation_occurrence_refs_unverified")
    );
}

#[test]
fn audit_explain_unknown_recommendation_detail_does_not_interpret_copy_refs() {
    let mut input = value();
    input["remediation"]["recommendations"][0]["detail_status"] = "future_detail".into();
    let report = report(&input);
    let result = select(&report, "npm:demo@1.0.0").expect("match");
    assert_eq!(result.recommendation_indices, BTreeSet::from([0]));
    assert!(
        result.recommendation_scopes.is_empty(),
        "expected no recommendation scopes, found {}",
        result.recommendation_scopes.len()
    );
    assert!(
        result
            .issues
            .contains("recommendation_copy_detail_unavailable")
    );
    assert_eq!(result.sources[0].relations.len(), 2);
}

#[test]
fn audit_explain_relation_declared_path_mismatch_is_not_silently_discarded() {
    let mut input = value();
    input["remediation"]["trace"]["relations"][0]["path"] = "other/package-lock.json".into();
    let report = report(&input);
    let result = select(&report, "npm:demo@1.0.0").expect("match");
    assert!(
        result.sources[0]
            .issues
            .contains("relation_source_unverified")
    );
    assert_eq!(result.sources[0].relations.len(), 1);
}
