use super::*;
use crate::api::audit::Report;
use crate::test_support::audit::{clean, findings, unsupported};
use serde_json::{Value, json};

fn interpreted(v: &Value) -> Assessment {
    let report = Report::from_bytes(&serde_json::to_vec(v).expect("json")).expect("report");
    super::assess(&report, &crate::config::Audit::default())
}

#[test]
fn audit_report_counts_findings_and_honest_gaps_without_inventing_an_inventory() {
    let a = interpreted(&findings());
    assert!(a.attention && a.incomplete);
    assert!(a.unverified.is_empty(), "{:?}", a.unverified);
    assert_eq!(a.summary.dependencies, 2);
    assert_eq!(a.summary.duplicates, 1);
    let a = interpreted(&clean());
    assert!(
        !a.attention && !a.incomplete && a.unverified.is_empty(),
        "expected a non-empty value"
    );
    let a = interpreted(&unsupported());
    assert!(a.attention && a.incomplete);
    assert!(a.unverified.is_empty(), "{:?}", a.unverified);
}

#[test]
fn audit_report_bad_coverage_cannot_make_an_empty_findings_report_clean() {
    for (path, value) in [
        ("/coverage/vulnerabilities/candidates_count", json!(0)),
        ("/coverage/vulnerabilities/checked_count", json!(0)),
        ("/lifecycle/coverage/deprecation/checked_count", json!(0)),
        ("/coverage/outdated/unknown_count", json!(u64::MAX)),
        ("/summary/dependencies", json!(0)),
        ("/summary/incomplete_checks", json!(1)),
    ] {
        let mut v = clean();
        *v.pointer_mut(path).expect("path") = value;
        let a = interpreted(&v);
        assert!(
            a.attention && a.incomplete && !a.unverified.is_empty(),
            "{path}"
        );
    }
}

#[test]
fn audit_report_origin_and_path_mismatches_are_explicitly_unverified() {
    for (path, value) in [
        ("/findings/vulnerabilities/0/paths", json!([])),
        (
            "/lifecycle/unknowns/0/paths",
            json!(["web/package-lock.json", "web/package-lock.json"]),
        ),
        (
            "/findings/duplicates/0/versions/0/origins/0/path",
            json!("wrong.lock"),
        ),
        ("/findings/duplicates/0/versions/0/origins", json!([])),
        ("/findings/duplicates/0/versions/1/version", json!("1.0.0")),
        (
            "/findings/duplicates/0/versions/0/origins/0/requested_requirement",
            Value::Null,
        ),
    ] {
        let mut v = findings();
        *v.pointer_mut(path).expect("path") = value;
        assert!(!interpreted(&v).unverified.is_empty(), "{path}");
    }
    let mut v = findings();
    v["findings"]["duplicates"][0]["versions"]
        .as_array_mut()
        .expect("versions")
        .pop();
    assert!(
        !interpreted(&v).unverified.is_empty(),
        "expected a non-empty value"
    );
    let mut v = findings();
    let repeated = v["findings"]["duplicates"][0].clone();
    v["findings"]["duplicates"]
        .as_array_mut()
        .expect("groups")
        .push(repeated);
    v["summary"]["duplicates"] = 2.into();
    assert!(
        !interpreted(&v).unverified.is_empty(),
        "expected a non-empty value"
    );
}

#[test]
fn audit_report_gap_counters_reconcile_distinct_sources_and_exclusions() {
    for path in [
        "/summary/vulnerabilities",
        "/summary/excluded_dependencies",
        "/summary/incomplete_sources",
        "/summary/incomplete_checks",
    ] {
        let mut v = findings();
        *v.pointer_mut(path).expect("counter") = 99.into();
        assert!(!interpreted(&v).unverified.is_empty(), "{path}");
    }
    for key in ["sources", "excluded_dependencies"] {
        let mut v = findings();
        let repeated = v["unknowns"][key][0].clone();
        v["unknowns"][key]
            .as_array_mut()
            .expect("gaps")
            .push(repeated);
        assert!(!interpreted(&v).unverified.is_empty(), "{key}");
    }
}

#[test]
fn audit_report_recorded_unattributed_requirements_need_a_literal_requirement() {
    for requirement in [Value::Null, json!("")] {
        let mut v = findings();
        let origin = &mut v["findings"]["duplicates"][0]["unattributed_requirements"][0];
        origin["requirement_status"] = "recorded".into();
        origin["requested_requirement"] = requirement;
        assert!(
            !interpreted(&v).unverified.is_empty(),
            "expected a non-empty value"
        );
    }
}

#[test]
fn audit_report_qualified_advisories_and_open_strings_stay_honest() {
    let mut v = findings();
    v["coverage"]["vulnerabilities"]["checked_count"] = 2.into();
    v["coverage"]["vulnerabilities"]["unknown_count"] = 0.into();
    v["unknowns"]["vulnerabilities"][0]["status"] = "non_affecting".into();
    v["summary"]["incomplete_checks"] = 1.into();
    v["findings"]["duplicates"][0]["versions"][0]["origins"][0]["status"] = "future_origin".into();
    let a = interpreted(&v);
    assert!(a.attention && a.incomplete);
    assert!(a.unverified.is_empty(), "{:?}", a.unverified);
    let mut v = clean();
    for key in ["vulnerabilities", "outdated"] {
        v["coverage"][key]["candidates_count"] = 0.into();
        v["coverage"][key]["checked_count"] = 0.into();
    }
    for (_, facet) in v["lifecycle"]["coverage"]
        .as_object_mut()
        .expect("coverage")
    {
        *facet = crate::test_support::audit::facet(0, 0, 0, 0, 0, "npm");
    }
    v["summary"]["dependencies"] = 0.into();
    assert!(
        !interpreted(&v).attention,
        "zero eligible coordinates is valid"
    );
}

#[test]
fn audit_report_native_mismatch_attention_and_accounting() {
    let mut v = clean();
    v["findings"]["manifest_lock_mismatches"] = json!([{
        "path":"Cargo.lock", "declaration_path":"Cargo.toml", "name":"demo",
        "requested_requirement":"2", "requirement_status":"recorded",
        "locked_versions":["1.0.0"], "recorded_requirements":["1"],
        "declared_scope":"normal", "recorded_scopes":["normal"],
        "reason":"locked_version_does_not_satisfy_request"
    }]);
    let assessment = interpreted(&v);
    assert!(assessment.attention && !assessment.incomplete);
    assert!(
        assessment.unverified.is_empty(),
        "{:?}",
        assessment.unverified
    );
    v["summary"]["manifest_lock_mismatches"] = 1.into();
    assert!(
        interpreted(&v).unverified.is_empty(),
        "{:?}",
        interpreted(&v).unverified
    );
    v["summary"]["manifest_lock_mismatches"] = 0.into();
    assert!(interpreted(&v).incomplete);
    v["summary"]["manifest_lock_mismatches"] = 1.into();
    for (field, invalid) in [
        ("path", json!("")),
        ("declaration_path", json!("")),
        ("requested_requirement", Value::Null),
        ("requested_requirement", json!("")),
    ] {
        let mut invalid_report = v.clone();
        invalid_report["findings"]["manifest_lock_mismatches"][0][field] = invalid;
        assert!(interpreted(&invalid_report).incomplete, "{field}");
    }
}

#[test]
fn audit_report_recorded_native_requests_require_a_nonempty_range() {
    for requirement in [Value::Null, json!("")] {
        let mut v = clean();
        v["unknowns"]["resolution"] = json!([{
            "path":"Cargo.lock", "name":"missing", "reason":"unmet_dependency",
            "requester":{"name":"app","version":null}, "kind":"FUTURE_KIND",
            "requested_requirement":requirement, "requirement_status":"recorded"
        }]);
        assert!(
            interpreted(&v)
                .unverified
                .contains("native requests or declarations lack a recorded requirement")
        );
    }
}

#[test]
fn audit_native_grouping_and_attribution_inconsistencies_are_incomplete() {
    for mutation in [
        "event",
        "observation",
        "affected",
        "paths",
        "scope",
        "count",
        "facet",
    ] {
        let mut value = findings();
        let event = &mut value["lifecycle"]["findings"][0];
        match mutation {
            "event" => {
                let repeated = event.clone();
                value["lifecycle"]["findings"]
                    .as_array_mut()
                    .expect("events")
                    .push(repeated);
                value["summary"]["lifecycle"] = 2.into();
            }
            "observation" => {
                let repeated = event["observations"][0].clone();
                event["observations"]
                    .as_array_mut()
                    .expect("observations")
                    .push(repeated);
            }
            "affected" => {
                let repeated = event["observations"][0]["affected"][0].clone();
                event["observations"][0]["affected"]
                    .as_array_mut()
                    .expect("references")
                    .push(repeated);
            }
            "paths" => event["observations"][0]["affected"][0]["paths"] = json!([]),
            "scope" => event["scope"] = "package".into(),
            "count" => value["summary"]["lifecycle"] = 0.into(),
            _ => {
                value["lifecycle"]["coverage"]["withdrawal"]["not_collected_count"] =
                    u64::MAX.into();
            }
        }
        let assessment = interpreted(&value);
        assert!(
            assessment.attention && assessment.incomplete && !assessment.unverified.is_empty(),
            "{mutation}"
        );
    }
}

#[test]
fn audit_native_retained_warning_counts_once_without_inventing_a_native_event() {
    let mut value = clean();
    value["lifecycle"]["retained_warnings"] = json!([{
        "coordinate":{"registry":"nuget","name":"Demo","version":"1.0.0"},
        "paths":["packages.lock.json"],"classification":"legacy_unclassified","reason":"Publisher warning"}]);
    value["summary"]["retained_lifecycle_warnings"] = 1.into();
    let assessment = interpreted(&value);
    assert!(assessment.attention && !assessment.incomplete);
    assert!(
        assessment.unverified.is_empty(),
        "{:?}",
        assessment.unverified
    );
    assert_eq!(assessment.summary.lifecycle, 0);
    assert_eq!(assessment.summary.retained_lifecycle_warnings, 1);
}

#[test]
fn audit_report_outdated_coverage_requires_actual_checked_evidence() {
    let mut value = clean();
    value["coverage"]["outdated"]["checked_count"] = 0.into();
    // Only native lifecycle facets define applicability; extra metadata fields
    // cannot replace missing checked outdated evidence.
    value["coverage"]["outdated"]["not_applicable_count"] = 2.into();
    value["coverage"]["outdated"]["not_applicable_registries"] = json!(["pypi"]);
    let assessment = interpreted(&value);
    assert!(assessment.attention && assessment.incomplete);
    assert!(
        assessment
            .unverified
            .contains("metadata coverage does not account for eligible packages")
    );
}
