use super::*;
use crate::api::audit::Report;
use crate::test_support::audit::{v2_clean, v2_findings, v2_unsupported};
use serde_json::{Value, json};

fn interpreted(v: &Value) -> Assessment {
    let report = Report::from_bytes(&serde_json::to_vec(v).expect("json")).expect("report");
    super::super::assess(&report, &crate::config::Audit::default()).expect("known")
}

#[test]
fn audit_v2_counts_findings_and_honest_gaps_without_inventing_an_inventory() {
    let a = interpreted(&v2_findings());
    assert!(a.attention && a.incomplete);
    assert!(a.unverified.is_empty(), "{:?}", a.unverified);
    assert_eq!(a.summary.dependencies, 2);
    assert_eq!(a.summary.duplicates, 1);
    let a = interpreted(&v2_clean());
    assert!(
        !a.attention && !a.incomplete && a.unverified.is_empty(),
        "expected a non-empty value"
    );
    let a = interpreted(&v2_unsupported());
    assert!(a.attention && a.incomplete);
    assert!(a.unverified.is_empty(), "{:?}", a.unverified);
}

#[test]
fn audit_v2_bad_coverage_cannot_make_an_empty_findings_report_clean() {
    for (path, value) in [
        ("/coverage/vulnerabilities/candidates_count", json!(0)),
        ("/coverage/vulnerabilities/checked_count", json!(0)),
        ("/coverage/deprecation/checked_count", json!(0)),
        ("/coverage/outdated/unknown_count", json!(u64::MAX)),
        ("/summary/dependencies", json!(0)),
        ("/summary/incomplete_checks", json!(1)),
    ] {
        let mut v = v2_clean();
        *v.pointer_mut(path).expect("path") = value;
        let a = interpreted(&v);
        assert!(
            a.attention && a.incomplete && !a.unverified.is_empty(),
            "{path}"
        );
    }
}

#[test]
fn audit_v2_origin_and_path_mismatches_are_explicitly_unverified() {
    for (path, value) in [
        ("/findings/vulnerabilities/0/paths", json!([])),
        (
            "/unknowns/metadata/0/paths",
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
        let mut v = v2_findings();
        *v.pointer_mut(path).expect("path") = value;
        assert!(!interpreted(&v).unverified.is_empty(), "{path}");
    }
    let mut v = v2_findings();
    v["findings"]["duplicates"][0]["versions"]
        .as_array_mut()
        .expect("versions")
        .pop();
    assert!(
        !interpreted(&v).unverified.is_empty(),
        "expected a non-empty value"
    );
    let mut v = v2_findings();
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
fn audit_v2_gap_counters_reconcile_distinct_sources_and_exclusions() {
    for path in [
        "/summary/vulnerabilities",
        "/summary/excluded_dependencies",
        "/summary/incomplete_sources",
        "/summary/incomplete_checks",
    ] {
        let mut v = v2_findings();
        *v.pointer_mut(path).expect("counter") = 99.into();
        assert!(!interpreted(&v).unverified.is_empty(), "{path}");
    }
    for key in ["sources", "excluded_dependencies"] {
        let mut v = v2_findings();
        let repeated = v["unknowns"][key][0].clone();
        v["unknowns"][key]
            .as_array_mut()
            .expect("gaps")
            .push(repeated);
        assert!(!interpreted(&v).unverified.is_empty(), "{key}");
    }
}

#[test]
fn audit_v2_recorded_unattributed_requirements_need_a_literal_requirement() {
    for requirement in [Value::Null, json!("")] {
        let mut v = v2_findings();
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
fn audit_v2_qualified_advisories_and_open_strings_stay_honest() {
    let mut v = v2_findings();
    v["coverage"]["vulnerabilities"]["checked_count"] = 2.into();
    v["coverage"]["vulnerabilities"]["unknown_count"] = 0.into();
    v["unknowns"]["vulnerabilities"][0]["status"] = "non_affecting".into();
    v["summary"]["incomplete_checks"] = 1.into();
    v["findings"]["duplicates"][0]["versions"][0]["origins"][0]["status"] = "future_origin".into();
    let a = interpreted(&v);
    assert!(a.attention && a.incomplete);
    assert!(a.unverified.is_empty(), "{:?}", a.unverified);
    let mut v = v2_clean();
    for key in ["vulnerabilities", "deprecation", "outdated"] {
        v["coverage"][key]["candidates_count"] = 0.into();
        v["coverage"][key]["checked_count"] = 0.into();
    }
    v["summary"]["dependencies"] = 0.into();
    assert!(
        !interpreted(&v).attention,
        "zero eligible coordinates is valid"
    );
}

#[test]
fn audit_v2_native_mismatch_attention_and_accounting() {
    let mut v = v2_clean();
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
fn audit_v2_recorded_native_requests_require_a_nonempty_range() {
    for requirement in [Value::Null, json!("")] {
        let mut v = v2_clean();
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
