use super::*;
use crate::api::audit::Report;
use crate::test_support::audit::{clean, findings as fixture};

fn interpreted(value: &serde_json::Value) -> Assessment {
    let r = Report::from_bytes(&serde_json::to_vec(value).expect("json")).expect("report");
    assess(&r).expect("known")
}

#[test]
fn audit_interpretation_counts_combined_versions_without_assessing_advisories() {
    let a = interpreted(&fixture());
    assert!(a.attention);
    assert!(a.unverified.is_empty(), "{:?}", a.unverified);
    assert_eq!(a.summary.dependencies, 2);
    assert_eq!(a.summary.duplicates, 1);
    let a = interpreted(&clean());
    assert!(!a.attention, "{:?}", a.unverified);
    assert_eq!(
        a.summary.duplicates, 0,
        "repeated one version is not a duplicate group"
    );
}

#[test]
fn audit_missing_coverage_or_bad_references_never_qualify_as_clean() {
    for mutation in ["candidate", "owner", "summary", "exclusion", "reference"] {
        let mut value = clean();
        match mutation {
            "candidate" => value["coverage"]["vulnerabilities"]["candidates_count"] = 0.into(),
            "owner" => value["coverage"]["sources"] = serde_json::json!([]),
            "summary" => value["summary"]["dependencies"] = 0.into(),
            "exclusion" => {
                value["unknowns"]["excluded_occurrences"] =
                    serde_json::json!([{"occurrence_id":"missing","reason":"new_reason"}]);
            }
            "reference" => {
                value["inputs"]["declarations"][0]["manifest_path"] = "missing.json".into();
            }
            _ => unreachable!(),
        }
        let a = interpreted(&value);
        assert!(a.attention && !a.unverified.is_empty(), "{mutation}");
    }
}

#[test]
fn audit_partial_and_unfamiliar_resolution_and_diagnostics_are_attention() {
    for status in ["partial", "timeout", "max_iterations", "future_status"] {
        let mut value = clean();
        value["inputs"]["resolutions"] =
            serde_json::json!([{"path":"package.json","status":status,"diagnostics":[]}]);
        assert!(interpreted(&value).attention, "{status}");
    }
    let mut value = clean();
    value["inputs"]["resolutions"] = serde_json::json!([{"path":"package.json","status":"complete","diagnostics":[{"name":"demo","reason":"non_registry_source"}]}]);
    assert!(interpreted(&value).attention);
    value["inputs"]["resolutions"][0]["diagnostics"] = serde_json::json!([]);
    assert!(!interpreted(&value).attention);
}

#[test]
fn audit_openapi_example_is_usable_without_mandatory_manifest_source_rows() {
    let report = Report::from_bytes(include_bytes!(
        "../../tests/fixtures/audit/openapi-example.json"
    ))
    .expect("public example");
    let a = assess(&report).expect("known");
    assert!(a.attention);
    assert!(a.unverified.is_empty(), "{:?}", a.unverified);
}
