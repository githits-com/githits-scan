//! Native applicability, unavailable observations and partial withdrawal remain independent.
use super::*;
use crate::support::audit::{facet, pypi_not_applicable};
use serde_json::{Value, json};

fn execute(value: &Value, args: &[&str]) -> Output {
    let root = repo();
    let mock = server(&serde_json::to_vec(value).expect("report"));
    let output = run(root.path(), Some(&mock.origin()), args);
    assert_eq!(mock.requests().len(), 3);
    assert!(output.stderr.is_empty(), "{}", stderr(&output));
    output
}

fn result(value: &Value, exit: i32) -> Value {
    let output = execute(value, &["--json", "--quiet"]);
    assert_eq!(output.status.code(), Some(exit), "{}", stdout(&output));
    serde_json::from_slice(&output.stdout).expect("JSON view")
}

#[test]
fn audit_applicability_native_pypi_and_mixed_coverage_do_not_claim_checked_negatives() {
    for checked in [0, 1] {
        let mut value = pypi_not_applicable();
        value["lifecycle"]["coverage"]["deprecation"] =
            facet(2, checked, 0, 0, 2 - checked, "pypi");
        let view = result(&value, 0);
        assert_eq!(view["incomplete"], false);
        assert!(view.get("issues").is_none());
        assert_eq!(
            view["lifecycle"]["coverage"]["deprecation"]["checked_count"],
            checked
        );
        assert_eq!(
            view["lifecycle"]["coverage"]["deprecation"]["not_applicable_count"],
            2 - checked
        );
        assert_eq!(view["lifecycle"]["findings"], json!([]));
        let text = stdout(&execute(&value, &["--no-color", "--quiet"]));
        assert!(!text.contains("Incomplete checks") && !text.contains("not a checked negative"));
        let details = stdout(&execute(&value, &["--no-color", "--quiet", "--details"]));
        assert!(
            details.contains("deprecation does not apply")
                && details.contains("not a checked negative")
        );
    }
}

#[test]
fn audit_applicability_native_unknowns_keep_the_actual_cause() {
    for (reason, explanation) in [
        ("metadata_unavailable", "package metadata was unavailable"),
        ("lookup_failed", "could not obtain the package metadata"),
        (
            "future_reason",
            "the service supplied no recognized explanation for this outcome",
        ),
        (
            "native_evidence_unavailable",
            "stored metadata does not include the native observation",
        ),
    ] {
        let mut value = pypi_not_applicable();
        value["lifecycle"]["coverage"]["deprecation"] = facet(2, 0, 1, 0, 1, "pypi");
        value["lifecycle"]["unknowns"] = json!([{"coordinate":{"registry":"pypi","name":"demo","version":"1.0.0"},"paths":["package-lock.json"],"check":"deprecation","status":"unknown","reason":reason}]);
        value["summary"]["incomplete_checks"] = 1.into();
        let view = result(&value, 1);
        assert_eq!(view["incomplete"], true);
        assert_eq!(view["lifecycle"]["unknowns"][0]["reason"], reason);
        assert!(
            !view["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .any(|i| i["check"] == "report")
        );
        let text = stdout(&execute(&value, &["--no-color", "--quiet"]));
        assert!(
            text.contains(explanation)
                && text.contains("pypi:demo@1.0.0")
                && text.contains("package-lock.json")
        );
        assert!(!text.contains(reason));
    }
}

#[test]
fn audit_applicability_partial_file_withdrawal_can_coexist_with_unknown() {
    let mut value = pypi_not_applicable();
    let coordinate = json!({"registry":"pypi","name":"demo","version":"1.0.0"});
    value["lifecycle"]["findings"] = json!([{"registry":"pypi","name":"demo","version":"1.0.0","category":"withdrawal","kind":"partially_yanked","scope":"files","source":"pypi.file_availability","observations":[{"source_version":"1.0.0","observed_at":null,"reason":"A published file was withdrawn","reason_codes":[],"replacement":null,"affected":[{"coordinate":coordinate,"paths":["package-lock.json"]}]}]}]);
    value["lifecycle"]["coverage"]["withdrawal"] = facet(2, 1, 1, 0, 0, "pypi");
    value["lifecycle"]["unknowns"] = json!([{"coordinate":coordinate,"paths":["package-lock.json"],"check":"withdrawal","status":"unknown","reason":"native_evidence_unavailable"}]);
    value["summary"]["lifecycle"] = 1.into();
    value["summary"]["incomplete_checks"] = 1.into();
    let view = result(&value, 1);
    assert_eq!(view["incomplete"], true);
    assert_eq!(view["summary"]["vulnerabilities"], 0);
    assert_eq!(view["summary"]["lifecycle"], 1);
    assert!(
        !view["issues"]
            .as_array()
            .expect("issues")
            .iter()
            .any(|i| i["check"] == "report")
    );
    let text = stdout(&execute(&value, &["--no-color", "--quiet"]));
    assert!(
        text.contains("partly yanked (affected files only)")
            && text.contains("A published file was withdrawn")
    );
    assert!(!text.contains("partially_yanked") && !text.contains("native_evidence_unavailable"));
}

#[test]
fn audit_applicability_zero_candidates_do_not_prove_health() {
    let mut value = pypi_not_applicable();
    value["summary"]["dependencies"] = 0.into();
    for check in ["vulnerabilities", "outdated"] {
        value["coverage"][check]["candidates_count"] = 0.into();
        value["coverage"][check]["checked_count"] = 0.into();
    }
    for (_, coverage) in value["lifecycle"]["coverage"]
        .as_object_mut()
        .expect("facets")
    {
        *coverage = facet(0, 0, 0, 0, 0, "pypi");
    }
    let view = result(&value, 0);
    assert_eq!(view["incomplete"], false);
    let text = stdout(&execute(&value, &["--no-color", "--quiet"]));
    assert!(text.contains("available evidence") && !text.contains("fully checked"));
}
