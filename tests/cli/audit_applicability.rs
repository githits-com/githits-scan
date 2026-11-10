//! Explicit applicability is coverage, independent of findings and real gaps.
use super::*;
use crate::support::audit::{metadata_coverage, pypi_not_applicable};
use serde_json::{Value, json};

fn execute(value: &Value, args: &[&str]) -> Output {
    let root = repo();
    let server = server(&serde_json::to_vec(value).expect("report"));
    let output = run(root.path(), Some(&server.origin()), args);
    assert_eq!(server.requests().len(), 3);
    assert!(output.stderr.is_empty(), "{}", stderr(&output));
    output
}

fn result(value: &Value, exit: i32) -> Value {
    let output = execute(value, &["--json", "--quiet"]);
    assert_eq!(output.status.code(), Some(exit), "{}", stdout(&output));
    serde_json::from_slice(&output.stdout).expect("JSON view")
}

#[test]
fn audit_applicability_pypi_and_mixed_coverage_are_visible_without_issues() {
    for (version, checked) in [(1, 0), (1, 1), (2, 0), (2, 1)] {
        let mut value = pypi_not_applicable(version);
        if version == 1 && checked == 1 {
            value["occurrences"][0]["coordinate"]["registry"] = "npm".into();
        }
        value["coverage"]["deprecation"]["checked_count"] = checked.into();
        value["coverage"]["deprecation"]["not_applicable_count"] = (2 - checked).into();
        let expected = format!(
            "deprecation coverage: {checked} of 2 packages checked; {} not applicable (pypi)",
            2 - checked
        );
        let view = result(&value, 0);
        assert_eq!(view["incomplete"], false);
        assert!(view.get("issues").is_none());
        assert!(view.get("deprecated").is_none());
        assert_eq!(value["unknowns"]["metadata"], json!([]));
        assert_eq!(value["summary"]["incomplete_checks"], 0);
        assert_eq!(view["limitations"], json!([expected]));
        let output = execute(&value, &["--no-color", "--quiet"]);
        assert_eq!(output.status.code(), Some(0));
        assert!(stdout(&output).contains(&expected));
        assert!(!stdout(&output).contains("Incomplete checks"));
    }
}

fn gap(version: u8, status: &str, reason: Option<&str>) -> Value {
    let mut value = pypi_not_applicable(version);
    value["coverage"]["deprecation"]["not_applicable_count"] = 1.into();
    let mut row = json!({"coordinate":{"registry":"pypi","name":"demo","version":"1.0.0"},
        "check":"deprecation","status":status,"reason":reason});
    if version == 1 {
        row["occurrence_ids"] = json!(["one"]);
    } else {
        row["paths"] = json!(["package-lock.json"]);
    }
    value["unknowns"]["metadata"] = json!([row]);
    value["summary"]["incomplete_checks"] = 1.into();
    if status == "not_collected" {
        value["coverage"]["deprecation"]["not_collected_count"] = 1.into();
        value["coverage"]["deprecation"]["not_collected_registries"] = json!(["pypi"]);
    } else {
        value["coverage"]["deprecation"]["unknown_count"] = 1.into();
    }
    value
}

#[test]
fn audit_applicability_keeps_real_unknowns_failures_and_uncollected_issues() {
    for version in [1, 2] {
        for (status, reason, expected) in [
            (
                "unknown",
                Some("metadata_unavailable"),
                "package metadata missing",
            ),
            ("unknown", Some("lookup_failed"), "lookup_failed"),
            ("not_collected", None, ""),
        ] {
            let value = gap(version, status, reason);
            let view = result(&value, 1);
            assert_eq!(view["incomplete"], true);
            let issues = view["issues"].as_array().expect("issues");
            assert!(issues.iter().any(|i| i["status"] == status));
            assert!(
                issues
                    .iter()
                    .any(|i| i["reason"] == "0 of 2 packages checked; 1 not applicable")
            );
            assert!(!issues.iter().any(|i| i["check"] == "report"));
            assert!(stdout(&execute(&value, &["--no-color", "--quiet"])).contains(expected));
        }
    }
}

#[test]
fn audit_applicability_preserves_retained_positive_pypi_findings() {
    for version in [1, 2] {
        let mut value = pypi_not_applicable(version);
        value["coverage"]["deprecation"]["checked_count"] = 1.into();
        value["coverage"]["deprecation"]["not_applicable_count"] = 1.into();
        let mut finding = json!({"coordinate":{"registry":"pypi","name":"demo","version":"1.0.0"},
            "reason":"retained positive deprecation evidence"});
        if version == 1 {
            finding["occurrence_ids"] = json!(["one"]);
        } else {
            finding["paths"] = json!(["package-lock.json"]);
        }
        value["findings"]["deprecated"] = json!([finding]);
        value["summary"]["deprecated"] = 1.into();
        let view = result(&value, 1);
        assert_eq!(view["incomplete"], false);
        assert!(view.get("issues").is_none());
        assert_eq!(view["deprecated"][0]["package"], "pypi:demo@1.0.0");
        assert_eq!(
            view["deprecated"][0]["reason"],
            "retained positive deprecation evidence"
        );
    }
}

#[test]
fn audit_applicability_legacy_not_collected_stays_incomplete() {
    for version in [1, 2] {
        let mut value = gap(version, "not_collected", None);
        value["coverage"]["deprecation"]["checked_count"] = 1.into();
        let coverage = value["coverage"]["deprecation"]
            .as_object_mut()
            .expect("coverage");
        coverage.remove("not_applicable_count");
        coverage.remove("not_applicable_registries");
        coverage.insert("not_collected_count".into(), 1.into());
        let outdated = value["coverage"]["outdated"]
            .as_object_mut()
            .expect("coverage");
        outdated.remove("not_applicable_count");
        outdated.remove("not_applicable_registries");
        let view = result(&value, 1);
        assert_eq!(view["incomplete"], true);
        assert!(view.get("limitations").is_none());
        assert!(
            view["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .any(|i| i["status"] == "not_collected")
        );
    }
}

#[test]
fn audit_applicability_zero_candidates_add_no_notice_or_issue() {
    for version in [1, 2] {
        let mut value = metadata_coverage(version);
        value["summary"]["dependencies"] = 0.into();
        if version == 1 {
            value["occurrences"] = json!([]);
            value["summary"]["occurrences"] = 0.into();
            value["coverage"]["sources"] = json!([]);
        }
        for check in ["deprecation", "outdated", "vulnerabilities", "duplicates"] {
            value["coverage"][check]["candidates_count"] = 0.into();
        }
        for check in ["deprecation", "outdated", "vulnerabilities"] {
            value["coverage"][check]["checked_count"] = 0.into();
        }
        let view = result(&value, 0);
        assert_eq!(view["incomplete"], false);
        assert!(view.get("issues").is_none() && view.get("limitations").is_none());
    }
}

#[test]
fn audit_applicability_saved_replay_retains_explicit_counts_and_legacy_absence() {
    for current in [true, false] {
        let value = if current {
            pypi_not_applicable(2)
        } else {
            crate::support::audit::v2_clean()
        };
        let root = repo();
        let file = root.path().join("analysis.json");
        let server = server(&serde_json::to_vec(&value).expect("report"));
        let output = run(
            root.path(),
            Some(&server.origin()),
            &[
                "--json",
                "--quiet",
                "--save-analysis",
                file.to_str().expect("path"),
            ],
        );
        assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
        assert_eq!(server.requests().len(), 3);
        let saved: Value = serde_json::from_slice(&fs::read(&file).expect("saved")).expect("JSON");
        assert_eq!(
            saved["producer_report"]["coverage"]["deprecation"],
            value["coverage"]["deprecation"]
        );
        let replay = offline(&file, &["--json", "--quiet"]);
        assert_eq!(replay.status.code(), Some(0));
        let mut view: Value = serde_json::from_slice(&replay.stdout).expect("replay");
        view.as_object_mut().expect("view").remove("analysis");
        let online: Value = serde_json::from_slice(&output.stdout).expect("online");
        assert_eq!(view, online);
    }
}

#[test]
fn audit_applicability_notices_name_the_check_and_allow_unlisted_registries() {
    let mut value = pypi_not_applicable(2);
    value["coverage"]["deprecation"]["not_applicable_registries"] = json!([]);
    value["coverage"]["outdated"]["checked_count"] = 1.into();
    value["coverage"]["outdated"]["not_applicable_count"] = 1.into();
    let view = result(&value, 0);
    assert_eq!(
        view["limitations"],
        json!([
            "deprecation coverage: 0 of 2 packages checked; 2 not applicable",
            "outdated coverage: 1 of 2 packages checked; 1 not applicable"
        ])
    );
}

#[test]
fn audit_applicability_bad_partition_and_overflow_stay_unverified() {
    for version in [1, 2] {
        for (checked, not_applicable) in [(0, 1), (3, u64::MAX)] {
            let mut value = pypi_not_applicable(version);
            value["coverage"]["deprecation"]["checked_count"] = checked.into();
            value["coverage"]["deprecation"]["not_applicable_count"] = not_applicable.into();
            let view = result(&value, 1);
            assert_eq!(view["incomplete"], true);
            assert!(
                view["issues"]
                    .as_array()
                    .expect("issues")
                    .iter()
                    .any(|i| i["check"] == "report" && i["status"] == "unverified")
            );
        }
    }
}
