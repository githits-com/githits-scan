//! Binary coverage for supplied blocker dependency identities and old reports.
use super::*;

fn named_blocker() -> Value {
    serde_json::from_slice(include_bytes!("../fixtures/audit/blocker.json"))
        .expect("authored named blocker")
}

#[test]
fn audit_blocker_dependency_name_human_uses_only_supplied_identity() {
    for (name, requirement) in [
        (None, "requires ^0.7.1"),
        (Some("cookie"), "requires cookie ^0.7.1"),
        (Some("@demo/alias"), "requires @demo/alias ^0.7.1"),
        (
            Some("org.example:cookie"),
            "requires org.example:cookie ^0.7.1",
        ),
        (
            Some("cookie\n\u{1b}[2J"),
            "requires cookie\\n\\u{1b}[2J ^0.7.1",
        ),
    ] {
        let mut b = named_blocker();
        b.as_object_mut()
            .expect("blocker")
            .remove("dependency_name");
        if let Some(name) = name {
            b["dependency_name"] = name.into();
        }
        b["future_fact"] = json!({"ignored": true});
        let mut input = remediation_report();
        input["remediation"]["recommendations"][0]["blockers"] = json!([b]);
        let text = human_report(&input);
        assert!(text.contains(&format!(
            "    blocker: express@5.1.0 {requirement} [package-lock.json]; parent dependency excludes the target\n"
        )), "{text}");
        assert!(!text.contains('\u{1b}'));
    }
}

#[test]
fn audit_blocker_dependency_name_json_preserves_presence_and_absence() {
    for named in [false, true] {
        let mut b = named_blocker();
        if !named {
            b.as_object_mut()
                .expect("blocker")
                .remove("dependency_name");
        }
        let mut input = remediation_report();
        input["remediation"]["recommendations"][0]["blockers"] = json!([b]);
        input["remediation"]["recommendations"][0]["blockers"][0]["future_fact"] = 7.into();
        let result = json_report(&input);
        assert_eq!(
            result["remediation"]["recommendations"][0]["blockers"][0],
            b
        );
    }
}

#[test]
fn audit_blocker_dependency_name_keeps_requirement_status() {
    for (requirement, status, expected) in [
        (
            json!("^0.7.1"),
            "withheld",
            "requires cookie ^0.7.1 (withheld)",
        ),
        (
            Value::Null,
            "not_recorded",
            "requires cookie (requirement not recorded)",
        ),
        (
            Value::Null,
            "future_status",
            "requires cookie (requirement future_status)",
        ),
    ] {
        let mut b = named_blocker();
        b["requested_requirement"] = requirement;
        b["requirement_status"] = status.into();
        let mut input = remediation_report();
        input["remediation"]["recommendations"][0]["blockers"] = json!([b]);
        let text = human_report(&input);
        assert!(
            text.contains(&format!("express@5.1.0 {expected} [package-lock.json]")),
            "{text}"
        );
        assert_eq!(
            json_report(&input)["remediation"]["recommendations"][0]["blockers"][0],
            b
        );
    }
}

#[test]
fn audit_blocker_dependency_name_rejects_wrong_types_without_overwriting_output() {
    let root = repo();
    let path = root.path().join("audit.json");
    fs::write(&path, "keep existing").expect("existing output");
    for invalid in [Value::Null, json!(1), json!(true), json!([]), json!({})] {
        let mut b = named_blocker();
        b["dependency_name"] = invalid;
        let mut input = remediation_report();
        input["remediation"]["recommendations"][0]["blockers"] = json!([b]);
        let output = execute_report(
            &input,
            &["--json", "--output", path.to_str().expect("path")],
        );
        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        assert!(output.stdout.is_empty(), "{:?}", output.stdout);
        assert!(stderr(&output).contains("invalid"), "{}", stderr(&output));
        assert_eq!(
            fs::read_to_string(&path).expect("preserved output"),
            "keep existing"
        );
    }
}

#[test]
fn audit_blocker_dependency_name_saved_explanation_preserves_distinct_names() {
    let root = repo();
    let path = root.path().join("analysis.json");
    let mut archive: Value =
        serde_json::from_slice(include_bytes!("../fixtures/audit/analysis-v1.json"))
            .expect("compatibility archive");
    let named = named_blocker();
    let mut different = named.clone();
    different["dependency_name"] = "@demo/alias".into();
    let mut unnamed = named.clone();
    unnamed
        .as_object_mut()
        .expect("blocker")
        .remove("dependency_name");
    let blockers = json!([named, named, different, unnamed]);
    archive["producer_report"]["remediation"]["recommendations"][0]["blockers"] = blockers.clone();
    fs::write(&path, serde_json::to_vec(&archive).expect("JSON")).expect("archive");
    for flags in [&["--details"][..], &["--explain", "npm:demo@1.0.0"][..]] {
        let output = offline(&path, flags);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
        let text = stdout(&output);
        for requirement in ["cookie ^0.7.1", "@demo/alias ^0.7.1", "^0.7.1"] {
            assert_eq!(
                text.matches(&format!("blocker: express@5.1.0 requires {requirement} ["))
                    .count(),
                1,
                "{text}"
            );
        }
        assert_eq!(text.matches("blocker: express@5.1.0").count(), 3, "{text}");
        let mut flags = flags.to_vec();
        flags.push("--json");
        let output = offline(&path, &flags);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        let result: Value = serde_json::from_slice(&output.stdout).expect("JSON");
        assert_eq!(
            result["remediation"]["recommendations"][0]["blockers"],
            blockers
        );
    }
}
