//! Explicit registry exclusions do not excuse independent missing evidence.
use super::*;
use serde_json::{Value, json};

fn excluded() -> Value {
    let mut v = clean();
    v["unknowns"]["excluded_dependencies"] = json!([{"name":"workspace-helper","version":"0.1.0","paths":["Cargo.lock","tools/Cargo.lock"],"reason":"non_registry_source"}]);
    v["summary"]["excluded_dependencies"] = 1.into();
    v
}

#[test]
fn audit_non_registry_exclusion_is_neutral_and_replays_with_full_facts() {
    let r = repo();
    let saved = r.path().join("analysis.json");
    let s = server(&serde_json::to_vec(&excluded()).expect("JSON"));
    let output = run(
        r.path(),
        Some(&s.origin()),
        &["--json", "--save-analysis", saved.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(s.requests().len(), 3);
    let result: Value = serde_json::from_slice(&output.stdout).expect("report");
    assert_eq!(result["incomplete"], true);
    assert_eq!(result["actionable_incomplete"], false);
    assert_eq!(result["issues"][0]["actionable"], false);
    assert_eq!(
        result["issues"][0]["packages"],
        json!(["workspace-helper@0.1.0"])
    );
    assert_eq!(
        result["issues"][0]["files"],
        json!(["Cargo.lock", "tools/Cargo.lock"])
    );
    let replay = offline(&saved, &["--json"]);
    assert_eq!(replay.status.code(), Some(0));
    let replay: Value = serde_json::from_slice(&replay.stdout).expect("replay");
    assert_eq!(replay["issues"], result["issues"]);
    let human = offline(&saved, &["--no-color", "--quiet"]);
    assert_eq!(human.status.code(), Some(0));
    let text = stdout(&human);
    for expected in [
        "No audit findings in available evidence",
        "Coverage notes",
        "outside public package registries",
        "excluded from registry vulnerability and update checks",
        "workspace-helper@0.1.0",
        "Cargo.lock",
        "tools/Cargo.lock",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    for warning in [
        "Incomplete checks",
        "Packages not checked",
        "action:",
        "non_registry_source",
        "checked safe",
        "local workspace",
    ] {
        assert!(!text.contains(warning), "{warning}: {text}");
    }
}

#[test]
fn audit_non_registry_reason_only_qualifies_exclusion_context() {
    for family in [
        "sources",
        "resolution",
        "vulnerabilities",
        "metadata",
        "excluded_dependencies",
    ] {
        let mut v = excluded();
        match family {
            "sources" => {
                v["unknowns"][family] =
                    json!([{"path":"tools/Cargo.lock","reasons":["non_registry_source"]}]);
                v["summary"]["incomplete_sources"] = 1.into();
            }
            "resolution" => {
                v["unknowns"][family] =
                    json!([{"path":"tools/Cargo.lock","name":null,"reason":"non_registry_source"}]);
            }
            "excluded_dependencies" => v["unknowns"][family][0]["reason"] = "future_reason".into(),
            "metadata" => {
                v["unknowns"][family] = json!([{"coordinate":{"registry":"npm","name":"demo","version":"2.0.0"},"paths":["Cargo.lock"],"check":"outdated","status":"unknown","reason":"non_registry_source"}]);
                v["coverage"]["outdated"]["checked_count"] = 1.into();
                v["coverage"]["outdated"]["unknown_count"] = 1.into();
                v["summary"]["incomplete_checks"] = 1.into();
            }
            _ => {
                let mut gap = crate::support::audit::findings()["unknowns"][family][0].clone();
                gap["reasons"] = json!(["non_registry_source"]);
                v["unknowns"][family] = json!([gap]);
                v["coverage"]["vulnerabilities"]["checked_count"] = 1.into();
                v["coverage"]["vulnerabilities"]["unknown_count"] = 1.into();
                v["summary"]["incomplete_checks"] = 1.into();
            }
        }
        let s = server(&serde_json::to_vec(&v).expect("JSON"));
        let r = repo();
        let output = run(r.path(), Some(&s.origin()), &["--json"]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{family}: {}",
            stderr(&output)
        );
        let result: Value = serde_json::from_slice(&output.stdout).expect("report");
        assert_eq!(result["actionable_incomplete"], true, "{family}");
        assert!(
            result["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .any(|i| i["actionable"] == true)
        );
        assert_eq!(s.requests().len(), 3);
    }
}

#[test]
fn audit_non_registry_exclusion_does_not_hide_missing_inputs_or_inconsistencies() {
    for case in [
        "missing input",
        "count",
        "attribution",
        "advisory",
        "source mismatch",
    ] {
        let mut v = excluded();
        match case {
            "missing input" => {
                v["unknowns"]["sources"] =
                    json!([{"path":"tools/Cargo.lock","reasons":["dependency_list_unavailable"]}]);
                v["summary"]["incomplete_sources"] = 1.into();
            }
            "count" => v["summary"]["excluded_dependencies"] = 0.into(),
            "attribution" => v["unknowns"]["excluded_dependencies"][0]["paths"] = json!([]),
            "source mismatch" => {
                v["unknowns"]["resolution"] = json!([{"path":"Cargo.lock","name":null,"reason":"recorded_git_source_differs"}]);
            }
            _ => {
                v["findings"]["vulnerabilities"] =
                    crate::support::audit::findings()["findings"]["vulnerabilities"].clone();
                v["summary"]["vulnerabilities"] = 1.into();
            }
        }
        let s = server(&serde_json::to_vec(&v).expect("JSON"));
        let r = repo();
        let output = run(r.path(), Some(&s.origin()), &["--json"]);
        assert_eq!(output.status.code(), Some(1), "{case}: {}", stderr(&output));
        let result: Value = serde_json::from_slice(&output.stdout).expect("report");
        assert_eq!(
            result["actionable_incomplete"],
            case != "advisory",
            "{case}"
        );
        assert!(
            result["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .any(|i| i["actionable"] == false)
        );
        assert_eq!(s.requests().len(), 3);
    }
}
