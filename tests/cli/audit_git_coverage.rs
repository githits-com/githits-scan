//! Normal Git limits are evidence notes; independent defects remain actionable.
use super::*;
use serde_json::{Value, json};

fn git_limits() -> Value {
    let mut v = clean();
    v["unknowns"]["sources"] = json!([{"path":"mix.lock", "reasons":["git_dependency_graph_unavailable", "git_registry_checks_not_supported"]}]);
    v["unknowns"]["excluded_dependencies"] = json!([{"name":"git-demo","version":null,"paths":["mix.lock"],"reason":"git_registry_checks_not_supported"}]);
    v["unknowns"]["resolution"] =
        json!([{ "path":"mix.lock", "name":null, "reason":"git_dependency_graph_unavailable" }]);
    v["summary"]["incomplete_sources"] = 1.into();
    v["summary"]["excluded_dependencies"] = 1.into();
    v
}

#[test]
fn audit_git_coverage_notes_keep_facts_without_failing_and_replay_offline() {
    let r = repo();
    let saved = r.path().join("analysis.json");
    let s = server(&serde_json::to_vec(&git_limits()).expect("JSON"));
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
    assert!(
        result["issues"]
            .as_array()
            .expect("issues")
            .iter()
            .all(|i| i["actionable"] == false)
    );
    let replay = offline(&saved, &["--json"]);
    assert_eq!(replay.status.code(), Some(0), "{}", stderr(&replay));
    let replay: Value = serde_json::from_slice(&replay.stdout).expect("replay");
    assert_eq!(replay["issues"], result["issues"]);
    assert_eq!(replay["actionable_incomplete"], false);
    let human = offline(&saved, &["--no-color", "--quiet"]);
    assert_eq!(human.status.code(), Some(0));
    let human = stdout(&human);
    assert!(
        human.contains("No audit findings in available evidence"),
        "{human}"
    );
    assert!(human.contains("Coverage notes"), "{human}");
    let notes: Vec<_> = human
        .lines()
        .filter(|line| line.contains(" [mix.lock]"))
        .collect();
    assert_eq!(notes.len(), 2, "{human}");
    assert!(
        notes.iter().all(|line| !line.contains("dependencies, Git")),
        "{human}"
    );
    assert!(
        human.contains("Registry checks do not cover Git-based dependencies"),
        "{human}"
    );
    assert!(
        human.contains("Git dependency relationships are not recorded"),
        "{human}"
    );
    for misleading in [
        "Incomplete checks",
        "Packages not checked",
        "action:",
        "git_registry_checks_not_supported",
        "\u{1b}[",
    ] {
        assert!(!human.contains(misleading), "{misleading}: {human}");
    }
}

#[test]
fn audit_git_coverage_mixed_unknown_and_unverified_reports_still_fail() {
    for reason in [
        "required_input_not_supplied",
        "recorded_git_source_differs",
        "umbrella_members_not_captured",
        "future_reason",
        "",
    ] {
        let mut v = git_limits();
        v["unknowns"]["sources"][0]["reasons"] =
            json!(["git_dependency_graph_unavailable", reason]);
        v["unknowns"]["resolution"] = json!([
            {"path":"mix.lock", "name":null, "reason":"git_dependency_graph_unavailable"},
            {"path":"mix.lock", "name":null, "reason":reason}
        ]);
        let s = server(&serde_json::to_vec(&v).expect("JSON"));
        let r = repo();
        let output = run(r.path(), Some(&s.origin()), &["--json"]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{reason}: {}",
            stderr(&output)
        );
        assert_eq!(s.requests().len(), 3);
        let result: Value = serde_json::from_slice(&output.stdout).expect("report");
        assert_eq!(result["actionable_incomplete"], true, "{reason}");
        assert!(
            result["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .any(|i| i["actionable"] == true)
        );
        assert!(
            result["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .any(|i| i["actionable"] == false)
        );
    }
    let mut v = git_limits();
    v["summary"]["incomplete_sources"] = 0.into();
    let s = server(&serde_json::to_vec(&v).expect("JSON"));
    let r = repo();
    let output = run(r.path(), Some(&s.origin()), &["--json"]);
    assert_eq!(output.status.code(), Some(1));
    let result: Value = serde_json::from_slice(&output.stdout).expect("report");
    assert_eq!(result["actionable_incomplete"], true);
    assert!(stdout(&output).contains("unverified"));
    assert_eq!(s.requests().len(), 3);
}

#[test]
fn audit_git_coverage_findings_and_saved_explanations_remain_actionable() {
    let mut v = git_limits();
    let source = crate::support::audit::findings();
    v["findings"]["vulnerabilities"] = source["findings"]["vulnerabilities"].clone();
    v["summary"]["vulnerabilities"] = 1.into();
    let r = repo();
    let saved = r.path().join("analysis.json");
    let s = server(&serde_json::to_vec(&v).expect("JSON"));
    let output = run(
        r.path(),
        Some(&s.origin()),
        &["--json", "--save-analysis", saved.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(s.requests().len(), 3);
    let result: Value = serde_json::from_slice(&output.stdout).expect("report");
    assert_eq!(result["actionable_incomplete"], false);
    assert_eq!(
        result["vulnerabilities"]
            .as_array()
            .expect("findings")
            .len(),
        1
    );
    let selected = result["vulnerabilities"][0]["package"]
        .as_str()
        .expect("package");
    let explanation = offline(&saved, &["--json", "--explain", selected]);
    assert_eq!(
        explanation.status.code(),
        Some(1),
        "{}",
        stderr(&explanation)
    );
    let explanation: Value = serde_json::from_slice(&explanation.stdout).expect("explanation");
    assert_eq!(explanation["audit_incomplete"], true);
    assert_eq!(explanation["audit_actionable_incomplete"], false);
    assert!(
        explanation["audit_issues"]
            .as_array()
            .expect("issues")
            .iter()
            .all(|i| i["actionable"] == false)
    );
}

#[test]
fn audit_git_coverage_source_mismatch_is_explained_and_still_actionable() {
    let mut v = git_limits();
    v["findings"]["manifest_lock_mismatches"] = json!([{"name":"git-demo","path":"mix.lock","declaration_path":"mix.exs","reason":"recorded_git_source_differs","requirement_status":"not_recorded","requested_requirement":null,"declared_scope":"runtime","recorded_scopes":[],"recorded_requirements":[],"locked_versions":[]}]);
    v["summary"]["manifest_lock_mismatches"] = 1.into();
    let s = server(&serde_json::to_vec(&v).expect("JSON"));
    let r = repo();
    let output = run(r.path(), Some(&s.origin()), &["--no-color"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.contains("Git source recorded in the lockfile differs from the declaration"),
        "{text}"
    );
    assert!(!text.contains("recorded_git_source_differs"), "{text}");
    assert!(text.contains("Coverage notes"), "{text}");
    assert_eq!(s.requests().len(), 3);
}

#[test]
fn audit_git_coverage_ignored_findings_keep_a_qualified_success_headline() {
    let mut v = git_limits();
    let mut finding = crate::support::audit::findings()["findings"]["vulnerabilities"][0].clone();
    finding["advisory_id"] = "TEST-IGNORED".into();
    v["findings"]["vulnerabilities"] = json!([finding]);
    v["summary"]["vulnerabilities"] = 1.into();
    let r = repo();
    fs::write(
        r.path().join("githits-scan.toml"),
        "version=1\n[lockfiles]\ninclude=['package-lock.json']\n[[audit.ignore]]\nid='TEST-IGNORED'\nreason='Reviewed test advisory'\n",
    )
    .expect("policy");
    let s = server(&serde_json::to_vec(&v).expect("JSON"));
    let output = run(r.path(), Some(&s.origin()), &["--no-color"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.starts_with("No unignored audit findings in available evidence\n"),
        "{text}"
    );
    assert!(text.contains("Coverage notes"), "{text}");
    assert!(text.contains("Reviewed test advisory"), "{text}");
    assert_eq!(s.requests().len(), 3);
}
