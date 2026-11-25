//! Problem grouping and exact joint/partial action scopes.
use super::*;

fn grouping_report() -> Value {
    let base = remediation_report();
    let mut value = crate::support::audit::clean();
    let first = base["findings"]["vulnerabilities"][0].clone();
    let mut second = first.clone();
    second["advisory_id"] = "GHSA-second".into();
    second["aliases"] = json!([]);
    let mut other = first.clone();
    other["coordinate"]["version"] = "2.0.0".into();
    other["advisory_id"] = "GHSA-other".into();
    other["aliases"] = json!([]);
    other["paths"] = json!(["other/package-lock.json"]);
    value["findings"]["vulnerabilities"] = json!([first, second, other]);
    value["summary"]["vulnerabilities"] = 3.into();
    value["remediation"] = base["remediation"].clone();
    let a = value["remediation"]["recommendations"][0].clone();
    let mut b = a.clone();
    b["subject"]["version"] = "2.0.0".into();
    b["finding_refs"] = json!([2]);
    b["addressed_finding_refs"] = json!([2]);
    b["changes"][0]["from_version"] = "2.0.0".into();
    b["changes"][0]["target_version"] = "2.1.0".into();
    let mut next_a = a.clone();
    next_a["finding_refs"] = json!([1]);
    next_a["addressed_finding_refs"] = json!([1]);
    next_a["changes"][0]["target_version"] = "1.1.2".into();
    value["remediation"]["recommendations"] = json!([a, b, next_a]);
    value
}

fn ordinary_and_focused(value: &Value) -> (String, String) {
    let text = human_report(value);
    let root = repo();
    let archive = root.path().join("analysis.json");
    let mock = server(&serde_json::to_vec(value).expect("report"));
    let output = run(
        root.path(),
        Some(&mock.origin()),
        &[
            "--quiet",
            "--json",
            "--save-analysis",
            archive.to_str().expect("path"),
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(mock.requests().len(), 3);
    let replay = offline(&archive, &["--explain", "npm:demo@1.0.0", "--no-color"]);
    assert_eq!(replay.status.code(), Some(1), "{}", stderr(&replay));
    assert!(replay.stderr.is_empty(), "{:?}", replay.stderr);
    (text, stdout(&replay))
}

#[test]
fn audit_remediation_groups_alternatives_by_exact_subject() {
    let input = grouping_report();
    let output = execute_report(&input, &["--quiet", "--no-color", "--details"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    for heading in ["npm:demo@1.0.0 — vulnerable", "npm:demo@2.0.0 — vulnerable"] {
        assert_eq!(text.matches(heading).count(), 1, "{text}");
    }
    for advisory in ["GHSA-demo", "GHSA-second", "GHSA-other"] {
        let line = format!("    {advisory}");
        assert_eq!(
            text.lines().filter(|l| l.starts_with(&line)).count(),
            1,
            "{text}"
        );
    }
    let first = text.find("1.0.0 -> 1.1.1").expect("first A");
    let second = text.find("1.0.0 -> 1.1.2").expect("second A");
    let other = text.find("2.0.0 -> 2.1.0").expect("B");
    assert!(first < second && second < other, "{text}");
    assert_eq!(text.matches("Alternative 1").count(), 1, "{text}");
    assert_eq!(text.matches("Alternative 2").count(), 1, "{text}");
    assert!(text.contains("would address: GHSA-demo"), "{text}");
    assert!(text.contains("would address: GHSA-second"), "{text}");
    let structured = json_report(&input);
    assert_eq!(
        structured["remediation"]["recommendations"]
            .as_array()
            .expect("records")
            .len(),
        3
    );
    assert_eq!(
        structured["remediation"]["recommendations"][1]["subject"],
        "npm:demo@2.0.0"
    );
}

#[test]
fn audit_remediation_grouping_compact_prioritizes_supported_alternatives() {
    let mut input = grouping_report();
    let advisory = &mut input["findings"]["vulnerabilities"][1];
    advisory["severity_score"] = json!(7.5);
    advisory["severity_type"] = "CVSS".into();
    advisory["malicious"] = true.into();
    let alternatives = input["remediation"]["recommendations"]
        .as_array_mut()
        .expect("records");
    alternatives[0]["checks"]["requirements"] = "blocked".into();
    alternatives[0]["blockers"] =
        json!([
            serde_json::from_slice::<Value>(include_bytes!("../fixtures/audit/blocker.json"))
                .expect("constraint")
        ]);
    alternatives[1]["checks"]["requirements"] = "unchecked".into();
    alternatives.swap(0, 1);
    let output = execute_report(&input, &["--quiet", "--no-color"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let compact = stdout(&output);
    let supported = compact
        .find("Upgrade: npm:demo 1.0.0 -> 1.1.2")
        .expect(&compact);
    let blocked = compact
        .find("Candidate: npm:demo 1.0.0 -> 1.1.1")
        .expect(&compact);
    let unresolved = compact.find("Needs a decision").expect(&compact);
    assert!(supported < blocked && blocked < unresolved, "{compact}");
    assert!(
        compact.contains("GHSA-second (CVSS 7.5) MALICIOUS"),
        "{compact}"
    );
    assert!(
        compact.contains("Dependency requirements conflict with this candidate."),
        "{compact}"
    );
    assert!(
        !compact.contains("Alternative 1") && !compact.contains("Manifests"),
        "{compact}"
    );
    assert!(
        !compact.contains("verified advisory fixes") && !compact.contains("Upgrade search"),
        "{compact}"
    );
    assert_eq!(compact.matches("Use --details").count(), 1, "{compact}");
    let detailed = human_report(&input);
    assert!(
        detailed.contains("Alternative 1") && detailed.contains("Manifests"),
        "{detailed}"
    );
    assert!(
        detailed.contains("verified advisory fixes:") && detailed.contains("MALICIOUS"),
        "{detailed}"
    );
}

#[test]
fn audit_remediation_grouping_compact_assigns_shared_findings_in_display_order() {
    let mut input = grouping_report();
    let mut related = input["findings"]["vulnerabilities"][2].clone();
    related["coordinate"]["name"] = "related".into();
    related["advisory_id"] = "GHSA-related".into();
    related["paths"] = json!(["related/package-lock.json"]);
    input["findings"]["vulnerabilities"]
        .as_array_mut()
        .expect("findings")
        .push(related);
    input["summary"]["vulnerabilities"] = 4.into();
    let alternatives = input["remediation"]["recommendations"]
        .as_array_mut()
        .expect("records");
    alternatives[0]["finding_refs"] = json!([0, 3]);
    alternatives[0]["remaining_finding_refs"] = json!([3]);
    alternatives[0]["outcome"] = "partial".into();
    alternatives[1]["finding_refs"] = json!([2, 3]);
    alternatives[1]["checks"]["requirements"] = "unchecked".into();
    alternatives.swap(0, 1);
    let output = execute_report(&input, &["--quiet", "--no-color"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let compact = prose(&stdout(&output));
    let associated = "Advisories npm:related@2.0.0 [related/package-lock.json]: GHSA-related";
    let (suggestions, decisions) = compact.split_once("Needs a decision").expect(&compact);
    assert!(
        suggestions.contains(associated) && !decisions.contains(associated),
        "{compact}"
    );
    assert_eq!(suggestions.matches(associated).count(), 1, "{compact}");
    assert!(
        suggestions.contains(
            "Still unresolved: npm:related@2.0.0 — GHSA-related in related/package-lock.json."
        ),
        "{compact}"
    );
}

#[test]
fn audit_remediation_grouping_compact_mentions_shared_search_limit_once() {
    let mut input = grouping_report();
    input["remediation"]["status"] = "limited".into();
    input["remediation"]["limits"]["reasons"] = json!(["parent_candidate_limit"]);
    for index in [0, 2] {
        let candidate = &mut input["remediation"]["recommendations"][index];
        candidate["checks"]["requirements"] = "blocked".into();
        candidate["checks"]["parent_search"] = "limited".into();
        candidate["limitations"] = json!(["parent_candidate_limit"]);
    }
    let output = execute_report(&input, &["--quiet", "--no-color"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let compact = prose(&stdout(&output));
    let limit = "reached its limit for checking upgrades";
    assert_eq!(compact.matches(limit).count(), 1, "{compact}");
    assert_eq!(prose(&human_report(&input)).matches(limit).count(), 3);
}

#[test]
fn audit_remediation_grouping_compact_preserves_report_wide_planning_deadline() {
    let mut input = grouping_report();
    input["remediation"]["status"] = "limited".into();
    input["remediation"]["limits"]["reasons"] =
        json!(["planning_deadline", "parent_candidate_limit"]);
    let candidate = &mut input["remediation"]["recommendations"][0];
    candidate["checks"]["requirements"] = "blocked".into();
    candidate["limitations"] = json!(["planning_deadline"]);
    let output = execute_report(&input, &["--quiet", "--no-color"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let compact = prose(&stdout(&output));
    assert!(compact.contains("Suggested updates"), "{compact}");
    assert!(
        compact.contains("The upgrade conflicts with dependency requirements."),
        "{compact}"
    );
    assert!(
        compact.contains("Fix guidance is incomplete. Mitigation planning time limit reached."),
        "{compact}"
    );
    assert_eq!(
        compact.matches("planning time limit").count(),
        1,
        "{compact}"
    );
    assert!(
        !compact.contains("limit for checking upgrades"),
        "{compact}"
    );
}

#[test]
fn audit_remediation_grouping_preserves_joint_and_partial_alternatives() {
    for (problem, other_problem, changed) in [
        (
            json!(["a/package-lock.json"]),
            json!(["b/package-lock.json"]),
            json!(["a/package-lock.json", "b/package-lock.json"]),
        ),
        (
            json!(["a/package-lock.json"]),
            json!(["b/package-lock.json"]),
            json!(["a/package-lock.json"]),
        ),
    ] {
        let mut input = grouping_report();
        input["findings"]["vulnerabilities"][0]["paths"] = problem;
        input["findings"]["vulnerabilities"][1]["paths"] = other_problem;
        input["remediation"]["recommendations"][0]["changes"][0]["paths"] = changed;
        let outputs: [String; 2] = ordinary_and_focused(&input).into();
        for text in outputs {
            let first = text
                .split_once("Alternative 1")
                .expect("first alternative")
                .1
                .split_once("Alternative 2")
                .expect("second alternative")
                .0;
            assert!(first.contains("Change in: a/package-lock.json"), "{text}");
            assert!(first.contains("would address: GHSA-demo"), "{text}");
        }
    }
}

#[test]
fn audit_remediation_grouping_keeps_joint_scope_in_focused_output() {
    let mut input = grouping_report();
    input["findings"]["vulnerabilities"][0]["paths"] = json!(["a/package-lock.json"]);
    input["findings"]["vulnerabilities"][2]["paths"] = json!(["b/package-lock.json"]);
    input["remediation"]["recommendations"][0]["finding_refs"] = json!([0, 2]);
    input["remediation"]["recommendations"][0]["addressed_finding_refs"] = json!([0, 2]);
    input["remediation"]["recommendations"][0]["changes"][0]["paths"] =
        json!(["a/package-lock.json", "b/package-lock.json"]);
    let mut second_change = input["remediation"]["recommendations"][0]["changes"][0].clone();
    second_change["name"] = "parent".into();
    input["remediation"]["recommendations"][0]["changes"]
        .as_array_mut()
        .expect("changes")
        .push(second_change);
    let (ordinary, focused) = ordinary_and_focused(&input);
    assert_eq!(
        ordinary.matches("npm:demo@2.0.0 — vulnerable").count(),
        1,
        "{ordinary}"
    );
    let first = focused
        .split_once("Alternative 1")
        .expect("alternative")
        .1
        .split_once("Alternative 2")
        .expect("alternative")
        .0;
    assert!(first.contains("change together"), "{focused}");
    assert!(first.contains("Upgrade npm:parent"), "{focused}");
    assert!(
        first.contains("Change in: a/package-lock.json, b/package-lock.json"),
        "{focused}"
    );
    assert!(first.contains("would address:"), "{focused}");
    assert!(first.contains("npm:demo@2.0.0 — GHSA-other"), "{focused}");
}

#[test]
fn audit_remediation_grouping_keeps_unowned_problems_and_independent_checks() {
    let mut input = grouping_report();
    input["findings"]["vulnerabilities"][2]["coordinate"]["name"] = "aaa".into();
    input["remediation"]["recommendations"][0]["finding_refs"] = json!([0, 2]);
    input["remediation"]["recommendations"][0]["addressed_finding_refs"] = json!([0]);
    input["remediation"]["recommendations"][0]["remaining_finding_refs"] = json!([2]);
    input["remediation"]["recommendations"][0]["outcome"] = "partial".into();
    input["remediation"]["recommendations"]
        .as_array_mut()
        .expect("records")
        .remove(1);
    input["remediation"]["recommendations"][1]["changes"][0]["target_version"] = "1.1.1".into();
    input["remediation"]["recommendations"][1]["checks"]["requirements"] = "not_checked".into();
    let text = human_report(&input);
    assert_eq!(
        text.matches("npm:aaa@2.0.0 — vulnerable").count(),
        1,
        "{text}"
    );
    assert!(
        text.find("npm:aaa@2.0.0 — vulnerable").expect("problem")
            < text.find("Alternative 1").expect("alternative"),
        "{text}"
    );
    assert!(
        text.find("npm:demo@1.0.0 — vulnerable").expect("subject")
            < text
                .find("npm:aaa@2.0.0 — vulnerable")
                .expect("related problem"),
        "{text}"
    );
    let first = text
        .split_once("Alternative 1")
        .expect("first")
        .1
        .split_once("Alternative 2")
        .expect("second")
        .0;
    assert!(
        first.contains("Suggested fix:") && first.contains("(partial)"),
        "{text}"
    );
    assert!(
        first.contains("still unresolved: npm:aaa@2.0.0 — GHSA-other"),
        "{text}"
    );
    let second = text.split_once("Alternative 2").expect("second").1;
    assert!(second.contains("Candidate change:"), "{text}");
    assert!(
        second.contains(
            "The report does not establish whether the project's dependency requirements"
        ),
        "{text}"
    );
    assert!(!second.contains("project resolver/build not run"), "{text}");
    assert_eq!(text.matches("1.0.0 -> 1.1.1").count(), 2, "{text}");
}

#[test]
fn audit_remediation_grouping_keeps_registry_identity() {
    let mut other_registry = grouping_report();
    other_registry["findings"]["vulnerabilities"][2]["coordinate"]["registry"] = "pypi".into();
    other_registry["findings"]["vulnerabilities"][2]["coordinate"]["version"] = "1.0.0".into();
    other_registry["remediation"]["recommendations"][1]["subject"] =
        json!({"registry":"pypi","name":"demo","version":"1.0.0"});
    let text = human_report(&other_registry);
    assert_eq!(
        text.matches("npm:demo@1.0.0 — vulnerable").count(),
        1,
        "{text}"
    );
    assert_eq!(
        text.matches("pypi:demo@1.0.0 — vulnerable").count(),
        1,
        "{text}"
    );
}
