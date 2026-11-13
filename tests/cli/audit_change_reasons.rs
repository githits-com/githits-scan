//! Checked reasons are concise in ordinary output and evidenced in explanations.
use super::*;

fn reasons() -> Vec<Value> {
    serde_json::from_slice(include_bytes!("../fixtures/audit/change-reasons.json"))
        .expect("reasons")
}
fn graph() -> Value {
    serde_json::from_slice(include_bytes!("../fixtures/audit/graph.json")).expect("graph")
}
fn with_reasons(reason: Value, change: usize) -> Value {
    let mut input = graph();
    input["remediation"]["recommendations"][0]["changes"][change]["reasons"] =
        Value::Array(vec![reason]);
    input
}
fn explain(input: &Value, json: bool) -> Output {
    let root = repo();
    let path = root.path().join("analysis.json");
    let mock = server(&serde_json::to_vec(input).expect("report"));
    let save = run(
        root.path(),
        Some(&mock.origin()),
        &[
            "--json",
            "--quiet",
            "--save-analysis",
            path.to_str().expect("path"),
        ],
    );
    assert_eq!(save.status.code(), Some(1), "{}", stderr(&save));
    assert_eq!(mock.requests().len(), 3);
    let flags = if json {
        vec!["--explain", "npm:demo@1.0.0", "--json"]
    } else {
        vec!["--explain", "npm:demo@1.0.0", "--no-color"]
    };
    let out = offline(&path, &flags);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(out.stderr.is_empty(), "{}", stderr(&out));
    out
}

#[test]
fn audit_change_reason_summary_explains_parent_target_without_request_dump() {
    let mut input = with_reasons(reasons()[1].clone(), 1);
    input["remediation"]["recommendations"][0]["changes"][0]["reasons"] =
        json!([reasons()[0].clone()]);
    let text = human_report(&input);
    assert!(text.contains("Upgrade npm:parent 2.0.0 -> 2.1.0"), "{text}");
    assert!(
        text.contains("why: accepts npm:demo@1.1.1, which the current requested range excludes"),
        "{text}"
    );
    for noise in [
        "original request:",
        "replacement request:",
        "recorded request for",
        "finding_refs",
        "occurrence_refs",
    ] {
        assert!(!text.contains(noise), "{noise}: {text}");
    }
    let detail = stdout(&explain(&input, false));
    assert!(
        detail.contains("original request: parent@2.0.0 requires alias <1.1"),
        "{detail}"
    );
    assert!(
        detail.contains("replacement request: parent@2.1.0 requires alias ^1.1.0"),
        "{detail}"
    );
}

#[test]
fn audit_change_reason_removal_and_advisory_effects_are_independent_and_scoped() {
    let mut input = with_reasons(reasons()[2].clone(), 1);
    input["remediation"]["recommendations"][0]["changes"][1]["reasons"]
        .as_array_mut()
        .expect("reasons")
        .push(reasons()[0].clone());
    let text = human_report(&input);
    assert!(
        text.contains("why: removes a route to npm:demo@1.0.0"),
        "{text}"
    );
    assert!(text.contains("why: addresses GHSA-example"), "{text}");
    assert!(
        !text.contains("uninstalled") && !text.contains("all copies"),
        "{text}"
    );
    let value = json_report(&input);
    let reason = &value["remediation"]["recommendations"][0]["changes"][1]["reasons"][1];
    assert_eq!(reason["code"], "advisory_remediation");
    assert_eq!(reason["findings"][0]["advisory"], "GHSA-example");
    assert!(reason.get("finding_refs").is_none());
    assert!(reason.get("occurrence_refs").is_none());
}

#[test]
fn audit_change_reason_absence_future_and_unavailable_do_not_invent_summaries() {
    for reason in [
        reasons()[3].clone(),
        json!({"code":"future\nreason","evidence":[{"private":"ignored"}]}),
    ] {
        let input = with_reasons(reason.clone(), 1);
        let text = human_report(&input);
        assert!(!text.contains("why:"), "{text}");
        let detail = stdout(&explain(&input, false));
        let expected = if reason["code"] == "unavailable" {
            "The report does not include a checked explanation for this change."
        } else {
            "the service supplied an unfamiliar reason; see JSON for the supplied value"
        };
        assert!(detail.contains(expected), "{detail}");
        let value = json_report(&input);
        assert_eq!(
            value["remediation"]["recommendations"][0]["changes"][1]["reasons"][0]["code"],
            reason["code"]
        );
        assert!(
            !serde_json::to_string(&value)
                .expect("JSON")
                .contains("private")
        );
    }
    let old = json_report(&graph());
    assert!(
        old["remediation"]["recommendations"][0]["changes"][0]
            .get("reasons")
            .is_none()
    );
}

#[test]
fn audit_change_reason_traceless_inline_evidence_stays_useful_and_escaped() {
    let mut input = with_reasons(reasons()[1].clone(), 1);
    input["remediation"]["trace"] =
        json!({"status":"not_retained","occurrences":[],"relations":[]});
    input["remediation"]["recommendations"][0]["detail_status"] = "not_retained".into();
    let reason = &mut input["remediation"]["recommendations"][0]["changes"][1]["reasons"][0];
    reason["occurrence_refs"] = json!([]);
    reason["dependency_occurrence_refs"] = json!([]);
    reason["dependency"]["name"] = "demo\n\u{1b}[2J".into();
    reason["path"] = "lock\nfile".into();
    let text = human_report(&input);
    assert!(
        text.contains(
            "why: accepts npm:demo\\n\\u{1b}[2J@1.1.1, which the current requested range excludes [lock\\nfile]"
        ),
        "{text}"
    );
    assert!(!text.contains('\u{1b}'));
}

#[test]
fn audit_change_reason_bad_consumed_refs_suppress_actions_not_findings() {
    let mut reason = reasons()[0].clone();
    reason["finding_refs"] = json!([9999]);
    let input = with_reasons(reason, 0);
    let output = json_report(&input);
    assert!(output.get("remediation").is_none());
    assert_eq!(output["vulnerabilities"][0]["advisory"], "GHSA-example");
    assert_eq!(output["incomplete"], true);
}

#[test]
fn audit_change_reason_malformed_known_evidence_preserves_output_file() {
    let root = repo();
    let path = root.path().join("report.json");
    fs::write(&path, "keep existing").expect("existing output");
    for invalid in [
        Value::Null,
        json!({}),
        json!([{"code":"advisory_remediation","occurrence_refs":[],"finding_refs":null}]),
    ] {
        let mut input = graph();
        input["remediation"]["recommendations"][0]["changes"][0]["reasons"] = invalid;
        let output = execute_report(
            &input,
            &["--json", "--output", path.to_str().expect("path")],
        );
        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        assert!(output.stdout.is_empty(), "{:?}", output.stdout);
        assert_eq!(fs::read_to_string(&path).expect("output"), "keep existing");
    }
}

#[test]
fn audit_change_reason_single_complete_fix_avoids_repeating_the_advisory() {
    let mut input = with_reasons(reasons()[0].clone(), 0);
    input["remediation"]["recommendations"][0]["changes"]
        .as_array_mut()
        .expect("changes")
        .truncate(1);
    input["remediation"]["recommendations"][0]["checks"]["deprecated_target"] = false.into();
    let text = human_report(&input);
    assert!(text.contains("Suggested fix:"), "{text}");
    assert!(!text.contains("why: addresses"), "{text}");
    let detail = stdout(&explain(&input, false));
    assert!(detail.contains("why: addresses GHSA-example"), "{detail}");
}

fn future_reason_input() -> (Value, Value) {
    let mut input = with_reasons(reasons()[1].clone(), 1);
    let future = json!({"code":"future_cause","future_payload":{"ordered":[1,"two"]}});
    input["remediation"]["recommendations"][0]["changes"][1]["reasons"]
        .as_array_mut()
        .expect("reasons")
        .push(future.clone());
    (input, future)
}

#[test]
fn audit_change_reason_json_and_saved_projection_keep_the_right_evidence() {
    let (input, _) = future_reason_input();
    let compact = json_report(&input);
    let detail: Value =
        serde_json::from_slice(&explain(&input, true).stdout).expect("explanation JSON");
    let path = "/remediation/recommendations/0/changes/1/reasons";
    assert_eq!(detail.pointer(path), compact.pointer(path));
    let projected = &compact.pointer(path).expect("reasons")[0];
    assert_eq!(
        projected["dependency"],
        input.pointer(path).expect("wire reasons")[0]["dependency"]
    );
    let encoded = serde_json::to_string(projected).expect("projected JSON");
    for unused in [
        "occurrence_refs",
        "dependency_occurrence_refs",
        "declaration_ref",
        "context",
    ] {
        assert!(!encoded.contains(unused), "{encoded}");
    }
    assert_eq!(
        compact.pointer(path).expect("reasons")[1],
        json!({"code":"future_cause"})
    );
}

#[test]
fn audit_change_reason_saved_unknown_evidence_survives_replay() {
    let (input, future) = future_reason_input();
    let compact = json_report(&input);
    let path = "/remediation/recommendations/0/changes/1/reasons";
    let root = repo();
    let archive = root.path().join("analysis.json");
    let mock = server(&serde_json::to_vec(&input).expect("report"));
    let saved = run(
        root.path(),
        Some(&mock.origin()),
        &[
            "--quiet",
            "--json",
            "--save-analysis",
            archive.to_str().expect("path"),
        ],
    );
    assert_eq!(saved.status.code(), Some(1), "{}", stderr(&saved));
    let stored: Value =
        serde_json::from_slice(&fs::read(&archive).expect("archive")).expect("saved JSON");
    assert_eq!(
        stored["producer_report"]["remediation"]["recommendations"][0]["changes"][1]["reasons"][1],
        future
    );
    let replay = offline(&archive, &["--json"]);
    assert_eq!(replay.status.code(), Some(1), "{}", stderr(&replay));
    let replayed: Value = serde_json::from_slice(&replay.stdout).expect("replay JSON");
    assert_eq!(replayed.pointer(path), compact.pointer(path));
    assert_eq!(mock.requests().len(), 3);
}

#[test]
fn audit_change_reason_partial_advisory_and_mixed_records_avoid_hidden_or_duplicate_facts() {
    let mut input = with_reasons(reasons()[0].clone(), 0);
    let r = &mut input["remediation"]["recommendations"][0];
    r["outcome"] = "partial".into();
    r["remaining_finding_refs"] = json!([0]);
    r["changes"].as_array_mut().expect("changes").truncate(1);
    let text = human_report(&input);
    assert!(text.contains("would address: GHSA-example"), "{text}");
    assert!(!text.contains("why: addresses"), "{text}");
    let mixed = with_reasons(reasons()[1].clone(), 1);
    let text = human_report(&mixed);
    assert!(text.contains("recorded request for"), "{text}");
    let mut complete = mixed;
    complete["remediation"]["recommendations"][0]["changes"][0]["reasons"] =
        json!([reasons()[0].clone()]);
    let text = human_report(&complete);
    assert!(!text.contains("recorded request for"), "{text}");
}

#[test]
fn audit_change_reason_proof_limits_are_readable_and_do_not_change_findings_exit() {
    for (code, text) in [
        (
            "change_reason_deadline",
            "time limit reached while checking change reasons",
        ),
        (
            "change_reason_membership_limit",
            "requirement-check limit reached while checking change reasons",
        ),
    ] {
        let mut input = with_reasons(reasons()[3].clone(), 1);
        input["remediation"]["status"] = "limited".into();
        input["remediation"]["limits"]["reasons"] = json!([code]);
        let human = human_report(&input);
        assert!(human.contains(text), "{human}");
        assert!(!human.contains(code), "{human}");
        assert!(human.contains("Suggested fix"), "{human}");
        assert_eq!(
            json_report(&input)["remediation"]["limits"]["reasons"],
            json!([code])
        );
        assert!(stdout(&explain(&input, false)).contains(text));
    }
}

#[test]
fn audit_change_reason_path_omits_repetition_and_keeps_distinct_locations() {
    for (paths, expected) in [
        (json!(["package-lock.json"]), ""),
        (json!(["other/package-lock.json"]), " [package-lock.json]"),
        (
            json!(["package-lock.json", "other/package-lock.json"]),
            " [package-lock.json]",
        ),
        (json!([]), " [package-lock.json]"),
    ] {
        let mut input = with_reasons(reasons()[1].clone(), 1);
        input["remediation"]["recommendations"][0]["changes"][1]["paths"] = paths;
        let text = human_report(&input);
        let line = text
            .lines()
            .find(|line| line.contains("why: accepts"))
            .expect("reason");
        assert_eq!(
            line.trim(),
            format!(
                "why: accepts npm:demo@1.1.1, which the current requested range excludes{expected}"
            ),
            "{text}"
        );
    }
    let mut input = with_reasons(reasons()[1].clone(), 1);
    input["remediation"]["recommendations"][0]["changes"][0]["paths"] =
        json!(["other/package-lock.json"]);
    let text = human_report(&input);
    assert!(text.contains("files: package-lock.json"), "{text}");
    assert!(
        text.lines().any(|line| line.trim()
            == "why: accepts npm:demo@1.1.1, which the current requested range excludes"),
        "{text}"
    );
}

#[test]
fn audit_change_reason_deduplicates_identical_effects_but_keeps_distinct_paths() {
    let reason = reasons()[1].clone();
    let mut other = reason.clone();
    other["path"] = "other/package-lock.json".into();
    let mut input = graph();
    input["remediation"]["recommendations"][0]["changes"][1]["reasons"] =
        json!([reason, reason, other]);
    let text = human_report(&input);
    assert_eq!(text.matches("why: accepts").count(), 2, "{text}");
    assert_eq!(
        text.matches("which the current requested range excludes\n")
            .count(),
        1,
        "{text}"
    );
    assert_eq!(
        text.matches("which the current requested range excludes [other/package-lock.json]")
            .count(),
        1,
        "{text}"
    );
}

#[test]
fn audit_change_reason_empty_advisory_keeps_recorded_request_context() {
    let mut input = with_reasons(reasons()[1].clone(), 1);
    input["remediation"]["recommendations"][0]["changes"][0]["reasons"] =
        json!([{"code":"advisory_remediation", "finding_refs":[]}]);
    let text = human_report(&input);
    assert!(!text.contains("why: addresses"), "{text}");
    assert!(text.contains("recorded request for"), "{text}");
    let detail = stdout(&explain(&input, false));
    assert!(!detail.contains("why: addresses"), "{detail}");
    assert!(detail.contains("recorded request for"), "{detail}");
}

#[test]
fn audit_change_reason_advisory_only_joint_changes_keep_request_relationship() {
    let mut input = with_reasons(reasons()[0].clone(), 0);
    let mut parent_finding = input["findings"]["vulnerabilities"][0].clone();
    parent_finding["coordinate"] = json!({"registry":"npm", "name":"parent", "version":"2.0.0"});
    parent_finding["advisory_id"] = "GHSA-parent-example".into();
    parent_finding["fixed_in_versions"] = json!(["2.1.0"]);
    input["findings"]["vulnerabilities"]
        .as_array_mut()
        .expect("findings")
        .push(parent_finding);
    input["summary"]["vulnerabilities"] = 2.into();
    let record = &mut input["remediation"]["recommendations"][0];
    record["finding_refs"] = json!([0, 1]);
    record["addressed_finding_refs"] = json!([0, 1]);
    record["changes"][1]["reasons"] = json!([{"code":"advisory_remediation", "finding_refs":[1]}]);
    for limited in [false, true] {
        if limited {
            input["remediation"]["status"] = "limited".into();
            input["remediation"]["limits"]["reasons"] = json!(["change_reason_deadline"]);
        }
        for text in [human_report(&input), stdout(&explain(&input, false))] {
            assert!(text.contains("why: addresses GHSA-example"), "{text}");
            assert!(
                text.contains("why: addresses GHSA-parent-example"),
                "{text}"
            );
            assert!(text.contains("recorded request for npm:demo@1.0.0: <1.1.0; owner parent@2.0.0 [package-lock.json]"), "{text}");
        }
    }
}
