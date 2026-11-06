//! Real binary save/replay contract and exact action-set preservation.
use super::*;
use serde_json::{Value, json};

fn graph() -> Value {
    serde_json::from_slice(include_bytes!("../fixtures/audit/graph.json")).expect("authored graph")
}

#[test]
fn audit_explain_binary_polishes_recorded_request_context() {
    let root = repo();
    let path = root.path().join("analysis.json");
    let mut input: Value =
        serde_json::from_slice(include_bytes!("../fixtures/audit/analysis-v1.json"))
            .expect("archive");
    let request =
        &mut input["producer_report"]["remediation"]["trace"]["relations"][1]["requests"][0];
    request["requirement_status"] = "not_recorded".into();
    request["requested_requirement"] = Value::Null;
    fs::write(&path, serde_json::to_vec(&input).expect("JSON")).expect("archive file");
    let output = offline(&path, &["--explain", "npm:demo@1.0.0", "--no-color"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.contains("requirement not recorded (locked requirement)"),
        "{text}"
    );
    assert!(!text.contains("not_recorded"), "{text}");
    assert!(
        !text.contains("locked requirement; package-lock.json"),
        "{text}"
    );
    assert!(text.contains("project declaration; package.json"), "{text}");
}

#[test]
fn audit_explain_binary_deduplicates_blockers_and_translates_limits() {
    let root = repo();
    let path = root.path().join("analysis.json");
    let mut input: Value =
        serde_json::from_slice(include_bytes!("../fixtures/audit/analysis-v1.json"))
            .expect("archive");
    let record = &mut input["producer_report"]["remediation"]["recommendations"][0];
    let blocker = json!({
        "owner":{"name":"parent","version":"2.0.0"},"owner_role":"third_party",
        "path":"package-lock.json","kind":"dependency","requested_requirement":"<1.1.0",
        "requirement_status":"recorded","basis":"lockfile","context":{"copy":1},
        "reason":"checked_occurrence_changed_by_other_recommendation",
        "other_target_versions":["2.2.0"]
    });
    let mut equivalent = blocker.clone();
    equivalent["context"]["copy"] = 2.into();
    let mut different = blocker.clone();
    different["other_target_versions"] = json!(["2.3.0"]);
    let mut future = blocker.clone();
    future["owner"]["name"] = "future-parent".into();
    future["requested_requirement"] = Value::Null;
    future["requirement_status"] = "not_checked".into();
    record["blockers"] = json!([blocker, equivalent, different, future]);
    record["limitations"] = json!([
        "assignment_limit",
        "parent_evidence_incomplete",
        "parent_exact_lookup_limit",
        "introduction_not_recorded",
        "unsupported_selector",
        "release_existence_unverified"
    ]);
    let expected_blockers = record["blockers"].clone();
    let expected_limits = record["limitations"].clone();
    fs::write(&path, serde_json::to_vec(&input).expect("JSON")).expect("archive file");
    let output = offline(&path, &["--explain", "npm:demo@1.0.0", "--no-color"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    assert_eq!(
        text.matches("constraint: parent@2.0.0 requires <1.1.0")
            .count(),
        2,
        "{text}"
    );
    assert_eq!(
        text.matches("other recommended targets: 2.2.0").count(),
        2,
        "{text}"
    );
    assert!(
        text.contains("future-parent@2.0.0 requirement not_checked"),
        "{text}"
    );
    assert!(!text.contains("project resolver/build not run"), "{text}");
    assert_eq!(
        text.matches("other recommended targets: 2.3.0").count(),
        1,
        "{text}"
    );
    for expected in [
        "parent upgrade search reached its combination limit",
        "parent dependency evidence is incomplete",
        "parent release metadata lookup limit reached",
        "how the dependency was introduced is not recorded",
        "dependency requirement could not be evaluated",
        "target release availability not verified",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    let output = offline(&path, &["--explain", "npm:demo@1.0.0", "--json"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let output: Value = serde_json::from_slice(&output.stdout).expect("explanation JSON");
    let actual = &output["remediation"]["recommendations"][0];
    assert_eq!(actual["blockers"], expected_blockers);
    assert_eq!(actual["limitations"], expected_limits);
}

#[test]
fn audit_explain_binary_deduplicates_reference_warnings_without_losing_json_issues() {
    let root = repo();
    let path = root.path().join("analysis.json");
    let mut input: Value =
        serde_json::from_slice(include_bytes!("../fixtures/audit/analysis-v1.json"))
            .expect("archive");
    input["producer_report"]["remediation"]["trace"]["relations"][0]["from_ref"] = json!(999_999);
    input["producer_report"]["remediation"]["trace"]["relations"][1]["path"] =
        "other/package-lock.json".into();
    fs::write(&path, serde_json::to_vec(&input).expect("JSON")).expect("archive file");
    let output = offline(&path, &["--explain", "npm:demo@1.0.0", "--no-color"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(
        stdout(&output)
            .matches(
                "Some recorded requests have unverified references; affected routes are not shown."
            )
            .count(),
        1
    );
    let output = offline(&path, &["--explain", "npm:demo@1.0.0", "--json"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let output: Value = serde_json::from_slice(&output.stdout).expect("explanation JSON");
    let issues = output["sources"][0]["issues"].as_array().expect("issues");
    assert!(issues.contains(&json!("relation_refs_unverified")));
    assert!(issues.contains(&json!("relation_source_unverified")));
}

#[test]
fn audit_saved_binary_save_replay_preserve_facts_without_network() {
    let root = repo();
    let path = root.path().join("analysis.json");
    let mut input = graph();
    input["private_inventory"] = json!({"native_id":"never-export"});
    let mock = server(&serde_json::to_vec(&input).expect("report"));
    let output = run(
        root.path(),
        Some(&mock.origin()),
        &[
            "--save-analysis",
            path.to_str().expect("path"),
            "--json",
            "--quiet",
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    let initial: Value = serde_json::from_slice(&output.stdout).expect("compact");
    assert!(initial.get("analysis").is_none());
    assert!(
        initial["remediation"]["recommendations"][0]["changes"][0]
            .get("occurrence_refs")
            .is_none()
    );
    let bytes = fs::read(&path).expect("saved");
    let stored: Value = serde_json::from_slice(&bytes).expect("archive");
    assert_eq!(
        stored["producer_report"]["remediation"]["recommendations"][0]["changes"][0]["occurrence_refs"],
        json!([0])
    );
    assert!(!String::from_utf8_lossy(&bytes).contains("never-export"));
    assert!(!String::from_utf8_lossy(&bytes).contains("test-token"));
    fs::write(
        root.path().join("githits-scan.toml"),
        "invalid configuration [",
    )
    .expect("poison config");
    let replay = offline(&path, &["--json"]);
    assert_eq!(replay.status.code(), Some(1), "{}", stderr(&replay));
    assert!(replay.stderr.is_empty(), "{:?}", replay.stderr);
    let mut replayed: Value = serde_json::from_slice(&replay.stdout).expect("replay");
    assert_eq!(replayed["analysis"]["generated_at"], input["generated_at"]);
    replayed.as_object_mut().expect("object").remove("analysis");
    assert_eq!(replayed, initial);
    assert_eq!(mock.requests().len(), 3, "replay never submits");
}

#[test]
fn audit_explain_binary_preserves_joint_actions_and_problem_order() {
    let root = repo();
    let path = root.path().join("analysis.json");
    let mock = server(&serde_json::to_vec(&graph()).expect("report"));
    let saved = run(
        root.path(),
        Some(&mock.origin()),
        &[
            "--save-analysis",
            path.to_str().expect("path"),
            "--json",
            "--quiet",
        ],
    );
    assert_eq!(saved.status.code(), Some(1), "{}", stderr(&saved));
    let explained = offline(
        &path,
        &["--explain", "npm:demo@1.0.0", "--no-color", "--quiet"],
    );
    assert_eq!(explained.status.code(), Some(1), "{}", stderr(&explained));
    let text = stdout(&explained);
    assert!(
        text.find("npm:demo@1.0.0 — vulnerable").expect("problem")
            < text.find("Requested by").expect("requesters")
    );
    assert!(
        text.find("Requested by").expect("requesters")
            < text.find("Suggested fix — change together:").expect("fix")
    );
    for expected in [
        "<1.1.0",
        "Upgrade npm:demo 1.0.0 -> 1.1.1",
        "Upgrade npm:parent 2.0.0 -> 2.1.0",
        "target is deprecated",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    for unwanted in [
        "catalog freshness",
        "native resolution",
        "Verify changes",
        "private_inventory",
    ] {
        assert!(!text.contains(unwanted), "{text}");
    }
    let explained = offline(&path, &["--explain", "npm:demo@1.0.0", "--json"]);
    let result: Value = serde_json::from_slice(&explained.stdout).expect("explanation JSON");
    assert_eq!(result["kind"], "audit_explanation");
    assert_eq!(
        result["sources"][0]["nodes"]
            .as_array()
            .expect("nodes")
            .len(),
        3
    );
    assert_eq!(
        result["remediation"]["recommendations"][0]["changes"]
            .as_array()
            .expect("joint")
            .len(),
        2
    );
    assert_eq!(mock.requests().len(), 3, "replay never submits");
}

#[test]
fn audit_saved_binary_bad_archives_and_selection_use_usage_exit() {
    let root = repo();
    let path = root.path().join("saved.json");
    let mut archive: Value =
        serde_json::from_slice(include_bytes!("../fixtures/audit/analysis-v1.json"))
            .expect("archive");
    let mut corrupt = archive.clone();
    corrupt["producer_report"] = json!({"schema_version":2});
    let mut future = archive.clone();
    future["schema_version"] = 99.into();
    for bytes in [
        Vec::new(),
        b"{".to_vec(),
        serde_json::to_vec(&corrupt).expect("corrupt"),
        serde_json::to_vec(&future).expect("future"),
        serde_json::to_vec(&json!({"schema_version":1})).expect("compact"),
    ] {
        fs::write(&path, bytes).expect("input");
        let output = offline(&path, &["--json"]);
        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
        assert!(output.stdout.is_empty(), "{:?}", output.stdout);
        assert!(stderr(&output).contains("invalid analysis"));
    }
    fs::write(&path, serde_json::to_vec(&archive).expect("archive")).expect("write");
    let output = offline(&path, &["--explain", "npm:missing@1.0.0"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("no vulnerable component matched"));
    assert_eq!(
        offline(&root.path().join("missing.json"), &[])
            .status
            .code(),
        Some(2)
    );
    archive["producer_report"]["schema_version"] = 3.into();
    fs::write(&path, serde_json::to_vec(&archive).expect("future inner")).expect("write");
    assert_eq!(offline(&path, &[]).status.code(), Some(2));
}

#[test]
fn audit_saved_binary_existing_destination_stops_before_discovery_or_upload() {
    let root = repo();
    let file = root.path().join("existing.json");
    fs::write(&file, b"preserve this").expect("file");
    fs::write(root.path().join("githits-scan.toml"), "invalid [").expect("config");
    let output = run(
        root.path(),
        Some("http://127.0.0.1:1"),
        &["--save-analysis", file.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("already exists"));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert_eq!(fs::read(&file).expect("preserved"), b"preserve this");
}

#[test]
fn audit_saved_binary_late_save_failure_writes_no_report() {
    for report in [json!({"schema_version":3}), graph()] {
        let root = repo();
        let file = root.path().join("missing-parent").join("analysis.json");
        let mock = server(&serde_json::to_vec(&report).expect("report"));
        let output = run(
            root.path(),
            Some(&mock.origin()),
            &["--save-analysis", file.to_str().expect("path"), "--json"],
        );
        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        assert!(output.stdout.is_empty(), "{:?}", output.stdout);
        assert!(!file.exists());
        assert!(!stderr(&output).contains("saved "));
        assert_eq!(mock.requests().len(), 3);
    }
}

#[test]
fn audit_saved_binary_normal_save_announces_file_and_offline_ignores_bad_token() {
    let root = repo();
    let file = root.path().join("analysis.json");
    let mock = server(&serde_json::to_vec(&graph()).expect("report"));
    let output = run(
        root.path(),
        Some(&mock.origin()),
        &["--save-analysis", file.to_str().expect("path"), "--json"],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).contains("saved "));
    let replay = githits_scan()
        .args(["audit", "--from-analysis"])
        .arg(&file)
        .arg("--json")
        .env("GITHITS_API_TOKEN", "")
        .env("GITHITS_API_URL", "invalid")
        .output()
        .expect("offline");
    assert_eq!(replay.status.code(), Some(1), "{}", stderr(&replay));
}

#[test]
fn audit_explain_binary_partial_alternatives_keep_complete_actions_and_remaining() {
    let mut input = graph();
    let mut second = input["findings"]["vulnerabilities"][0].clone();
    second["advisory_id"] = "GHSA-second".into();
    input["findings"]["vulnerabilities"]
        .as_array_mut()
        .expect("findings")
        .push(second);
    input["summary"]["vulnerabilities"] = 2.into();
    let first = &mut input["remediation"]["recommendations"][0];
    first["finding_refs"] = json!([0, 1]);
    first["outcome"] = "partial".into();
    first["remaining_finding_refs"] = json!([1]);
    first["remaining_occurrence_refs"] = json!([0]);
    let mut alternative = first.clone();
    alternative["outcome"] = "proposed".into();
    alternative["addressed_finding_refs"] = json!([0, 1]);
    alternative["remaining_finding_refs"] = json!([]);
    alternative["remaining_occurrence_refs"] = json!([]);
    alternative["changes"][0]["target_version"] = "1.1.2".into();
    alternative["changes"][1]["target_version"] = "2.2.0".into();
    input["remediation"]["recommendations"]
        .as_array_mut()
        .expect("alternatives")
        .push(alternative);
    let root = repo();
    let path = root.path().join("analysis.json");
    let mock = server(&serde_json::to_vec(&input).expect("report"));
    let saved = run(
        root.path(),
        Some(&mock.origin()),
        &["--save-analysis", path.to_str().expect("path"), "--quiet"],
    );
    assert_eq!(saved.status.code(), Some(1), "{}", stderr(&saved));
    let output = offline(&path, &["--explain", "npm:demo@1.0.0", "--json"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let result: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let alternatives = result["remediation"]["recommendations"]
        .as_array()
        .expect("alternatives");
    assert_eq!(alternatives.len(), 2);
    for row in alternatives {
        assert_eq!(row["changes"].as_array().expect("joint").len(), 2);
    }
    assert_eq!(
        alternatives[0]["remaining_findings"][0]["advisory"],
        "GHSA-second"
    );
    let scope = &alternatives[0]["occurrence_scope"];
    assert_eq!(
        scope["subject"]["nodes"]
            .as_array()
            .expect("subject copies")
            .len(),
        1
    );
    assert_eq!(
        scope["remaining"]["nodes"]
            .as_array()
            .expect("remaining copies")
            .len(),
        1
    );
    assert_eq!(
        scope["changes"].as_array().expect("per-change scope").len(),
        2
    );

    assert_eq!(
        alternatives[1]["addressed_findings"]
            .as_array()
            .expect("addressed")
            .len(),
        2
    );
    let text = stdout(&offline(
        &path,
        &["--explain", "npm:demo@1.0.0", "--no-color"],
    ));
    assert!(
        text.contains("Alternative 1")
            && text.contains("Alternative 2")
            && text.contains("still unresolved:")
            && text.contains("GHSA-second")
            && text.contains("Remaining copies:"),
        "{text}"
    );
    assert_eq!(mock.requests().len(), 3);
}

#[test]
fn audit_explain_binary_unavailable_detail_keeps_inline_joint_fixes() {
    let mut input = graph();
    input["remediation"]["trace"] =
        json!({"status":"not_retained","occurrences":[],"relations":[]});
    input["remediation"]["recommendations"][0]["occurrence_refs"] = json!([]);
    input["remediation"]["recommendations"][0]["detail_status"] = "not_retained".into();
    for change in input["remediation"]["recommendations"][0]["changes"]
        .as_array_mut()
        .expect("changes")
    {
        change["occurrence_refs"] = json!([]);
    }
    let root = repo();
    let path = root.path().join("analysis.json");
    let mock = server(&serde_json::to_vec(&input).expect("report"));
    let saved = run(
        root.path(),
        Some(&mock.origin()),
        &["--save-analysis", path.to_str().expect("path"), "--quiet"],
    );
    assert_eq!(saved.status.code(), Some(1), "{}", stderr(&saved));
    let output = offline(&path, &["--explain", "npm:demo@1.0.0", "--json"]);
    let result: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(result["sources"], json!([]));
    assert_eq!(result["issues"], json!(["trace_not_retained"]));
    assert_eq!(
        result["remediation"]["recommendations"][0]["changes"]
            .as_array()
            .expect("joint")
            .len(),
        2
    );
    let text = stdout(&offline(
        &path,
        &["--explain", "npm:demo@1.0.0", "--no-color"],
    ));
    assert!(text.contains("not retained") && text.contains("change together"));
    assert!(!text.contains("No matching recorded occurrence"));
    assert_eq!(mock.requests().len(), 3);
}

#[test]
fn audit_saved_binary_oversized_file_is_usage_error() {
    let root = repo();
    let path = root.path().join("too-large.json");
    fs::write(&path, vec![b' '; 16_777_217]).expect("oversize");
    let output = offline(&path, &["--json"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(stderr(&output).contains("16777216-byte limit"));
}

#[test]
fn audit_explain_binary_escapes_problem_and_request_text() {
    let mut input = graph();
    input["findings"]["vulnerabilities"][0]["summary"] = "unsafe\n\u{1b}[2J".into();
    input["remediation"]["trace"]["relations"][0]["requests"][0]["requested_requirement"] =
        "unsafe\n\u{1b}[2J".into();
    let root = repo();
    let path = root.path().join("analysis.json");
    let mock = server(&serde_json::to_vec(&input).expect("report"));
    let saved = run(
        root.path(),
        Some(&mock.origin()),
        &["--save-analysis", path.to_str().expect("path"), "--quiet"],
    );
    assert_eq!(saved.status.code(), Some(1));
    let output = offline(&path, &["--explain", "npm:demo@1.0.0", "--no-color"]);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(text.contains("unsafe\\n\\u{1b}[2J"), "{text}");
    assert!(!text.contains('\u{1b}'));
    assert_eq!(mock.requests().len(), 3);
}

#[cfg(unix)]
#[test]
fn audit_saved_binary_dangling_symlink_is_not_overwritten() {
    let root = repo();
    let target = root.path().join("missing-target.json");
    let file = root.path().join("analysis.json");
    std::os::unix::fs::symlink(&target, &file).expect("dangling symlink");
    fs::write(root.path().join("githits-scan.toml"), "invalid [").expect("poison config");
    let output = run(
        root.path(),
        Some("http://127.0.0.1:1"),
        &["--save-analysis", file.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("already exists"));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(
        fs::symlink_metadata(&file)
            .expect("symlink")
            .file_type()
            .is_symlink()
    );
    assert!(!target.exists());
}

#[cfg(unix)]
#[test]
fn audit_saved_binary_unwritable_parent_fails_preflight_without_upload() {
    let root = repo();
    let parent = root.path().join("blocked-parent");
    fs::write(&parent, b"preserve parent").expect("parent is a file");
    fs::write(root.path().join("githits-scan.toml"), "invalid [").expect("poison config");
    let file = parent.join("analysis.json");
    let output = run(
        root.path(),
        Some("http://127.0.0.1:1"),
        &["--save-analysis", file.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("cannot write"));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert_eq!(fs::read(&parent).expect("preserved"), b"preserve parent");
}

#[test]
fn audit_saved_output_routes_reports_and_explanations_offline() {
    let root = repo();
    let path = root.path().join("analysis.json");
    fs::write(&path, include_bytes!("../fixtures/audit/analysis-v1.json")).expect("archive");
    let target = root.path().join("report.json");
    for explain in [false, true] {
        let mut args = vec!["--json"];
        if explain {
            args.extend(["--explain", "npm:demo@1.0.0"]);
        }
        let original = offline(&path, &args);
        args.extend(["-o", target.to_str().expect("path")]);
        let output = offline(&path, &args);
        assert_eq!(
            output.status.code(),
            original.status.code(),
            "{}",
            stderr(&output)
        );
        assert_eq!(output.stdout, Vec::<u8>::new());
        assert!(stderr(&output).contains(&format!("saved {}", target.display())));
        assert_eq!(fs::read(&target).expect("report"), original.stdout);
        let last = args.len() - 1;
        args[last] = "-";
        let output = offline(&path, &args);
        assert_eq!(output.stdout, original.stdout);
    }
}
