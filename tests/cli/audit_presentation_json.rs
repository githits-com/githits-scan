//! Presentation transport and association; explanation meaning is tested at its owner.
use super::*;
use serde_json::{Value, json};

fn input() -> Value {
    let mut input = fixture();
    input["remediation"] =
        serde_json::from_slice(include_bytes!("../fixtures/audit/remediation.json"))
            .expect("remediation");
    let mut alternative = input["remediation"]["recommendations"][0].clone();
    alternative["changes"][0]["target_version"] = "1.2.0".into();
    input["remediation"]["recommendations"]
        .as_array_mut()
        .expect("records")
        .push(alternative);
    input
}
fn document(output: &Output) -> Value {
    assert_eq!(output.status.code(), Some(1), "{}", stderr(output));
    serde_json::from_slice(&output.stdout).expect("presentation JSON")
}

#[test]
fn audit_presentation_json_online_and_offline_share_facts_blocks_and_exit() {
    let root = repo();
    let archive = root.path().join("analysis.json");
    let mock = server(&serde_json::to_vec(&input()).expect("report"));
    let online = run(
        root.path(),
        Some(&mock.origin()),
        &[
            "--presentation-json",
            "--quiet",
            "--save-analysis",
            archive.to_str().expect("path"),
        ],
    );
    let online = document(&online);
    assert_eq!(
        mock.requests().len(),
        3,
        "one submit/events/result also supplies presentation and archive"
    );
    assert_eq!(online["schema_version"], 1);
    assert_eq!(online["kind"], "audit_presentation");
    assert_eq!(online["audit"]["schema_version"], 2);
    let replay = document(&offline(&archive, &["--presentation-json"]));
    assert_eq!(replay["remediation"], online["remediation"]);
    assert!(replay["audit"]["analysis"].is_object());
    let facts = document(&offline(&archive, &["--json"]));
    assert_eq!(
        replay["audit"], facts,
        "existing fact JSON is embedded without alteration"
    );
    let mut replay_facts = replay["audit"].clone();
    replay_facts
        .as_object_mut()
        .expect("facts")
        .remove("analysis");
    assert_eq!(replay_facts, online["audit"]);
    assert_eq!(
        document(&offline(
            &archive,
            &["--presentation-json", "--details", "--quiet"]
        )),
        replay
    );
    let records = online["remediation"]["recommendations"]
        .as_array()
        .expect("records");
    assert_eq!(records.len(), 2, "alternatives remain independent");
    for (index, explanation) in records.iter().enumerate() {
        let fact = &online["audit"]["remediation"]["recommendations"][index];
        assert_eq!(explanation["recommendation_index"], index);
        for key in [
            "subject",
            "findings",
            "addressed_findings",
            "remaining_findings",
        ] {
            assert_eq!(explanation[key], fact[key]);
        }
        for (change_index, change) in explanation["changes"]
            .as_array()
            .expect("changes")
            .iter()
            .enumerate()
        {
            assert_eq!(change["change_index"], change_index);
            assert!(change["summary"].is_string());
            assert!(change["details"].is_array() && change["reasons"].is_array());
            assert!(fact["changes"][change_index].is_object());
        }
    }
    assert!(
        !serde_json::to_string(&online)
            .expect("JSON")
            .contains("private_unused_id")
    );
    let destination = root.path().join("presentation.json");
    let output = offline(
        &archive,
        &[
            "--presentation-json",
            "--quiet",
            "--output",
            destination.to_str().expect("path"),
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(destination).expect("file")).expect("JSON"),
        replay
    );
}

#[test]
fn audit_presentation_json_flag_conflicts_are_usage_errors() {
    for flags in [vec!["--json"], vec!["--explain", "npm:demo@1.0.0"]] {
        let output = githits_scan()
            .args([
                "audit",
                "--from-analysis",
                "unused.json",
                "--presentation-json",
            ])
            .args(flags)
            .output()
            .expect("binary");
        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
        assert_eq!(output.stdout, b"");
        assert!(stderr(&output).contains("cannot be used with"));
    }
    let output = githits_scan()
        .args(["audit", "--help"])
        .output()
        .expect("help");
    assert!(stdout(&output).contains("--presentation-json"));
}

#[test]
fn audit_presentation_json_failure_preserves_existing_file_and_never_resubmits() {
    let root = repo();
    let path = root.path().join("presentation.json");
    fs::write(&path, "keep this report").expect("existing output");
    let mut invalid = input();
    invalid["remediation"]["recommendations"][0]["changes"][0]["target_version"] = json!(23);
    let mock = server(&serde_json::to_vec(&invalid).expect("report"));
    let output = run(
        root.path(),
        Some(&mock.origin()),
        &[
            "--presentation-json",
            "--output",
            path.to_str().expect("path"),
        ],
    );
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert_eq!(output.stdout, b"");
    assert_eq!(fs::read_to_string(&path).expect("file"), "keep this report");
    assert_eq!(mock.requests().len(), 3);
    let invalid_archive = root.path().join("invalid-analysis.json");
    fs::write(&invalid_archive, "{}").expect("archive");
    let output = offline(
        &invalid_archive,
        &[
            "--presentation-json",
            "--output",
            path.to_str().expect("path"),
        ],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert_eq!(output.stdout, b"");
    assert_eq!(fs::read_to_string(path).expect("file"), "keep this report");
    let mock = server(&serde_json::to_vec(&input()).expect("report"));
    let output = run(
        root.path(),
        Some(&mock.origin()),
        &[
            "--presentation-json",
            "--output",
            root.path().to_str().expect("path"),
        ],
    );
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert_eq!(output.stdout, b"");
    assert_eq!(mock.requests().len(), 3);
}

#[test]
fn audit_presentation_json_replay_preserves_stored_ignore_policy() {
    let root = repo();
    let path = root.path().join("analysis.json");
    let mut archive: Value =
        serde_json::from_slice(include_bytes!("../fixtures/audit/analysis.json")).expect("archive");
    archive["audit_policy"] =
        json!({"ignore":[{"id":"GHSA-example","reason":"Authored review decision"}]});
    fs::write(&path, serde_json::to_vec(&archive).expect("JSON")).expect("archive file");
    let presentation = offline(&path, &["--presentation-json"]);
    let facts = offline(&path, &["--json"]);
    assert_eq!(presentation.status.code(), facts.status.code());
    let presentation: Value = serde_json::from_slice(&presentation.stdout).expect("presentation");
    let facts: Value = serde_json::from_slice(&facts.stdout).expect("facts");
    assert_eq!(presentation["audit"], facts);
    assert_eq!(presentation["audit"]["vulnerabilities"][0]["ignored"], true);
    assert_eq!(
        presentation["audit"]["vulnerabilities"][0]["ignore"]["reason"],
        "Authored review decision"
    );
    assert!(
        !presentation["remediation"]["recommendations"]
            .as_array()
            .expect("records")
            .is_empty(),
        "stored policy must not discard explanations"
    );
}
