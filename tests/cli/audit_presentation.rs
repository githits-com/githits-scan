//! Severity facts and readable labels through saved and online binary paths.
use super::*;
use serde_json::{Value, json};

type Case = (
    Option<f64>,
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
);

const CASES: &[Case] = &[
    (
        Some(7.0),
        Some("CVSS_V2"),
        Some("CVSS 7"),
        Some("CVSS_V2 7"),
    ),
    (
        Some(7.4),
        Some("CVSS_V3"),
        Some("CVSS 7.4"),
        Some("CVSS_V3 7.4"),
    ),
    (
        Some(9.1),
        Some("CVSS_V4"),
        Some("CVSS 9.1"),
        Some("CVSS_V4 9.1"),
    ),
    (Some(7.0), Some("CVSS"), Some("CVSS 7"), Some("CVSS 7")),
    (
        Some(6.0),
        Some("SEVERITY_LABEL"),
        Some("severity 6"),
        Some("SEVERITY_LABEL 6"),
    ),
    (
        Some(0.0),
        Some("SEVERITY_LABEL"),
        Some("severity 0"),
        Some("SEVERITY_LABEL 0"),
    ),
    (Some(4.0), None, Some("severity 4"), Some("score 4")),
    (Some(2.0), Some(""), Some("severity 2"), Some(" 2")),
    (
        Some(4.0),
        Some("FUTURE\nsource"),
        Some("severity 4; source: FUTURE\\nsource"),
        Some("FUTURE\nsource 4"),
    ),
    (None, Some("CVSS_V3"), None, None),
    (None, None, None, None),
];

fn archive() -> Value {
    serde_json::from_slice(include_bytes!("../fixtures/audit/analysis.json"))
        .expect("authored archive")
}

fn assert_facts(finding: &Value, case: &Case) {
    for (key, expected) in [
        ("severity", case.3.map(|s| json!(s))),
        ("severity_score", case.0.map(|s| json!(s))),
        ("severity_type", case.1.map(|s| json!(s))),
    ] {
        assert_eq!(finding.get(key), expected.as_ref(), "{key}: {finding}");
    }
}

fn assert_label(text: &str, label: Option<&str>) {
    let advisory = text
        .lines()
        .find(|line| line.contains("GHSA-"))
        .expect("visible advisory");
    if let Some(label) = label {
        assert!(advisory.contains(&format!("({label})")), "{advisory}");
    } else {
        assert!(
            !advisory.contains('('),
            "no severity placeholder: {advisory}"
        );
    }
    assert!(!advisory.contains("CVSS_V"), "{advisory}");
    assert!(!advisory.contains("SEVERITY_LABEL"), "{advisory}");
}

fn assert_saved_case(path: &Path, case: &Case, covered: bool) {
    let mut input = archive();
    let finding = &mut input["producer_report"]["findings"]["vulnerabilities"][0];
    finding["severity_score"] = json!(case.0);
    finding["severity_type"] = json!(case.1);
    if !covered {
        input["producer_report"]
            .as_object_mut()
            .expect("producer object")
            .remove("remediation");
    }
    let bytes = serde_json::to_vec(&input).expect("archive JSON");
    fs::write(path, &bytes).expect("write archive");
    for args in [
        vec!["--no-color"],
        vec!["--details", "--no-color"],
        vec!["--explain", "npm:demo@1.0.0", "--no-color"],
    ] {
        let output = offline(path, &args);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
        assert_label(&stdout(&output), case.2);
    }
    for (args, field) in [
        (vec!["--json"], "vulnerabilities"),
        (vec!["--explain", "npm:demo@1.0.0", "--json"], "problems"),
    ] {
        let output = offline(path, &args);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
        let view: Value = serde_json::from_slice(&output.stdout).expect("view JSON");
        assert_facts(&view[field][0], case);
        assert_eq!(view["schema_version"], 2, "{view}");
    }
    assert_eq!(fs::read(path).expect("unchanged archive"), bytes);
}

#[test]
fn audit_presentation_saved_severity_preserves_facts_and_readable_labels() {
    let root = repo();
    let path = root.path().join("analysis.json");
    for case in CASES {
        for covered in [false, true] {
            assert_saved_case(&path, case, covered);
        }
    }
}

#[test]
fn audit_presentation_keeps_typed_and_display_severity() {
    let root = repo();
    let case = &CASES[1];
    let mut input = fixture();
    input["findings"]["vulnerabilities"][0]["severity_score"] = json!(case.0);
    input["findings"]["vulnerabilities"][0]["severity_type"] = json!(case.1);
    input["findings"]["vulnerabilities"][0]["summary"] = "Authored example vulnerability".into();
    let bytes = serde_json::to_vec(&input).expect("native JSON");
    let s = server(&bytes);
    let output = run(root.path(), Some(&s.origin()), &["--json"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let view: Value = serde_json::from_slice(&output.stdout).expect("view JSON");
    assert_facts(&view["vulnerabilities"][0], case);
    let s = server(&bytes);
    let output = run(root.path(), Some(&s.origin()), &["--no-color"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_label(&stdout(&output), case.2);
}

#[test]
fn audit_presentation_archive_replay_matches_recorded_analysis() {
    let root = repo();
    let path = root.path().join("analysis.json");
    let bytes = include_bytes!("../fixtures/audit/analysis.json");
    fs::write(&path, bytes).expect("archive");
    let input = archive();
    let s = server(&serde_json::to_vec(&input["producer_report"]).expect("producer JSON"));
    let online = run(root.path(), Some(&s.origin()), &["--json", "--quiet"]);
    assert_eq!(online.status.code(), Some(1), "{}", stderr(&online));
    let expected: Value = serde_json::from_slice(&online.stdout).expect("online JSON");
    fs::write(root.path().join("githits-scan.toml"), "invalid [").expect("poison config");
    let output = offline(&path, &["--json"]);
    assert_eq!(output.status.code(), online.status.code());
    assert!(output.stderr.is_empty(), "{}", stderr(&output));
    let mut actual: Value = serde_json::from_slice(&output.stdout).expect("offline JSON");
    actual.as_object_mut().expect("view").remove("analysis");
    assert_eq!(
        actual, expected,
        "all finding and coverage facts survive replay"
    );
    assert_eq!(fs::read(&path).expect("unchanged archive"), bytes);
    assert_eq!(
        s.requests().len(),
        3,
        "only the loopback online analysis submits"
    );
}

#[test]
fn audit_presentation_new_dependency_limit_keeps_raw_codes_and_coverage() {
    let root = repo();
    let path = root.path().join("analysis.json");
    let mut input = archive();
    input["producer_report"]["remediation"]["recommendations"][0]["limitations"] =
        json!(["new_dependency_not_checked", "future_limit"]);
    fs::write(&path, serde_json::to_vec(&input).expect("JSON")).expect("archive");
    for args in [vec!["--no-color"], vec!["--explain", "npm:demo@1.0.0"]] {
        let output = offline(&path, &args);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        let text = stdout(&output);
        assert!(text.contains("a new dependency was not checked"), "{text}");
        assert!(!text.contains("new_dependency_not_checked"), "{text}");
        assert!(text.contains("future_limit"), "{text}");
    }
    let output = offline(&path, &["--json"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let view: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        view["remediation"]["recommendations"][0]["limitations"],
        json!(["new_dependency_not_checked", "future_limit"])
    );
    let baseline = archive();
    fs::write(&path, serde_json::to_vec(&baseline).expect("JSON")).expect("archive");
    let output = offline(&path, &["--json"]);
    let original: Value = serde_json::from_slice(&output.stdout).expect("baseline JSON");
    for field in ["summary", "incomplete", "issues", "vulnerabilities"] {
        assert_eq!(view.get(field), original.get(field), "{field}");
    }
}
