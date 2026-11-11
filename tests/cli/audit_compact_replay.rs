//! Detail visibility changes presentation, never saved or structured facts.
use super::*;
use crate::support::audit::{clean, findings};
use serde_json::Value;

#[test]
fn audit_details_replay_and_json_preserve_all_maintenance_facts() {
    let root = repo();
    let archive = root.path().join("analysis.json");
    let mock = server(&serde_json::to_vec(&findings()).expect("report"));
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
    assert_eq!(mock.requests().len(), 3);
    let live: Value = serde_json::from_slice(&saved.stdout).expect("JSON");
    for args in [&["--json"][..], &["--json", "--details"][..]] {
        let output = offline(&archive, args);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(output.stderr.is_empty(), "{:?}", output.stderr);
        let mut replay: Value = serde_json::from_slice(&output.stdout).expect("JSON");
        replay.as_object_mut().expect("document").remove("analysis");
        assert_eq!(replay, live);
        assert_eq!(
            replay["lifecycle"]["findings"]
                .as_array()
                .expect("native findings")
                .len(),
            1
        );
        for key in ["outdated", "duplicates"] {
            assert_eq!(replay[key].as_array().expect("findings").len(), 1, "{key}");
        }
    }
    let compact = offline(&archive, &[]);
    let full = offline(&archive, &["--details"]);
    for output in [&compact, &full] {
        assert_eq!(output.status.code(), Some(1), "{}", stderr(output));
        assert!(output.stderr.is_empty(), "{:?}", output.stderr);
        assert!(stdout(output).contains("GHSA-demo"));
        assert!(stdout(output).contains("Incomplete checks"));
    }
    for heading in ["Outdated versions", "Duplicate versions"] {
        assert!(!stdout(&compact).contains(heading));
        assert!(stdout(&full).contains(heading));
    }
}

#[test]
fn audit_compact_maintenance_only_is_still_a_finding() {
    let mut report = clean();
    report["findings"]["outdated"] = findings()["findings"]["outdated"].clone();
    report["summary"]["outdated"] = 1.into();
    let root = repo();
    for args in [
        &["--quiet"][..],
        &["--quiet", "--details"][..],
        &["--quiet", "--details", "--json"][..],
    ] {
        let mock = server(&serde_json::to_vec(&report).expect("report"));
        let output = run(root.path(), Some(&mock.origin()), args);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(output.stderr.is_empty(), "{:?}", output.stderr);
        assert_eq!(mock.requests().len(), 3);
        if args.contains(&"--json") {
            let json: Value = serde_json::from_slice(&output.stdout).expect("JSON");
            assert_eq!(json["summary"]["outdated"], 1);
            assert_eq!(json["incomplete"], false);
        } else {
            assert!(stdout(&output).contains("1 outdated"));
            assert_eq!(
                stdout(&output).contains("Outdated versions"),
                args.contains(&"--details")
            );
        }
    }
}

#[test]
fn audit_details_selects_human_file_output_and_keeps_explanation_scope() {
    let root = repo();
    let destination = root.path().join("audit.txt");
    for details in [false, true] {
        let mock = server(&serde_json::to_vec(&findings()).expect("report"));
        let mut args = vec!["--quiet", "--output", destination.to_str().expect("path")];
        if details {
            args.push("--details");
        }
        let output = run(root.path(), Some(&mock.origin()), &args);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        assert_eq!(mock.requests().len(), 3);
        let text = fs::read_to_string(&destination).expect("human file");
        assert!(text.contains("GHSA-demo"));
        assert_eq!(text.contains("Outdated versions"), details);
    }
    let archive = root.path().join("analysis.json");
    fs::write(&archive, include_bytes!("../fixtures/audit/analysis.json")).expect("archive");
    let normal = offline(&archive, &["--explain", "npm:demo@1.0.0"]);
    let detailed = offline(&archive, &["--explain", "npm:demo@1.0.0", "--details"]);
    assert_eq!(normal.status.code(), Some(1), "{}", stderr(&normal));
    assert_eq!(normal.status.code(), detailed.status.code());
    assert!(normal.stderr.is_empty() && detailed.stderr.is_empty());
    assert_eq!(normal.stdout, detailed.stdout);
}
