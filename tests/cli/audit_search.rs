//! New evidence travels with the same completed audit through every output path.
use super::*;
use serde_json::{Value, json};

fn input() -> Value {
    let mut value = fixture();
    value["remediation"] =
        serde_json::from_slice(include_bytes!("../fixtures/audit/remediation.json"))
            .expect("remediation");
    let r = &mut value["remediation"]["recommendations"][0];
    r["search_detail_status"] = "retained".into();
    r["search_details"] = json!([{
        "kind":"unavailable","operation":"release","reasons":["lookup_failed"],
        "witness":{"coordinate":{"registry":"npm","name":"example-parent","version":"3.0.0"},"acquisition":"lookup_failed","private_unused_id":"omit"}
    }]);
    value["remediation"]["limits"]["omitted_search_details"] = 1.into();
    value
}
fn json_output(output: &Output) -> Value {
    assert_eq!(output.status.code(), Some(1), "{}", stderr(output));
    serde_json::from_slice(&output.stdout).expect("document")
}
#[test]
fn audit_search_binary_one_result_preserves_evidence_through_archive_and_outputs() {
    let root = repo();
    let archive = root.path().join("analysis.json");
    let mock = server(&serde_json::to_vec(&input()).expect("report"));
    let online = run(
        root.path(),
        Some(&mock.origin()),
        &[
            "--presentation-json",
            "--save-analysis",
            archive.to_str().expect("path"),
        ],
    );
    let online = json_output(&online);
    let replay = json_output(&offline(&archive, &["--presentation-json"]));
    let facts = json_output(&offline(&archive, &["--json"]));
    assert_eq!(online["remediation"], replay["remediation"]);
    assert_eq!(replay["audit"], facts);
    let record = &facts["remediation"]["recommendations"][0];
    assert_eq!(record["search_detail_status"], "retained");
    assert_eq!(
        record["search_details"][0]["witness"]["coordinate"]["name"],
        "example-parent"
    );
    assert_eq!(facts["remediation"]["limits"]["omitted_search_details"], 1);
    let explanation = &replay["remediation"]["recommendations"][0]["search_explanations"][0];
    assert_eq!(explanation["search_detail_index"], 0);
    let summary = explanation["summary"].as_str().expect("summary");
    for flags in [
        vec!["--no-color"],
        vec!["--explain", "npm:demo@1.0.0", "--no-color"],
    ] {
        let output = offline(&archive, &flags);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(
            prose(&stdout(&output)).contains(&prose(summary)),
            "{}",
            stdout(&output)
        );
        assert_eq!(
            stdout(&output).matches("\n    Upgrade search:\n").count(),
            1
        );
        assert!(stdout(&output).contains("\n      Release metadata for "));
        assert!(!stdout(&output).contains("lookup_failed"));
    }
    let stored = fs::read_to_string(&archive).expect("saved analysis");
    assert!(stored.contains("search_details") && stored.contains("lookup_failed"));
    assert!(!stored.contains("private_unused_id"));
    assert_eq!(
        mock.requests().len(),
        3,
        "offline paths do not submit another job"
    );
}
#[test]
fn audit_search_binary_malformed_evidence_preserves_existing_output() {
    let root = repo();
    let path = root.path().join("keep.json");
    fs::write(&path, "keep existing output").expect("output");
    let mut value = input();
    value["remediation"]["recommendations"][0]["search_details"][0]["reasons"] = json!([]);
    let mock = server(&serde_json::to_vec(&value).expect("report"));
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
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(
        fs::read_to_string(&path).expect("output"),
        "keep existing output"
    );
    assert_eq!(mock.requests().len(), 3);
    let archive = root.path().join("invalid-analysis.json");
    let mut saved: Value =
        serde_json::from_slice(include_bytes!("../fixtures/audit/analysis.json")).expect("archive");
    saved["producer_report"]["remediation"]["recommendations"][0]["search_detail_status"] =
        "retained".into();
    fs::write(&archive, serde_json::to_vec(&saved).expect("bytes")).expect("archive");
    let output = offline(
        &archive,
        &[
            "--presentation-json",
            "--output",
            path.to_str().expect("path"),
        ],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(
        fs::read_to_string(path).expect("output"),
        "keep existing output"
    );
}
