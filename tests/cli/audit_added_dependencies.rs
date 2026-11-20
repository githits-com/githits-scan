//! Registry branch facts travel through live and saved audit presentation.
use super::*;
use serde_json::Value;

fn report() -> Value {
    let mut value = fixture();
    value["remediation"] =
        serde_json::from_slice(include_bytes!("../fixtures/audit/remediation.json"))
            .expect("remediation");
    value
}

fn document(output: &Output) -> Value {
    assert_eq!(output.status.code(), Some(1), "{}", stderr(output));
    serde_json::from_slice(&output.stdout).expect("document")
}

#[test]
fn audit_added_dependencies_keeps_checked_branch_and_losing_candidates() {
    let branches: Value =
        serde_json::from_slice(include_bytes!("../fixtures/audit/added-dependencies.json"))
            .expect("branches");
    let mut value = report();
    let r = &mut value["remediation"]["recommendations"][0];
    r["changes"][0]["added_dependencies"] = branches["added_dependencies"].clone();
    r["search_detail_status"] = "retained".into();
    r["search_details"] = branches["search_details"].clone();

    let root = repo();
    let archive = root.path().join("analysis.json");
    let mock = server(&serde_json::to_vec(&value).expect("response"));
    let online = document(&run(
        root.path(),
        Some(&mock.origin()),
        &[
            "--presentation-json",
            "--save-analysis",
            archive.to_str().expect("path"),
        ],
    ));
    let replay = document(&offline(&archive, &["--presentation-json"]));
    assert_eq!(online["remediation"], replay["remediation"]);
    let facts = document(&offline(&archive, &["--json"]));
    assert_eq!(replay["audit"], facts);
    let record = &facts["remediation"]["recommendations"][0];
    assert_eq!(
        record["changes"][0]["added_dependencies"],
        branches["added_dependencies"]
    );
    for (actual, expected) in record["search_details"]
        .as_array()
        .expect("search details")
        .iter()
        .zip(
            branches["search_details"]
                .as_array()
                .expect("fixture details"),
        )
    {
        assert_eq!(actual["added_dependency"], expected["added_dependency"]);
        assert_eq!(
            actual["witness"]["coordinate"],
            expected["witness"]["coordinate"]
        );
        assert_eq!(actual["witness"]["source"]["path"], "package-lock.json");
    }

    let presentation = &replay["remediation"]["recommendations"][0];
    assert_eq!(presentation["details_recommended"], true);
    assert_eq!(
        presentation["compact_summary"],
        concat!(
            "Bump npm:demo 1.0.0 -> 1.1.1 in package-lock.json. Addresses GHSA-demo. ",
            "Adds new dependency npm:added-child@1.0.0."
        )
    );
    let change = &presentation["changes"][0];
    assert_eq!(change["change_index"], 0);
    let details = change["details"].to_string();
    assert!(details.contains("child-alias npm:added-child@^1"));
    assert!(details.contains("registry checks selected npm:added-child@1.0.0"));
    assert!(details.contains(
        "No affecting advisories found for npm:added-child@1.0.0, npm:optional-descendant@1.0.0."
    ));
    let searches = &presentation["search_explanations"];
    assert_eq!(searches[0]["search_detail_index"], 0);
    assert_eq!(searches[1]["search_detail_index"], 1);
    assert_eq!(searches[2]["search_detail_index"], 2);
    for (index, wording) in [
        (0, "An advisory affects a selected version."),
        (
            1,
            "The service could not complete the checks for this request.",
        ),
    ] {
        assert!(
            searches[index]["summary"]
                .as_str()
                .expect("summary")
                .contains(wording)
        );
    }
    assert_eq!(
        searches[2]["summary"],
        "Candidate npm:demo@1.3.0 [package-lock.json] requires child-alias npm:added-child@^1 as a new dependency."
    );

    for flags in [
        vec!["--no-color"],
        vec!["--explain", "npm:demo@1.0.0", "--no-color"],
    ] {
        let output = offline(&archive, &flags);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert_native(&prose(&stdout(&output)));
    }
    assert_eq!(mock.requests().len(), 3, "replay never submits another job");
}

fn assert_native(output: &str) {
    let (selected, search) = output.split_once("Upgrade search:").expect(output);
    assert!(selected.contains("GHSA-demo"), "{output}");
    assert!(selected.contains("npm:demo 1.0.0 -> 1.1.1"), "{output}");
    assert!(
        selected.contains("child-alias npm:added-child@^1"),
        "{output}"
    );
    assert!(
        selected.contains(concat!(
            "project installer may select different package copies or apply different policy ",
            "than these registry checks."
        )),
        "{output}"
    );
    assert!(
        selected.contains("No affecting advisories found for npm:added-child@1.0.0, npm:optional-descendant@1.0.0."),
        "{output}"
    );
    assert!(
        search.contains("Candidate npm:demo@1.2.0 [package-lock.json]"),
        "{output}"
    );
    assert!(search.contains("npm:affected-descendant@1.0.0 found applicable advisories (AUDIT-ADDED-affected-descendant)"), "{output}");
    assert!(
        search.contains("Candidate npm:demo@1.3.0 [package-lock.json]"),
        "{output}"
    );
    assert!(
        search.contains(concat!(
            "No affecting advisories found for npm:debug@4.4.3, npm:depd@2.0.0, ",
            "npm:is-promise@4.0.0, npm:ms@2.1.3, npm:parseurl@1.3.3, ",
            "npm:path-to-regexp@8.4.2, npm:router@2.3.0."
        )),
        "{output}"
    );
    assert!(
        search.contains(
            "Dependency check for is-promise@4.0.0 — the dependency list was unavailable, so its dependencies could not be fully checked."
        ),
        "{output}"
    );
    assert!(!output.contains("added_coordinate_affected"));
    assert!(!output.contains("registry_resolution"));
    assert!(!output.contains("dependency_list_unavailable"));
}

#[test]
fn audit_added_dependencies_older_archive_keeps_its_existing_guidance() {
    let root = repo();
    let archive = root.path().join("older.json");
    fs::write(&archive, include_bytes!("../fixtures/audit/analysis.json")).expect("archive");
    let result = document(&offline(&archive, &["--presentation-json"]));
    let record = &result["audit"]["remediation"]["recommendations"][0];
    assert!(record["changes"][0].get("added_dependencies").is_none());
    assert!(record.get("search_details").is_none());
    let output = offline(&archive, &["--no-color"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let output = stdout(&output);
    assert!(output.contains("GHSA-example"), "{output}");
    assert!(output.contains("1.0.0 -> 1.1.1"), "{output}");
    assert!(!output.contains("project installer may select"), "{output}");
    assert!(!output.contains("Upgrade search:"), "{output}");
}
