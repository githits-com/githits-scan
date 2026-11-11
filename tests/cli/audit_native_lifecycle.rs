//! Native lifecycle policy and offline fact-preservation regressions.
use super::*;
use crate::support::audit::{facet, pypi_not_applicable};
use serde_json::{Value, json};

fn online(
    root: &std::path::Path,
    bytes: &[u8],
    args: &[&str],
) -> (std::process::Output, crate::support::jobs::ScriptedServer) {
    let mock = server(bytes);
    let output = run(root, Some(&mock.origin()), args);
    (output, mock)
}

fn assert_exit(output: &std::process::Output, expected: i32) {
    assert_eq!(output.status.code(), Some(expected), "{}", stderr(output));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
}

fn successful_online(root: &std::path::Path, bytes: &[u8], args: &[&str]) -> std::process::Output {
    let (output, mock) = online(root, bytes, args);
    assert_exit(&output, 0);
    assert_eq!(mock.requests().len(), 3);
    output
}

fn json_view(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("JSON view")
}

fn assert_collection_facet(
    coverage: &Value,
    name: &str,
    checked_count: u64,
    not_applicable_count: u64,
    not_applicable_registries: &[&str],
    not_collected_count: u64,
    not_collected_registries: &[&str],
) {
    let facet = &coverage[name];
    assert_eq!(facet["candidates_count"], 2, "{name}");
    assert_eq!(facet["checked_count"], checked_count, "{name}");
    assert_eq!(facet["unknown_count"], 0, "{name}");
    assert_eq!(
        facet["not_applicable_count"], not_applicable_count,
        "{name}"
    );
    assert_eq!(
        facet["not_applicable_registries"],
        json!(not_applicable_registries),
        "{name}"
    );
    assert_eq!(facet["not_collected_count"], not_collected_count, "{name}");
    assert_eq!(
        facet["not_collected_registries"],
        json!(not_collected_registries),
        "{name}"
    );
}

fn assert_collection_json(report: &Value) {
    assert_eq!(report["incomplete"], false);
    assert_eq!(report["lifecycle"]["findings"], json!([]));
    assert_eq!(report["lifecycle"]["retained_warnings"], json!([]));
    assert_eq!(report["lifecycle"]["unknowns"], json!([]));
    assert!(report.get("issues").is_none());

    let coverage = &report["lifecycle"]["coverage"];
    assert_collection_facet(coverage, "deprecation", 0, 2, &["pypi"], 0, &[]);
    assert_collection_facet(coverage, "withdrawal", 2, 0, &[], 0, &[]);
    assert_collection_facet(coverage, "registry_archival", 0, 0, &[], 2, &["pypi"]);
    assert_collection_facet(coverage, "repository_archival", 0, 0, &[], 2, &["pypi"]);
}

fn assert_ordinary_limits_hidden(text: &str) {
    assert!(text.contains("No audit findings in available evidence"));
    for omitted in [
        "registry archival",
        "repository archival",
        "does not apply",
        "not collected",
        "not a checked negative",
        "Package warnings",
        "Incomplete checks",
    ] {
        assert!(!text.contains(omitted), "{omitted}: {text}");
    }
}

fn assert_details_limits_visible(text: &str) {
    for expected in [
        "deprecation does not apply to 2 dependencies (pypi); this is not a checked negative",
        "registry archival was not collected for 2 dependencies (pypi)",
        "repository archival was not collected for 2 dependencies (pypi)",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
}

#[test]
fn audit_native_collection_limits_are_not_failures() {
    let root = repo();
    let bytes = serde_json::to_vec(&pypi_not_applicable()).expect("native lifecycle report");
    let report = json_view(&successful_online(
        root.path(),
        &bytes,
        &["--json", "--quiet"],
    ));
    assert_collection_json(&report);

    let ordinary = successful_online(root.path(), &bytes, &["--no-color", "--quiet"]);
    assert_ordinary_limits_hidden(&stdout(&ordinary));
    let details = successful_online(root.path(), &bytes, &["--no-color", "--quiet", "--details"]);
    assert_details_limits_visible(&stdout(&details));
}

fn go_repo() -> tempfile::TempDir {
    let root = repo();
    fs::write(
        root.path().join("go.mod"),
        "module example.com/root\n\ngo 1.23\n\nrequire example.com/widget v1.4.0\n",
    )
    .expect("root Go module");
    fs::create_dir_all(root.path().join("web")).expect("nested Go module directory");
    fs::write(
        root.path().join("web/go.mod"),
        "module example.com/web\n\ngo 1.23\n\nrequire example.com/widget v2.1.0\n",
    )
    .expect("nested Go module");
    root
}

fn package_event() -> Value {
    json!({
        "registry":"go",
        "name":"example.com/widget",
        "version":null,
        "category":"deprecation",
        "kind":"deprecated",
        "scope":"package",
        "source":"pkg.go.dev",
        "observations":[
            {
                "source_version":"v3.0.0",
                "observed_at":"2026-10-03T12:00:00Z",
                "reason":"The maintainer announced retirement of the first line.",
                "reason_codes":[],
                "replacement":null,
                "affected":[{
                    "coordinate":{"registry":"go","name":"example.com/widget","version":"v1.4.0"},
                    "paths":["go.mod"]
                }]
            },
            {
                "source_version":"v4.0.0",
                "observed_at":"2026-11-03T12:00:00Z",
                "reason":"The maintainer confirmed the package is deprecated.",
                "reason_codes":[],
                "replacement":null,
                "affected":[{
                    "coordinate":{"registry":"go","name":"example.com/widget","version":"v2.1.0"},
                    "paths":["web/go.mod"]
                }]
            }
        ]
    })
}

fn go_package_report() -> (Value, Value) {
    let event = package_event();
    let mut report = clean();
    report["summary"]["lifecycle"] = 1.into();
    report["lifecycle"]["findings"] = json!([event]);
    report["lifecycle"]["coverage"]["deprecation"] = facet(2, 2, 0, 0, 0, "go");
    for check in ["withdrawal", "registry_archival", "repository_archival"] {
        report["lifecycle"]["coverage"][check] = facet(2, 0, 0, 2, 0, "go");
    }
    (report, event)
}

fn assert_package_event(actual: &Value, expected: &Value) {
    assert_eq!(actual["scope"], "package");
    assert!(actual["version"].is_null());
    assert_eq!(actual, expected);
}

fn read_archive(path: &std::path::Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("saved analysis")).expect("analysis archive")
}

fn assert_archive(archive: &Value, expected_event: &Value) {
    assert_eq!(archive["schema_version"], 2);
    assert_eq!(archive["producer_report"]["schema_version"], 3);
    assert_package_event(
        &archive["producer_report"]["lifecycle"]["findings"][0],
        expected_event,
    );
}

#[test]
fn audit_native_save_replay_preserves_observations() {
    let root = go_repo();
    let (input, expected_event) = go_package_report();
    let path = root.path().join("analysis.json");
    let bytes = serde_json::to_vec(&input).expect("native report");
    let (saved, mock) = online(
        root.path(),
        &bytes,
        &[
            "--save-analysis",
            path.to_str().expect("analysis path"),
            "--json",
            "--quiet",
        ],
    );
    assert_exit(&saved, 1);

    let initial = json_view(&saved);
    assert_eq!(initial["schema_version"], 2);
    assert_eq!(initial["incomplete"], false);
    assert_eq!(initial["summary"]["lifecycle"], 1);
    assert_package_event(&initial["lifecycle"]["findings"][0], &expected_event);
    assert_archive(&read_archive(&path), &expected_event);

    fs::write(
        root.path().join("githits-scan.toml"),
        "invalid configuration [",
    )
    .expect("poison config");
    let replay = offline(&path, &["--json"]);
    assert_exit(&replay, 1);
    let mut replayed = json_view(&replay);
    assert_eq!(replayed["analysis"]["archive_schema_version"], 2);
    assert_eq!(replayed["analysis"]["producer_schema_version"], 3);
    assert_package_event(&replayed["lifecycle"]["findings"][0], &expected_event);
    replayed
        .as_object_mut()
        .expect("replay JSON object")
        .remove("analysis");
    assert_eq!(replayed, initial);
    assert_eq!(mock.requests().len(), 3, "offline replay never submits");
}
