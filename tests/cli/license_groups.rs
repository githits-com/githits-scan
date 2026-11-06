//! Explicit Pipenv occurrence context is presentation evidence, not inventory deduplication.
use super::*;
use serde_json::{Value, json};

fn context(group: &str) -> Value {
    json!({"dev_only":false,"group_conditions":[{"group":group,"marker":""}]})
}

fn component(group: &str) -> Value {
    json!({"bom_ref":group,"name":"requests","version":"2.32.0",
        "purl":"pkg:pypi/requests@2.32.0","type":"library","scope":null,
        "record_kind":"locked_package","licenses":[{"expression":"MIT"}],
        "observed_licenses":[],"publisher_evidence":null,"source_evidence":null,
        "external_references":[],"hashes":[],"context":context(group),
        "inputs":{"manifest_paths":[],"lockfile_paths":["Pipfile.lock"]}})
}

fn report(version: u8) -> Value {
    let mut components = json!([component("default"), component("develop")]);
    if version == 1 {
        for (index, c) in components
            .as_array_mut()
            .expect("components")
            .iter_mut()
            .enumerate()
        {
            let ctx = c
                .as_object_mut()
                .expect("component")
                .remove("context")
                .expect("context");
            c["properties"] = json!([
                {"name":"githits:context","value":ctx.to_string()},
                {"name":"githits:package_id","value":(index + 1).to_string()},
                {"name":"githits:role","value":"transitive_dependency"},
                {"name":"githits:lockfile_path","value":"Pipfile.lock"}]);
        }
    }
    json!({"schema_version":version,"inventory":{"completeness":"recorded_lockfile_inventory",
        "properties":[],"compositions":[],"dependencies":[],"notices":[],"coverage":[]},
        "components":components})
}

fn sbom() -> Value {
    let mut value = report(1);
    value["bomFormat"] = "CycloneDX".into();
    for c in value["components"].as_array_mut().expect("components") {
        let reference = c
            .as_object_mut()
            .expect("component")
            .remove("bom_ref")
            .expect("ref");
        c["bom-ref"] = reference;
    }
    value
}

fn run(value: &Value, check: bool, flags: &[&str]) -> Output {
    let repo = repository(&[("githits-scan.toml", "version=1\n[licenses]\nallow=[]\n")]);
    let file = repo.path().join("input.json");
    fs::write(&file, serde_json::to_vec(value).expect("json")).expect("input");
    let mut command = githits_scan();
    command.args(["license", if check { "check" } else { "report" }]);
    if check {
        command.arg(repo.path());
    }
    command
        .arg(if check { "--sbom" } else { "--from-report" })
        .arg(file)
        .args(["--quiet", "--no-color"])
        .args(flags)
        .env_remove("GITHITS_API_TOKEN")
        .env("GITHITS_API_URL", "invalid-origin")
        .output()
        .expect("offline presentation")
}

#[test]
fn license_groups_compact_reports_combine_only_explicit_distinct_groups() {
    for version in [1, 2] {
        let value = report(version);
        let output = run(&value, false, &[]);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let text = stdout(&output);
        assert_eq!(text.matches("requests 2.32.0").count(), 1, "{text}");
        assert!(text.contains("[default, develop]"), "{text}");
        assert_eq!(text.lines().count(), 2, "{text}");
        let details = stdout(&run(&value, false, &["--details"]));
        assert!(details.contains("2 reported occurrences"), "{details}");
        assert_eq!(details.matches("requests 2.32.0").count(), 2, "{details}");
        assert!(
            details.contains("[default]") && details.contains("[develop]"),
            "{details}"
        );
        assert_eq!(
            run(&value, false, &["--json"]).stdout,
            serde_json::to_vec(&value).expect("json")
        );
    }
}

#[test]
fn license_groups_check_keeps_occurrence_verdicts_and_detail_references() {
    let value = sbom();
    let output = run(&value, true, &[]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    assert_eq!(text.matches("requests 2.32.0").count(), 1, "{text}");
    assert!(text.contains("[default, develop]"), "{text}");
    assert!(
        text.contains("2 occurrence violations in 2 components"),
        "{text}"
    );
    let details = stdout(&run(&value, true, &["--details"]));
    for expected in [
        "component reference: default",
        "component reference: develop",
        "[default]",
        "[develop]",
    ] {
        assert!(details.contains(expected), "{details}");
    }
    let json: Value =
        serde_json::from_slice(&run(&value, true, &["--json"]).stdout).expect("verdict");
    assert_eq!(json["components"], 2);
    assert_eq!(json["violations"].as_array().expect("violations").len(), 2);
    assert_eq!(json["violations"][0]["bom_ref"], "default");
    assert_eq!(json["violations"][1]["bom_ref"], "develop");
}

#[test]
fn license_groups_report_never_hides_source_platform_or_evidence_differences() {
    for (field, different) in [
        (
            "purl",
            json!("pkg:pypi/requests@2.32.0?repository_url=https://example.invalid"),
        ),
        ("version", json!("2.31.0")),
        ("licenses", json!([{"expression":"GPL-3.0-only"}])),
        (
            "license_evidence",
            json!({"applicability_reason":"source_substitution"}),
        ),
        (
            "source_evidence",
            json!({"url":"https://example.invalid/repository"}),
        ),
        ("future_evidence", json!({"different":true})),
        (
            "inputs",
            json!({"manifest_paths":[],"lockfile_paths":["other/Pipfile.lock"]}),
        ),
        (
            "context",
            json!({"dev_only":false,"group_conditions":[{"group":"develop","marker":"python_version < '3.10'"}]}),
        ),
    ] {
        let mut value = report(2);
        value["components"][1][field] = different;
        let output = run(&value, false, &[]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{field}: {}",
            stderr(&output)
        );
        let text = stdout(&output);
        assert_eq!(text.matches("requests ").count(), 2, "{field}: {text}");
        assert!(!text.contains("[default, develop]"), "{field}: {text}");
        if field == "context" {
            assert!(text.contains("python_version < '3.10'"), "{text}");
        }
    }
}

#[test]
fn license_groups_check_conflicting_evidence_retains_policy_meaning() {
    let mut value = sbom();
    value["components"][1]["licenses"] = json!([{"expression":"GPL-3.0-only"}]);
    let output = run(&value, true, &[]);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(text.matches("requests 2.32.0").count(), 2, "{text}");
    assert!(
        text.contains("MIT") && text.contains("GPL-3.0-only"),
        "{text}"
    );
    assert!(
        text.contains("[default]") && text.contains("[develop]"),
        "{text}"
    );
}

#[test]
fn license_groups_unusable_context_and_repeated_groups_remain_separate() {
    for (field, replacement) in [
        ("context", Value::Null),
        ("context", json!({"group_conditions":"future"})),
        ("context", context("default")),
        ("bom_ref", Value::Null),
        ("bom_ref", json!("default")),
    ] {
        let mut value = report(2);
        value["components"][1][field] = replacement;
        let output = run(&value, false, &[]);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let text = stdout(&output);
        assert_eq!(text.matches("requests 2.32.0").count(), 2, "{text}");
    }
}

#[test]
fn license_groups_nested_check_keeps_distinct_assembly_owners() {
    let mut value = sbom();
    let children = value["components"].clone();
    value["components"] = json!([
        {"bom-ref":"parent","name":"root","properties":[{"name":"githits:record_kind","value":"manifest"}],"components":children}
    ]);
    let output = run(&value, true, &[]);
    assert_eq!(
        stdout(&output).matches("requests 2.32.0").count(),
        1,
        "{}",
        stdout(&output)
    );
    let mut second = value["components"][0].clone();
    second["bom-ref"] = "other-parent".into();
    second["components"][0]["bom-ref"] = "other-default".into();
    second["components"][1]["bom-ref"] = "other-develop".into();
    value["components"]
        .as_array_mut()
        .expect("components")
        .push(second);
    let output = run(&value, true, &[]);
    assert_eq!(
        stdout(&output).matches("requests 2.32.0").count(),
        2,
        "{}",
        stdout(&output)
    );
    assert!(stdout(&output).contains("4 occurrence violations in 4 components"));
}

#[test]
fn license_groups_context_is_bounded_escaped_and_file_output_matches_stdout() {
    let mut value = report(2);
    value["components"][0]["context"] = context(&format!("default\u{1b}[31m{}", "x".repeat(300)));
    let repo = repository(&[]);
    let target = repo.path().join("presentation.txt");
    let output = run(&value, false, &["--output", target.to_str().expect("path")]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, b"");
    let text = fs::read_to_string(target).expect("rendered file");
    assert_eq!(text, stdout(&run(&value, false, &[])));
    assert!(!text.contains('\u{1b}'), "{text}");
    assert!(
        text.contains("Abbreviated evidence; use --json for full values."),
        "{text}"
    );
    assert!(
        text.lines().all(|line| line.chars().count() <= 260),
        "{text}"
    );
    assert_eq!(
        run(&value, false, &["--json"]).stdout,
        serde_json::to_vec(&value).expect("json")
    );
}

#[test]
fn license_groups_report_singletons_keep_the_existing_compact_output() {
    let mut value = report(2);
    value["components"]
        .as_array_mut()
        .expect("components")
        .truncate(1);
    assert_eq!(
        stdout(&run(&value, false, &[])),
        "Package          License\nrequests 2.32.0  MIT\n"
    );
}

#[test]
fn license_groups_check_disambiguates_other_input_files_after_grouping() {
    let mut value = sbom();
    let mut other = value["components"].clone();
    for c in other.as_array_mut().expect("other") {
        c["bom-ref"] = format!("other-{}", c["bom-ref"].as_str().expect("reference")).into();
        let properties = c["properties"].as_array_mut().expect("properties");
        properties.last_mut().expect("path")["value"] = "other/Pipfile.lock".into();
    }
    value["components"]
        .as_array_mut()
        .expect("components")
        .extend(other.as_array().expect("other").iter().cloned());
    let output = run(&value, true, &[]);
    let text = stdout(&output);
    assert_eq!(text.matches("requests 2.32.0").count(), 2, "{text}");
    assert!(
        text.contains("input file: Pipfile.lock")
            && text.contains("input file: other/Pipfile.lock"),
        "{text}"
    );
}

#[test]
fn license_groups_ignored_additions_do_not_introduce_a_decode_failure() {
    let raw = serde_json::to_string(&report(2)).expect("json");
    let surrogate = raw
        .replace(
            "\"hashes\":[]",
            "\"hashes\":[],\"future_evidence\":\"\\ud800\"",
        )
        .into_bytes();
    let invalid_utf8 = raw
        .replace(
            "\"hashes\":[]",
            "\"hashes\":[],\"future_evidence\":\"INVALID_UTF8\"",
        )
        .into_bytes()
        .windows(12)
        .position(|window| window == b"INVALID_UTF8")
        .expect("placeholder");
    let mut invalid = raw
        .replace(
            "\"hashes\":[]",
            "\"hashes\":[],\"future_evidence\":\"INVALID_UTF8\"",
        )
        .into_bytes();
    invalid[invalid_utf8] = 0xff;
    for bytes in [surrogate, invalid] {
        assert_ignored_replay(&bytes);
    }
}

fn assert_ignored_replay(bytes: &[u8]) {
    let repo = repository(&[]);
    let path = repo.path().join("report.json");
    fs::write(&path, bytes).expect("report");
    for flags in [vec![], vec!["--details"], vec!["--json"]] {
        let output = githits_scan()
            .args(["license", "report", "--from-report"])
            .arg(&path)
            .arg("--quiet")
            .args(&flags)
            .env_remove("GITHITS_API_TOKEN")
            .output()
            .expect("accepted replay");
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        if flags.contains(&"--json") {
            assert_eq!(output.stdout, bytes);
        } else {
            let text = stdout(&output);
            assert_eq!(text.matches("requests 2.32.0").count(), 2, "{text}");
            assert!(!text.contains("[default"), "{text}");
        }
    }
}

#[test]
fn license_groups_exceptions_summarize_repeated_labels_without_changing_json() {
    let repo = repository(&[(
        "githits-scan.toml",
        concat!(
            "version=1\n[licenses]\nallow=[]\n[[licenses.exceptions]]\n",
            "purl='pkg:pypi/requests'\nreason='reviewed'\n"
        ),
    )]);
    let path = repo.path().join("bom.json");
    fs::write(&path, serde_json::to_vec(&sbom()).expect("json")).expect("sbom");
    for json_output in [false, true] {
        let mut command = githits_scan();
        command
            .args(["license", "check"])
            .arg(repo.path())
            .arg("--sbom")
            .arg(&path)
            .args(["--quiet", "--no-color"])
            .env_remove("GITHITS_API_TOKEN");
        if json_output {
            command.arg("--json");
        }
        let output = command.output().expect("excepted check");
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        if json_output {
            let value: Value = serde_json::from_slice(&output.stdout).expect("json");
            assert_eq!(
                value["exceptions_applied"][0]["components"],
                json!(["requests 2.32.0", "requests 2.32.0"])
            );
        } else {
            let text = stdout(&output);
            assert_eq!(text.matches("requests 2.32.0").count(), 1, "{text}");
            assert!(text.contains("requests 2.32.0 (2 occurrences)"), "{text}");
        }
    }
}

#[test]
fn license_groups_equal_markers_survive_combining_and_truncated_labels_have_details() {
    let marker = "python_version >= '3.8'";
    let mut value = report(2);
    for c in value["components"].as_array_mut().expect("components") {
        c["context"]["group_conditions"][0]["marker"] = marker.into();
    }
    let output = run(&value, false, &[]);
    let text = stdout(&output);
    assert_eq!(text.matches("requests 2.32.0").count(), 1, "{text}");
    assert!(
        text.contains("[default, develop; python_version >= '3.8']"),
        "{text}"
    );
    let marker = format!("python_version >= '3.8' and {}", "🦀".repeat(70));
    for c in value["components"].as_array_mut().expect("components") {
        c["context"]["group_conditions"][0]["marker"] = marker.clone().into();
    }
    let output = run(&value, false, &[]);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        text.contains(&format!("group context: default, develop; {marker}")),
        "{text}"
    );
    assert!(text.contains("Abbreviated evidence"), "{text}");
}

#[test]
fn license_groups_mixed_singletons_and_additional_context_properties_stay_distinct() {
    let mut value = report(1);
    for (index, c) in value["components"]
        .as_array_mut()
        .expect("components")
        .iter_mut()
        .enumerate()
    {
        c["properties"]
            .as_array_mut()
            .expect("properties")
            .push(json!({
            "name":"githits:context","value":json!({"extra":index}).to_string()}));
    }
    let output = run(&value, false, &[]);
    assert_eq!(
        stdout(&output).matches("requests 2.32.0").count(),
        2,
        "{}",
        stdout(&output)
    );
    let mut value = sbom();
    let mut singleton = value["components"][0].clone();
    singleton["name"] = "urllib3".into();
    singleton["bom-ref"] = "singleton".into();
    value["components"]
        .as_array_mut()
        .expect("components")
        .push(singleton);
    let text = stdout(&run(&value, true, &[]));
    let line = text
        .lines()
        .find(|line| line.contains("urllib3"))
        .expect("singleton row");
    assert!(!line.contains("[default]"), "{text}");
}
