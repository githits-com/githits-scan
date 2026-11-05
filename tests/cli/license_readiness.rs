//! Release-facing license policy and presentation regressions.
use super::*;

const REPORT: &[u8] = include_bytes!("../fixtures/licenses/report-v1.json");

fn replay(value: &serde_json::Value, flags: &[&str]) -> Output {
    let raw = serde_json::to_string(value).expect("json");
    let repo = repository(&[("report.json", &raw)]);
    githits_scan()
        .args(["license", "report", "--from-report"])
        .arg(repo.path().join("report.json"))
        .args(["--quiet", "--no-color"])
        .args(flags)
        .env_remove("GITHITS_API_TOKEN")
        .env("GITHITS_API_URL", "invalid-origin")
        .output()
        .expect("offline replay")
}

fn evaluate(document: &serde_json::Value, policy: &str, flags: &[&str]) -> Output {
    let raw = serde_json::to_string(document).expect("json");
    let repo = repository(&[("bom.json", &raw), ("githits-scan.toml", policy)]);
    let mut command = githits_scan();
    command
        .args(["license", "check"])
        .arg(repo.path())
        .arg("--sbom")
        .arg(repo.path().join("bom.json"))
        .args(["--no-color"])
        .args(flags)
        .env_remove("GITHITS_API_TOKEN")
        .env("GITHITS_API_URL", "invalid-origin");
    command.output().expect("offline check")
}

#[test]
fn license_check_readiness_nested_types_and_derived_evidence_agree_with_verdict() {
    let doc = serde_json::json!({"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"name":"outer","licenses":[{"expression":"MIT"}],"components":[
        {"name":"nested","licenses":[{"license":{"name":"MIT OR Apache-2.0"}},{"license":{"id":"GPL-3.0-only"}}]},
        {"name":"file","type":"file"}
    ]}]});
    let result = evaluate(
        &doc,
        "version=1\n[licenses]\nallow=[\"MIT\"]\n",
        &["--json"],
    );
    assert_eq!(result.status.code(), Some(1), "{}", stderr(&result));
    let json: serde_json::Value = serde_json::from_slice(&result.stdout).expect("verdict");
    assert_eq!(json["components"], 3);
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["violations"][0]["reason"], "no_license");
    assert_eq!(
        json["violations"][1]["expression"],
        "(MIT OR Apache-2.0) AND (GPL-3.0-only)"
    );
    assert_eq!(json["violations"][1]["reason"], "not_allowed");
    let empty = evaluate(
        &serde_json::json!({"bomFormat":"CycloneDX","components":[]}),
        "version=1\n[licenses]\nallow=[]\n",
        &[],
    );
    assert_eq!(empty.status.code(), Some(0));
    assert!(stdout(&empty).contains("no components evaluated"));
}

#[test]
fn license_check_readiness_checks_children_of_skipped_project_and_local_parents() {
    for (marker, value, local_count) in [
        ("githits:record_kind", "manifest", 0),
        ("githits:source_kind", "LOCKED_PACKAGE_SOURCE_KIND_LOCAL", 1),
    ] {
        let doc = serde_json::json!({"bomFormat":"CycloneDX","components":[
            {"name":"skipped","properties":[{"name":marker,"value":value}],"components":[
                {"name":"child","licenses":[{"expression":"GPL-3.0-only"}]}
            ]}
        ]});
        let output = evaluate(
            &doc,
            "version=1\n[licenses]\nallow=[\"MIT\"]\n",
            &["--json"],
        );
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        let verdict: serde_json::Value = serde_json::from_slice(&output.stdout).expect("verdict");
        assert_eq!(verdict["components"], 1);
        assert_eq!(verdict["local_packages"], local_count);
        assert_eq!(verdict["violations"][0]["name"], "child");
        assert_eq!(verdict["violations"][0]["reason"], "not_allowed");
    }
}

#[test]
fn license_check_readiness_policy_errors_precede_document_evaluation() {
    for table in [
        "allow=[\"gnu gpl v2\"]",
        "allow=[\"MIT OR Apache-2.0\"]",
        "allow=[]\n[[licenses.exceptions]]\npurl=\"pkg:cargo/name@1\"\nreason=\"reviewed\"",
    ] {
        let text = format!("version=1\n[licenses]\n{table}\n");
        let repo = repository(&[("githits-scan.toml", &text), ("bom.json", "not JSON")]);
        let file = repo.path().join("bom.json");
        let output = check(repo.path(), &["--sbom", file.to_str().expect("path")]);
        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
        assert_eq!(output.stdout, Vec::<u8>::new());
        assert!(stderr(&output).contains("licenses."));
        assert!(!stderr(&output).contains("cannot read"));
    }
}

#[test]
fn license_check_readiness_never_guesses_and_preserves_long_evidence_in_json() {
    let name = format!("display\n\u{1b}[31m{}", "a".repeat(300));
    let evidence = format!("full license\n{}\u{1b}[0m", "text ".repeat(600));
    let doc = serde_json::json!({"bomFormat":"CycloneDX","components":[
        {"name":name,"licenses":[{"license":{"name":evidence}}]},
        {"name":"slash","licenses":[{"expression":"Unlicense/MIT"}]}
    ]});
    let policy = "version=1\n[licenses]\nallow=[\"MIT\"]\n";
    let human = evaluate(&doc, policy, &[]);
    assert_eq!(human.status.code(), Some(1));
    let text = stdout(&human);
    assert!(!text.contains('\u{1b}'));
    assert!(!text.contains("display\n"));
    assert!(text.contains("use --json"));
    assert!(
        text.lines().all(|line| line.chars().count() < 320),
        "{text}"
    );
    let result = evaluate(&doc, policy, &["--json"]);
    let json: serde_json::Value = serde_json::from_slice(&result.stdout).expect("json");
    assert_eq!(json["violations"][0]["name"], name);
    assert_eq!(json["violations"][0]["expression"], evidence);
    assert_eq!(json["violations"][1]["reason"], "unparsable_expression");
}

#[test]
fn license_report_readiness_distinguishes_variants_and_retains_occurrences_and_bytes() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    let mut root = value["components"][0].clone();
    root["name"] = "z-project".into();
    let mut a = value["components"][1].clone();
    a["name"] = "nokogiri".into();
    a["purl"] = "pkg:gem/nokogiri@1.2.3?platform=arm64-darwin".into();
    let mut b = a.clone();
    b["purl"] = "pkg:gem/nokogiri@1.2.3?platform=x86_64-linux".into();
    value["components"] = serde_json::json!([root, b, a.clone(), a]);
    let human = replay(&value, &[]);
    assert_eq!(human.status.code(), Some(0));
    let text = stdout(&human);
    assert!(text.contains("?platform=arm64-darwin"));
    assert!(text.contains("?platform=x86_64-linux"));
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("nokogiri "))
            .count(),
        3
    );
    assert!(text.find("nokogiri").expect("package") < text.find("z-project").expect("root"));
    assert!(text.contains("z-project 1.0.0 [project]"));
    assert_eq!(
        replay(&value, &["--json"]).stdout,
        serde_json::to_vec(&value).expect("original bytes")
    );
}

#[test]
fn license_report_readiness_details_compress_noise_without_erasing_issues_or_links() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    let component = &mut value["components"][1];
    component["external_references"] = serde_json::json!([
        {"type":"vcs","url":"https://example.invalid/repository"},
        {"type":"vcs","url":"https://example.invalid/repository"},
        {"type":"license","url":"https://example.invalid/repository"}
    ]);
    component["publisher_evidence"] = serde_json::json!({"observations":[
        {"relationship":"controlling","observation":{"scope":"release","field":"license","statements":[]},"interpretation":{"status":"absent"}},
        {"interpretation":{"status":"absent","issues":[{"code":"invalid_token"}]}},
        {"interpretation":{"status":"future_status"}}
    ]});
    value["components"] = serde_json::json!([component.clone()]);
    let result = replay(&value, &["--details"]);
    assert_eq!(result.status.code(), Some(0));
    let text = stdout(&result);
    assert_eq!(
        text.matches("  repository: https://example.invalid/repository")
            .count(),
        1
    );
    assert!(text.contains("  license: https://example.invalid/repository"));
    assert!(!text.contains("interpretation: absent"));
    assert!(!text.contains("publisher statement (scope: release)"));
    assert!(text.contains("issue: unrecognized text in license expression"));
    assert!(text.contains("interpretation: unrecognized evidence (retained in JSON)"));
}

#[test]
fn license_report_readiness_long_text_is_bounded_in_both_human_views() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    value["components"][0]["name"] = format!("name\n\u{1b}[31m{}", "x".repeat(500)).into();
    value["components"][0]["licenses"] =
        serde_json::json!([{"license":{"name":"full license\n".repeat(200)}}]);
    value["components"] = serde_json::json!([value["components"][0].clone()]);
    for flags in [vec![], vec!["--details"]] {
        let result = replay(&value, &flags);
        assert_eq!(result.status.code(), Some(0));
        let text = stdout(&result);
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains("name\n"));
        assert!(text.contains("--json"));
        assert!(
            text.lines().all(|line| line.chars().count() < 320),
            "{text}"
        );
    }
    assert_eq!(
        replay(&value, &["--json"]).stdout,
        serde_json::to_vec(&value).expect("bytes")
    );
}

#[cfg(unix)]
#[test]
fn license_report_readiness_diagnostics_escape_gitignore_config_and_selected_paths() {
    for (file, text) in [
        (".gitignore", "[z-\u{1b}]\n"),
        (
            "githits-scan.toml",
            "version=1\n[licenses]\nallow=[\"MIT\"\u{1b}]\n",
        ),
    ] {
        let repo = repository(&[(file, text)]);
        let output = githits_scan()
            .args(["license", "report"])
            .arg(repo.path())
            .env("GITHITS_API_TOKEN", "test-token")
            .env("GITHITS_API_URL", "http://127.0.0.1:9")
            .output()
            .expect("local failure");
        assert!(!output.status.success());
        assert!(!stderr(&output).contains('\u{1b}'));
        assert!(stderr(&output).contains("\\u{1b}"));
    }
    let repo = repository(&[("bad\u{1b}.json", "{}")]);
    let output = githits_scan()
        .args(["license", "report", "--from-report"])
        .arg(repo.path().join("bad\u{1b}.json"))
        .env_remove("GITHITS_API_TOKEN")
        .output()
        .expect("invalid report");
    assert_eq!(output.status.code(), Some(2));
    assert!(!stderr(&output).contains('\u{1b}'));
    assert_eq!(
        stderr(&output)
            .matches("invalid dependency-license report")
            .count(),
        1
    );
}

#[test]
fn license_report_readiness_details_retain_choices_hidden_by_the_compact_budget() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    let choices = [
        "MIT",
        "Apache-2.0",
        "BSD-3-Clause",
        "ISC",
        "Zlib",
        "BSL-1.0",
        "MPL-2.0",
        "GPL-3.0-only",
        "LGPL-2.1-only",
    ];
    value["components"][0]["licenses"] =
        serde_json::json!(choices.map(|id| serde_json::json!({"expression":id})));
    value["components"] = serde_json::json!([value["components"][0].clone()]);
    let result = replay(&value, &["--details"]);
    assert_eq!(result.status.code(), Some(0));
    assert!(stdout(&result).contains("reported license: LGPL-2.1-only"));
    assert_eq!(
        replay(&value, &["--json"]).stdout,
        serde_json::to_vec(&value).expect("source")
    );
}

#[cfg(unix)]
#[test]
fn license_report_readiness_inventory_path_diagnostics_escape_controls() {
    for case in ["upload", "skipped", "drift"] {
        let file = if case == "skipped" {
            "bad\n\u{1b}/package.json"
        } else {
            "bad\n\u{1b}/Cargo.lock"
        };
        let data = if case == "skipped" {
            "{}"
        } else {
            "version=4\n"
        };
        let repo = repository(&[(file, data)]);
        if case == "drift" {
            fs::write(repo.path().join("githits-scan.toml"), "version=1\n")
                .expect("inventory config");
        }
        let mut command = githits_scan();
        command
            .args(["license", "report"])
            .arg(repo.path())
            .env("GITHITS_API_TOKEN", "test-token")
            .env("GITHITS_API_URL", "http://127.0.0.1:9");
        if case == "skipped" {
            command.arg("--lockfiles-only");
        }
        let result = command.output().expect("local inventory error");
        assert_eq!(
            result.status.code(),
            Some(if case == "upload" { 2 } else { 1 }),
            "{}",
            stderr(&result)
        );
        let text = stderr(&result);
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains("bad\n"));
        assert!(text.contains("bad\\n\\u{1b}"), "{text}");
    }
}

#[test]
fn license_report_readiness_ordinary_coordinates_and_links_stay_whole() {
    for (name, version) in [
        (
            "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver",
            "v0.99.0",
        ),
        (
            "org.springframework.boot:spring-boot-starter-data-elasticsearch",
            "3.2.5",
        ),
        ("@aws-sdk/client-secrets-manager", "3.758.0"),
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
        let component = &mut value["components"][1];
        component["name"] = name.into();
        component["version"] = version.into();
        component["licenses"] = serde_json::json!([{"expression":"MIT"}]);
        let url = format!("https://example.invalid/{}", "r".repeat(140));
        component["external_references"] = serde_json::json!([{"type":"vcs", "url":url}]);
        value["components"] = serde_json::json!([component.clone()]);
        let compact = replay(&value, &[]);
        assert_eq!(compact.status.code(), Some(0));
        let text = stdout(&compact);
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(
            text.lines()
                .nth(1)
                .expect("row")
                .starts_with(&format!("{name} {version}  MIT"))
        );
        let details = replay(&value, &["--details"]);
        assert!(
            stdout(&details)
                .lines()
                .any(|line| line == format!("  repository: {url}"))
        );
    }
}

#[test]
fn license_report_readiness_supplied_purl_bases_disambiguate_equal_names() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    let a = value["components"][1].clone();
    let mut b = a.clone();
    b["purl"] = "pkg:cargo/same-package@1.2.3".into();
    value["components"] = serde_json::json!([a, b]);
    let result = replay(&value, &[]);
    assert_eq!(result.status.code(), Some(0));
    let text = stdout(&result);
    assert!(text.contains("package URL: pkg:cargo/same-package@1.2.3"));
    assert!(text.contains("package URL: pkg:npm/same-package@1.2.3"));
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("same-package 1.2.3"))
            .count(),
        2
    );
}

#[test]
fn license_check_readiness_help_explains_scope_setup_and_offline_input() {
    let output = githits_scan()
        .args(["license", "check", "--help"])
        .output()
        .expect("help");
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for contract in [
        "nested assemblies",
        "including files",
        "not their children",
        "offline without a token",
        "inventory drift only",
        "not guessed",
        "detect --save",
        "Enable [licenses]",
        "--sbom bom.cdx.json --json",
    ] {
        assert!(text.contains(contract), "missing {contract}: {text}");
    }
}

#[test]
fn license_check_readiness_variants_and_expression_continuation_keep_the_verdict() {
    let expression = format!("{}GPL-3.0-only", "MIT AND ".repeat(12));
    let doc = serde_json::json!({"bomFormat":"CycloneDX","components":[
        {"name":"same","version":"1","purl":"pkg:gem/same@1?platform=arm64","licenses":[{"expression":expression}]},
        {"name":"same","version":"1","purl":"pkg:npm/same@1?platform=x86","licenses":[{"expression":"GPL-3.0-only"}]}
    ]});
    let output = evaluate(&doc, "version=1\n[licenses]\nallow=[\"MIT\"]\n", &[]);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    for supplied in [
        "?platform=arm64",
        "?platform=x86",
        "pkg:gem/same@1",
        "pkg:npm/same@1",
        "license evidence:",
        "GPL-3.0-only",
    ] {
        assert!(text.contains(supplied), "missing {supplied}: {text}");
    }
    assert_eq!(text.matches("use --json").count(), 1);
    assert!(text.contains(&expression));
}

#[test]
fn license_check_readiness_bounds_all_auxiliary_text_and_aligns_unresolved_paths() {
    let long = format!("controlled\n\u{1b}{}", "a".repeat(300));
    let resolutions = serde_json::to_string(&serde_json::json!([
        {"path":"a/Cargo.toml","status":"partial"},
        {"path":"longer/Cargo.toml","status":"partial"},
        {"path":long,"status":long,"diagnostics":[{"reason":long}]}
    ]))
    .expect("resolutions");
    let doc = serde_json::json!({"bomFormat":"CycloneDX","properties":[
        {"name":"githits:completeness","value":long},
        {"name":"githits:resolutions","value":resolutions}],"components":[
        {"name":"excepted","purl":"pkg:cargo/excepted@1"}
    ]});
    let policy = format!(
        "version=1\n[licenses]\nallow=[]\n[[licenses.exceptions]]\npurl=\"pkg:cargo/excepted\"\nreason={}\n",
        serde_json::to_string(&long).expect("toml-compatible string")
    );
    let output = evaluate(&doc, &policy, &[]);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(!text.contains('\u{1b}'));
    assert!(!text.contains("controlled\n"));
    assert!(
        text.lines().all(|line| line.chars().count() < 420),
        "{text}"
    );
    let paths: Vec<_> = text
        .lines()
        .filter(|line| line.contains("Cargo.toml"))
        .collect();
    assert_eq!(paths.len(), 2);
    assert_eq!(paths[0].find("partial"), paths[1].find("partial"));
    assert_eq!(text.matches("use --json").count(), 1);
    let json: serde_json::Value =
        serde_json::from_slice(&evaluate(&doc, &policy, &["--json"]).stdout).expect("json");
    assert_eq!(json["completeness"], long);
    assert_eq!(json["exceptions_applied"][0]["reason"], long);
    assert!(
        json["unresolved_projects"]
            .as_array()
            .expect("projects")
            .iter()
            .any(|p| p["status"] == long && p["path"] == long && p["reasons"][0] == long)
    );
}

#[test]
fn license_report_readiness_folds_free_text_beside_an_identifier() {
    let mut value: serde_json::Value = serde_json::from_slice(REPORT).expect("fixture");
    value["components"][0]["licenses"] =
        serde_json::json!([{"license":{"id":"MIT","name":"The MIT\n\nLicense"}}]);
    value["components"] = serde_json::json!([value["components"][0].clone()]);
    let output = replay(&value, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).contains("MIT (The MIT License)"));
    assert_eq!(
        replay(&value, &["--json"]).stdout,
        serde_json::to_vec(&value).expect("bytes")
    );
}

#[test]
fn license_check_readiness_malformed_nested_errors_identify_the_parent_chain() {
    let doc = serde_json::json!({"bomFormat":"CycloneDX","components":[
        {"name":"valid","licenses":[{"expression":"MIT"}]},
        {"name":"parent","components":[{"name":"child","licenses":null}]}
    ]});
    let output = evaluate(&doc, "version=1\n[licenses]\nallow=[\"MIT\"]\n", &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("component 1: component 0: `licenses` is not an array"));
    assert_eq!(output.stdout, Vec::<u8>::new());
}

#[cfg(unix)]
#[test]
fn license_setup_detect_readiness_escapes_paths_without_changing_json() {
    let path = "bad\n\u{1b}/Cargo.toml";
    let repo = repository(&[(path, "[package]\nname=\"example\"\nversion=\"1.0.0\"\n")]);
    let human = githits_scan()
        .arg("detect")
        .arg(repo.path())
        .arg("--no-color")
        .output()
        .expect("detect");
    assert_eq!(human.status.code(), Some(2), "{}", stderr(&human));
    assert!(!stdout(&human).contains('\u{1b}'));
    assert!(!stdout(&human).contains("bad\n"));
    assert!(stdout(&human).contains("bad\\n\\u{1b}/Cargo.toml"));
    let json = githits_scan()
        .arg("detect")
        .arg(repo.path())
        .arg("--json")
        .output()
        .expect("detect JSON");
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).expect("json");
    assert_eq!(value["manifest_only"][0]["path"], path);
}
