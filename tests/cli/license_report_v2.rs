//! Compact report replay exercises the shipped command, without authentication.

use super::*;

const REPORT: &[u8] = include_bytes!("../fixtures/licenses/report-v2.json");

fn run(value: &serde_json::Value, flags: &[&str]) -> Output {
    let repo = repository(&[]);
    let path = repo.path().join("report.json");
    fs::write(&path, serde_json::to_vec(value).expect("json")).expect("report");
    githits_scan()
        .args(["license", "report", "--from-report"])
        .arg(path)
        .args(flags)
        .env_remove("GITHITS_API_TOKEN")
        .env("GITHITS_API_URL", "invalid-origin")
        .output()
        .expect("offline report")
}

fn fixture() -> serde_json::Value {
    serde_json::from_slice(REPORT).expect("fixture")
}

#[test]
fn license_report_v2_replays_compact_details_and_exact_json() {
    let repo = repository(&[]);
    let file = repo.path().join("report.json");
    fs::write(&file, REPORT).expect("report");
    for flags in [&["--json"][..], &["--json", "--quiet"][..]] {
        let output = githits_scan()
            .args(["license", "report", "--from-report"])
            .arg(&file)
            .args(flags)
            .env_remove("GITHITS_API_TOKEN")
            .env("GITHITS_API_URL", "invalid-origin")
            .output()
            .expect("replay");
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(output.stdout, REPORT);
    }
    let output = run(&fixture(), &["--quiet", "--no-color"]);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(text.lines().count(), 9, "{text}");
    assert!(text.contains("license-example 1.0.0 [project]"));
    assert!(text.contains("local-dependency [local]"));
    assert!(!text.contains("metadata:") && !text.contains("Coverage"));
    let details = run(&fixture(), &["--details", "--quiet", "--no-color"]);
    let text = stdout(&details);
    for expected in [
        "8 reported occurrences",
        "library classification assumed from inventory",
        "recorded lockfiles and manifest resolution",
        "dependency coverage: catalog-dependency 1.0.0 (inputs: native/vcpkg.json): unknown",
        "reason: dependencies not expanded",
        "notice: Recorded inventory, not an exact installed build; artifacts were not inspected.",
        "manifest: app/package.json",
        "notice: Target conditions were retained, not evaluated.",
        "deprecated license identifier (GPL-2.0)",
        "registry metadata may not apply",
        "metadata: unavailable",
        "not eligible for registry metadata",
        "recorded source revision",
        "catalog baseline was not applied",
        "never-resolved-dependency",
        "requested: ^9.0.0",
        "declared and locked versions differ",
        "locked version: 1.0.0",
        "manifest/lockfile consistency: not checked",
        "observed licenses:",
        "observed file:",
        "Inventory completeness is not license coverage",
    ] {
        assert!(text.contains(expected), "missing {expected}:\n{text}");
    }
    for routine in [
        "artifact verification:",
        "license syntax:",
        "publisher capture:",
        "publisher statement coverage:",
        "lookup: registry",
    ] {
        assert!(!text.contains(routine), "{text}");
    }
}

#[test]
fn license_report_v2_preserves_occurrences_qualifiers_and_inputs() {
    let mut value = fixture();
    let mut c = value["components"][1].clone();
    c["purl"] = "pkg:npm/dependency@1.0.0?arch=arm64".into();
    c["inputs"]["lockfile_paths"] =
        serde_json::json!(["arm/package-lock.json", "arm/package-lock.json"]);
    value["components"][1]["purl"] = "pkg:npm/dependency@1.0.0?arch=x86_64".into();
    value["components"]
        .as_array_mut()
        .expect("components")
        .push(c);
    let output = run(&value, &["--quiet"]);
    let text = stdout(&output);
    assert_eq!(text.matches("dependency 1.0.0 ?arch=").count(), 2, "{text}");
    assert!(
        text.contains("arch=arm64") && text.contains("arch=x86_64"),
        "{text}"
    );
    assert_eq!(text.matches("input file: arm/package-lock.json").count(), 1);
    let json = run(&value, &["--json"]);
    assert_eq!(json.stdout, serde_json::to_vec(&value).expect("json"));
}

#[test]
fn license_report_v2_open_items_and_nullable_versions_stay_usable() {
    let mut value = fixture();
    value["inventory"]["resolutions"][0]["diagnostics"] =
        serde_json::json!([{}, {"name":[], "reason":7}]);
    value["inventory"]["declaration_agreement"][0]["locked_versions"] = serde_json::json!([null]);
    value["components"][0]["license_evidence"]["raw"] = "different statement".into();
    value["components"][0]["license_evidence"]["status"] = "absent".into();
    value["components"][0]["source_selector"] = "main".into();
    value["components"][0]["source_selector_kind"] = "branch".into();
    value["components"][1]["publisher_evidence"]["capture_status"] = "future_capture".into();
    value["components"][1]["publisher_evidence"]["coverage"] = "selected_only".into();
    let output = run(&value, &["--details", "--quiet"]);
    let text = stdout(&output);
    assert!(!text.contains("license interpretation:"));
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    for expected in [
        "diagnostic: unrecognized evidence (retained in JSON)",
        "locked version: not reported",
        "publisher capture: unrecognized evidence",
        "publisher statement coverage: selected statements only",
        "license statement: different statement",
        "recorded source selector: main",
        "source selector kind: branch",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    assert_eq!(
        run(&value, &["--json"]).stdout,
        serde_json::to_vec(&value).expect("json")
    );
}

#[test]
fn license_report_v2_coverage_scopes_never_imply_license_checks() {
    for (coverage, expected) in [
        (
            serde_json::json!([{"aggregate":"unknown","services":["service"]}]),
            "service inventory: unknown",
        ),
        (
            serde_json::json!([{"aggregate":"complete","assemblies":[]}]),
            "component inventory: complete; no subject references reported",
        ),
        (
            serde_json::json!([{"aggregate":"complete"}]),
            "inventory coverage: complete; unrecognized scope",
        ),
        (
            serde_json::json!([{"aggregate":"incomplete"}]),
            "inventory coverage: incomplete; unrecognized scope",
        ),
    ] {
        let mut value = fixture();
        value["inventory"]["coverage"] = coverage;
        let output = run(&value, &["--details", "--quiet"]);
        assert_eq!(output.status.code(), Some(0));
        assert!(stdout(&output).contains(expected), "{}", stdout(&output));
    }
}

#[test]
fn license_report_v2_declarations_follow_input_status_and_routine_summaries_are_omitted() {
    let mut value = fixture();
    value["inventory"]["resolutions"][1]["status"] = serde_json::Value::Null;
    value["inventory"]["declaration_agreement"][0]["status"] = "matched".into();
    value["inventory"]["lockfiles"] = serde_json::json!([{"path":"routine.lock", "association_status":"associated", "completeness":"LOCKFILE_COMPLETENESS_PACKAGE_ENTRIES_AND_RECORDED_RELATIONSHIPS"}]);
    let output = run(&value, &["--details", "--quiet"]);
    let text = stdout(&output);
    assert!(
        text.contains("declaration: name: never-resolved-dependency"),
        "{text}"
    );
    assert!(!text.contains("declaration agreement:") && !text.contains("routine.lock"));
    value["inventory"]["resolutions"][1]["status"] = "complete".into();
    assert!(!stdout(&run(&value, &["--details", "--quiet"])).contains("never-resolved-dependency"));
}

#[test]
fn license_report_v2_bounds_and_escapes_new_fields_without_losing_json() {
    let mut value = fixture();
    let hostile = format!("\u{1b}[31m{}\nend", "x".repeat(4000));
    value["components"][0]["source_revision"] = hostile.clone().into();
    value["inventory"]["declarations"][0]["name"] = hostile.into();
    let output = run(&value, &["--details", "--quiet"]);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0));
    assert!(!text.contains('\u{1b}') && !text.contains(&"x".repeat(241)));
    assert!(text.contains("...") && text.contains("use --json for complete evidence"));
    assert_eq!(
        run(&value, &["--json"]).stdout,
        serde_json::to_vec(&value).expect("json")
    );
}

#[test]
fn license_report_v2_malformed_shapes_preserve_output_file() {
    let repo = repository(&[]);
    let file = repo.path().join("bad.json");
    let target = repo.path().join("output.json");
    fs::write(&target, b"original").expect("target");
    for malformed in [serde_json::json!({"schema_version":2}), {
        let mut v = fixture();
        v["components"][0]["inputs"] = false.into();
        v
    }] {
        fs::write(&file, serde_json::to_vec(&malformed).expect("json")).expect("report");
        let output = githits_scan()
            .args(["license", "report", "--json", "--from-report"])
            .arg(&file)
            .arg("--output")
            .arg(&target)
            .env_remove("GITHITS_API_TOKEN")
            .output()
            .expect("replay");
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(output.stdout, [] as [u8; 0]);
        assert!(stderr(&output).contains("invalid dependency-license report"));
        assert_eq!(fs::read(&target).expect("target"), b"original");
    }
}

#[test]
fn license_report_v2_named_gaps_and_domain_outcomes_keep_their_owners() {
    let mut value = fixture();
    value["inventory"]["resolution_basis"] = "manifest_resolution".into();
    for (index, reason) in [
        "missing_identity_facets",
        "unsupported_registry",
        "invalid_coordinate",
    ]
    .iter()
    .enumerate()
    {
        value["components"][index]["purl_omission_reason"] = (*reason).into();
    }
    value["inventory"]["declaration_agreement"][0]["requirement_status"] = "not_recorded".into();
    let mut agreement = value["inventory"]["declaration_agreement"][0].clone();
    agreement["requirement_status"] = "withheld".into();
    agreement["status"] = "absent".into();
    value["inventory"]["declaration_agreement"]
        .as_array_mut()
        .expect("agreements")
        .push(agreement);
    value["inventory"]["lockfiles"][0]["association_status"] = "ambiguous".into();
    value["inventory"]["lockfiles"][0]["manifest_lock_consistency"] = "absent".into();
    let unrecorded = value["inventory"]["declaration_agreement"][0].clone();
    value["inventory"]["declaration_agreement"]
        .as_array_mut()
        .expect("agreements")
        .push(unrecorded);
    value["inventory"]["declaration_agreement"][0]["requirement_status"] = "ambiguous".into();
    value["inventory"]["lockfiles"][0]["association_diagnostics"] =
        serde_json::json!([{"reason":"ambiguous"}, {"reason":"missing_input"}, {"future":true}]);
    value["inventory"]["dependency_coverage"]["ghost"] = serde_json::json!({"state":"unknown"});
    value["components"][0]["license_evidence"]["issues"] =
        serde_json::json!([null, {"future":true}]);
    let output = run(&value, &["--details", "--quiet"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    for expected in [
        "inventory construction: manifest dependency resolution",
        "package identity is incomplete",
        "registry is not supported",
        "package coordinate is invalid",
        "requirement: not recorded",
        "requirement: ambiguous",
        "manifest/lockfile consistency: absent",
        "diagnostic: reason: ambiguous",
        "requirement: withheld",
        "association: ambiguous",
        "outcome: absent",
        "diagnostic: reason: required input was not supplied",
        "diagnostic: unrecognized evidence (retained in JSON)",
        "dependency coverage: unresolved reference ghost: unknown",
        "license issue: unrecognized issue (retained in JSON)",
    ] {
        assert!(text.contains(expected), "missing {expected}:\n{text}");
    }
    assert!(!text.contains("association: ambiguous license evidence"));
    assert!(!text.contains("outcome: not reported"));
    assert!(!text.contains("diagnostic: reason: ambiguous license evidence"));
    assert!(!text.contains("requirement: ambiguous license evidence"));
    assert_eq!(
        run(&value, &["--json"]).stdout,
        serde_json::to_vec(&value).expect("json")
    );
}

#[test]
fn license_report_v2_empty_partial_report_retains_warning_and_declarations() {
    let mut value = fixture();
    value["inventory"]["completeness"] = "partial_manifest_inventory".into();
    value["components"] = serde_json::json!([]);
    for flags in [
        &["--quiet"][..],
        &["--details"][..],
        &["--json", "--quiet"][..],
    ] {
        let output = run(&value, flags);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(
            stderr(&output),
            "warning: dependency resolution is incomplete\n"
        );
        if flags.contains(&"--json") {
            assert_eq!(output.stdout, serde_json::to_vec(&value).expect("json"));
        } else if flags.contains(&"--details") {
            assert!(stdout(&output).contains("0 reported occurrences"));
            assert!(stdout(&output).contains("declaration: name: never-resolved-dependency"));
        } else {
            assert_eq!(stdout(&output), "Package  License\n");
        }
    }
}

#[test]
fn license_report_v2_routine_evidence_does_not_fill_details_with_noise() {
    let mut value = fixture();
    value["components"] = serde_json::json!([value["components"][1].clone()]);
    value["inventory"] = serde_json::json!({
        "completeness":"recorded_lockfile_inventory", "resolution_basis":"lockfile_records",
        "notices":[], "coverage":[{"aggregate":"complete", "assemblies":["registry"], "dependencies":["registry"], "services":["service"]}],
        "resolutions":[{"path":"app/package.json", "status":"complete", "diagnostics":[]}],
        "dependency_coverage":{"registry":{"state":"complete", "reasons":[]}}
    });
    value["components"][0]["license_evidence"] = serde_json::json!({
        "source":"registry_declared", "lookup_basis":"registry_name_version",
        "artifact_verification":"not_checked", "status":"expression", "syntax":"spdx",
        "interpretation_methods":["spdx_expression"]
    });
    for reason in ["publisher_release_metadata", "uploaded_declaration"] {
        value["components"][0]["license_evidence"]["applicability_reason"] = reason.into();
        let output = run(&value, &["--details", "--quiet"]);
        assert_eq!(output.status.code(), Some(0));
        let text = stdout(&output);
        assert!(text.contains("dependency 1.0.0") && text.contains("MIT"));
        assert!(text.contains("input file: app/package-lock.json"));
        for prefix in [
            "metadata:",
            "resolution basis:",
            "source kind:",
            "license applicability:",
            "license evidence source:",
            "license interpretation:",
            "license interpretation method:",
            "license syntax:",
            "inventory construction:",
            "resolution:",
            "dependency coverage:",
            "component inventory:",
            "dependency relationships:",
            "service inventory:",
        ] {
            assert!(!text.contains(prefix), "unexpected {prefix}:\n{text}");
        }
    }
}
