//! Minimal authored native audit evidence, shared by pure and binary regressions.

/// Source-qualified findings, common evidence gaps and useful duplicate origins.
pub fn findings() -> serde_json::Value {
    serde_json::from_slice(include_bytes!("../fixtures/audit/native-findings.json"))
        .expect("native fixture")
}

/// Exact native facet accounting for an authored set of selected coordinates.
pub fn facet(
    n: u64,
    checked: u64,
    unknown: u64,
    uncollected: u64,
    na: u64,
    registry: &str,
) -> serde_json::Value {
    serde_json::json!({"candidates_count":n,"checked_count":checked,"unknown_count":unknown,
        "not_collected_count":uncollected,"not_collected_registries":if uncollected==0 {vec![]} else {vec![registry]},
        "not_applicable_count":na,"not_applicable_registries":if na==0 {vec![]} else {vec![registry]}})
}

/// Complete available evidence without findings; normal collection limits remain explicit.
pub fn clean() -> serde_json::Value {
    let mut v = findings();
    for name in ["vulnerabilities", "outdated", "duplicates"] {
        v["findings"][name] = serde_json::json!([]);
    }
    for name in [
        "vulnerabilities",
        "metadata",
        "sources",
        "resolution",
        "excluded_dependencies",
    ] {
        v["unknowns"][name] = serde_json::json!([]);
    }
    for name in ["vulnerabilities", "outdated"] {
        v["coverage"][name]["checked_count"] = 2.into();
        v["coverage"][name]["unknown_count"] = 0.into();
    }
    for (name, n) in v["summary"].as_object_mut().expect("summary") {
        if name != "dependencies" {
            *n = 0.into();
        }
    }
    v["lifecycle"]["findings"] = serde_json::json!([]);
    v["lifecycle"]["unknowns"] = serde_json::json!([]);
    v["lifecycle"]["coverage"]["deprecation"] = facet(2, 2, 0, 0, 0, "npm");
    v
}

/// A genuine unsupported advisory outcome; lifecycle collection limits are independent.
pub fn unsupported() -> serde_json::Value {
    let mut v = clean();
    v["coverage"]["vulnerabilities"]["checked_count"] = 1.into();
    v["coverage"]["vulnerabilities"]["unsupported_count"] = 1.into();
    v["coverage"]["vulnerabilities"]["unsupported_registries"] = serde_json::json!(["zig"]);
    v["unknowns"]["vulnerabilities"] = serde_json::json!([{
        "coordinate":{"registry":"zig","name":"demo","version":"1.0.0"},
        "paths":["module/build.zig.zon"],"check":"vulnerabilities","status":"unsupported","reasons":[],"advisory_ids":[]}]);
    v["summary"]["incomplete_checks"] = 1.into();
    v["lifecycle"]["coverage"]["deprecation"] = facet(2, 1, 0, 1, 0, "zig");
    for name in ["withdrawal", "registry_archival", "repository_archival"] {
        v["lifecycle"]["coverage"][name]["not_collected_registries"] =
            serde_json::json!(["npm", "zig"]);
    }
    v
}

/// Explicit native PyPI deprecation applicability, without a checked-negative claim.
pub fn pypi_not_applicable() -> serde_json::Value {
    let mut v = clean();
    v["lifecycle"]["coverage"]["deprecation"] = facet(2, 0, 0, 0, 2, "pypi");
    v["lifecycle"]["coverage"]["withdrawal"] = facet(2, 2, 0, 0, 0, "pypi");
    for name in ["registry_archival", "repository_archival"] {
        v["lifecycle"]["coverage"][name] = facet(2, 0, 0, 2, 0, "pypi");
    }
    v
}
