//! Authored public-safe audit reports shared across pure and binary tests.

/// A report with all finding categories and one advisory evidence gap.
pub fn findings() -> serde_json::Value {
    serde_json::from_slice(include_bytes!("../fixtures/audit/findings.json")).expect("fixture")
}

/// Fully checked one-coordinate evidence with two occurrences and no findings.
pub fn clean() -> serde_json::Value {
    let mut value = findings();
    value["occurrences"][1]["coordinate"]["version"] = "1.0.0".into();
    value["occurrences"][1]["version"] = "1.0.0".into();
    for category in ["vulnerabilities", "deprecated", "outdated", "duplicates"] {
        value["findings"][category] = serde_json::json!([]);
    }
    value["unknowns"]["vulnerabilities"] = serde_json::json!([]);
    for category in ["vulnerabilities", "deprecation", "outdated"] {
        value["coverage"][category]["candidates_count"] = 1.into();
        value["coverage"][category]["checked_count"] = 1.into();
        value["coverage"][category]["unknown_count"] = 0.into();
    }
    value["coverage"]["duplicates"]["candidates_count"] = 1.into();
    for category in [
        "vulnerabilities",
        "deprecated",
        "outdated",
        "duplicates",
        "incomplete_checks",
    ] {
        value["summary"][category] = 0.into();
    }
    value["summary"]["dependencies"] = 1.into();
    value
}

/// Compact authored findings with exact, absent and unattributed origins.
pub fn v2_findings() -> serde_json::Value {
    serde_json::from_slice(include_bytes!("../fixtures/audit/v2-findings.json"))
        .expect("v2 fixture")
}

/// Complete compact report with no findings or gaps.
pub fn v2_clean() -> serde_json::Value {
    let mut value = v2_findings();
    for category in ["vulnerabilities", "deprecated", "outdated", "duplicates"] {
        value["findings"][category] = serde_json::json!([]);
    }
    for category in [
        "vulnerabilities",
        "metadata",
        "sources",
        "resolution",
        "excluded_dependencies",
    ] {
        value["unknowns"][category] = serde_json::json!([]);
    }
    for category in ["vulnerabilities", "deprecation", "outdated"] {
        value["coverage"][category]["checked_count"] = 2.into();
        value["coverage"][category]["unknown_count"] = 0.into();
    }
    for (name, count) in value["summary"].as_object_mut().expect("summary") {
        if name != "dependencies" {
            *count = 0.into();
        }
    }
    value
}

/// Complete accounting with unsupported advisory and uncollected metadata checks.
pub fn v2_unsupported() -> serde_json::Value {
    let mut v = v2_clean();
    let c = serde_json::json!({"registry":"zig","name":"demo","version":"1.0.0"});
    let paths = serde_json::json!(["module/build.zig.zon"]);
    v["coverage"]["vulnerabilities"]["checked_count"] = 1.into();
    v["coverage"]["vulnerabilities"]["unsupported_count"] = 1.into();
    v["coverage"]["vulnerabilities"]["unsupported_registries"] = serde_json::json!(["zig"]);
    v["coverage"]["deprecation"]["checked_count"] = 1.into();
    v["coverage"]["deprecation"]["not_collected_count"] = 1.into();
    v["coverage"]["deprecation"]["not_collected_registries"] = serde_json::json!(["zig"]);
    v["unknowns"]["vulnerabilities"] = serde_json::json!([{"coordinate":c,"paths":paths,"check":"vulnerabilities","status":"unsupported","reasons":[],"advisory_ids":[]}]);
    v["unknowns"]["metadata"] = serde_json::json!([{"coordinate":c,"paths":paths,"check":"deprecation","status":"not_collected","reason":null}]);
    v["summary"]["incomplete_checks"] = 2.into();
    v
}
