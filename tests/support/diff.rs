//! Authored dependency-diff fixtures; never captured private repository data.
use serde_json::{Value, json};

pub fn files(head: bool) -> (&'static str, &'static str) {
    if head {
        (
            include_str!("../fixtures/diff/head/package.json"),
            include_str!("../fixtures/diff/head/package-lock.json"),
        )
    } else {
        (
            include_str!("../fixtures/diff/base/package.json"),
            include_str!("../fixtures/diff/base/package-lock.json"),
        )
    }
}

pub fn inventory(head: bool) -> Value {
    let (manifest, lock) = files(head);
    let manifest: Value = serde_json::from_str(manifest).expect("manifest fixture");
    let lock: Value = serde_json::from_str(lock).expect("lock fixture");
    let packages = lock["packages"].as_object().expect("packages");
    let components: Vec<_> = packages.iter().filter(|(name, _)| !name.is_empty()).map(|(path, package)| {
        json!({"type":"library", "name":path.strip_prefix("node_modules/").expect("fixture package"), "version":package["version"], "properties":[
            {"name":"githits:registry","value":"npm"}, {"name":"githits:source_kind","value":"LOCKED_PACKAGE_SOURCE_KIND_REGISTRY"}, {"name":"githits:record_kind","value":"locked_package"},
            {"name":"githits:lockfile_path","value":"package-lock.json"}
        ]})
    }).collect();
    let declarations: Vec<_> = manifest["dependencies"]
        .as_object()
        .expect("dependencies")
        .keys()
        .map(|name| json!({"name":name,"manifest_path":"package.json","source_type":"registry"}))
        .collect();
    let agreements: Vec<_> = manifest["dependencies"].as_object().expect("dependencies").keys().map(|name| {
        json!({"name":name,"path":"package-lock.json","declaration_path":"package.json","status":"matched",
            "matched_versions":[packages[&format!("node_modules/{name}")]["version"]]})
    }).collect();
    json!({"bomFormat":"CycloneDX", "specVersion":"1.7", "components":components,"properties":[
        {"name":"githits:completeness","value":"recorded_lockfile_inventory"},
        {"name":"githits:declarations","value":declarations_to_string(&declarations)},
        {"name":"githits:declaration_agreement","value":declarations_to_string(&agreements)}
    ]})
}

fn declarations_to_string(values: &[Value]) -> String {
    serde_json::to_string(values).expect("fixture JSON")
}

pub fn audit(head: bool) -> Value {
    let mut report = super::audit::v2_clean();
    let mut findings = vec![finding(
        "leaf",
        if head { "1.0.0" } else { "2.0.0" },
        "GHSA-unchanged",
    )];
    if head {
        findings.push(finding("leaf", "1.0.0", "GHSA-introduced"));
    } else {
        findings.push(finding("minimist", "1.2.5", "GHSA-fixed"));
    }
    report["findings"]["vulnerabilities"] = json!(findings);
    report["summary"]["dependencies"] = 4.into();
    report["summary"]["vulnerabilities"] = 2.into();
    for category in ["vulnerabilities", "deprecation", "outdated"] {
        report["coverage"][category]["candidates_count"] = 4.into();
        report["coverage"][category]["checked_count"] = 4.into();
    }
    report
}

fn finding(name: &str, version: &str, id: &str) -> Value {
    json!({"coordinate":{"registry":"npm","name":name,"version":version},"paths":["package-lock.json"],
        "advisory_id":id,"aliases":[],"summary":null,"severity_score":null,"severity_type":null,"malicious":false,
        "fixed_in_versions":[],"verified_remedies":[]})
}

pub fn review(name: &str, from: &str, to: &str) -> Value {
    json!({"registry":"npm","name":name,"current_version":from,"target_version":to,"version_delta":"patch",
        "unknown_details":[],"security":{"current":{"version":from,"assessment_status":"affected","unknown_count":0},
            "target":{"version":to,"assessment_status":"non_affecting","unknown_count":0},"fixed":[{"id":"GHSA-fixed"}],"introduced":[],"unchanged":[]},
        "changelog":{"source":"releases","entries":[{"version":to,"html_url":"https://example.invalid/releases/1.2.8"}],"total_entries":1,"truncated":false}})
}

pub fn exchanges(head: bool, audit: bool) -> Vec<Vec<u8>> {
    let mut snapshot = super::jobs::snapshot("succeeded", "succeeded", 1);
    let (media, body) = if audit {
        snapshot["kind"] = "audit".into();
        snapshot["format"] = "json".into();
        ("application/json", self::audit(head))
    } else {
        ("application/vnd.cyclonedx+json", inventory(head))
    };
    vec![
        super::jobs::accept_response(),
        super::jobs::events_response(&[snapshot]),
        super::response(
            "200 OK",
            &[("Content-Type", media)],
            &serde_json::to_vec(&body).expect("fixture JSON"),
        ),
    ]
}
