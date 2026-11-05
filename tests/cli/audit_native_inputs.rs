//! All upload commands share native Cargo member evidence selection.
use super::*;
use crate::support::audit::v2_clean;

const MANIFEST: &str = "[workspace]\nmembers = [\"crates/*\"]\n";
const CONFIG: &str = "version = 1\n\n[lockfiles]\ninclude = [\"Cargo.lock\"]\nmanifests = []\n\n[licenses]\nallow = [\"MIT\"]\n";
const DOCUMENT: &[u8] = br#"{"bomFormat":"CycloneDX","specVersion":"1.7","properties":[{"name":"githits:completeness","value":"recorded_lockfile_inventory"}],"components":[]}"#;
const UPLOADED: [&str; 4] = [
    "Cargo.lock",
    "Cargo.toml",
    "crates/one/Cargo.toml",
    "crates/two/Cargo.toml",
];

#[test]
fn native_member_evidence_is_shared_by_upload_commands_under_configuration() {
    let r = repository(&[
        ("githits-scan.toml", CONFIG),
        ("Cargo.lock", "# workspace lock\n"),
        ("Cargo.toml", MANIFEST),
        (
            "crates/one/Cargo.toml",
            "[package]\nname = \"one\"\nversion = \"1.0.0\"\n",
        ),
        (
            "crates/two/Cargo.toml",
            "[package]\nname = \"two\"\nversion = \"2.0.0\"\n",
        ),
        (
            "unrelated/Cargo.toml",
            "[package]\nname = \"unrelated\"\nversion = \"1.0.0\"\n",
        ),
    ]);
    let report = serde_json::to_vec(&v2_clean()).expect("clean audit report");

    let audit_server = server(&report);
    let output = run(
        r.path(),
        Some(&audit_server.origin()),
        &["--json", "--lockfiles-only"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_uploaded_members(&audit_server.requests());

    let sbom_server = ScriptedServer::success("cyclonedx", DOCUMENT);
    let output = generate(
        r.path(),
        Some("test-token"),
        Some(&sbom_server.origin()),
        &["--lockfiles-only"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, DOCUMENT);
    assert_uploaded_members(&sbom_server.requests());

    let license_server = ScriptedServer::success("cyclonedx", DOCUMENT);
    let output = githits_scan()
        .args(["license", "check", "--json"])
        .arg(r.path())
        .arg("--lockfiles-only")
        .env("GITHITS_API_TOKEN", "test-token")
        .env("GITHITS_API_URL", license_server.origin())
        .output()
        .expect("run generated license check");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_uploaded_members(&license_server.requests());

    let license_server = ScriptedServer::respond_with(vec![
        accept_response(),
        events_response(&[snapshot("succeeded", "succeeded", 1)]),
        response(
            "200 OK",
            &[("Content-Type", "application/json")],
            include_bytes!("../fixtures/licenses/report-v1.json"),
        ),
    ]);
    let output = githits_scan()
        .args(["license", "report", "--json"])
        .arg(r.path())
        .arg("--lockfiles-only")
        .env("GITHITS_API_TOKEN", "test-token")
        .env("GITHITS_API_URL", license_server.origin())
        .output()
        .expect("generated license report");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_uploaded_members(&license_server.requests());
}

fn assert_uploaded_members(requests: &[Vec<u8>]) {
    assert_eq!(requests.len(), 3, "one job, events and result");
    let request = String::from_utf8_lossy(&requests[0]);
    assert_eq!(
        request.matches("filename=").count(),
        UPLOADED.len(),
        "{request}"
    );
    for path in UPLOADED {
        assert_eq!(
            request.matches(&format!("filename=\"{path}\"")).count(),
            1,
            "{request}"
        );
    }
    assert!(
        !request.contains("filename=\"unrelated/Cargo.toml\""),
        "{request}"
    );
    assert!(
        !request.contains("filename=\"crates/one/Cargo.lock\""),
        "{request}"
    );
    assert!(
        !request.contains("filename=\"crates/two/Cargo.lock\""),
        "{request}"
    );
}

#[test]
fn automatic_cargo_member_limit_names_counts_and_explicit_partial_scan() {
    let mut owned = vec![
        ("Cargo.lock".to_owned(), "# workspace lock\n".to_owned()),
        (
            "Cargo.toml".to_owned(),
            "[workspace]\nmembers = [\"crates/*\"]\n".to_owned(),
        ),
    ];
    for index in 0..255 {
        owned.push((
            format!("crates/member{index}/Cargo.toml"),
            format!("[package]\nname = \"member-{index}\"\nversion = \"1.0.0\"\n"),
        ));
    }
    let files: Vec<_> = owned
        .iter()
        .map(|(path, contents)| (path.as_str(), contents.as_str()))
        .collect();
    let r = repository(&files);

    let output = run(r.path(), Some("http://127.0.0.1:9"), &["--json"]);
    let diagnostic = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{diagnostic}");
    assert!(output.stdout.is_empty(), "{}", stdout(&output));
    assert!(
        diagnostic.contains("257 files exceed the 256-file upload limit"),
        "{diagnostic}"
    );
    assert!(
        diagnostic.contains("automatic workspace member manifests: 255"),
        "{diagnostic}"
    );
    assert!(
        diagnostic.contains("--exclude 'crates/member0/Cargo.toml'"),
        "{diagnostic}"
    );
    assert!(
        diagnostic.contains("required evidence may remain incomplete"),
        "{diagnostic}"
    );
    assert!(!diagnostic.contains("scan a smaller tree"), "{diagnostic}");

    let mut partial = v2_clean();
    partial["unknowns"]["sources"] = serde_json::json!([
        {"path":"Cargo.lock","reasons":["required_input_not_supplied"]}
    ]);
    partial["unknowns"]["resolution"] = serde_json::json!([
        {"path":"Cargo.lock","name":null,"reason":"required_input_not_supplied",
            "required_path":"crates/member0/Cargo.toml"}
    ]);
    partial["summary"]["incomplete_sources"] = 1.into();
    let response = serde_json::to_vec(&partial).expect("partial audit report");
    let mock = server(&response);
    let output = run(
        r.path(),
        Some(&mock.origin()),
        &["--json", "--exclude", "crates/**/Cargo.toml"],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("audit JSON");
    assert_eq!(report["incomplete"], true);
    let issues = report["issues"].as_array().expect("issues");
    let issue = issues
        .iter()
        .find(|issue| issue["check"] == "dependency information")
        .expect("retained source gap");
    assert_eq!(issue["status"], "incomplete");
    assert_eq!(issue["files"], serde_json::json!(["Cargo.lock"]));
    assert_eq!(
        issue["required_files"],
        serde_json::json!(["crates/member0/Cargo.toml"])
    );

    let requests = mock.requests();
    assert_eq!(requests.len(), 3, "one job, events and result");
    let request = String::from_utf8_lossy(&requests[0]);
    assert_eq!(request.matches("filename=").count(), 2, "{request}");
    for path in ["Cargo.lock", "Cargo.toml"] {
        assert_eq!(
            request.matches(&format!("filename=\"{path}\"")).count(),
            1,
            "{request}"
        );
    }
    assert!(
        !request.contains("filename=\"crates/member0/Cargo.toml\""),
        "{request}"
    );
}
