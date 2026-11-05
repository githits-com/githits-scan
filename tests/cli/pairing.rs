//! Binary compatibility coverage for pairing lockfiles with their owning
//! manifests.

use super::*;

const DOCUMENT: &[u8] =
    br#"{"properties":[{"name":"githits:completeness","value":"recorded_lockfile_inventory"}]}"#;

fn pairing_repository() -> tempfile::TempDir {
    repository(&[
        ("Cargo.lock", "# lock\n"),
        ("Cargo.toml", "[package]\n"),
        ("py/Pipfile.lock", "{}"),
        ("py/pyproject.toml", "[project]\n"),
        ("net/packages.lock.json", "{}"),
        ("net/App.csproj", "<Project />"),
        ("net/Tool.csproj", "<Project />"),
    ])
}

#[test]
fn detect_json_reports_uncombined_manifests_and_ambiguous_lockfiles() {
    let repo = pairing_repository();

    let output = detect(repo.path(), &["--json"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(output.stderr.is_empty(), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["lockfiles"][0]["manifests"][0]["path"], "Cargo.toml");
    assert_eq!(value["lockfiles"][1]["path"], "py/Pipfile.lock");
    assert_eq!(value["lockfiles"][1]["manifests"], serde_json::json!([]));
    assert_eq!(
        value["uncombined"],
        serde_json::json!([{
            "path": "py/pyproject.toml",
            "ecosystem": "python",
            "bytes": 10,
            "lockfile": "py/Pipfile.lock",
        }])
    );
    assert_eq!(
        value["ambiguous"],
        serde_json::json!([{
            "path": "net/packages.lock.json",
            "ecosystem": "dotnet",
            "bytes": 2,
            "manifests": ["net/App.csproj", "net/Tool.csproj"],
        }])
    );
    let manifest_only: Vec<&str> = value["manifest_only"]
        .as_array()
        .expect("manifest_only")
        .iter()
        .filter_map(|m| m["path"].as_str())
        .collect();
    assert_eq!(manifest_only, ["net/App.csproj", "net/Tool.csproj"]);
}

#[test]
fn generate_warns_about_an_ambiguous_lockfile_and_resolves_its_projects() {
    let repo = pairing_repository();
    let server = ScriptedServer::success("cyclonedx", DOCUMENT);

    let output = generate(repo.path(), Some("test-token"), Some(&server.origin()), &[]);
    let requests = server.requests();

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, DOCUMENT);
    let stderr = stderr(&output);
    assert!(
        stderr.contains(
            "warning: net/packages.lock.json is not uploaded: net/App.csproj, net/Tool.csproj could each own it, so they are manifest-only projects; exclude the lockfile to accept this\n"
        ),
        "{stderr}"
    );
    let request = String::from_utf8_lossy(&requests[0]);
    assert_eq!(
        request.matches("filename=").count(),
        5,
        "selected files only"
    );
    for path in [
        "Cargo.lock",
        "Cargo.toml",
        "py/Pipfile.lock",
        "net/App.csproj",
        "net/Tool.csproj",
    ] {
        assert_eq!(
            request.matches(&format!("filename=\"{path}\"")).count(),
            1,
            "{path}"
        );
    }
}

#[test]
fn excluding_the_ambiguous_lockfile_accepts_it_without_a_warning() {
    let repo = pairing_repository();
    let server = ScriptedServer::success("cyclonedx", DOCUMENT);

    let output = generate(
        repo.path(),
        Some("test-token"),
        Some(&server.origin()),
        &["--exclude", "net/packages.lock.json"],
    );
    let requests = server.requests();

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!stderr(&output).contains("warning"), "{}", stderr(&output));
    let request = String::from_utf8_lossy(&requests[0]);
    assert_eq!(
        request.matches("filename=").count(),
        5,
        "selected files only"
    );
    assert!(!request.contains("packages.lock.json"));
    assert!(!request.contains("py/pyproject.toml"));
}
