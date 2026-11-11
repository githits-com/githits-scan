//! Live request against the real GitHits API.
//!
//! Ignored by default; run manually with a real token in the environment:
//!
//! ```text
//! cargo nextest run --run-ignored ignored-only -E 'test(=generates_recorded_npm_and_cargo_workspace_inventory)'
//! ```
//!
//! Token-requiring tests fail closed when it is absent. The license-report and
//! combined SBOM cases support private signed-in CLI acquisition for their Scan
//! child; see docs/implementation/license-report.md for environment selection.

mod support;

use std::path::Path;
use std::process::Command;

use support::write_file;

#[test]
#[ignore = "requires a supplied API token or explicitly selected signed-in CLI environment, and network access"]
fn license_report_uses_deployed_api_and_saved_report_offline() {
    let token = live_token();
    let repo = live_minimist_fixture();
    let output = Command::new(env!("CARGO_BIN_EXE_githits-scan"))
        .args(["license", "report"])
        .arg(repo.path())
        .args(["--json", "--quiet"])
        .env("GITHITS_API_TOKEN", &token)
        .output()
        .expect("run license report");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains(&token) && !stderr.contains(&token),
        "credential found; output withheld"
    );
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("licenses JSON");
    assert_eq!(report["schema_version"], 2);
    let components = report["components"].as_array().expect("occurrences");
    let root = components
        .iter()
        .find(|c| c["name"] == "audit-live-minimist" && c["record_kind"] == "manifest")
        .expect("root project occurrence");
    let minimist = components
        .iter()
        .find(|c| c["name"] == "minimist" && c["version"] == "0.0.8")
        .expect("minimist occurrence");
    for component in [root, minimist] {
        assert!(
            ["manifest_paths", "lockfile_paths"].iter().any(|field| {
                component["inputs"][*field]
                    .as_array()
                    .is_some_and(|paths| !paths.is_empty())
            }),
            "{} has supplied input attribution",
            component["name"]
        );
    }
    let mut input_paths = Vec::new();
    for component in components {
        for field in ["manifest_paths", "lockfile_paths"] {
            input_paths.extend(
                component["inputs"][field]
                    .as_array()
                    .expect("typed input paths")
                    .iter()
                    .map(|path| path.as_str().expect("input path").to_owned()),
            );
        }
    }
    let saved = repo.path().join("licenses.json");
    write_file(&saved, &output.stdout);
    let offline = |flags: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_githits-scan"))
            .args(["license", "report", "--from-report"])
            .arg(&saved)
            .args(flags)
            .env_remove("GITHITS_API_TOKEN")
            .env("GITHITS_API_URL", "invalid-origin")
            .output()
            .expect("offline report")
    };
    let replays = [
        offline(&["--quiet", "--no-color"]),
        offline(&["--details", "--quiet", "--no-color"]),
        offline(&["--json", "--quiet"]),
    ];
    for replay in &replays {
        assert!(
            !String::from_utf8_lossy(&replay.stdout).contains(&token)
                && !String::from_utf8_lossy(&replay.stderr).contains(&token),
            "credential found; output withheld"
        );
        assert_eq!(replay.status.code(), Some(0));
    }
    let compact = String::from_utf8_lossy(&replays[0].stdout);
    assert!(compact.contains("audit-live-minimist 1.0.0") && compact.contains("minimist 0.0.8"));
    assert_eq!(
        compact
            .lines()
            .next()
            .expect("header")
            .split_whitespace()
            .collect::<Vec<_>>(),
        ["Package", "License"]
    );
    let details = String::from_utf8_lossy(&replays[1].stdout);
    assert!(details.contains("audit-live-minimist 1.0.0") && details.contains("minimist 0.0.8"));
    for path in input_paths {
        assert!(details.contains(&format!("input file: {path}")), "{path}");
    }
    assert_eq!(
        replays[2].stdout, output.stdout,
        "JSON replay preserves exact bytes"
    );
}

#[test]
fn license_report_live_harness_accepts_release_environment_without_cli_login() {
    use support::jobs::{ID, ScriptedServer, accept_response, events_response, snapshot};
    let mut value: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/licenses/report-v2.json"))
            .expect("fixture");
    value["components"][0]["name"] = "audit-live-minimist".into();
    value["components"][1]["name"] = "minimist".into();
    value["components"][1]["version"] = "0.0.8".into();
    value["components"][1]["purl"] = "pkg:npm/minimist@0.0.8".into();
    let server = ScriptedServer::respond_with(vec![
        accept_response(),
        events_response(&[snapshot("succeeded", "succeeded", 1)]),
        support::response(
            "200 OK",
            &[("Content-Type", "application/json")],
            &serde_json::to_vec(&value).expect("JSON"),
        ),
    ]);
    // Run the actual ignored case with the release job's credential source and no login selector.
    let output = Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "license_report_uses_deployed_api_and_saved_report_offline",
            "--ignored",
        ])
        .env("GITHITS_API_TOKEN", "test-token")
        .env("GITHITS_API_URL", server.origin())
        .env_remove("GITHITS_ENV")
        .output()
        .expect("release-shaped live harness");
    assert!(
        output.status.success(),
        "child test stdout:\n{}\nchild test stderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    for request in &requests {
        assert!(support::head(request).contains("authorization: bearer test-token"));
    }
    assert!(
        support::head(&requests[2])
            .starts_with(&format!("get /v1/experimental/license-reports/{ID} "))
    );
}

// Credential acquisition belongs only to this explicitly invoked test harness.
// Never pass the acquired value to Cargo/nextest, arguments, files or diagnostics.
#[cfg(test)]
fn live_token() -> String {
    if let Some(token) = std::env::var_os("GITHITS_API_TOKEN") {
        let token = token
            .into_string()
            .map_err(|_| "credential environment encoding invalid; value withheld")
            .expect("credential environment is not UTF-8");
        assert!(!token.trim().is_empty(), "live credential is empty");
        return token.trim().to_owned();
    }
    let environment = std::env::var("GITHITS_ENV").ok();
    let origin = std::env::var("GITHITS_API_URL").ok();
    assert!(
        matches!(
            (environment.as_deref(), origin.as_deref()),
            (Some("prod"), None | Some("https://api.githits.dev"))
        ),
        "set GITHITS_ENV=prod for the production origin, or provide GITHITS_API_TOKEN"
    );
    let acquired = Command::new("npx")
        .args(["-y", "githits@latest", "auth", "token"])
        .env_remove("GITHITS_API_TOKEN")
        .output()
        .expect("credential command failed; output withheld");
    assert!(
        acquired.status.success(),
        "credential acquisition failed; output withheld"
    );
    // UTF-8 errors retain input bytes; discard them before assertion diagnostics.
    let token = String::from_utf8(acquired.stdout)
        .map_err(|_| "credential encoding invalid; output withheld")
        .expect("credential acquisition returned invalid encoding");
    let token = token.trim().to_owned();
    assert!(
        !token.is_empty(),
        "credential acquisition returned no value"
    );
    token
}

#[test]
#[ignore = "requires GITHITS_API_TOKEN and network access"]
fn audit_remediation_live_cli_consumes_final_contract() {
    let token = std::env::var("GITHITS_API_TOKEN").expect("live credential required");
    assert!(!token.is_empty(), "live credential required");
    let repo = live_minimist_fixture();
    let output = Command::new(env!("CARGO_BIN_EXE_githits-scan"))
        .arg("audit")
        .arg(repo.path())
        .arg("--json")
        .output()
        .expect("run audit");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains(&token),
        "credential found; output withheld"
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains(&token),
        "credential found; output withheld"
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("audit JSON");
    assert_compact_audit_report(&result);
    assert_live_minimist_recommendation(&result);
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("assessing"),
        "JSON suppresses progress"
    );
}

#[cfg(test)]
fn live_minimist_fixture() -> tempfile::TempDir {
    let repo = tempfile::tempdir().expect("tempdir");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/audit/live-minimist");
    for name in ["package.json", "package-lock.json"] {
        write_file(
            &repo.path().join(name),
            &std::fs::read(fixtures.join(name)).expect("fixture"),
        );
    }
    repo
}

#[cfg(test)]
fn assert_live_minimist_recommendation(result: &serde_json::Value) {
    // Native evidence can legitimately remain unavailable independently of remediation.
    assert!(result["incomplete"].is_boolean());
    assert_eq!(result["remediation"]["status"], "completed");
    let records = result["remediation"]["recommendations"]
        .as_array()
        .expect("recommendations required");
    let record = records
        .iter()
        .find(|r| r["subject"] == "npm:minimist@0.0.8")
        .expect("minimist recommendation required");
    assert_eq!(record["outcome"], "proposed");
    assert_eq!(record["changes"][0]["target_version"], "0.2.4");
    assert_eq!(record["changes"][0]["strategy"], "upgrade");
    assert_eq!(record["checks"]["release_availability"], "observed");
    assert_eq!(record["checks"]["advisories"], "non_affecting");
    assert_eq!(record["checks"]["requirements"], "matched");
    assert_eq!(record["checks"]["native_resolution"], "not_checked");
    let addressed = record["addressed_findings"]
        .as_array()
        .expect("addressed findings");
    for id in ["GHSA-vh95-rmgr-6w4m", "GHSA-xvch-5gv4-984h"] {
        assert!(
            addressed.iter().any(|f| f["advisory"] == id),
            "missing addressed advisory {id}"
        );
    }
}

/// One analysis qualifies both registry npm evidence and native Cargo project joins.
#[test]
#[ignore = "requires a supplied API token or explicitly selected signed-in CLI environment, and network access"]
fn generates_recorded_npm_and_cargo_workspace_inventory() {
    let token = live_token();
    let parent = local_workspace();
    let root = parent.path().join("workspace");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sbom");
    for name in ["package-lock.json", "package.json"] {
        write_file(
            &root.join(name),
            &std::fs::read(fixtures.join(name)).expect("fixture present"),
        );
    }
    let output = Command::new(env!("CARGO_BIN_EXE_githits-scan"))
        .args(["sbom", "generate"])
        .arg(&root)
        .env("GITHITS_API_TOKEN", &token)
        .output()
        .expect("run githits-scan sbom generate");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains(&token)
            && !String::from_utf8_lossy(&output.stderr).contains(&token),
        "credential found; output withheld"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("uploaded 2 lockfiles and 3 manifests"),
        "{stderr}"
    );
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CycloneDX JSON on stdout");
    assert_recorded_workspace_inventory(&document);
    assert_workspace_license_exclusion(&root, &output.stdout);
}

#[cfg(test)]
fn assert_recorded_workspace_inventory(document: &serde_json::Value) {
    assert_eq!(document["bomFormat"], "CycloneDX");
    assert_eq!(document["specVersion"], "1.7");
    assert_eq!(
        property(document, "githits:completeness"),
        Some("recorded_lockfile_inventory")
    );
    let components = document["components"].as_array().expect("components");
    assert!(
        components.iter().any(|c| {
            c["name"] == "left-pad"
                && c["version"] == "1.3.0"
                && property(c, "githits:record_kind") == Some("locked_package")
        }),
        "locked left-pad 1.3.0 missing from {components:?}"
    );
    assert_cargo_workspace_join(components);
    assert_unjoined_local_source(components);
}

#[cfg(test)]
fn assert_cargo_workspace_join(components: &[serde_json::Value]) {
    let members: Vec<_> = components
        .iter()
        .filter(|c| c["name"] == "localcrate" && c["version"] == "1.0.0")
        .collect();
    assert_eq!(
        members.len(),
        1,
        "the member and lock record are joined: {components:?}"
    );
    let member = members[0];
    assert_eq!(property(member, "githits:record_kind"), Some("manifest"));
    assert_eq!(property(member, "githits:project_subject"), Some("true"));
    assert_eq!(
        property(member, "githits:manifest_path"),
        Some("local/Cargo.toml")
    );
    let records: serde_json::Value = serde_json::from_str(
        property(member, "githits:adopted_lock_records").expect("adopted lock records"),
    )
    .expect("lock records JSON");
    assert!(
        records.as_array().expect("lock records").iter().any(|r| {
            r["name"] == "localcrate"
                && r["version"] == "1.0.0"
                && r["facts"]["lockfile_path"] == "Cargo.lock"
                && r["facts"]["source_kind"] == "LOCKED_PACKAGE_SOURCE_KIND_LOCAL"
        }),
        "adopted local lock facts missing: {records}"
    );
}

#[cfg(test)]
fn assert_unjoined_local_source(components: &[serde_json::Value]) {
    let external: Vec<_> = components
        .iter()
        .filter(|c| c["name"] == "externalcrate" && c["version"] == "1.2.0")
        .collect();
    assert_eq!(
        external.len(),
        1,
        "out-of-tree path dependency: {components:?}"
    );
    let external = external[0];
    assert_eq!(
        property(external, "githits:record_kind"),
        Some("locked_package")
    );
    assert_eq!(
        property(external, "githits:source_kind"),
        Some("LOCKED_PACKAGE_SOURCE_KIND_LOCAL"),
        "unjoined local lock records retain the policy marker: {external:?}"
    );
}

#[cfg(test)]
fn assert_workspace_license_exclusion(repo: &Path, document: &[u8]) {
    let saved = repo.join("bom.json");
    write_file(&saved, document);
    write_file(
        &repo.join("githits-scan.toml"),
        b"version = 1\n[licenses]\nallow = [\"WTFPL\"]\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_githits-scan"))
        .args(["license", "check"])
        .arg(repo)
        .arg("--sbom")
        .arg(saved)
        .arg("--json")
        .env_remove("GITHITS_API_TOKEN")
        .env("GITHITS_API_URL", "invalid-origin")
        .output()
        .expect("offline license check");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("license JSON");
    assert_eq!(
        report["components"], 1,
        "only the registry npm package is evaluated"
    );
    assert_eq!(
        report["local_packages"], 1,
        "only the unjoined out-of-tree dependency is a local package"
    );
    assert_eq!(report["violations"], serde_json::json!([]));
}

/// Temporary parent holding a workspace and an out-of-tree local path dependency.
#[cfg(test)]
fn local_workspace() -> tempfile::TempDir {
    let repo = tempfile::tempdir().expect("tempdir");
    for (name, contents) in [
        (
            "workspace/Cargo.toml",
            r#"[package]
name = "liveapp"
version = "0.1.0"
edition = "2024"

[workspace]
members = [".", "local"]

[dependencies]
localcrate = { path = "local" }
externalcrate = { path = "../external" }
"#,
        ),
        (
            "workspace/local/Cargo.toml",
            r#"[package]
name = "localcrate"
version = "1.0.0"
edition = "2024"
"#,
        ),
        (
            "external/Cargo.toml",
            "[package]\nname = \"externalcrate\"\nversion = \"1.2.0\"\nedition = \"2024\"\n",
        ),
        ("external/src/lib.rs", ""),
        ("workspace/src/lib.rs", ""),
        ("workspace/local/src/lib.rs", ""),
        (
            "workspace/Cargo.lock",
            r#"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "externalcrate"
version = "1.2.0"

[[package]]
name = "liveapp"
version = "0.1.0"
dependencies = [
 "externalcrate",
 "localcrate",
]

[[package]]
name = "localcrate"
version = "1.0.0"
"#,
        ),
    ] {
        write_file(&repo.path().join(name), contents.as_bytes());
    }
    repo
}

#[test]
fn local_workspace_fixture_matches_cargo_generated_lockfile() {
    let parent = local_workspace();
    let root = parent.path().join("workspace");
    let lockfile = root.join("Cargo.lock");
    let expected = std::fs::read(&lockfile).expect("fixture lockfile");
    let output = Command::new("cargo")
        .current_dir(&root)
        .args(["generate-lockfile", "--offline"])
        .output()
        .expect("generate the isolated local lockfile");
    assert!(output.status.success(), "Cargo accepts the local workspace");
    assert_eq!(
        std::fs::read(&lockfile).expect("generated lockfile"),
        expected
    );
}

/// Qualifies text Bun support without manifest-only resolution against the
/// configured origin. Release checks use the default production origin.
#[test]
#[ignore = "requires GITHITS_API_TOKEN and authorized API network access"]
fn generates_a_recorded_bun_inventory_for_the_fixture() {
    assert!(
        std::env::var_os("GITHITS_API_TOKEN").is_some_and(|value| !value.is_empty()),
        "GITHITS_API_TOKEN must be set for the live test"
    );
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sbom");
    let repo = tempfile::tempdir().expect("tempdir");
    for (source, name) in [
        ("bun/bun.lock", "bun.lock"),
        ("package.json", "package.json"),
    ] {
        let contents = std::fs::read(fixtures.join(source)).expect("fixture present");
        write_file(&repo.path().join(name), &contents);
    }
    let output = Command::new(env!("CARGO_BIN_EXE_githits-scan"))
        .args(["sbom", "generate"])
        .arg(repo.path())
        .output()
        .expect("run githits-scan sbom generate");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CycloneDX JSON on stdout");
    assert_eq!(document["bomFormat"], "CycloneDX");
    assert_eq!(
        property(&document, "githits:completeness"),
        Some("recorded_lockfile_inventory")
    );
    let locks: serde_json::Value =
        serde_json::from_str(property(&document, "githits:lockfiles").expect("lockfile evidence"))
            .expect("lockfile JSON");
    assert_eq!(locks[0]["path"], "bun.lock");
    assert_eq!(locks[0]["format"], "LOCKFILE_FORMAT_BUN_TEXT");
    let components = document["components"].as_array().expect("components");
    assert!(
        components
            .iter()
            .any(|c| c["name"] == "left-pad" && c["version"] == "1.3.0")
    );
    assert!(
        stderr.contains("uploaded 1 lockfile and 1 manifest (package.json)\n"),
        "{stderr}"
    );
}

/// Qualifies manifest-only Go, vcpkg, and Zig resolution against the configured
/// origin. Release checks use the default production origin.
#[test]
#[ignore = "requires GITHITS_API_TOKEN and authorized API network access"]
fn resolves_go_vcpkg_and_zig_manifest_only_projects() {
    assert!(
        std::env::var_os("GITHITS_API_TOKEN").is_some_and(|value| !value.is_empty()),
        "GITHITS_API_TOKEN must be set for the live test"
    );
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sbom/manifests");
    let repo = tempfile::tempdir().expect("tempdir");
    for (name, path) in [
        ("go.mod", "go/go.mod"),
        ("vcpkg.json", "cpp/vcpkg.json"),
        ("build.zig.zon", "zig/build.zig.zon"),
    ] {
        let contents = std::fs::read(fixtures.join(name)).expect("fixture present");
        write_file(&repo.path().join(path), &contents);
    }
    let output = Command::new(env!("CARGO_BIN_EXE_githits-scan"))
        .args(["sbom", "generate"])
        .arg(repo.path())
        .output()
        .expect("run githits-scan sbom generate");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains(
            "uploaded 0 lockfiles and 3 manifests (cpp/vcpkg.json, go/go.mod, zig/build.zig.zon)"
        ),
        "{stderr}"
    );
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CycloneDX JSON on stdout");
    assert_eq!(
        property(&document, "githits:resolution_basis"),
        Some("manifest_resolution")
    );
    for (path, dependencies) in [
        ("go/go.mod", ["github.com/google/uuid", "golang.org/x/text"]),
        ("cpp/vcpkg.json", ["fmt", "zlib"]),
        (
            "zig/build.zig.zon",
            ["gh/ziglibs/diffz", "gh/ziglibs/known-folders"],
        ),
    ] {
        let resolved = resolved_dependency_names(&document, path).expect("manifest root");
        for name in dependencies {
            assert!(
                resolved.contains(&name),
                "{path}: {name} not in {resolved:?}"
            );
        }
    }
}

/// Names of the components the manifest root for `path` depends on, or `None`
/// when the document has no root component for that manifest.
fn resolved_dependency_names<'a>(
    document: &'a serde_json::Value,
    path: &str,
) -> Option<Vec<&'a str>> {
    let components = document["components"].as_array()?;
    let root = components.iter().find(|c| {
        property(c, "githits:record_kind") == Some("manifest")
            && property(c, "githits:manifest_path") == Some(path)
    })?;
    let edges = document["dependencies"]
        .as_array()?
        .iter()
        .find(|d| d["ref"] == root["bom-ref"])
        .and_then(|d| d["dependsOn"].as_array());
    Some(
        edges
            .into_iter()
            .flatten()
            .filter_map(|target| components.iter().find(|c| c["bom-ref"] == *target))
            .filter_map(|c| c["name"].as_str())
            .collect(),
    )
}

/// A named entry of a CycloneDX `properties` array.
fn property<'a>(component: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    component["properties"]
        .as_array()?
        .iter()
        .find(|p| p["name"] == name)
        .and_then(|p| p["value"].as_str())
}

#[cfg(test)]
fn assert_compact_audit_report(report: &serde_json::Value) {
    assert_eq!(report["schema_version"], 2);
    assert!(
        report["summary"]["dependencies"]
            .as_u64()
            .expect("dependency count")
            > 0
    );
    assert!(
        report
            .get("issues")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|rows| rows.iter().all(|row| row["check"] != "report")),
        "service accounting must remain verified"
    );
    assert!(report["lifecycle"]["findings"].is_array());
    assert!(report["lifecycle"]["coverage"].is_object());
    assert!(report.get("deprecated").is_none());
    assert!(report.get("occurrences").is_none() && report.get("inputs").is_none());
    for category in ["vulnerabilities", "outdated", "duplicates"] {
        assert!(
            report.get(category).is_none_or(serde_json::Value::is_array),
            "{category}"
        );
    }
}
