//! Binary compatibility coverage for the manifest-only ecosystems: Go modules,
//! vcpkg, and Zig.

use super::*;

// Public-safe manifests shared with the opt-in service qualification.
const VCPKG: &str = include_str!("../fixtures/sbom/manifests/vcpkg.json");
const ZIG: &str = include_str!("../fixtures/sbom/manifests/build.zig.zon");
const GO: &str = include_str!("../fixtures/sbom/manifests/go.mod");

fn manifest_only_repository() -> tempfile::TempDir {
    repository(&[
        ("cpp/vcpkg.json", VCPKG),
        ("zig/build.zig.zon", ZIG),
        ("go/go.mod", GO),
        ("go/go.sum", "github.com/google/uuid v1.6.0 h1:x\n"),
        ("go/vendor/golang.org/x/text/go.mod", GO),
        ("go/testdata/broken/go.mod", "not a module\n"),
        ("go/testdata/npm/package-lock.json", "{}"),
    ])
}

#[test]
fn detect_reports_go_vcpkg_and_zig_manifests_as_manifest_only() {
    let repo = manifest_only_repository();

    let default = detect(repo.path(), &["--json"]);
    let lockfiles_only = detect(repo.path(), &["--json", "--lockfiles-only"]);

    assert_eq!(default.status.code(), Some(0), "{}", stderr(&default));
    assert_eq!(
        lockfiles_only.status.code(),
        Some(1),
        "{}",
        stderr(&lockfiles_only)
    );
    for output in [&default, &lockfiles_only] {
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
        assert_eq!(
            value["lockfiles"][0]["path"],
            "go/testdata/npm/package-lock.json"
        );
        assert_eq!(value["lockfiles"][0]["status"], "excluded");
        assert_eq!(value["nested"], serde_json::json!([]));
        let selected: Vec<_> = value["manifest_only"]
            .as_array()
            .expect("manifests")
            .iter()
            .filter(|entry| entry["status"] != "excluded")
            .map(|entry| entry["path"].as_str().expect("path"))
            .collect();
        assert_eq!(
            selected,
            ["cpp/vcpkg.json", "go/go.mod", "zig/build.zig.zon"]
        );
        assert!(
            value["manifest_only"]
                .as_array()
                .expect("manifests")
                .iter()
                .any(|entry| entry["path"] == "go/testdata/broken/go.mod"
                    && entry["status"] == "excluded")
        );
    }
}

#[test]
fn detect_never_pairs_vcpkg_with_conan_or_go_mod_with_go_dep() {
    let repo = repository(&[
        ("conan.lock", "{}"),
        ("vcpkg.json", VCPKG),
        ("legacy/Gopkg.lock", ""),
        ("legacy/go.mod", GO),
    ]);

    let output = detect(repo.path(), &[]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report = stdout(&output);
    assert!(
        report.starts_with("2 lockfiles in 2 ecosystems, 2 manifest-only projects included\n"),
        "{report}"
    );
    let companion = |path: &str| {
        report
            .lines()
            .find(|line| line.split_whitespace().next() == Some(path))
            .and_then(|line| line.split("  ").filter(|cell| !cell.is_empty()).last())
            .map(str::trim)
    };
    assert_eq!(companion("conan.lock"), Some("-"), "{report}");
    assert_eq!(companion("legacy/Gopkg.lock"), Some("-"), "{report}");
    assert_eq!(companion("vcpkg.json"), Some("(no lockfile)"), "{report}");
    assert_eq!(
        companion("legacy/go.mod"),
        Some("(no lockfile)"),
        "{report}"
    );
    let value: serde_json::Value =
        serde_json::from_slice(&detect(repo.path(), &["--json"]).stdout).expect("JSON");
    for lock in value["lockfiles"].as_array().expect("lockfiles") {
        assert_eq!(lock["manifests"], serde_json::json!([]), "{lock}");
    }
}

#[test]
fn generate_uploads_manifest_only_projects_unless_lockfiles_only() {
    let repo = manifest_only_repository();

    let skipped = generate(
        repo.path(),
        Some("test-token"),
        Some("http://127.0.0.1:9"),
        &["--lockfiles-only"],
    );
    assert_eq!(skipped.status.code(), Some(1), "{}", stderr(&skipped));
    assert!(skipped.stdout.is_empty(), "{:?}", skipped.stdout);
    assert!(
        stderr(&skipped).contains(
            "3 manifest-only projects not uploaded (--lockfiles-only): \
             cpp/vcpkg.json, go/go.mod, zig/build.zig.zon"
        ),
        "{}",
        stderr(&skipped)
    );
    assert!(!stderr(&skipped).contains("submitting"));

    let document = br#"{"properties":[{"name":"githits:completeness","value":"resolved_manifest_inventory"}]}"#;
    let server = ScriptedServer::success("cyclonedx", document);
    let output = generate(repo.path(), Some("test-token"), Some(&server.origin()), &[]);
    let requests = server.requests();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, document);
    assert!(
        stderr(&output).contains("uploaded 0 lockfiles and 3 manifests"),
        "{}",
        stderr(&output)
    );
    let request = String::from_utf8_lossy(&requests[0]);
    assert_eq!(
        request.matches("filename=").count(),
        3,
        "selected files only"
    );
    for (path, contents) in [
        ("cpp/vcpkg.json", VCPKG),
        ("go/go.mod", GO),
        ("zig/build.zig.zon", ZIG),
    ] {
        assert_eq!(
            request.matches(&format!("filename=\"{path}\"")).count(),
            1,
            "{path}"
        );
        assert!(request.contains(contents), "{path} bytes");
    }
}
