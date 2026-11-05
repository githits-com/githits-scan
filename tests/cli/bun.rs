//! Binary compatibility coverage for Bun text lockfiles.

use super::*;

// Public-safe JSONC fixture shared with the opt-in service qualification.
const BUN: &str = include_str!("../fixtures/sbom/bun/bun.lock");

#[test]
fn bun_detect_reports_root_and_nested_pairs_as_javascript() {
    let repo = repository(&[
        ("bun.lock", BUN),
        ("package.json", "{}"),
        ("app/bun.lock", BUN),
        ("app/package.json", "{}"),
        ("app/packages/core/package.json", "{}"),
    ]);
    let output = detect(repo.path(), &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("detect JSON");
    let locks = value["lockfiles"].as_array().expect("lockfiles");
    assert_eq!(locks.len(), 2);
    for (lock, path, manifest) in [
        (&locks[0], "app/bun.lock", "app/package.json"),
        (&locks[1], "bun.lock", "package.json"),
    ] {
        assert_eq!(lock["path"], path);
        assert_eq!(lock["ecosystem"], "javascript");
        assert_eq!(lock["bytes"], BUN.len());
        assert_eq!(lock["manifests"].as_array().expect("companions").len(), 1);
        assert_eq!(lock["manifests"][0]["path"], manifest);
    }
    assert_eq!(value["nested"][0]["path"], "app/packages/core/package.json");
    assert_eq!(value["nested"][0]["lockfile"], "app/bun.lock");
    assert_eq!(value["manifest_only"], serde_json::json!([]));
}

#[test]
fn bun_default_generate_uploads_raw_text_and_deduplicated_companions() {
    let repo = repository(&[
        ("bun.lock", BUN),
        ("package-lock.json", "{}"),
        ("package.json", "{}"),
        ("app/bun.lock", BUN),
        ("app/package.json", "{}"),
        ("standalone/bun.lock", BUN),
        ("app/packages/core/package.json", "{}"),
        ("node_modules/ignored/bun.lock", BUN),
        (".hidden/bun.lock", BUN),
        ("ignored/bun.lock", BUN),
        (".gitignore", "ignored/\n"),
        ("bun.lock.bak", BUN),
    ]);
    fs::write(repo.path().join("bun.lockb"), [0xff, 0xfe]).expect("binary Bun fixture");
    let document = br#"{"properties":[{"name":"githits:completeness","value":"recorded_lockfile_inventory"}]}"#;
    let server = ScriptedServer::success("cyclonedx", document);
    let output = generate(repo.path(), Some("test-token"), Some(&server.origin()), &[]);
    let requests = server.requests();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, document);
    assert!(
        stderr(&output)
            .contains("uploaded 4 lockfiles and 2 manifests (app/package.json, package.json)\n")
    );
    assert!(stderr(&output).contains("inventory: recorded_lockfile_inventory;"));
    assert_eq!(requests.len(), 3);
    let request = String::from_utf8_lossy(&requests[0]);
    assert_eq!(
        request.matches("filename=").count(),
        6,
        "selected files only"
    );
    for path in [
        "bun.lock",
        "package-lock.json",
        "package.json",
        "app/bun.lock",
        "app/package.json",
        "standalone/bun.lock",
    ] {
        assert_eq!(
            request.matches(&format!("filename=\"{path}\"")).count(),
            1,
            "{path}"
        );
    }
    assert_eq!(request.matches(BUN).count(), 3, "raw JSONC bytes");
}

#[test]
fn bun_exclude_leaves_no_default_upload_and_makes_no_request() {
    let repo = repository(&[("bun.lock", BUN), ("package.json", "{}")]);
    let output = generate(
        repo.path(),
        Some("test-token"),
        Some("http://127.0.0.1:9"),
        &["--exclude", "bun.lock"],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(
        stderr(&output).contains("every lockfile is excluded"),
        "{}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains("submitting"));
}

#[test]
fn bun_over_file_limit_is_rejected_before_submission() {
    let repo = repository(&[("bun.lock", "")]);
    let file = fs::File::create(repo.path().join("bun.lock")).expect("Bun file");
    file.set_len(githits_scan::api::MAX_FILE_BYTES + 1)
        .expect("oversized file");
    let output = generate(
        repo.path(),
        Some("test-token"),
        Some("http://127.0.0.1:9"),
        &[],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(
        stderr(&output).contains("bun.lock is 5242881 bytes, over the 5242880-byte limit per file")
    );
    assert!(!stderr(&output).contains("submitting"));
}
