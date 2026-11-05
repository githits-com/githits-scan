//! Pre-release selection and diagnostic regressions.

use super::*;

const COMMANDS: &[&[&str]] = &[
    &["detect"],
    &["sbom", "generate"],
    &["audit"],
    &["license", "report"],
    &["license", "check"],
];

#[test]
fn explicit_config_must_be_readable_for_every_command() {
    let repo = repository(&[("Cargo.lock", ""), ("githits-scan.toml", LICENSE_CONFIG)]);
    let missing = repo.path().join("typo.toml");
    let directory = repo.path().join("not-a-file.toml");
    fs::create_dir(&directory).expect("config directory");
    for args in COMMANDS {
        for config in [&missing, &directory] {
            let output = githits_scan()
                .args(*args)
                .arg(repo.path())
                .arg("--config")
                .arg(config)
                .env("GITHITS_API_TOKEN", "test-token")
                .env("GITHITS_API_URL", "http://127.0.0.1:9")
                .output()
                .expect("command");
            assert_eq!(
                output.status.code(),
                Some(2),
                "{args:?}: {}",
                stderr(&output)
            );
            assert!(output.stdout.is_empty(), "{args:?}");
            assert!(stderr(&output).contains(config.to_str().expect("path")));
        }
    }
    let output = detect(
        repo.path(),
        &["--config", missing.to_str().expect("path"), "--save"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        fs::read_to_string(&missing)
            .expect("template")
            .contains("# [licenses]")
    );
}

#[test]
fn fixture_defaults_are_visible_saved_and_overridable() {
    let repo = repository(&[
        ("Cargo.lock", ""),
        ("tests/Fixtures/a/package-lock.json", ""),
        ("test/__fixtures__/a/uv.lock", ""),
        ("parser/testdata/a/yarn.lock", ""),
        ("test-data/a/yarn.lock", ""),
        ("test_data/a/composer.lock", ""),
        ("crates/ty_completion_eval/truth/a/uv.lock", ""),
        ("tests/integration/Cargo.lock", ""),
    ]);
    let output = detect(repo.path(), &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
    let excluded = value["lockfiles"]
        .as_array()
        .expect("lockfiles")
        .iter()
        .filter(|entry| entry["status"] == "excluded")
        .count();
    assert_eq!(excluded, 5, "{value}");
    assert!(
        value["test_paths"]
            .as_array()
            .expect("test paths")
            .iter()
            .any(|p| p == "tests/integration/Cargo.lock")
    );
    let human = detect(repo.path(), &[]);
    assert!(stdout(&human).contains("excluded"));
    assert!(stdout(&human).contains("Test-looking paths"));
    let saved = detect(repo.path(), &["--save"]);
    assert_eq!(saved.status.code(), Some(0), "{}", stderr(&saved));
    let config_path = repo.path().join("githits-scan.toml");
    let config = githits_scan::config::load(&config_path)
        .expect("load")
        .expect("config");
    assert_eq!(
        config.include,
        [
            "Cargo.lock",
            "crates/ty_completion_eval/truth/a/uv.lock",
            "tests/integration/Cargo.lock"
        ]
    );
    fs::write(&config_path, "version = 1\n[lockfiles]\ninclude = [\"Cargo.lock\", \"tests/Fixtures/a/package-lock.json\", \"tests/integration/Cargo.lock\"]\n").expect("override");
    let output = detect(repo.path(), &["--json", "--save"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
    assert!(
        value["lockfiles"]
            .as_array()
            .expect("lockfiles")
            .iter()
            .any(
                |entry| entry["path"] == "tests/Fixtures/a/package-lock.json"
                    && entry["status"] == "included"
            )
    );
    let output = detect(repo.path(), &["--json", "--exclude", "tests/Fixtures/**"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
    assert!(
        !value["lockfiles"]
            .as_array()
            .expect("locks")
            .iter()
            .any(|entry| entry["path"] == "tests/Fixtures/a/package-lock.json")
    );
    assert_eq!(
        value["excluded_directory_patterns"],
        serde_json::json!(["tests/Fixtures/**"])
    );
}

#[test]
fn account_access_errors_explain_the_action_and_exit_two() {
    let repo = repository(&[("Cargo.lock", ""), ("githits-scan.toml", LICENSE_CONFIG)]);
    for code in [
        "FEATURE_FLAG_REQUIRED",
        "TERMS_ACCEPTANCE_REQUIRED",
        "ACCOUNT_INACTIVE",
    ] {
        for args in &COMMANDS[1..] {
            let body = format!(r#"{{"status":403,"code":"{code}"}}"#);
            let server = MockServer::respond_with(response(
                "403 Forbidden",
                &[("Content-Type", "application/problem+json")],
                body.as_bytes(),
            ));
            let output = githits_scan()
                .args(*args)
                .arg(repo.path())
                .env("GITHITS_API_TOKEN", "test-token")
                .env("GITHITS_API_URL", server.origin())
                .output()
                .expect("command");
            drop(server.request());
            assert_eq!(
                output.status.code(),
                Some(2),
                "{args:?}: {}",
                stderr(&output)
            );
            assert!(output.stdout.is_empty(), "{args:?}");
            let diagnostic = stderr(&output);
            assert!(diagnostic.contains(code), "{diagnostic}");
            assert!(
                diagnostic.contains("https://app.githits.com"),
                "{diagnostic}"
            );
            let action = match code {
                "TERMS_ACCEPTANCE_REQUIRED" => "accept the terms",
                "FEATURE_FLAG_REQUIRED" => "request access",
                _ => "reactivate",
            };
            assert!(diagnostic.contains(action), "{diagnostic}");
        }
    }
}

#[test]
fn upload_file_limit_suggests_selection_controls_before_network() {
    let repo = repository(&[]);
    for index in 0..257 {
        let dir = repo.path().join(index.to_string());
        fs::create_dir(&dir).expect("directory");
        fs::write(dir.join("Cargo.lock"), "").expect("lockfile");
    }
    let output = generate(
        repo.path(),
        Some("test-token"),
        Some("http://127.0.0.1:9"),
        &[],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let diagnostic = stderr(&output);
    for suggestion in [
        "257",
        "256",
        "--exclude",
        "--lockfiles-only",
        "detect --save",
    ] {
        assert!(diagnostic.contains(suggestion), "{diagnostic}");
    }
    let server = ScriptedServer::success("cyclonedx", b"{}");
    let output = generate(
        repo.path(),
        Some("test-token"),
        Some(&server.origin()),
        &["--exclude", "256/**"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let requests = server.requests();
    assert_eq!(
        String::from_utf8_lossy(&requests[0])
            .matches("filename=")
            .count(),
        256
    );
}

#[test]
fn fixture_defaults_filter_uploads_and_cargo_members_without_reading_fixtures() {
    let repo = repository(&[
        ("Cargo.lock", ""),
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\", \"fixtures/member\"]\n",
        ),
        (
            "crates/core/Cargo.toml",
            "[package]\nname = \"core\"\nversion = \"0.1.0\"\n",
        ),
        (
            "fixtures/member/Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        ),
        ("truth/bad/uv.lock", ""),
        ("testdata/only/package.json", ""),
        ("tests/fixtures/ambiguous/packages.lock.json", ""),
        ("tests/fixtures/ambiguous/A.csproj", ""),
        ("tests/fixtures/ambiguous/B.csproj", ""),
    ]);
    fs::write(repo.path().join("truth/bad/uv.lock"), [0xff, 0xfe]).expect("invalid fixture bytes");
    for restore in [false, true] {
        if restore {
            fs::write(repo.path().join("githits-scan.toml"), "version = 1\n[lockfiles]\ninclude = [\"Cargo.lock\"]\nmanifests = [\"fixtures/member/Cargo.toml\"]\n").expect("explicit fixture selection");
        }
        let server = ScriptedServer::success("cyclonedx", b"{}");
        let output = generate(
            repo.path(),
            Some("test-token"),
            Some(&server.origin()),
            &["--exclude", "truth/**"],
        );
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let requests = server.requests();
        let upload = String::from_utf8_lossy(&requests[0]);
        assert!(upload.contains("filename=\"Cargo.lock\""));
        assert!(upload.contains("filename=\"crates/core/Cargo.toml\""));
        assert_eq!(
            upload.contains("filename=\"fixtures/member/Cargo.toml\""),
            restore
        );
        assert!(
            !upload.contains("truth/")
                && !upload.contains("testdata/")
                && !upload.contains("ambiguous/")
        );
        assert!(!stderr(&output).contains("warning:"), "{}", stderr(&output));
    }
}

#[test]
fn a_tree_with_only_fixture_evidence_has_no_upload_or_drift() {
    let repo = repository(&[
        ("fixtures/package-lock.json", ""),
        ("testdata/package.json", "{}"),
    ]);
    for args in [&[][..], &["--lockfiles-only"][..], &["--save"][..]] {
        let output = detect(repo.path(), args);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(stdout(&output).contains("excluded"));
    }
    let output = generate(
        repo.path(),
        Some("test-token"),
        Some("http://127.0.0.1:9"),
        &[],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(!stderr(&output).contains("drift"), "{}", stderr(&output));
}

#[test]
fn save_drops_a_listed_companion_when_its_lockfile_is_excluded() {
    let repo = repository(&[
        ("Cargo.lock", ""),
        ("Cargo.toml", ""),
        (
            "githits-scan.toml",
            "version = 1\n[lockfiles]\ninclude = [\"Cargo.lock\"]\nmanifests = [\"Cargo.toml\"]\n",
        ),
    ]);
    let output = detect(
        repo.path(),
        &["--save", "--exclude", "Cargo.lock", "--json"],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let config = githits_scan::config::load(&repo.path().join("githits-scan.toml"))
        .expect("load")
        .expect("config");
    assert_eq!(config.include, Vec::<String>::new());
    assert_eq!(config.manifests, Vec::<String>::new());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
    assert_eq!(value["drift"]["missing"], serde_json::json!([]));
}

#[test]
fn fixture_defaults_silence_unsupported_notices_in_detect_and_upload() {
    let repo = repository(&[
        ("Cargo.lock", ""),
        ("requirements.txt", "normal unsupported input"),
        ("fixtures/requirements.txt", "fixture unsupported input"),
        ("testdata/pom.xml", "fixture unsupported input"),
    ]);
    let output = detect(repo.path(), &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
    let unsupported = value["unsupported"]
        .as_array()
        .expect("unsupported formats");
    assert_eq!(unsupported.len(), 1, "{value}");
    assert_eq!(unsupported[0]["path"], "requirements.txt");

    let server = ScriptedServer::success("cyclonedx", b"{}");
    let output = generate(repo.path(), Some("test-token"), Some(&server.origin()), &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let requests = server.requests();
    assert_eq!(
        String::from_utf8_lossy(&requests[0])
            .matches("filename=")
            .count(),
        1
    );
    let diagnostic = stderr(&output);
    assert!(
        diagnostic.contains("warning: 1 file is not supported yet")
            && diagnostic.contains("example: requirements.txt"),
        "{diagnostic}"
    );
    assert!(
        !diagnostic.contains("fixtures/") && !diagnostic.contains("testdata/"),
        "{diagnostic}"
    );
}
