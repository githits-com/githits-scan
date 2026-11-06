//! Pre-release public CLI consistency regressions.
use super::*;

#[test]
fn consistency_detect_output_quiet_save_and_schema() {
    let repo = repository(&[("Cargo.lock", "")]);
    let target = repo.path().join("inventory.json");
    let output = detect(
        repo.path(),
        &["--json", "-q", "-o", target.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, Vec::<u8>::new());
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(&target).expect("report")).expect("JSON");
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["lockfiles_only"], false);
    assert!(value.get("include_manifests").is_none());
    let saved_output = detect(
        repo.path(),
        &["--json", "-o", target.to_str().expect("path")],
    );
    assert!(stderr(&saved_output).contains(&format!("saved {}", target.display())));
    let stdout_report = detect(repo.path(), &["--json", "-o", "-"]);
    assert_eq!(fs::read(&target).expect("report"), stdout_report.stdout);
    let saved = detect(repo.path(), &["--save"]);
    assert!(stdout(&saved).contains("created "));
    assert!(!stdout(&saved).contains("inventory matches"));
    let quiet = detect(repo.path(), &["--save", "-q"]);
    assert!(stdout(&quiet).contains("Cargo.lock"));
    assert!(!stdout(&quiet).contains("is up to date"));
}

#[test]
fn consistency_check_file_validation_details_and_output() {
    let repo = repository(&[]);
    let missing = repo.path().join("missing.json");
    let output = check(repo.path(), &["--sbom", missing.to_str().expect("path")]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("cannot read"));
    assert!(!stderr(&output).contains("configuration file"));
    fs::write(repo.path().join("githits-scan.toml"), LICENSE_CONFIG).expect("policy");
    fs::write(&missing, CYCLONEDX).expect("document");
    let basic = check(
        repo.path(),
        &["--sbom", missing.to_str().expect("path"), "-q"],
    );
    assert_eq!(basic.status.code(), Some(1));
    assert_eq!(
        stderr(&basic),
        "warning: SBOM has no githits:completeness property; inventory completeness is unknown\n"
    );
    let target = repo.path().join("verdict.txt");
    let detailed = check(
        repo.path(),
        &[
            "--sbom",
            missing.to_str().expect("path"),
            "--details",
            "-q",
            "-o",
            target.to_str().expect("path"),
        ],
    );
    assert_eq!(detailed.status.code(), Some(1), "{}", stderr(&detailed));
    assert_eq!(detailed.stdout, Vec::<u8>::new());
    let text = fs::read_to_string(&target).expect("report");
    assert!(text.contains("component reference:"));
    assert!(text.contains("package URL:"));
    assert!(!stdout(&basic).contains("component reference:"));
}

#[test]
fn consistency_unsupported_files_and_ecosystem_headings() {
    let repo = repository(&[
        ("requirements.txt", "invalid"),
        ("deno.lock", "invalid"),
        ("pom.xml", "invalid"),
        ("node_modules/requirements.txt", "ignored"),
    ]);
    let output = detect(repo.path(), &["--json"]);
    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(value["unsupported"].as_array().expect("files").len(), 3);
    let human = detect(repo.path(), &[]);
    for name in ["requirements.txt", "deno.lock", "pom.xml"] {
        assert!(stdout(&human).contains(name));
        assert!(stdout(&human).contains("not supported yet"));
    }
    let online = generate(
        repo.path(),
        Some("test-token"),
        Some("http://127.0.0.1:1"),
        &["-q"],
    );
    assert_eq!(online.status.code(), Some(1));
    assert!(
        stderr(&online).contains("1 file is not supported yet")
            && stderr(&online).contains("example: requirements.txt")
    );
    for lock in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"] {
        let repo = repository(&[(lock, ""), ("member/package.json", "{}")]);
        let output = detect(repo.path(), &[]);
        assert!(stdout(&output).contains("JavaScript manifests below an ancestor lockfile"));
        assert!(!stdout(&output).contains("Cargo workspace"));
    }
}

#[test]
fn consistency_caller_api_errors_exit_two_and_retryable_errors_exit_three() {
    for (status, expected, problem) in [
        (400, 2),
        (401, 2),
        (403, 2),
        (404, 2),
        (408, 3),
        (409, 2),
        (413, 2),
        (415, 2),
        (422, 2),
        (429, 3),
        (500, 3),
        (503, 3),
    ]
    .into_iter()
    .flat_map(|(status, expected)| [false, true].map(|problem| (status, expected, problem)))
    {
        let body = if problem {
            format!(
                "{{\"status\":{status},\"code\":\"FUTURE_CODE\",\"detail\":\"A bearer credential is required.\"}}"
            )
        } else {
            String::new()
        };
        let response = format!("HTTP/1.1 {status} Error\r\nContent-Type: application/problem+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).into_bytes();
        let server = ScriptedServer::respond_with(vec![response]);
        let repo = repository(&[("package-lock.json", "{}")]);
        let output = generate(
            repo.path(),
            Some("test-token"),
            Some(&server.origin()),
            &["-q"],
        );
        assert_eq!(
            output.status.code(),
            Some(expected),
            "status {status}, problem {problem}: {}",
            stderr(&output)
        );
        if status == 401 && problem {
            assert!(stderr(&output).contains("token") && stderr(&output).contains("rejected"));
            assert!(!stderr(&output).contains("A bearer credential is required"));
        }
        if status == 401 && !problem {
            assert!(stderr(&output).contains("check GITHITS_API_TOKEN or proxy authentication"));
        }
        assert!(!stderr(&output).contains("test-token"));
        server.requests();
    }
}

#[test]
fn consistency_help_uses_clap_path_defaults_and_common_flags() {
    for command in [
        vec!["detect"],
        vec!["audit"],
        vec!["license", "check"],
        vec!["license", "report"],
        vec!["sbom", "generate"],
    ] {
        let output = githits_scan()
            .args(command)
            .arg("--help")
            .output()
            .expect("help");
        let help = stdout(&output);
        assert!(help.contains("[default: .]"), "{help}");
        assert!(!help.contains("(default: .)"), "{help}");
        assert!(
            help.contains("--quiet") && help.contains("--output"),
            "{help}"
        );
    }
}

#[test]
fn consistency_unsupported_notices_respect_invocation_and_config_exclusions() {
    for configuration in [false, true] {
        let repo = repository(&[
            ("requirements.txt", "never read"),
            ("module/pom.xml", "never read"),
        ]);
        let args = if configuration {
            fs::write(
                repo.path().join("githits-scan.toml"),
                "version = 1\n[lockfiles]\nexclude = [\"**\"]\n",
            )
            .expect("config");
            vec![]
        } else {
            vec!["--exclude", "**"]
        };
        let mut json_args = args.clone();
        json_args.push("--json");
        let output = detect(repo.path(), &json_args);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
        assert_eq!(value["unsupported"], serde_json::json!([]));
        let output = generate(
            repo.path(),
            Some("test-token"),
            Some("http://127.0.0.1:1"),
            &args,
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(!stderr(&output).contains("not supported yet"));
    }
}

#[test]
fn consistency_invalid_upload_text_is_a_usage_error_before_network() {
    let repo = repository(&[("Cargo.lock", "")]);
    fs::write(repo.path().join("Cargo.lock"), [0xff]).expect("invalid UTF-8");
    let output = generate(
        repo.path(),
        Some("test-token"),
        Some("http://127.0.0.1:1"),
        &["-q"],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("not valid UTF-8"));
    assert_eq!(output.stdout, Vec::<u8>::new());
}

#[cfg(target_os = "linux")]
#[test]
fn consistency_non_utf8_upload_path_is_a_usage_error() {
    use std::os::unix::ffi::OsStringExt as _;
    let repo = repository(&[]);
    let directory = repo.path().join(std::ffi::OsString::from_vec(vec![0xff]));
    fs::create_dir(&directory).expect("directory");
    fs::write(directory.join("Cargo.lock"), "").expect("lockfile");
    let output = detect(repo.path(), &[]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("relative UTF-8 path"));
}

#[test]
fn consistency_check_json_file_and_stdout_are_equivalent() {
    let repo = repository(&[
        ("githits-scan.toml", LICENSE_CONFIG),
        ("bom.json", CYCLONEDX),
    ]);
    let file = repo.path().join("bom.json");
    let target = repo.path().join("verdict.json");
    let output = check(
        repo.path(),
        &[
            "--sbom",
            file.to_str().expect("path"),
            "--json",
            "-q",
            "-o",
            target.to_str().expect("path"),
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(output.stdout, Vec::<u8>::new());
    assert_eq!(
        stderr(&output),
        "warning: SBOM has no githits:completeness property; inventory completeness is unknown\n"
    );
    let stdout_report = check(
        repo.path(),
        &["--sbom", file.to_str().expect("path"), "--json", "-o", "-"],
    );
    assert_eq!(stdout_report.status.code(), Some(1));
    let saved_output = check(
        repo.path(),
        &[
            "--sbom",
            file.to_str().expect("path"),
            "--json",
            "-o",
            target.to_str().expect("path"),
        ],
    );
    assert!(stderr(&saved_output).contains(&format!("saved {}", target.display())));
    assert_eq!(fs::read(&target).expect("verdict"), stdout_report.stdout);
}

#[test]
fn consistency_check_does_not_claim_saved_output_when_generation_stops() {
    for (drift, existing) in [false, true]
        .into_iter()
        .flat_map(|drift| [false, true].map(move |existing| (drift, existing)))
    {
        let policy = if drift {
            LICENSE_CONFIG
        } else {
            "version=1\n[licenses]\nallow=[\"MIT\"]\n"
        };
        let repo = repository(&[("githits-scan.toml", policy)]);
        let target = repo.path().join("verdict.json");
        if existing {
            fs::write(&target, "previous verdict").expect("previous");
        }
        let output = githits_scan()
            .args(["license", "check"])
            .arg(repo.path())
            .arg("-o")
            .arg(&target)
            .env("GITHITS_API_TOKEN", "test-token")
            .env("GITHITS_API_URL", "http://127.0.0.1:1")
            .output()
            .expect("check");
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(!stderr(&output).contains("saved "));
        assert_eq!(output.stdout, Vec::<u8>::new());
        assert_eq!(target.exists(), existing);
        if existing {
            assert_eq!(fs::read(&target).expect("previous"), b"previous verdict");
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn consistency_unsupported_non_utf8_paths_do_not_block_supported_evidence() {
    use std::os::unix::ffi::OsStringExt as _;
    let repo = repository(&[("Cargo.lock", "")]);
    let directory = repo.path().join(std::ffi::OsString::from_vec(vec![0xff]));
    fs::create_dir(&directory).expect("directory");
    fs::write(directory.join("requirements.txt"), [0xff]).expect("unsupported file");
    let output = detect(repo.path(), &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(value["unsupported"][0]["path"], "\u{fffd}/requirements.txt");
    assert_eq!(value["lockfiles"][0]["path"], "Cargo.lock");
}

#[test]
fn consistency_generated_license_check_quiet_keeps_verdict_without_routine_stderr() {
    for json in [false, true] {
        let repo = repository(&[("Cargo.lock", ""), ("githits-scan.toml", LICENSE_CONFIG)]);
        let server = ScriptedServer::success("cyclonedx", CYCLONEDX.as_bytes());
        let mut command = githits_scan();
        command
            .args(["license", "check"])
            .arg(repo.path())
            .arg("-q")
            .env("GITHITS_API_TOKEN", "test-token")
            .env("GITHITS_API_URL", server.origin());
        if json {
            command.arg("--json");
        }
        let output = command.output().expect("generated check");
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
        if json {
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
            assert_eq!(value["violations"].as_array().expect("violations").len(), 1);
        } else {
            assert!(stdout(&output).contains("violation"));
        }
        assert_eq!(server.requests().len(), 3);
    }
}
