//! Pre-public command behavior regressions.
use super::*;

#[test]
fn polish_explicit_new_config_uses_template_and_is_repeatable() {
    let repo = repository(&[("Cargo.lock", "")]);
    let path = repo.path().join("custom.toml");
    let output = detect(
        repo.path(),
        &["--config", path.to_str().expect("path"), "--save"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = fs::read_to_string(&path).expect("created config");
    for needle in [
        "# githits-scan configuration",
        "exclude = []",
        "# [licenses]",
        "Cargo.lock",
    ] {
        assert!(text.contains(needle), "{text}");
    }
    let output = detect(
        repo.path(),
        &["--config", path.to_str().expect("path"), "--save"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(fs::read_to_string(path).expect("config"), text);
}

#[test]
fn polish_detect_counts_only_selected_locks_and_omits_excluded_suggestions() {
    let repo = repository(&[
        ("Cargo.lock", ""),
        ("fixtures/Cargo.lock", ""),
        ("tests/Cargo.lock", ""),
    ]);
    let output = detect(repo.path(), &["--exclude", "tests/Cargo.lock"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.starts_with("1 lockfile in 1 ecosystem"), "{text}");
    assert!(text.contains("2 lockfiles excluded"), "{text}");
    assert!(!text.contains("Test-looking paths"), "{text}");
}

#[test]
fn polish_test_suggestions_are_bounded_and_json_is_complete() {
    let repo = repository(&[("Cargo.lock", "")]);
    for i in 0..15 {
        let dir = repo.path().join(format!("tests/p{i:02}"));
        fs::create_dir_all(&dir).expect("dir");
        fs::write(dir.join("Cargo.lock"), "").expect("lock");
    }
    let output = detect(repo.path(), &[]);
    let text = stdout(&output);
    let suggestions = text
        .split("Test-looking paths")
        .nth(1)
        .expect("suggestions");
    assert_eq!(
        suggestions
            .lines()
            .filter(|line| line.contains("/Cargo.lock"))
            .count(),
        10
    );
    assert!(suggestions.contains("5 more"), "{suggestions}");
    let output = detect(repo.path(), &["--json"]);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["test_paths"].as_array().expect("paths").len(), 15);
}

#[test]
fn polish_detect_previews_exact_npm_and_cargo_upload_paths() {
    for (lock, manifest, declaration, member, other) in [
        (
            "package-lock.json",
            "package.json",
            r#"{"workspaces":["packages/*"]}"#,
            "packages/a/package.json",
            "tools/x/package.json",
        ),
        (
            "Cargo.lock",
            "Cargo.toml",
            "[workspace]\nmembers=['packages/a']\n",
            "packages/a/Cargo.toml",
            "tools/x/Cargo.toml",
        ),
    ] {
        let repo = repository(&[
            (lock, ""),
            (manifest, declaration),
            (member, ""),
            (other, ""),
        ]);
        let output = detect(repo.path(), &["--json"]);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
        let paths = value["upload_paths"].as_array().expect("upload paths");
        assert_eq!(paths.len(), 3, "{value}");
        assert!(paths.iter().any(|p| p == member), "{value}");
        assert!(!paths.iter().any(|p| p == other), "{value}");
        let output = detect(repo.path(), &[]);
        let text = stdout(&output);
        assert!(
            text.contains("Workspace manifests included automatically"),
            "{text}"
        );
        assert!(text.contains("not uploaded"), "{text}");
    }
}

#[test]
fn polish_truth_is_included_but_eval_truth_is_annotated() {
    let repo = repository(&[
        ("truth/Cargo.lock", ""),
        ("crates/ruff_linter/resources/test/fixtures/Cargo.lock", ""),
        ("scripts/formatter_eval/truth/Cargo.lock", ""),
    ]);
    let output = detect(repo.path(), &["--json"]);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let paths = value["upload_paths"].as_array().expect("upload paths");
    assert!(paths.iter().any(|p| p == "truth/Cargo.lock"));
    assert!(
        value["test_paths"]
            .as_array()
            .expect("annotations")
            .iter()
            .any(|p| p == "scripts/formatter_eval/truth/Cargo.lock")
    );
}

#[cfg(unix)]
#[test]
fn polish_unreadable_directory_is_pruned_or_names_exclusion_remedy() {
    use std::os::unix::fs::PermissionsExt as _;
    let repo = repository(&[("Cargo.lock", ""), ("locked/Cargo.lock", "")]);
    let locked = repo.path().join("locked");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o0)).expect("permissions");
    let failure = detect(repo.path(), &[]);
    let excluded = detect(repo.path(), &["--exclude", "locked/**", "--json"]);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).expect("restore permissions");
    assert_eq!(
        failure.status.code(),
        Some(3),
        "permissions must be enforced: {}",
        stdout(&failure)
    );
    let error = stderr(&failure);
    assert!(
        error.contains("locked")
            && error.contains("--exclude")
            && error.contains("Permission denied"),
        "{error}"
    );
    assert!(error.contains("relative to the scan root"), "{error}");
    assert_eq!(excluded.status.code(), Some(0), "{}", stderr(&excluded));
    let value: serde_json::Value = serde_json::from_slice(&excluded.stdout).expect("json");
    assert_eq!(
        value["excluded_directory_patterns"],
        serde_json::json!(["locked/**"])
    );
}

#[test]
fn polish_config_pruning_preserves_explicit_inclusions_and_cli_wins() {
    let repo = repository(&[
        ("Cargo.lock", ""),
        ("locked/Cargo.lock", ""),
        (
            "githits-scan.toml",
            "version=1\n[lockfiles]\ninclude=['Cargo.lock','locked/Cargo.lock']\nexclude=['locked/**']\n",
        ),
    ]);
    for (extra, expected) in [
        (vec!["--json"], 2),
        (vec!["--exclude", "locked/**", "--json"], 1),
    ] {
        let output = detect(repo.path(), &extra);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
        assert_eq!(
            value["upload_paths"].as_array().expect("paths").len(),
            expected,
            "{value}"
        );
    }
}

#[test]
fn polish_common_help_is_consistent_and_output_io_is_execution_error() {
    for command in [
        vec!["detect"],
        vec!["audit"],
        vec!["sbom", "generate"],
        vec!["license", "check"],
        vec!["license", "report"],
    ] {
        let output = githits_scan()
            .args(command)
            .arg("--help")
            .output()
            .expect("help");
        let text = stdout(&output);
        assert!(
            text.contains(
                "Suppress progress and success messages; keep reports, warnings and errors"
            ),
            "{text}"
        );
        let positions: Vec<_> = [
            "--config",
            "--no-check",
            "--lockfiles-only",
            "--exclude",
            "--output",
            "--quiet",
            "--no-color",
        ]
        .iter()
        .map(|flag| {
            text.lines()
                .position(|line| help_line_has_flag(line, flag))
                .expect(flag)
        })
        .collect();
        assert!(positions.windows(2).all(|p| p[0] < p[1]), "{text}");
    }
    let repo = repository(&[("Cargo.lock", "")]);
    let path = repo.path().join("missing/report.txt");
    let output = detect(repo.path(), &["-o", path.to_str().expect("path")]);
    assert_eq!(output.status.code(), Some(3));
    assert!(stderr(&output).contains("cannot write"));
}

#[test]
fn polish_unexpected_method_response_names_origin_and_proxy() {
    let repo = repository(&[("Cargo.lock", "")]);
    let server = MockServer::respond_with(response("405 Method Not Allowed", &[], b""));
    let output = generate(repo.path(), Some("test-token"), Some(&server.origin()), &[]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("GITHITS_API_URL") && stderr(&output).contains("proxy"),
        "{}",
        stderr(&output)
    );
    assert!(
        String::from_utf8_lossy(&server.request())
            .starts_with("POST /v1/experimental/lockfile-jobs")
    );
}

#[test]
fn polish_excluded_companions_are_not_read_or_uploaded() {
    let repo = repository(&[("package-lock.json", "{}"), ("package.json", "")]);
    fs::write(repo.path().join("package.json"), [0xff]).expect("unreadable UTF-8 companion");
    for config in [false, true] {
        if config {
            fs::write(repo.path().join("githits-scan.toml"), "version=1\n[lockfiles]\ninclude=['package-lock.json']\nexclude=['**/package.json']\n").expect("config");
        }
        let flags = if config {
            vec!["--json"]
        } else {
            vec!["--json", "--exclude", "**/package.json"]
        };
        let output = detect(repo.path(), &flags);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
        assert_eq!(
            value["upload_paths"],
            serde_json::json!(["package-lock.json"])
        );
        let server = ScriptedServer::success("cyclonedx", b"{}");
        let extra = if config {
            vec![]
        } else {
            vec!["--exclude", "**/package.json"]
        };
        let output = generate(
            repo.path(),
            Some("test-token"),
            Some(&server.origin()),
            &extra,
        );
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        assert!(!String::from_utf8_lossy(&requests[0]).contains("filename=\"package.json\""));
    }
}

#[test]
fn polish_unmatched_audit_selector_suggests_saved_coordinates() {
    let repo = repository(&[(
        "analysis.json",
        include_str!("../fixtures/audit/analysis-v1.json"),
    )]);
    for selector in ["demo", "npm:demo@9", "dmeo", "unrelated"] {
        let output = githits_scan()
            .args(["audit", "--from-analysis"])
            .arg(repo.path().join("analysis.json"))
            .args(["--explain", selector])
            .env_remove("GITHITS_API_TOKEN")
            .env("GITHITS_API_URL", "invalid-origin")
            .output()
            .expect("offline explanation");
        assert_eq!(output.status.code(), Some(2));
        let error = stderr(&output);
        assert!(error.contains("npm:demo@1.0.0"), "{selector}: {error}");
        assert!(error.contains("saved report"), "{error}");
    }
}

#[test]
fn polish_license_check_details_omit_empty_fields_and_nest_values() {
    let repo = repository(&[
        (
            "githits-scan.toml",
            "version=1\n[licenses]\nallow=['MIT']\n",
        ),
        (
            "bom.json",
            r#"{"bomFormat":"CycloneDX","components":[{"name":"empty-ref","licenses":[{"license":{"id":"GPL-3.0-only"}}]},{"name":"with-ref","bom-ref":"subject","purl":"pkg:npm/with-ref@1","licenses":[{"license":{"id":"GPL-3.0-only"}}]}]}"#,
        ),
    ]);
    let output = githits_scan()
        .args(["license", "check"])
        .arg(repo.path())
        .arg("--sbom")
        .arg(repo.path().join("bom.json"))
        .arg("--details")
        .output()
        .expect("license check");
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(!text.contains("component reference: \n"), "{text}");
    assert!(
        text.contains(
            "  with-ref\n    component reference: subject\n    package URL: pkg:npm/with-ref@1"
        ),
        "{text}"
    );
}

#[test]
fn polish_unsupported_warning_labels_group_count_and_example() {
    let repo = repository(&[("Cargo.lock", ""), ("a/pom.xml", ""), ("b/pom.xml", "")]);
    let server = ScriptedServer::success("cyclonedx", b"{}");
    let output = generate(
        repo.path(),
        Some("test-token"),
        Some(&server.origin()),
        &["-q"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("warning: 2 files are not supported yet"),
        "{}",
        stderr(&output)
    );
    assert!(stderr(&output).contains("example: a/pom.xml"));
    assert_eq!(server.requests().len(), 3);
}

#[test]
fn polish_blocked_preview_keeps_inventory_with_and_without_save() {
    for case in ["file-limit", "workspace-limit", "invalid-utf8"] {
        for save in [false, true] {
            assert_blocked_preview(case, save);
        }
    }
}

fn blocked_repository(case: &str) -> tempfile::TempDir {
    let repo = repository(&[("Cargo.lock", "")]);
    match case {
        "file-limit" => {
            for index in 0..256 {
                let dir = repo.path().join(format!("tests/p{index}"));
                fs::create_dir_all(&dir).expect("directory");
                fs::write(dir.join("Cargo.lock"), "").expect("lock");
            }
        }
        "workspace-limit" => {
            fs::write(
                repo.path().join("Cargo.toml"),
                "[workspace]\nmembers=['tests/p*']\n",
            )
            .expect("workspace");
            for index in 0..255 {
                let dir = repo.path().join(format!("tests/p{index}"));
                fs::create_dir_all(&dir).expect("directory");
                fs::write(dir.join("Cargo.toml"), "").expect("manifest");
            }
        }
        _ => fs::write(repo.path().join("Cargo.lock"), [0xff]).expect("invalid UTF-8"),
    }
    repo
}

fn assert_blocked_preview(case: &str, save: bool) {
    let repo = blocked_repository(case);
    let flags = if save {
        vec!["--json", "--save"]
    } else {
        vec!["--json"]
    };
    let output = detect(repo.path(), &flags);
    assert_eq!(output.status.code(), Some(2), "{case}: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("inventory despite blocked upload");
    assert_ne!(value["lockfiles"].as_array().expect("locks").len(), 0);
    assert!(value["upload_paths"].is_null(), "{value}");
    assert!(value["upload_error"].is_string(), "{value}");
    if case != "invalid-utf8" {
        assert_ne!(
            value["test_paths"]
                .as_array()
                .expect("test candidates retained")
                .len(),
            0
        );
        let human = detect(repo.path(), &[]);
        let text = stdout(&human);
        assert!(
            !text
                .lines()
                .next()
                .expect("headline")
                .contains("candidates not uploaded"),
            "{text}"
        );
        assert!(text.contains("Test-looking paths"), "{text}");
        assert!(!text.contains("\\nuse --exclude"), "{text}");
    }
    assert_eq!(repo.path().join("githits-scan.toml").exists(), save);
}

#[cfg(unix)]
#[test]
fn polish_config_inclusion_does_not_read_excluded_siblings() {
    use std::os::unix::fs::PermissionsExt as _;
    let repo = repository(&[
        ("locked/a/Cargo.lock", ""),
        ("locked/b/Cargo.lock", ""),
        (
            "githits-scan.toml",
            "version=1\n[lockfiles]\ninclude=['locked/a/Cargo.lock']\nexclude=['locked/**']\n",
        ),
    ]);
    let locked = repo.path().join("locked/b");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o0)).expect("permission");
    let output = detect(repo.path(), &["--json"]);
    fs::set_permissions(locked, fs::Permissions::from_mode(0o700)).expect("restore");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(
        value["upload_paths"],
        serde_json::json!(["locked/a/Cargo.lock"])
    );
}

#[test]
fn polish_explicit_fixture_lock_keeps_default_excluded_owner() {
    let repo = repository(&[
        ("fixtures/Cargo.lock", ""),
        ("fixtures/Cargo.toml", ""),
        (
            "githits-scan.toml",
            "version=1\n[lockfiles]\ninclude=['fixtures/Cargo.lock']\n",
        ),
    ]);
    let output = detect(repo.path(), &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(
        value["upload_paths"],
        serde_json::json!(["fixtures/Cargo.lock", "fixtures/Cargo.toml"])
    );
}

#[test]
fn polish_missing_config_parent_is_an_execution_error() {
    let repo = repository(&[("Cargo.lock", "")]);
    let path = repo.path().join("absent/config.toml");
    let output = detect(
        repo.path(),
        &["--save", "--config", path.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("cannot write"));
}

#[test]
fn polish_selected_adjacent_manifests_remain_in_json_and_appear_once_in_human_output() {
    let repo = repository(&[
        ("a/Pipfile.lock", ""),
        ("a/pyproject.toml", ""),
        ("b/Pipfile.lock", ""),
        ("b/pyproject.toml", ""),
        (
            "githits-scan.toml",
            "version=1\n[lockfiles]\ninclude=['a/Pipfile.lock','b/Pipfile.lock']\nmanifests=['a/pyproject.toml']\n",
        ),
    ]);
    let output = detect(repo.path(), &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(
        value["uncombined"]
            .as_array()
            .expect("all adjacent candidates")
            .len(),
        2
    );
    assert!(
        value["upload_paths"]
            .as_array()
            .expect("selection")
            .iter()
            .any(|p| p == "a/pyproject.toml")
    );
    let output = detect(repo.path(), &[]);
    let text = stdout(&output);
    assert!(
        text.contains("1 additional manifest included, 1 adjacent candidate not uploaded"),
        "{text}"
    );
    assert_eq!(text.matches("a/pyproject.toml").count(), 1, "{text}");
    assert_eq!(text.matches("b/pyproject.toml").count(), 1, "{text}");
}

fn help_line_has_flag(line: &str, flag: &str) -> bool {
    line.trim_start().starts_with(flag) || line.contains(&format!(", {flag}"))
}

#[test]
fn polish_save_preserves_configured_inclusion_overrides_until_cli_excludes_them() {
    let repo = repository(&[
        ("locked/Cargo.lock", ""),
        ("locked/pyproject.toml", ""),
        (
            "githits-scan.toml",
            "version=1\n[lockfiles]\ninclude=['locked/Cargo.lock']\nmanifests=['locked/pyproject.toml']\nexclude=['locked/**']\n",
        ),
    ]);
    let saved = detect(repo.path(), &["--save", "--json"]);
    assert_eq!(saved.status.code(), Some(0), "{}", stderr(&saved));
    let replay = detect(repo.path(), &["--json"]);
    assert_eq!(replay.status.code(), Some(0), "{}", stderr(&replay));
    let value: serde_json::Value = serde_json::from_slice(&replay.stdout).expect("json");
    assert_eq!(
        value["upload_paths"],
        serde_json::json!(["locked/Cargo.lock", "locked/pyproject.toml"])
    );
    let excluded = detect(repo.path(), &["--save", "--json", "--exclude", "locked/**"]);
    assert_eq!(excluded.status.code(), Some(1), "{}", stderr(&excluded));
    let config = githits_scan::config::load(&repo.path().join("githits-scan.toml"))
        .expect("config")
        .expect("exists");
    assert_eq!(config.include, Vec::<String>::new());
    assert_eq!(config.manifests, Vec::<String>::new());
}

#[cfg(unix)]
#[test]
fn polish_installed_dependency_directories_are_not_traversed() {
    use std::os::unix::fs::PermissionsExt as _;
    let repo = repository(&[
        ("Cargo.lock", ""),
        ("vendor/Cargo.lock", ""),
        ("node_modules/package-lock.json", ""),
    ]);
    for dir in ["vendor", "node_modules"] {
        fs::set_permissions(repo.path().join(dir), fs::Permissions::from_mode(0o0))
            .expect("permissions");
    }
    let output = detect(repo.path(), &["--json"]);
    for dir in ["vendor", "node_modules"] {
        fs::set_permissions(repo.path().join(dir), fs::Permissions::from_mode(0o700))
            .expect("restore");
    }
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["upload_paths"], serde_json::json!(["Cargo.lock"]));
}

#[test]
fn polish_empty_selection_headline_names_inventory_drift() {
    let repo = repository(&[("Cargo.lock", ""), ("githits-scan.toml", "version=1\n")]);
    let output = detect(repo.path(), &[]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(
        stdout(&output).lines().next(),
        Some(
            format!(
                "no lockfiles selected in {}, drift against {}: 1 unlisted",
                repo.path().display(),
                repo.path().join("githits-scan.toml").display()
            )
            .as_str()
        )
    );
}

#[test]
fn polish_license_completeness_handles_mixed_and_absent_evidence_without_changing_json() {
    for (completeness, label) in [
        (
            serde_json::json!("mixed_dependency_inventory"),
            "recorded and resolved dependencies",
        ),
        (serde_json::Value::Null, "not reported"),
    ] {
        let mut report: serde_json::Value =
            serde_json::from_slice(include_bytes!("../fixtures/licenses/report-v1.json"))
                .expect("report");
        report["inventory"]["completeness"] = completeness;
        let text = serde_json::to_string(&report).expect("json");
        let repo = repository(&[("report.json", &text)]);
        let file = repo.path().join("report.json");
        let output = githits_scan()
            .args(["license", "report", "--from-report"])
            .arg(&file)
            .arg("--details")
            .output()
            .expect("report");
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert!(
            stdout(&output).contains(&format!("inventory: {label}")),
            "{}",
            stdout(&output)
        );
        let output = githits_scan()
            .args(["license", "report", "--from-report"])
            .arg(&file)
            .arg("--json")
            .output()
            .expect("json report");
        assert_eq!(output.stdout, text.as_bytes());
    }
}

#[test]
fn polish_known_resolution_reasons_are_readable_and_deduplicated() {
    let reasons = [
        "non_registry_source",
        "skipped_requirement",
        "unmet_dependency",
        "unresolved_dependency",
        "future_alpha",
        "future_beta",
    ];
    let resolutions = serde_json::json!([{"path":"app/package.json","status":"partial","diagnostics": reasons.iter().map(|r| serde_json::json!({"name":"dependency","reason":r})).collect::<Vec<_>>()}]);
    let document = serde_json::json!({"bomFormat":"CycloneDX","components":[],"properties":[{"name":"githits:resolutions","value":resolutions.to_string()}]});
    let repo = repository(&[
        (
            "githits-scan.toml",
            "version=1\n[licenses]\nallow=['MIT']\n",
        ),
        ("bom.json", &document.to_string()),
    ]);
    let mut command = githits_scan();
    command
        .args(["license", "check"])
        .arg(repo.path())
        .arg("--sbom")
        .arg(repo.path().join("bom.json"));
    let output = command.output().expect("human policy");
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    for label in [
        "non-registry dependency",
        "dependency requirement skipped",
        "unresolved dependency",
        "unrecognized evidence (retained in JSON)",
    ] {
        assert_eq!(text.matches(label).count(), 1, "{text}");
    }
    let output = command.arg("--json").output().expect("JSON policy");
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    for reason in reasons {
        assert!(
            value["unresolved_projects"][0]["reasons"]
                .as_array()
                .expect("raw reasons")
                .iter()
                .any(|r| r == reason),
            "{value}"
        );
    }
}

#[test]
fn polish_shared_fixture_companion_is_independent_of_sibling_lock_order() {
    for selected in ["package-lock.json", "yarn.lock"] {
        let config = format!("version=1\n[lockfiles]\ninclude=['fixtures/{selected}']\n");
        let repo = repository(&[
            ("fixtures/package-lock.json", ""),
            ("fixtures/yarn.lock", ""),
            ("fixtures/package.json", "{}"),
            ("githits-scan.toml", &config),
        ]);
        let output = detect(repo.path(), &["--json"]);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
        let mut expected = vec![
            format!("fixtures/{selected}"),
            "fixtures/package.json".into(),
        ];
        expected.sort();
        assert_eq!(value["upload_paths"], serde_json::json!(expected));
    }
}

#[test]
fn polish_pruned_upload_does_not_claim_no_lockfiles_exist() {
    for configured in [false, true] {
        let repo = repository(&[("app/Cargo.lock", "")]);
        if configured {
            fs::write(
                repo.path().join("githits-scan.toml"),
                "version=1\n[lockfiles]\nexclude=['app/**']\n",
            )
            .expect("config");
        }
        let flags = if configured {
            vec![]
        } else {
            vec!["--exclude", "app/**"]
        };
        let output = generate(
            repo.path(),
            Some("test-token"),
            Some("http://127.0.0.1:9"),
            &flags,
        );
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert_eq!(output.stdout, Vec::<u8>::new());
        assert!(
            stderr(&output).contains("no lockfiles selected"),
            "{}",
            stderr(&output)
        );
        assert!(stderr(&output).contains("not inspected"));
        assert!(!stderr(&output).contains("no lockfiles found"));
    }
}

#[test]
fn polish_license_report_deduplicates_translated_coverage_reasons() {
    let mut report: serde_json::Value =
        serde_json::from_slice(include_bytes!("../fixtures/licenses/report-v1.json"))
            .expect("report");
    report["inventory"]["properties"][2]["value"] = serde_json::json!({"root":{"state":"incomplete","reasons":["unmet_dependency","unresolved_dependency","future_alpha","future_beta"]}}).to_string().into();
    let text = report.to_string();
    let repo = repository(&[("report.json", &text)]);
    let output = githits_scan()
        .args(["license", "report", "--details", "--from-report"])
        .arg(repo.path().join("report.json"))
        .output()
        .expect("report");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    let coverage = text
        .split("Coverage and limitations")
        .nth(1)
        .expect("coverage");
    assert_eq!(
        coverage.matches("reason: unresolved dependency").count(),
        1,
        "{coverage}"
    );
    assert_eq!(
        coverage
            .matches("reason: unrecognized evidence (retained in JSON)")
            .count(),
        1,
        "{coverage}"
    );
}

#[test]
fn polish_license_resolution_statuses_explain_known_limits() {
    for (status, label) in [
        ("timeout", "resolution timed out"),
        ("max_iterations", "resolution iteration limit reached"),
    ] {
        let resolutions =
            serde_json::json!([{"path":"app/package.json","status":status,"diagnostics":[]}])
                .to_string();
        let document = serde_json::json!({"bomFormat":"CycloneDX","components":[],"properties":[{"name":"githits:resolutions","value":resolutions}]}).to_string();
        let mut report: serde_json::Value =
            serde_json::from_slice(include_bytes!("../fixtures/licenses/report-v1.json"))
                .expect("report");
        report["inventory"]["properties"][1]["value"] = resolutions.into();
        let repo = repository(&[
            (
                "githits-scan.toml",
                "version=1\n[licenses]\nallow=['MIT']\n",
            ),
            ("bom.json", &document),
            ("report.json", &report.to_string()),
        ]);
        let mut command = githits_scan();
        command
            .args(["license", "check", "--sbom"])
            .arg(repo.path().join("bom.json"))
            .arg(repo.path());
        let output = command.output().expect("human policy");
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(stdout(&output).contains(label), "{}", stdout(&output));
        let output = command.arg("--json").output().expect("JSON policy");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
        assert_eq!(value["unresolved_projects"][0]["status"], status);
        let output = githits_scan()
            .args(["license", "report", "--details", "--from-report"])
            .arg(repo.path().join("report.json"))
            .output()
            .expect("human report");
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert!(
            stdout(&output).contains(&format!("resolution: app/package.json: {label}")),
            "{}",
            stdout(&output)
        );
    }
}
