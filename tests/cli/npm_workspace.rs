//! Shared upload selection for bounded npm and Bun workspace declarations.
use super::*;
use crate::support::audit::clean;

const ROOT: &str = r#"{"name":"workspace","private":true,"workspaces":["packages/*"]}"#;
const MEMBER: &str = r#"{"name":"member","version":"1.0.0"}"#;
const POLICY: &str = "version=1\n[lockfiles]\ninclude=['package-lock.json']\nmanifests=[]\n[licenses]\nallow=['MIT']\n";
const DOCUMENT: &[u8] = br#"{"bomFormat":"CycloneDX","specVersion":"1.7","properties":[{"name":"githits:completeness","value":"recorded_lockfile_inventory"}],"components":[]}"#;
const LICENSES: &[u8] = include_bytes!("../fixtures/licenses/report-v1.json");

fn workspace() -> tempfile::TempDir {
    repository(&[
        ("package-lock.json", "{}"),
        ("package.json", ROOT),
        (
            "packages/a/package.json",
            r#"{"name":"a","version":"1.0.0"}"#,
        ),
        (
            "packages/b/package.json",
            r#"{"name":"b","version":"1.0.0"}"#,
        ),
        ("packages/a/nested/package.json", MEMBER),
        ("unrelated/package.json", MEMBER),
    ])
}

fn assert_paths(requests: &[Vec<u8>], expected: &[&str]) {
    assert_eq!(requests.len(), 3, "one submission, events and result");
    let body = String::from_utf8_lossy(&requests[0]);
    let actual: Vec<_> = body
        .split("filename=\"")
        .skip(1)
        .map(|part| part.split_once('"').expect("filename terminator").0)
        .collect();
    assert_eq!(
        actual, expected,
        "exact paths, order and single upload: {body}"
    );
}

fn assert_commands(root: &Path, extra: &[&str], expected: &[&str]) {
    let report = serde_json::to_vec(&clean()).expect("report");
    let api = server(&report);
    let output = run(root, Some(&api.origin()), extra);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_paths(&api.requests(), expected);

    let api = ScriptedServer::success("cyclonedx", DOCUMENT);
    let output = generate(root, Some("test-token"), Some(&api.origin()), extra);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_paths(&api.requests(), expected);

    let api = ScriptedServer::success("cyclonedx", DOCUMENT);
    let mut command = githits_scan();
    command
        .args(["license", "check", "--json"])
        .arg(root)
        .args(extra)
        .env("GITHITS_API_TOKEN", "test-token")
        .env("GITHITS_API_URL", api.origin());
    // License checking always needs a policy; keep the other default scans unconfigured.
    let policy = tempfile::tempdir().expect("policy directory");
    if !root.join("githits-scan.toml").exists() {
        let file = policy.path().join("policy.toml");
        fs::write(&file, POLICY).expect("policy");
        command.arg("--config").arg(file);
    }
    let output = command.output().expect("generated license check");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_paths(&api.requests(), expected);

    let api = license_server();
    let output = githits_scan()
        .args(["license", "report", "--json"])
        .arg(root)
        .args(extra)
        .env("GITHITS_API_TOKEN", "test-token")
        .env("GITHITS_API_URL", api.origin())
        .output()
        .expect("license report");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, LICENSES);
    assert_paths(&api.requests(), expected);
}

fn license_server() -> ScriptedServer {
    ScriptedServer::respond_with(vec![
        accept_response(),
        events_response(&[snapshot("succeeded", "succeeded", 1)]),
        response("200 OK", &[("Content-Type", "application/json")], LICENSES),
    ])
}

#[test]
fn automatic_npm_members_are_shared_by_all_commands_and_selection_modes() {
    for (strict, lockfiles_only) in [(false, false), (false, true), (true, false), (true, true)] {
        let root = workspace();
        if strict {
            fs::write(root.path().join("githits-scan.toml"), POLICY).expect("strict config");
        }
        let extra = if lockfiles_only {
            &["--lockfiles-only"][..]
        } else {
            &[]
        };
        assert_commands(
            root.path(),
            extra,
            &[
                "package-lock.json",
                "package.json",
                "packages/a/package.json",
                "packages/b/package.json",
            ],
        );
    }
}

#[test]
fn automatic_npm_exclusions_keep_existing_explicit_manifest_precedence() {
    for (listed, invocation_excluded, include_b) in [
        (false, false, false),
        (true, false, true),
        (true, true, false),
    ] {
        let root = workspace();
        let manifests = if listed {
            "['packages/b/package.json']"
        } else {
            "[]"
        };
        fs::write(root.path().join("githits-scan.toml"), format!(
            "version=1\n[lockfiles]\ninclude=['package-lock.json']\nmanifests={manifests}\nexclude=['packages/b/**']\n[licenses]\nallow=['MIT']\n"
        )).expect("config");
        let extra = if invocation_excluded {
            &["--exclude", "packages/b/**"][..]
        } else {
            &[]
        };
        let mut expected = vec![
            "package-lock.json",
            "package.json",
            "packages/a/package.json",
        ];
        if include_b {
            expected.push("packages/b/package.json");
        }
        let api = server(&serde_json::to_vec(&clean()).expect("report"));
        let output = run(root.path(), Some(&api.origin()), extra);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_paths(&api.requests(), &expected);
    }
}

#[test]
fn automatic_npm_coexisting_locks_use_owner_directory_and_deduplicate() {
    let root = workspace();
    fs::write(root.path().join("npm-shrinkwrap.json"), [0xff]).expect("excluded non-UTF8 lock");
    fs::write(root.path().join("yarn.lock"), [0xff]).expect("excluded other lock");
    let api = server(&serde_json::to_vec(&clean()).expect("report"));
    let output = run(
        root.path(),
        Some(&api.origin()),
        &["--exclude", "npm-shrinkwrap.json", "--exclude", "yarn.lock"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_paths(
        &api.requests(),
        &[
            "package-lock.json",
            "package.json",
            "packages/a/package.json",
            "packages/b/package.json",
        ],
    );
    fs::write(root.path().join("npm-shrinkwrap.json"), "{}").expect("selected shrinkwrap");
    let api = server(&serde_json::to_vec(&clean()).expect("report"));
    let output = run(
        root.path(),
        Some(&api.origin()),
        &["--exclude", "yarn.lock"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_paths(
        &api.requests(),
        &[
            "npm-shrinkwrap.json",
            "package-lock.json",
            "package.json",
            "packages/a/package.json",
            "packages/b/package.json",
        ],
    );
}

#[test]
fn automatic_npm_never_crosses_child_lock_or_discovery_boundaries() {
    let root = repository(&[
        ("package-lock.json", "{}"),
        ("package.json", r#"{"workspaces":["packages/**"]}"#),
        ("packages/a/package.json", MEMBER),
        ("packages/child/package-lock.json", "{}"),
        (
            "packages/child/package.json",
            r#"{"workspaces":["members/*"]}"#,
        ),
        ("packages/child/members/y/package.json", MEMBER),
        ("packages/ignored/package.json", MEMBER),
        ("packages/.hidden/package.json", MEMBER),
        (".gitignore", "packages/ignored/\n"),
    ]);
    #[cfg(unix)]
    let outside = repository(&[("package.json", MEMBER)]);
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), root.path().join("packages/linked"))
        .expect("symlink");
    for (exclude_child, expected) in [
        (
            false,
            vec![
                "package-lock.json",
                "package.json",
                "packages/a/package.json",
                "packages/child/members/y/package.json",
                "packages/child/package-lock.json",
                "packages/child/package.json",
            ],
        ),
        (
            true,
            vec![
                "package-lock.json",
                "package.json",
                "packages/a/package.json",
            ],
        ),
    ] {
        let api = server(&serde_json::to_vec(&clean()).expect("report"));
        let extra = if exclude_child {
            &["--exclude", "packages/child/package-lock.json"][..]
        } else {
            &[]
        };
        let output = run(root.path(), Some(&api.origin()), extra);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_paths(&api.requests(), &expected);
    }
}

#[test]
fn automatic_npm_unsupported_declarations_keep_explicit_selection_available() {
    let root = workspace();
    fs::write(
        root.path().join("package.json"),
        r#"{"workspaces":["packages/*","!packages/b"]}"#,
    )
    .expect("unsupported declaration");
    fs::write(root.path().join("githits-scan.toml"), "version=1\n[lockfiles]\ninclude=['package-lock.json']\nmanifests=['packages/a/package.json']\n").expect("explicit config");
    let api = server(&serde_json::to_vec(&clean()).expect("report"));
    let output = run(root.path(), Some(&api.origin()), &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_paths(
        &api.requests(),
        &[
            "package-lock.json",
            "package.json",
            "packages/a/package.json",
        ],
    );
}

#[test]
fn javascript_workspace_members_follow_supported_lock_families() {
    for (lock, expected) in [
        ("pnpm-lock.yaml", &["package.json", "pnpm-lock.yaml"][..]),
        ("yarn.lock", &["package.json", "yarn.lock"][..]),
        (
            "bun.lock",
            &["bun.lock", "package.json", "packages/a/package.json"][..],
        ),
    ] {
        let root = repository(&[
            (lock, "{}"),
            ("package.json", ROOT),
            ("packages/a/package.json", MEMBER),
        ]);
        let api = server(&serde_json::to_vec(&clean()).expect("report"));
        let output = run(root.path(), Some(&api.origin()), &[]);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_paths(&api.requests(), expected);
    }
}

fn large_workspace(count: usize, cargo: bool) -> tempfile::TempDir {
    let root = repository(&[("package-lock.json", "{}"), ("package.json", ROOT)]);
    for index in 0..count {
        let dir = root.path().join(format!("packages/member{index}"));
        fs::create_dir_all(&dir).expect("member directory");
        fs::write(
            dir.join("package.json"),
            format!(r#"{{"name":"m{index}"}}"#),
        )
        .expect("member");
    }
    if cargo {
        fs::write(root.path().join("Cargo.lock"), "").expect("Cargo lock");
        fs::write(
            root.path().join("Cargo.toml"),
            "[workspace]\nmembers=['crates/*']\n",
        )
        .expect("Cargo root");
        fs::create_dir_all(root.path().join("crates/a")).expect("Cargo member directory");
        fs::write(
            root.path().join("crates/a/Cargo.toml"),
            "[package]\nname='a'\n",
        )
        .expect("Cargo member");
    }
    root
}

#[test]
fn automatic_npm_file_count_boundary_and_mixed_family_hints() {
    let root = large_workspace(254, false);
    let api = server(&serde_json::to_vec(&clean()).expect("report"));
    let output = run(root.path(), Some(&api.origin()), &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        String::from_utf8_lossy(&api.requests()[0])
            .matches("filename=")
            .count(),
        256
    );
    for (count, cargo, total, automatic) in [(255, false, 257, 255), (252, true, 257, 253)] {
        let root = large_workspace(count, cargo);
        let output = run(root.path(), Some("http://127.0.0.1:9"), &["--json"]);
        let diagnostic = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{diagnostic}");
        assert!(output.stdout.is_empty(), "{}", stdout(&output));
        assert!(
            diagnostic.contains(&format!("{total} files exceed the 256-file upload limit")),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains(&format!(
                "automatic workspace member manifests: {automatic}"
            )),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains("--exclude 'packages/member0/package.json'"),
            "{diagnostic}"
        );
        assert_eq!(
            diagnostic.contains("--exclude 'crates/a/Cargo.toml'"),
            cargo,
            "{diagnostic}"
        );
    }
}

#[test]
fn automatic_npm_saved_analysis_keeps_selected_members_and_replay_facts() {
    let root = workspace();
    let path = root.path().join("analysis.json");
    let archive: serde_json::Value =
        serde_json::from_slice(include_bytes!("../fixtures/audit/analysis.json"))
            .expect("archive fixture");
    let api = server(&serde_json::to_vec(&archive["producer_report"]).expect("report"));
    let output = run(
        root.path(),
        Some(&api.origin()),
        &[
            "--save-analysis",
            path.to_str().expect("path"),
            "--json",
            "--quiet",
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let live: serde_json::Value = serde_json::from_slice(&output.stdout).expect("live JSON");
    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("archive")).expect("stored JSON");
    assert_eq!(
        stored["selected_manifests"],
        serde_json::json!([
            "package.json",
            "packages/a/package.json",
            "packages/b/package.json"
        ])
    );
    fs::write(root.path().join("githits-scan.toml"), "invalid [").expect("poison config");
    let output = offline(&path, &["--json"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let mut replay: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("replay JSON");
    replay.as_object_mut().expect("view").remove("analysis");
    assert_eq!(replay, live);
    assert_paths(
        &api.requests(),
        &[
            "package-lock.json",
            "package.json",
            "packages/a/package.json",
            "packages/b/package.json",
        ],
    );
}

#[test]
fn automatic_npm_help_names_member_exclusions() {
    for command in [
        vec!["detect"],
        vec!["audit"],
        vec!["sbom", "generate"],
        vec!["license", "check"],
        vec!["license", "report"],
    ] {
        let output = githits_scan()
            .args(&command)
            .arg("--help")
            .output()
            .expect("help");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{command:?}: {}",
            stderr(&output)
        );
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
        let text = stdout(&output)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            text.contains("including owning and workspace manifests"),
            "{command:?}: {text}"
        );
    }
}

#[test]
fn automatic_npm_limit_remedy_keeps_explicit_partial_scope() {
    let root = large_workspace(255, false);
    let mut partial = clean();
    partial["unknowns"]["sources"] = serde_json::json!([
        {"path":"package-lock.json","reasons":["required_input_not_supplied"]}
    ]);
    partial["unknowns"]["resolution"] = serde_json::json!([
        {"path":"package-lock.json","name":null,"reason":"required_input_not_supplied",
         "required_path":"packages/member0/package.json"}
    ]);
    partial["summary"]["incomplete_sources"] = 1.into();
    let api = server(&serde_json::to_vec(&partial).expect("partial report"));
    let output = run(
        root.path(),
        Some(&api.origin()),
        &["--json", "--exclude", "**/package.json"],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(report["incomplete"], true);
    let issue = report["issues"]
        .as_array()
        .expect("issues")
        .iter()
        .find(|issue| issue["check"] == "dependency information")
        .expect("source gap");
    assert_eq!(issue["status"], "incomplete");
    assert_eq!(
        issue["required_files"],
        serde_json::json!(["packages/member0/package.json"])
    );
    assert_paths(&api.requests(), &["package-lock.json"]);
}

#[test]
fn automatic_npm_detect_keeps_ecosystem_specific_selection_guidance() {
    let root = repository(&[
        ("package-lock.json", "{}"),
        ("package.json", ROOT),
        ("packages/a/package.json", MEMBER),
        ("poetry.lock", ""),
        ("pyproject.toml", ""),
        ("python/member/pyproject.toml", ""),
    ]);
    let output = detect(root.path(), &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report = stdout(&output);
    assert!(
        report.contains("Workspace manifests included automatically"),
        "{report}"
    );
    let python = report
        .lines()
        .find(|line| line.starts_with("Python manifests below"))
        .expect("Python section");
    assert!(
        python.contains("not uploaded; list explicitly in configuration"),
        "{report}"
    );
    assert!(!python.contains("upload automatically"), "{report}");
}

#[test]
fn automatic_npm_honors_default_fixture_exclusions_and_explicit_override() {
    let root = repository(&[
        ("package-lock.json", "{}"),
        ("package.json", r#"{"workspaces":["packages/**"]}"#),
        ("packages/app/package.json", MEMBER),
        ("packages/fixtures/member/package.json", MEMBER),
    ]);
    fs::write(
        root.path().join("packages/fixtures/member/package.json"),
        [0xff],
    )
    .expect("excluded unreadable fixture");
    let api = server(&serde_json::to_vec(&clean()).expect("report"));
    let output = run(root.path(), Some(&api.origin()), &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_paths(
        &api.requests(),
        &[
            "package-lock.json",
            "package.json",
            "packages/app/package.json",
        ],
    );

    fs::write(
        root.path().join("packages/fixtures/member/package.json"),
        MEMBER,
    )
    .expect("explicit fixture");
    fs::write(root.path().join("githits-scan.toml"), "version=1\n[lockfiles]\ninclude=['package-lock.json']\nmanifests=['packages/fixtures/member/package.json']\n").expect("explicit configuration");
    let api = server(&serde_json::to_vec(&clean()).expect("report"));
    let output = run(root.path(), Some(&api.origin()), &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_paths(
        &api.requests(),
        &[
            "package-lock.json",
            "package.json",
            "packages/app/package.json",
            "packages/fixtures/member/package.json",
        ],
    );
}
