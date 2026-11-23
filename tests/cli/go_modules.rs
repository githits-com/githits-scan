//! Go evidence selection and multipart shaping through the real binary.

use super::*;

const MODULE: &str = "module example.com/project\n\ngo 1.23.0\n";
const TOOLS: &str = "module example.com/project/tools\n\ngo 1.23.0\n";
const SUM: &str = "example.com/dep v1.2.3 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
const WORK: &str = "go 1.23.0\n\nuse (\n\t.\n\t./tools\n)\n";
const NESTED_WORK: &str = "go 1.23.0\nuse .\n";
const MAIN: &str = "/* Copyright example */\npackage main\n\nfunc main() {}\n";
const MAIN_HINT: &str = r#"{"main_package":true}"#;

fn upload_paths(output: &Output) -> serde_json::Value {
    serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("detect JSON")["upload_paths"]
        .clone()
}

#[test]
fn go_modules_detect_and_send_the_same_paths_and_original_bytes() {
    let repo = repository(&[
        ("go.mod", MODULE),
        ("go.sum", SUM),
        ("go.work", WORK),
        ("go.work.sum", SUM),
        ("cmd/product/start.go", MAIN),
        ("tools/go.mod", TOOLS),
        ("tools/go.sum", SUM),
        ("tools/library.go", "package tools\n"),
        ("tools/go.work", NESTED_WORK),
        ("tools/go.work.sum", SUM),
        ("orphan/go.sum", SUM),
        ("vendor/dep/go.mod", MODULE),
        ("vendor/dep/go.sum", SUM),
        ("vendor/dep/main.go", MAIN),
        (".githits-go.json", r#"{"main_package":false}"#),
        ("tools/.githits-go.json", MAIN_HINT),
    ]);

    let selected = [
        (".githits-go.json", MAIN_HINT),
        ("go.mod", MODULE),
        ("go.sum", SUM),
        ("go.work", WORK),
        ("go.work.sum", SUM),
        ("tools/go.mod", TOOLS),
        ("tools/go.sum", SUM),
        ("tools/go.work", NESTED_WORK),
        ("tools/go.work.sum", SUM),
    ];
    let detected = detect(repo.path(), &["--json"]);
    assert_eq!(detected.status.code(), Some(0), "{}", stderr(&detected));
    assert_eq!(
        upload_paths(&detected),
        serde_json::json!(selected.map(|(path, _)| path))
    );
    let human = stdout(&detect(repo.path(), &[]));
    assert!(
        human.contains("Go evidence included in the upload"),
        "{human}"
    );
    assert!(
        human.contains(".githits-go.json (generated from a Go package main declaration)"),
        "{human}"
    );
    assert!(human.contains("tools/go.sum"), "{human}");
    assert!(human.contains("go.work.sum"), "{human}");
    assert!(!human.contains("orphan/go.sum"), "{human}");

    let server = ScriptedServer::success("cyclonedx", b"{}");
    let output = generate(repo.path(), Some("test-token"), Some(&server.origin()), &[]);
    let requests = server.requests();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stderr(&output).lines().any(|line| line.trim()
            == "uploaded 0 lockfiles and 2 manifests (go.mod, tools/go.mod), plus 7 Go evidence files"),
        "{}",
        stderr(&output)
    );
    let request = String::from_utf8_lossy(&requests[0]);
    assert_eq!(request.matches("filename=").count(), selected.len());
    for (path, contents) in selected {
        assert!(
            request.contains(&format!(
                "name=\"files[]\"; filename=\"{path}\"\r\nContent-Type: application/octet-stream\r\n\r\n{contents}\r\n"
            )),
            "multipart part for {path}"
        );
    }
}

#[test]
fn go_modules_keep_existing_skip_and_exclusion_policy() {
    let repo = repository(&[
        ("go.mod", MODULE),
        ("go.sum", SUM),
        ("go.work", WORK),
        ("go.work.sum", SUM),
        ("tools/go.mod", TOOLS),
        ("tools/go.sum", SUM),
        ("tools/main.go", MAIN),
        ("ignored/go.mod", MODULE),
        ("ignored/main.go", MAIN),
        (".gitignore", "ignored/go.mod\n"),
    ]);
    let skipped = detect(repo.path(), &["--json", "--lockfiles-only"]);
    assert_eq!(skipped.status.code(), Some(1));
    assert_eq!(upload_paths(&skipped), serde_json::json!([]));

    let excluded = detect(
        repo.path(),
        &[
            "--json",
            "--exclude",
            "tools/go.mod",
            "--exclude",
            "go.work",
        ],
    );
    assert_eq!(excluded.status.code(), Some(0), "{}", stderr(&excluded));
    assert_eq!(
        upload_paths(&excluded),
        serde_json::json!(["go.mod", "go.sum"])
    );

    fs::write(
        repo.path().join("githits-scan.toml"),
        "version = 1\n[lockfiles]\nmanifests = ['tools/go.mod']\nexclude = ['tools/main.go', 'go.work.sum']\n",
    )
    .expect("write config");
    let configured = detect(repo.path(), &["--json", "--lockfiles-only"]);
    assert_eq!(configured.status.code(), Some(0), "{}", stderr(&configured));
    assert_eq!(
        upload_paths(&configured),
        serde_json::json!(["go.work", "tools/go.mod", "tools/go.sum"])
    );
}

#[test]
fn go_modules_do_not_create_inventory_from_sums_or_workspaces() {
    let repo = repository(&[
        ("go.sum", SUM),
        ("go.work", WORK),
        ("go.work.sum", SUM),
        ("tools/go.sum", SUM),
        ("main.go", MAIN),
    ]);
    let output = detect(repo.path(), &["--json"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(upload_paths(&output), serde_json::json!([]));
}

#[test]
fn go_modules_require_a_positive_production_package_in_each_module() {
    let truncated_header = format!("/*{}*/\n{MAIN}", " ".repeat(8_192));
    let repo = repository(&[
        ("go.mod", MODULE),
        ("tools/go.mod", TOOLS),
        (
            "tools/cmd/tool/entry.misc_linux.go",
            "\u{feff}/* header */\npackage /* name */ main // command\nfunc main() {}\n",
        ),
        ("mixed/entry.go", MAIN),
        ("mixed/helper.go", "package lib\n"),
        ("unclear/entry.go", MAIN),
        ("unclear/helper.go", &truncated_header),
        ("comment/entry.go", "/* package main */\npackage lib\n"),
        ("name/entry.go", "package mainly\n"),
        ("invalid/entry.go", "package main +\n"),
        ("fixtures/entry.go", MAIN),
        ("testdata/entry.go", MAIN),
        ("examples/demo/entry.go", MAIN),
        ("testonly/entry_test.go", MAIN),
        ("hidden/_entry.go", MAIN),
        ("hidden/_scratch/entry.go", MAIN),
        ("conditional/tag.go", "//go:build ignore\n\npackage main\n"),
        (
            "conditional/legacy.go",
            "// +build ignore\n\npackage main\n",
        ),
        ("conditional/entry_linux_arm64.go", MAIN),
        ("conditional/cmd_linux.gen.go", MAIN),
        ("conditional/cmd_linux_test.gen.go", MAIN),
    ]);
    let output = detect(repo.path(), &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        upload_paths(&output),
        serde_json::json!(["go.mod", "tools/.githits-go.json", "tools/go.mod"])
    );
}

#[test]
fn go_modules_save_only_manifests_and_allow_excluding_each_evidence_part() {
    let repo = repository(&[
        ("go.mod", MODULE),
        ("go.sum", SUM),
        ("go.work", WORK),
        ("go.work.sum", SUM),
        ("cmd/project/main.go", MAIN),
    ]);
    let saved = detect(repo.path(), &["--json", "--save"]);
    assert_eq!(saved.status.code(), Some(0), "{}", stderr(&saved));
    let config = fs::read_to_string(repo.path().join("githits-scan.toml")).expect("saved config");
    assert!(config.contains("go.mod"));
    assert!(!config.contains("go.sum"));
    assert!(!config.contains("go.work"));
    assert!(!config.contains(".githits-go.json"));

    let excluded = detect(
        repo.path(),
        &[
            "--json",
            "--exclude",
            "go.sum",
            "--exclude",
            ".githits-go.json",
        ],
    );
    assert_eq!(excluded.status.code(), Some(0), "{}", stderr(&excluded));
    assert_eq!(
        upload_paths(&excluded),
        serde_json::json!(["go.mod", "go.work", "go.work.sum"])
    );
}

#[test]
fn go_modules_count_generated_evidence_against_the_upload_limit() {
    let repo = repository(&[("go.mod", MODULE), ("main.go", MAIN)]);
    for index in 0..255 {
        let dir = repo.path().join(format!("lock{index}"));
        fs::create_dir(&dir).expect("lock directory");
        fs::write(dir.join("Cargo.lock"), "").expect("lock");
    }

    let output = detect(repo.path(), &["--json"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stdout(&output).contains("257 files exceed the limit of 256 files"));
    assert_eq!(upload_paths(&output), serde_json::Value::Null);

    let excluded = detect(repo.path(), &["--json", "--exclude", ".githits-go.json"]);
    assert_eq!(excluded.status.code(), Some(0), "{}", stderr(&excluded));
    assert_eq!(
        upload_paths(&excluded).as_array().expect("paths").len(),
        256
    );
}

#[test]
fn go_modules_accept_a_complete_package_clause_before_a_split_code_point() {
    let source = format!("{MAIN}//{}é\n", " ".repeat(8_191 - MAIN.len() - 2));
    let repo = repository(&[("go.mod", MODULE), ("main.go", &source)]);
    let output = detect(repo.path(), &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        upload_paths(&output),
        serde_json::json!([".githits-go.json", "go.mod"])
    );
}

#[test]
fn go_modules_probe_explicit_fixture_modules_within_their_own_boundary() {
    let repo = repository(&[
        ("testdata/app/go.mod", MODULE),
        ("testdata/app/go.sum", SUM),
        ("testdata/app/main.go", MAIN),
        ("testdata/app/fixtures/helper/main.go", MAIN),
        (
            "githits-scan.toml",
            "version = 1\n[lockfiles]\nmanifests = ['testdata/app/go.mod']\n",
        ),
    ]);
    let output = detect(repo.path(), &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        upload_paths(&output),
        serde_json::json!([
            "testdata/app/.githits-go.json",
            "testdata/app/go.mod",
            "testdata/app/go.sum"
        ])
    );
    let excluded = detect(
        repo.path(),
        &["--json", "--exclude", "testdata/app/main.go"],
    );
    assert_eq!(excluded.status.code(), Some(0), "{}", stderr(&excluded));
    assert_eq!(
        upload_paths(&excluded),
        serde_json::json!(["testdata/app/go.mod", "testdata/app/go.sum"])
    );
}

#[test]
fn go_modules_workspaces_follow_explicit_members_in_the_selected_scope() {
    let repo = repository(&[
        ("go.mod", MODULE),
        ("tools/go.mod", TOOLS),
        ("dir with spaces/go.mod", "module example.com/spaces\n"),
        ("go.work", "go 1.23.0\nuse ./tools\n"),
        ("go.work.sum", SUM),
        (
            "work/go.work",
            r#"go 1.23.0
// (
replace (
    example.com/pkg => ../unselected
)
use( // members
    "../dir\x20with spaces" // quoted directory
    ../tools/../tools
) // done
"#,
        ),
        ("work/go.work.sum", SUM),
        ("other/go.work", "use ../../outside\n"),
        ("other/go.work.sum", SUM),
        ("testdata/fixture/go.work", "use ../..\n"),
        ("testdata/fixture/go.work.sum", SUM),
    ]);
    let root_only = detect(
        repo.path(),
        &[
            "--json",
            "--exclude",
            "tools/**",
            "--exclude",
            "dir with spaces/**",
        ],
    );
    assert_eq!(root_only.status.code(), Some(0), "{}", stderr(&root_only));
    assert_eq!(upload_paths(&root_only), serde_json::json!(["go.mod"]));

    let nested = detect(
        repo.path(),
        &[
            "--json",
            "--exclude",
            "tools/**",
            "--exclude",
            "work/go.work.sum",
        ],
    );
    assert_eq!(nested.status.code(), Some(0), "{}", stderr(&nested));
    assert_eq!(
        upload_paths(&nested),
        serde_json::json!(["dir with spaces/go.mod", "go.mod", "work/go.work"])
    );
    let no_nested_workspace = detect(repo.path(), &["--json", "--exclude", "work/go.work"]);
    assert_eq!(
        no_nested_workspace.status.code(),
        Some(0),
        "{}",
        stderr(&no_nested_workspace)
    );
    assert_eq!(
        upload_paths(&no_nested_workspace),
        serde_json::json!([
            "dir with spaces/go.mod",
            "go.mod",
            "go.work",
            "go.work.sum",
            "tools/go.mod"
        ])
    );

    let selected = detect(repo.path(), &["--json"]);
    assert_eq!(selected.status.code(), Some(0), "{}", stderr(&selected));
    assert_eq!(
        upload_paths(&selected),
        serde_json::json!([
            "dir with spaces/go.mod",
            "go.mod",
            "go.work",
            "go.work.sum",
            "tools/go.mod",
            "work/go.work",
            "work/go.work.sum"
        ])
    );
}
