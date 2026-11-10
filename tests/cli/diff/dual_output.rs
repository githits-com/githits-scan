//! Named diff destinations use one consumed report, including output failures.
use super::{githits_scan, pair, stderr};
use crate::support::{diff as fixture, jobs::ScriptedServer};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

fn command(root: &Path, origin: &str) -> Command {
    let mut command = githits_scan();
    command
        .arg("diff")
        .arg(root)
        .args(["--base", "HEAD~1", "--head", "HEAD"])
        .env("GITHITS_API_TOKEN", "test-token")
        .env("GITHITS_API_URL", origin);
    command
}

fn assert_one_job(server: ScriptedServer) {
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with(b"POST /v1/experimental/dependency-diffs HTTP/1.1"));
    let base = crate::support::jobs::BASE;
    assert!(requests[1].starts_with(format!("GET {base}/events HTTP/1.1").as_bytes()));
    assert!(requests[2].starts_with(format!("GET {base}/result HTTP/1.1").as_bytes()));
}

#[test]
fn diff_named_outputs_write_exact_json_and_escaped_markdown_from_one_job() {
    let repo = pair();
    let outputs = tempfile::tempdir().expect("outputs");
    let json = outputs.path().join("diff.json");
    let markdown = outputs.path().join("diff.md");
    fs::write(&json, "old JSON").expect("old output");
    fs::write(&markdown, "old Markdown").expect("old output");
    let mut value = fixture::report();
    value["additive_field"] = serde_json::json!({"future":true});
    value["changes"][0]["package"]["name"] = "evil|<script> @team".into();
    value["snapshots"]["head"]["coverage"]["resolution"] = serde_json::json!([
        {"path":"package-lock.json","reason":"required_input_not_supplied",
         "required_path":"packages/worker @team/package.json"}
    ]);
    let bytes = format!(
        " \n{}\n ",
        serde_json::to_string_pretty(&value).expect("JSON")
    )
    .into_bytes();
    let server = ScriptedServer::respond_with(fixture::exchanges(&bytes));
    let output = command(repo.path(), &server.origin())
        .arg("--output-json")
        .arg(&json)
        .arg("--output-markdown")
        .arg(&markdown)
        .output()
        .expect("diff");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(fs::read(&json).expect("JSON"), bytes);
    let text = fs::read_to_string(&markdown).expect("Markdown");
    assert!(text.contains("Dependency changes"));
    assert!(text.contains("@&#8203;team"));
    assert!(!text.contains("<script>"));
    assert!(text.contains("release notes"));
    assert!(text.contains(
        "packages/worker @&#8203;team/package&#46;json was not among the files read from that revision"
    ));
    assert!(
        text.contains("Check the file, workspace declarations and &#45;&#45;exclude settings&#46;")
    );
    assert_eq!(stderr(&output).matches("saved ").count(), 2);
    assert_one_job(server);
}

#[test]
fn diff_named_outputs_keep_every_returned_release_note() {
    let repo = pair();
    let outputs = tempfile::tempdir().expect("outputs");
    let json = outputs.path().join("diff.json");
    let markdown = outputs.path().join("diff.md");
    let mut value = fixture::report();
    let log = &mut value["direct_reviews"]["data"][0]["data"]["changelog"];
    log["entries"] = serde_json::json!(
        (0..7)
            .map(|i| serde_json::json!({
                "version":format!("1.2.{i}"), "headline":format!("returned entry {i}"),
                "html_url":format!("https://example.invalid/{i}"), "signals":[]
            }))
            .collect::<Vec<_>>()
    );
    log["coverage"]["returned_entries"] = serde_json::json!(7);
    let bytes = serde_json::to_vec_pretty(&value).expect("JSON");
    let server = ScriptedServer::respond_with(fixture::exchanges(&bytes));
    let output = command(repo.path(), &server.origin())
        .arg("--output-json")
        .arg(&json)
        .arg("--output-markdown")
        .arg(&markdown)
        .output()
        .expect("diff");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(fs::read(&json).expect("JSON"), bytes);
    let text = fs::read_to_string(markdown).expect("Markdown");
    for i in 0..7 {
        assert!(text.contains(&format!("returned entry {i}")));
        assert!(text.contains(&format!("<https://example.invalid/{i}>")));
    }
    assert!(text.contains("Release notes are incomplete"));
    assert_one_job(server);
}

#[test]
fn diff_named_outputs_render_producer_explanations_from_one_job() {
    use serde_json::json;

    let repo = pair();
    let outputs = tempfile::tempdir().expect("outputs");
    let json = outputs.path().join("diff.json");
    let markdown = outputs.path().join("diff.md");
    let mut value = fixture::report();
    value["changes"][0]["directness"]["head"] = "unknown".into();
    value["changes"][0]["after_ids"] = json!(["head:o1"]);
    value["snapshots"]["head"]["occurrences"] = json!([{
        "id":"head:o1",
        "directness":"unknown",
        "directness_proof_ids":["head:proof"]
    }]);
    value["snapshots"]["head"]["reachability"] = json!([{
        "id":"head:proof",
        "reasons":[{
            "code":"unproved_link",
            "message":"The dependency could not be matched @team <script>",
            "source_key":"package-lock.json",
            "manifest_path":"packages/worker @team/package.json",
            "declaration_id":"head:d1",
            "dependency_name":"helper @team"
        }]
    }]);
    value["snapshots"]["head"]["declarations"][0]["declared_name"] = "helper @team".into();
    value["snapshots"]["head"]["declarations"][0]["declaring_manifest"] =
        "packages/worker @team/package.json".into();
    value["direct_reviews"]["status"] = "partial".into();
    value["direct_reviews"]["data"][0]["status"] = "unavailable".into();
    value["direct_reviews"]["data"][0]["reason"] = "review_failed".into();
    value["direct_reviews"]["data"][0]["failure"] = json!({
        "scope":"batch",
        "code":"safe_batch_error",
        "message":"The combined review report could not be prepared @team <script>"
    });
    let bytes = format!(
        " \n{}\n ",
        serde_json::to_string_pretty(&value).expect("JSON")
    )
    .into_bytes();
    let server = ScriptedServer::respond_with(fixture::exchanges(&bytes));
    let output = command(repo.path(), &server.origin())
        .arg("--output-json")
        .arg(&json)
        .arg("--output-markdown")
        .arg(&markdown)
        .output()
        .expect("diff");

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(fs::read(&json).expect("JSON"), bytes);
    let text = fs::read_to_string(&markdown).expect("Markdown");
    assert!(text.contains("The dependency could not be matched @&#8203;team &lt;script&gt;"));
    assert!(text.contains("packages/worker @&#8203;team/package&#46;json"));
    assert!(text.contains(
        "Declared as helper @&#8203;team in packages/worker @&#8203;team/package&#46;json&#46;"
    ));
    assert!(text.contains("preparing the combined report failed"));
    assert!(
        text.contains(
            "The combined review report could not be prepared @&#8203;team &lt;script&gt;"
        )
    );
    for unpublished in [
        "safe_batch_error",
        "safe&#95;batch&#95;error",
        "unproved_link",
        "unproved&#95;link",
        "review_failed",
        "review&#95;failed",
        "unknown",
    ] {
        assert!(!text.contains(unpublished), "{unpublished}");
    }
    assert!(!text.contains("<script>"));
    assert!(!text.contains("@team"));
    assert!(!text.contains("Review detail not interpreted"));
    assert_one_job(server);
}

#[test]
fn diff_named_outputs_support_either_stdout_direction_and_quiet() {
    let repo = pair();
    let outputs = tempfile::tempdir().expect("outputs");
    let file = outputs.path().join("document");
    let bytes = serde_json::to_vec(&fixture::report()).expect("JSON");
    for json_stdout in [false, true] {
        let server = ScriptedServer::respond_with(fixture::exchanges(&bytes));
        let output = command(repo.path(), &server.origin())
            .args(["--quiet", "--output-json"])
            .arg(if json_stdout { Path::new("-") } else { &file })
            .arg("--output-markdown")
            .arg(if json_stdout { &file } else { Path::new("-") })
            .output()
            .expect("diff");
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let saved = fs::read(&file).expect("document");
        let (json, markdown) = if json_stdout {
            (&output.stdout, &saved)
        } else {
            (&saved, &output.stdout)
        };
        assert_eq!(*json, bytes);
        assert!(String::from_utf8_lossy(markdown).contains("Dependency changes"));
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
        assert_one_job(server);
    }
}

#[test]
fn diff_named_single_outputs_emit_only_the_selected_document() {
    let repo = pair();
    let outputs = tempfile::tempdir().expect("outputs");
    let file = outputs.path().join("document");
    let bytes = serde_json::to_vec_pretty(&fixture::report()).expect("JSON");
    for (flag, destination) in [
        ("--output-json", file.as_path()),
        ("--output-json", Path::new("-")),
        ("--output-markdown", file.as_path()),
        ("--output-markdown", Path::new("-")),
    ] {
        let server = ScriptedServer::respond_with(fixture::exchanges(&bytes));
        let output = command(repo.path(), &server.origin())
            .arg(flag)
            .arg(destination)
            .output()
            .expect("diff");
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let document = if destination == Path::new("-") {
            output.stdout.clone()
        } else {
            assert_eq!(output.stdout, [] as [u8; 0]);
            fs::read(&file).expect("document")
        };
        if flag == "--output-json" {
            assert_eq!(document, bytes);
        } else {
            assert!(String::from_utf8_lossy(&document).contains("Dependency changes"));
        }
        assert_one_job(server);
    }
}

#[test]
fn diff_named_outputs_preserve_partial_unknown_and_future_schema_qualifications() {
    let repo = pair();
    let outputs = tempfile::tempdir().expect("outputs");
    let markdown = outputs.path().join("diff.md");
    for future in [false, true] {
        let mut value = fixture::report();
        value["outcome"] = "partial".into();
        value["changes"][0]["directness"]["base"] = "unknown".into();
        value["advisories"] =
            serde_json::json!({"status":"unavailable","reason":"provider_unavailable"});
        if future {
            value = serde_json::json!({"schema_version":99,"kind":"diff","new_shape":true});
        }
        let bytes = serde_json::to_vec_pretty(&value).expect("JSON");
        let server = ScriptedServer::respond_with(fixture::exchanges(&bytes));
        let output = command(repo.path(), &server.origin())
            .args(["--output-json", "-", "--output-markdown"])
            .arg(&markdown)
            .output()
            .expect("diff");
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(output.stdout, bytes);
        let text = fs::read_to_string(&markdown).expect("Markdown");
        let expected: &[&str] = if future {
            &["Scan cannot explain this report", "format is newer"]
        } else {
            &[
                "Some checks could not be completed",
                "The service did not return its explanation",
                "the service's information provider was unavailable",
            ]
        };
        for expected in expected {
            assert!(text.contains(expected), "{expected}: {text}");
        }
        if !future {
            assert!(!text.contains("no supported results"));
            assert!(!text.contains("provider_unavailable"));
            assert!(!text.contains("provider&#95;unavailable"));
            assert!(!text.contains("unknown"));
        }
        assert_one_job(server);
    }
}

#[test]
fn diff_named_output_argument_conflicts_fail_before_credentials_or_analysis() {
    let outputs = tempfile::tempdir().expect("outputs");
    for args in [
        vec!["--output-json", "a", "--format", "human"],
        vec!["--output-markdown", "b", "--format", "json"],
        vec!["--output-json", "a", "-o", "c"],
        vec!["--output-markdown", "b", "--output", "c"],
        vec!["--output-json", "-", "--output-markdown", "-"],
        vec!["--output-json", ""],
        vec!["--output-markdown", ""],
    ] {
        let output = githits_scan()
            .current_dir(outputs.path())
            .args(["diff", "--base", "HEAD"])
            .args(&args)
            .env_remove("GITHITS_API_TOKEN")
            .output()
            .expect("diff");
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert_eq!(output.stdout, [] as [u8; 0]);
        assert!(!stderr(&output).contains("GITHITS_API_TOKEN"));
        assert!(!stderr(&output).contains("Git repository"));
        assert!(!stderr(&output).contains("unexpected argument"));
    }
    assert_eq!(fs::read_dir(outputs.path()).expect("outputs").count(), 0);
}

#[test]
fn diff_named_output_aliases_fail_before_analysis_without_touching_files() {
    let outputs = tempfile::tempdir().expect("outputs");
    fs::create_dir(outputs.path().join("sub")).expect("directory");
    for existing in [false, true] {
        let json = outputs.path().join("diff.json");
        if existing {
            fs::write(&json, "sentinel").expect("existing");
        }
        let output = githits_scan()
            .current_dir(outputs.path())
            .args([
                "diff",
                "--base",
                "HEAD",
                "--output-json",
                "diff.json",
                "--output-markdown",
                "sub/../diff.json",
            ])
            .env_remove("GITHITS_API_TOKEN")
            .output()
            .expect("diff");
        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
        assert!(stderr(&output).contains("distinct"));
        if existing {
            assert_eq!(fs::read(&json).expect("existing"), b"sentinel");
        } else {
            assert!(!json.exists());
        }
    }
}

#[cfg(unix)]
#[test]
fn diff_named_output_symlink_and_hardlink_aliases_fail_before_analysis() {
    use std::os::unix::fs::symlink;
    let outputs = tempfile::tempdir().expect("outputs");
    let json = outputs.path().join("diff.json");
    fs::write(&json, "sentinel").expect("existing");
    let symlink_path = outputs.path().join("symlink");
    symlink(&json, &symlink_path).expect("symlink");
    let hardlink = outputs.path().join("hardlink");
    fs::hard_link(&json, &hardlink).expect("hardlink");
    for alias in [&symlink_path, &hardlink] {
        let output = githits_scan()
            .args(["diff", "--base", "HEAD", "--output-json"])
            .arg(&json)
            .arg("--output-markdown")
            .arg(alias)
            .env_remove("GITHITS_API_TOKEN")
            .output()
            .expect("diff");
        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
        assert!(stderr(&output).contains("distinct"));
        assert_eq!(fs::read(&json).expect("existing"), b"sentinel");
    }
}

#[test]
fn diff_named_output_invalid_paths_fail_before_analysis_without_truncation() {
    let outputs = tempfile::tempdir().expect("outputs");
    let json = outputs.path().join("diff.json");
    fs::write(&json, "sentinel").expect("existing");
    for invalid in [
        outputs.path().to_path_buf(),
        outputs.path().join("missing/file"),
    ] {
        for (json_path, markdown_path) in [(&invalid, &json), (&json, &invalid)] {
            let output = githits_scan()
                .args(["diff", "--base", "HEAD", "--output-json"])
                .arg(json_path)
                .arg("--output-markdown")
                .arg(markdown_path)
                .env_remove("GITHITS_API_TOKEN")
                .output()
                .expect("diff");
            assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
            assert!(stderr(&output).contains("cannot write"));
            assert_eq!(fs::read(&json).expect("existing"), b"sentinel");
        }
    }
}

#[test]
fn diff_named_output_admission_and_invalid_result_errors_leave_both_files_untouched() {
    use crate::support::response;
    let repo = pair();
    let outputs = tempfile::tempdir().expect("outputs");
    let json = outputs.path().join("diff.json");
    let markdown = outputs.path().join("diff.md");
    for invalid_report in [false, true] {
        fs::write(&json, "old JSON").expect("existing");
        fs::write(&markdown, "old Markdown").expect("existing");
        let responses = if invalid_report {
            fixture::exchanges(b"{}")
        } else {
            vec![response(
                "422 Unprocessable Content",
                &[("Content-Type", "application/problem+json")],
                br#"{"status":422,"code":"UNUSABLE_MANIFEST"}"#,
            )]
        };
        let server = ScriptedServer::respond_with(responses);
        let output = command(repo.path(), &server.origin())
            .arg("--output-json")
            .arg(&json)
            .arg("--output-markdown")
            .arg(&markdown)
            .output()
            .expect("diff");
        assert_eq!(
            output.status.code(),
            Some(if invalid_report { 3 } else { 2 }),
            "{}",
            stderr(&output)
        );
        assert_eq!(output.stdout, [] as [u8; 0]);
        assert_eq!(fs::read(&json).expect("existing"), b"old JSON");
        assert_eq!(fs::read(&markdown).expect("existing"), b"old Markdown");
        assert_eq!(server.requests().len(), if invalid_report { 3 } else { 1 });
    }
}

#[test]
fn diff_named_output_broken_stdout_stops_without_resubmitting_or_rolling_back_json() {
    let repo = pair();
    let outputs = tempfile::tempdir().expect("outputs");
    let file = outputs.path().join("document");
    let bytes = br#"{"schema_version":99,"kind":"diff"}"#.to_vec();
    for json_stdout in [false, true] {
        fs::write(&file, "sentinel").expect("existing");
        let (closed, wait_closed) = std::sync::mpsc::channel();
        let mut responses = fixture::exchanges(&bytes);
        let result = responses.pop().expect("result response");
        let mut handlers: Vec<_> = responses
            .into_iter()
            .map(crate::support::jobs::response_handler)
            .collect();
        handlers.push(Box::new(move |stream| {
            wait_closed
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("stdout closed before result");
            crate::support::jobs::response_handler(result)(stream);
        }));
        let server = ScriptedServer::with_handlers(handlers);
        let mut child = command(repo.path(), &server.origin())
            .arg("--output-json")
            .arg(if json_stdout { Path::new("-") } else { &file })
            .arg("--output-markdown")
            .arg(if json_stdout { &file } else { Path::new("-") })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("diff");
        drop(child.stdout.take().expect("stdout pipe"));
        closed.send(()).expect("release result response");
        let output = child.wait_with_output().expect("diff output");
        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        assert!(stderr(&output).contains("cannot write to the output stream"));
        assert_eq!(
            fs::read(&file).expect("file"),
            if json_stdout {
                b"sentinel".as_slice()
            } else {
                bytes.as_slice()
            }
        );
        assert_eq!(stderr(&output).contains("saved "), !json_stdout);
        assert_one_job(server);
    }
}

#[test]
fn diff_legacy_single_format_file_outputs_remain_unchanged() {
    let repo = pair();
    let outputs = tempfile::tempdir().expect("outputs");
    let file = outputs.path().join("document");
    let bytes = serde_json::to_vec_pretty(&fixture::report()).expect("JSON");
    for format in ["json", "human", "markdown"] {
        let server = ScriptedServer::respond_with(fixture::exchanges(&bytes));
        let output = command(repo.path(), &server.origin())
            .args(["--format", format, "-o"])
            .arg(&file)
            .output()
            .expect("diff");
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(output.stdout, [] as [u8; 0]);
        let document = fs::read(&file).expect("document");
        if format == "json" {
            assert_eq!(document, bytes);
        } else {
            assert!(String::from_utf8_lossy(&document).contains("Dependency changes"));
        }
        assert_one_job(server);
    }
}

#[test]
fn diff_named_output_case_aliases_keep_json_when_identity_resolves_after_creation() {
    let repo = pair();
    let outputs = tempfile::tempdir().expect("outputs");
    fs::write(outputs.path().join("probe"), "probe").expect("filesystem case probe");
    let case_insensitive = outputs.path().join("PROBE").exists();
    let json = outputs.path().join("report.json");
    let markdown = outputs.path().join("REPORT.JSON");
    let bytes = serde_json::to_vec_pretty(&fixture::report()).expect("JSON");
    let server = ScriptedServer::respond_with(fixture::exchanges(&bytes));
    let output = command(repo.path(), &server.origin())
        .arg("--output-json")
        .arg(&json)
        .arg("--output-markdown")
        .arg(&markdown)
        .output()
        .expect("diff");
    assert_eq!(
        output.status.code(),
        Some(if case_insensitive { 2 } else { 0 }),
        "{}",
        stderr(&output)
    );
    assert_eq!(fs::read(&json).expect("JSON"), bytes);
    if case_insensitive {
        assert!(stderr(&output).contains("distinct"));
        assert_eq!(fs::read(&markdown).expect("same JSON file"), bytes);
    } else {
        assert!(
            fs::read_to_string(&markdown)
                .expect("Markdown")
                .contains("Dependency changes")
        );
    }
    assert_one_job(server);
}
