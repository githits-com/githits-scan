use super::*;

fn run(args: &[&str]) -> std::process::Output {
    githits_scan()
        .args(args)
        .env_remove("GITHITS_API_TOKEN")
        .env("GITHITS_API_URL", "not a valid origin")
        .output()
        .expect("githits-scan binary")
}

fn assert_usage_error(output: &std::process::Output, diagnostic: &str, context: &str) {
    let message = stderr(output);
    assert_eq!(output.status.code(), Some(2), "{context}: {message}");
    assert!(output.stdout.is_empty(), "{context}: {}", stdout(output));
    assert!(message.contains(diagnostic), "{context}: {message}");
}

#[test]
fn audit_saved_flags_reject_conflicts_before_execution() {
    let conflict_rows = [
        ("explicit PATH", vec!["."]),
        ("--config", vec!["--config", "config.toml"]),
        ("--exclude", vec!["--exclude", "**"]),
        ("--lockfiles-only", vec!["--lockfiles-only"]),
        ("--no-check", vec!["--no-check"]),
        (
            "--save-analysis",
            vec!["--save-analysis", "other-analysis.json"],
        ),
    ];
    assert_eq!(conflict_rows.len(), 6);
    let mut cases_executed = 0;
    for (name, conflict) in &conflict_rows {
        let mut args = vec!["audit", "--from-analysis", "/a/nonexistent-analysis.json"];
        args.extend_from_slice(conflict);
        let output = run(&args);
        assert_usage_error(&output, "cannot be used with", name);
        cases_executed += 1;
    }

    let explain_without_file = run(&["audit", "--explain", "npm:demo@1.0.0"]);
    assert_usage_error(
        &explain_without_file,
        "required arguments",
        "--explain without --from-analysis",
    );
    cases_executed += 1;

    let save_stdin = run(&["audit", "--save-analysis", "-"]);
    assert_usage_error(
        &save_stdin,
        "analysis requires a file path",
        "--save-analysis -",
    );
    cases_executed += 1;

    let replay_stdin = run(&["audit", "--from-analysis", "-"]);
    assert_usage_error(
        &replay_stdin,
        "analysis requires a file path",
        "--from-analysis -",
    );
    cases_executed += 1;

    assert_eq!(cases_executed, 6 + 1 + 2);
}
