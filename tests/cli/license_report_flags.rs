//! Source-mode flag conflicts for license report.

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
fn license_report_offline_flags_conflict() {
    let conflict_rows = [
        ("explicit PATH", vec!["."]),
        ("--config", vec!["--config", "missing.toml"]),
        ("--no-check", vec!["--no-check"]),
        ("--lockfiles-only", vec!["--lockfiles-only"]),
        ("--exclude", vec!["--exclude", "**"]),
    ];
    let mut cases_executed = 0;
    for (name, conflict) in &conflict_rows {
        let mut args = vec![
            "license",
            "report",
            "--from-report",
            "/a/nonexistent-licenses.json",
        ];
        args.extend_from_slice(conflict);
        let output = run(&args);
        assert_usage_error(&output, "cannot be used with", name);
        cases_executed += 1;
    }

    let replay_stdin = run(&["license", "report", "--from-report", "-"]);
    assert_usage_error(
        &replay_stdin,
        "report requires a file path; '-' is not supported",
        "--from-report -",
    );
    cases_executed += 1;

    assert_eq!(cases_executed, 6);
    println!("verified 6 license-report source-mode rejection rows");
}
