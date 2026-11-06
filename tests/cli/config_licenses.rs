//! Git exceptions suppress policy violations without manufacturing license evidence.
use super::*;
use serde_json::{Value, json};

#[test]
fn config_policy_git_exception_is_reported_as_excepted_in_json_and_text() {
    let repo = repository(&[(
        "githits-scan.toml",
        "version=1\n[licenses]\n[[licenses.exceptions]]\nname='grammar'\ngit='https://example.invalid/grammar'\nrev='0123456789abcdef'\nreason='Selected source reviewed'\n",
    )]);
    let file = repo.path().join("bom.json");
    let value = json!({"bomFormat":"CycloneDX","components":[{
        "type":"library","bom-ref":"fork","name":"grammar","version":"1.0.0",
        "properties":[
            {"name":"githits:source_kind","value":"LOCKED_PACKAGE_SOURCE_KIND_GIT"},
            {"name":"githits:source_locations","value":r#"[{"kind":"vcs_repository","owner":{"type":"source"},"url":"https://example.invalid/grammar"}]"#},
            {"name":"githits:source_revision","value":"0123456789abcdef"}]}]});
    let bytes = serde_json::to_vec(&value).expect("document");
    fs::write(&file, &bytes).expect("write SBOM");
    let policy_path = repo.path().join("githits-scan.toml");
    let policy_text = fs::read_to_string(&policy_path).expect("policy");
    fs::write(&policy_path, "version=1\n[licenses]\n").expect("policy without exception");
    for json in [false, true] {
        let mut cmd = githits_scan();
        cmd.args(["license", "check"])
            .arg(repo.path())
            .arg("--sbom")
            .arg(&file);
        cmd.arg(if json { "--json" } else { "--details" });
        let output = cmd.output().expect("source diagnostic");
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("https://example.invalid/grammar"), "{text}");
        assert!(text.contains("0123456789abcdef"), "{text}");
        if json {
            let report: Value = serde_json::from_slice(&output.stdout).expect("JSON");
            assert_eq!(
                report["violations"][0]["source"]["git"],
                "https://example.invalid/grammar"
            );
        }
    }
    fs::write(&policy_path, policy_text).expect("restore exception");
    for json in [false, true] {
        let mut cmd = githits_scan();
        cmd.args(["license", "check"])
            .arg(repo.path())
            .arg("--sbom")
            .arg(&file)
            .env_remove("GITHITS_API_TOKEN");
        if json {
            cmd.arg("--json");
        }
        let output = cmd.output().expect("check");
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        if json {
            let report: Value = serde_json::from_slice(&output.stdout).expect("JSON");
            assert_eq!(report["violations"], json!([]));
            let applied = &report["exceptions_applied"][0];
            assert_eq!(applied["git"], "https://example.invalid/grammar");
            assert_eq!(applied["rev"], "0123456789abcdef");
            assert_eq!(applied["reason"], "Selected source reviewed");
            assert!(applied.get("purl").is_none());
        } else {
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(text.contains("Exceptions applied:"), "{text}");
            assert!(text.contains("Selected source reviewed"), "{text}");
        }
    }
    assert_eq!(fs::read(file).expect("unchanged SBOM"), bytes);
}

#[test]
fn config_policy_invalid_exceptions_and_ignores_are_usage_errors() {
    for policy in [
        "[licenses]\n[[licenses.exceptions]]\nname='x'\ngit='https://example.invalid/repo'\n",
        "[licenses]\n[[licenses.exceptions]]\nname='x'\ngit='https://example.invalid/repo'\npurl='pkg:cargo/x'\nreason='r'\n",
        "[licenses]\n[[licenses.exceptions]]\nname='x'\ngit='https://example.invalid/repo'\nreason=' '\n",
        "[licenses]\n[[licenses.exceptions]]\npurl='pkg:cargo/x'\nreason=' '\n",
        "[licenses]\n[[licenses.exceptions]]\nname=' '\ngit='https://example.invalid/repo'\nreason='r'\n",
        "[licenses]\n[[licenses.exceptions]]\nname='x'\ngit='https://example.invalid/repo'\nrev=' '\nreason='r'\n",
        "[[audit.ignore]]\nid='RUSTSEC-2024-0436'\n",
        "[[audit.ignore]]\nid=' '\nreason='r'\n",
        "[[audit.ignore]]\nid='X'\nreason=' '\n",
        "[[audit.ignore]]\nid='X'\nreason='r'\nexpiry='2027-01-01'\n",
        "[[audit.ignore]]\nid='X'\nreason='r'\n[[audit.ignore]]\nid='X'\nreason='s'\n",
    ] {
        let prefix = if policy.starts_with("[licenses]") {
            ""
        } else {
            "[licenses]\n"
        };
        let repo = repository(&[
            ("githits-scan.toml", &format!("version=1\n{prefix}{policy}")),
            ("bom.json", r#"{"bomFormat":"CycloneDX","components":[]}"#),
        ]);
        let output = githits_scan()
            .args(["license", "check"])
            .arg(repo.path())
            .arg("--sbom")
            .arg(repo.path().join("bom.json"))
            .output()
            .expect("check");
        assert_eq!(
            output.status.code(),
            Some(2),
            "{policy}: {}",
            stderr(&output)
        );
        assert_eq!(output.stdout, [] as [u8; 0]);
    }
}

#[test]
fn config_policy_detect_save_preserves_exceptions_and_ignores() {
    let policy = "# policy decisions\n[licenses]\nallow=['MIT']\n[[licenses.exceptions]]\nname='grammar'\ngit='https://example.invalid/grammar'\nreason='Reviewed source' # keep reason\n[[audit.ignore]]\nid='RUSTSEC-2024-0436'\nreason='Reviewed advisory'\n";
    let repo = repository(&[
        ("Cargo.lock", ""),
        (
            "githits-scan.toml",
            &format!("version=1\n[lockfiles]\ninclude=[]\n{policy}"),
        ),
    ]);
    let output = githits_scan()
        .arg("detect")
        .arg(repo.path())
        .arg("--save")
        .output()
        .expect("save");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let saved = fs::read_to_string(repo.path().join("githits-scan.toml")).expect("saved config");
    assert!(saved.ends_with(policy), "{saved}");
}
