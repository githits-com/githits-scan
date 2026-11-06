//! Local configuration decisions remain visible without changing producer evidence.
use super::*;
use serde_json::{Value, json};

const POLICY: &str = "version=1\n[lockfiles]\ninclude=['package-lock.json']\n[[audit.ignore]]\nid='RUSTSEC-2024-0436'\nreason='Reviewed for this deployment'\n";

fn vulnerability_report(v2: bool) -> Value {
    let mut report = if v2 {
        crate::support::audit::v2_clean()
    } else {
        clean()
    };
    let mut finding = if v2 {
        crate::support::audit::v2_findings()
    } else {
        fixture()
    }["findings"]["vulnerabilities"][0]
        .clone();
    finding["advisory_id"] = "RUSTSEC-2024-0436".into();
    finding["aliases"] = json!(["GHSA-example"]);
    report["findings"]["vulnerabilities"] = json!([finding]);
    report["summary"]["vulnerabilities"] = 1.into();
    report
}

fn assert_audit_case(v2: bool, case: &str) {
    let repo = repo();
    fs::write(repo.path().join("githits-scan.toml"), POLICY).expect("policy");
    let mut value = vulnerability_report(v2);
    match case {
        "unmatched" => {
            value["findings"]["vulnerabilities"][0]["advisory_id"] = "OTHER-ID".into();
        }
        "mixed" => {
            let mut other = value["findings"]["vulnerabilities"][0].clone();
            other["advisory_id"] = "OTHER-ID".into();
            value["findings"]["vulnerabilities"]
                .as_array_mut()
                .expect("findings")
                .push(other);
            value["summary"]["vulnerabilities"] = 2.into();
        }
        "alias_only" => {
            value["findings"]["vulnerabilities"][0]["advisory_id"] = "OTHER-ID".into();
            value["findings"]["vulnerabilities"][0]["aliases"] = json!(["RUSTSEC-2024-0436"]);
        }
        "outdated" => {
            let original = if v2 {
                crate::support::audit::v2_findings()
            } else {
                fixture()
            };
            value["findings"]["outdated"] = original["findings"]["outdated"].clone();
            value["summary"]["outdated"] = value["findings"]["outdated"]
                .as_array()
                .expect("outdated")
                .len()
                .into();
        }
        "incomplete" => value["coverage"]["vulnerabilities"]["checked_count"] = 0.into(),
        _ => (),
    }
    let bytes = serde_json::to_vec(&value).expect("report");
    let service = server(&bytes);
    let output = run(repo.path(), Some(&service.origin()), &["--json"]);
    assert_eq!(
        output.status.code(),
        Some(i32::from(case != "ignored")),
        "v2={v2} {case}: {}",
        stderr(&output)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        report["summary"]["vulnerabilities"],
        if case == "mixed" { 2 } else { 1 }
    );
    assert_eq!(
        report["vulnerabilities"]
            .as_array()
            .expect("findings")
            .len(),
        if case == "mixed" { 2 } else { 1 }
    );
    if matches!(case, "unmatched" | "alias_only") {
        assert!(report["vulnerabilities"][0].get("ignored").is_none());
    } else {
        assert_eq!(report["summary"]["ignored_vulnerabilities"], 1);
        assert_eq!(report["vulnerabilities"][0]["ignored"], true);
        assert_eq!(
            report["vulnerabilities"][0]["ignore"]["reason"],
            "Reviewed for this deployment"
        );
    }
    let _ = service.requests();
    if matches!(case, "incomplete" | "outdated") {
        let service = server(&bytes);
        let output = run(repo.path(), Some(&service.origin()), &[]);
        assert_eq!(output.status.code(), Some(1));
        let text = String::from_utf8_lossy(&output.stdout);
        let headline = if case == "incomplete" {
            "Audit results\n"
        } else {
            "Audit findings\n"
        };
        assert!(text.starts_with(headline), "{text}");
        assert!(text.contains("Reviewed for this deployment"), "{text}");
        let _ = service.requests();
    }
}

#[test]
fn config_policy_audit_ignores_preserve_findings_and_other_failure_causes() {
    for v2 in [false, true] {
        for case in [
            "ignored",
            "unmatched",
            "mixed",
            "alias_only",
            "outdated",
            "incomplete",
        ] {
            assert_audit_case(v2, case);
        }
    }
}

#[test]
fn config_policy_audit_ignored_text_and_saved_replay_keep_reason() {
    let repo = repo();
    fs::write(repo.path().join("githits-scan.toml"), POLICY).expect("policy");
    let mut value = vulnerability_report(true);
    value["generated_at"] = "2026-11-06T00:00:00Z".into();
    let service = server(&serde_json::to_vec(&value).expect("report"));
    let archive = repo.path().join("analysis.json");
    let output = run(
        repo.path(),
        Some(&service.origin()),
        &["--save-analysis", archive.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.starts_with("No unignored audit findings in checked dependencies\n"),
        "{text}"
    );
    assert!(
        text.contains("1 ignored vulnerability (included in the total)"),
        "{text}"
    );
    assert!(text.contains("Ignored vulnerabilities"), "{text}");
    assert!(text.contains("Reviewed for this deployment"), "{text}");
    let _ = service.requests();
    fs::remove_file(repo.path().join("githits-scan.toml")).expect("remove config");
    let replay = offline(&archive, &["--json"]);
    assert_eq!(replay.status.code(), Some(0), "{}", stderr(&replay));
    let report: Value = serde_json::from_slice(&replay.stdout).expect("replay");
    assert_eq!(report["vulnerabilities"][0]["ignored"], true);
    assert_eq!(
        report["vulnerabilities"][0]["ignore"]["id"],
        "RUSTSEC-2024-0436"
    );
}

#[test]
fn config_policy_saved_explanation_labels_ignored_advisories() {
    let repo = repo();
    let archive = repo.path().join("analysis.json");
    let mut input: Value =
        serde_json::from_slice(include_bytes!("../fixtures/audit/analysis-v1.json"))
            .expect("archive");
    let id = input["producer_report"]["findings"]["vulnerabilities"][0]["advisory_id"].clone();
    input["producer_report"]["findings"]["vulnerabilities"][0]["aliases"] = json!(["CVE-example"]);
    input["audit_policy"] = json!({"ignore":[{"id":id,"reason":"Reviewed advisory"}]});
    fs::write(&archive, serde_json::to_vec(&input).expect("JSON")).expect("archive");
    for json in [false, true] {
        let flags = if json {
            vec!["--explain", "npm:demo@1.0.0", "--json"]
        } else {
            vec!["--explain", "npm:demo@1.0.0"]
        };
        let output = offline(&archive, &flags);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        if json {
            let report: Value = serde_json::from_slice(&output.stdout).expect("explanation");
            assert_eq!(report["problems"][0]["ignored"], true);
            assert_eq!(
                report["problems"][0]["ignore"]["reason"],
                "Reviewed advisory"
            );
        } else {
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(
                text.contains("GHSA-example / CVE-example IGNORED — Reviewed advisory"),
                "{text}"
            );
        }
    }
}

#[test]
fn config_policy_saved_analysis_rejects_invalid_ignores() {
    let repo = repo();
    let archive = repo.path().join("analysis.json");
    let mut input: Value =
        serde_json::from_slice(include_bytes!("../fixtures/audit/analysis-v1.json"))
            .expect("archive");
    for ignore in [
        json!({"id":"X","reason":" "}),
        json!({"id":"X"}),
        json!({"id":"X","reason":"r","unknown":true}),
    ] {
        input["audit_policy"] = json!({"ignore":[ignore]});
        fs::write(&archive, serde_json::to_vec(&input).expect("JSON")).expect("archive");
        let output = offline(&archive, &["--json"]);
        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
        assert_eq!(output.stdout, [] as [u8; 0]);
    }
}

#[test]
fn config_policy_audit_rejects_invalid_ignores_before_connecting() {
    let repo = repo();
    fs::write(
        repo.path().join("githits-scan.toml"),
        POLICY.replace("Reviewed for this deployment", " "),
    )
    .expect("invalid policy");
    // The child has finished before accept: a queued connection would prove
    // that invalid local policy reached HTTP, without an idle server thread.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
    listener.set_nonblocking(true).expect("nonblocking");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let output = run(repo.path(), Some(&origin), &["--json"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert!(stderr(&output).contains("audit.ignore[0].reason must not be blank"));
    assert_eq!(
        listener
            .accept()
            .expect_err("policy must fail before HTTP")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
}
