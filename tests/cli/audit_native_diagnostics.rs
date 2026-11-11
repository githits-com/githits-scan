//! Exact native input facts survive normal output and saved replay.
use super::*;
use crate::support::audit::clean;
use serde_json::{Value, json};

fn mismatch(reason: &str) -> Value {
    json!({"path":"package-lock.json","declaration_path":"package.json","name":"demo",
        "requested_requirement":"^2","requirement_status":"recorded","locked_versions":["1.5.0"],
        "recorded_requirements":["^1"],"declared_scope":"production","recorded_scopes":["development"],"reason":reason})
}

#[test]
fn native_diagnostics_mismatch_only_is_attention_with_precise_reason_and_optional_count() {
    for (reason, detail) in [
        (
            "locked_version_does_not_satisfy_request",
            "locked version does not satisfy the declaration",
        ),
        ("recorded_requirement_differs", "lock records ^1"),
        (
            "recorded_dependency_scope_differs",
            "declared scope production; lock records development",
        ),
        ("future_disagreement", "future_disagreement"),
    ] {
        let mut value = clean();
        value["findings"]["manifest_lock_mismatches"] = json!([mismatch(reason)]);
        let bytes = serde_json::to_vec(&value).expect("report");
        let s = server(&bytes);
        let output = run(repo().path(), Some(&s.origin()), &[]);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        let text = stdout(&output);
        assert!(text.contains("Audit findings"), "{text}");
        assert!(text.contains("Manifest/lock disagreements (1)"), "{text}");
        assert!(
            text.contains("demo requests ^2; locked 1.5.0 [package.json → package-lock.json]"),
            "{text}"
        );
        assert!(text.contains(detail), "{text}");
        assert!(!text.contains("No audit findings"), "{text}");
        assert!(!text.contains("report unverified"), "{text}");
        assert_eq!(s.requests().len(), 3);
    }
}

fn unmet(name: &str, requester: &str, requirement: Option<&str>, status: &str) -> Value {
    json!({"path":"package-lock.json","name":name,"reason":"unmet_dependency",
        "requester":{"name":requester,"version":"1.0.0"},"kind":"PEER",
        "requested_requirement":requirement,"requirement_status":status,"requester_scope":"unknown",
        "context":{"coverage":"native_coverage_telemetry","target_status":"ABSENT_UNMET",
            "marker":"platform == 'example'","requested_extras":["feature"],"future_context":"ignored"}})
}

#[test]
fn native_diagnostics_missing_peer_is_compact_and_saved_without_opaque_context() {
    let mut value = clean();
    value["unknowns"]["sources"] =
        json!([{"path":"package-lock.json","reasons":["unmet_dependency"]}]);
    value["summary"]["incomplete_sources"] = 1.into();
    let mut future = unmet("futuredep", "fourth", Some("<9"), "future_status");
    future["kind"] = "FUTURE_KIND".into();
    future["context"] = json!({"coverage":"native_coverage_telemetry"});
    value["unknowns"]["resolution"] = json!([
        unmet("missing", "first", Some("<2"), "recorded"),
        unmet("missing", "second", None, "withheld"),
        unmet("other", "third", None, "not_recorded"),
        future
    ]);
    value["generated_at"] = "2026-10-15T12:00:00Z".into();
    let bytes = serde_json::to_vec(&value).expect("report");
    let r = repo();
    let archive = r.path().join("analysis.json");
    let s = server(&bytes);
    let output = run(
        r.path(),
        Some(&s.origin()),
        &["--save-analysis", archive.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    assert_eq!(
        text.matches("dependency information incomplete").count(),
        1,
        "{text}"
    );
    assert_eq!(text.matches("[package-lock.json]").count(), 1, "{text}");
    for line in [
        "missing peer dependency: missing <2 — requested by first@1.0.0",
        "missing peer dependency: missing (requirement withheld) — requested by second@1.0.0",
        "missing peer dependency: other (requirement not recorded) — requested by third@1.0.0",
    ] {
        assert!(text.contains(line), "{text}");
    }
    assert!(text.contains("missing dependency: futuredep (requirement future_status) — requested by fourth@1.0.0 (kind: FUTURE_KIND)"), "{text}");
    assert!(!text.contains("futuredep <9"), "{text}");
    assert!(!text.contains("native_coverage_telemetry"), "{text}");
    let stored = fs::read_to_string(&archive).expect("saved archive");
    assert!(!stored.contains("native_coverage_telemetry"));
    assert!(!stored.contains("future_context"));
    let saved: Value = serde_json::from_str(&stored).expect("saved JSON");
    assert!(
        saved["producer_report"]["unknowns"]["resolution"][3]
            .get("context")
            .is_none()
    );
    for extra in [&[][..], &["--json"][..]] {
        let output = offline(&archive, extra);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
        if extra.is_empty() {
            assert!(
                stdout(&output)
                    .contains("missing peer dependency: missing <2 — requested by first@1.0.0")
            );
        } else {
            let result: Value = serde_json::from_slice(&output.stdout).expect("compact JSON");
            assert_eq!(result["issues"].as_array().expect("issues").len(), 1);
            let requests = result["issues"][0]["missing_requests"]
                .as_array()
                .expect("missing requests");
            assert_eq!(requests.len(), 4);
            assert_eq!(requests[0]["requester"], "first@1.0.0");
            assert_eq!(requests[0]["requested_requirement"], "<2");
            assert_eq!(requests[0]["conditions"]["marker"], "platform == 'example'");
            assert!(requests[0]["conditions"].get("coverage").is_none());
            assert_eq!(requests[1]["requirement_status"], "withheld");
            assert!(requests[1].get("requested_requirement").is_none());
            assert_eq!(requests[3]["kind"], "FUTURE_KIND");
            assert_eq!(requests[3]["requirement_status"], "future_status");
            assert!(requests[3].get("conditions").is_none());
        }
    }
    assert_eq!(s.requests().len(), 3, "replay never submits a job");
}

#[test]
fn native_diagnostics_mismatch_archive_replay_preserves_findings_and_counts() {
    let mut value = clean();
    value["findings"]["manifest_lock_mismatches"] =
        json!([mismatch("recorded_requirement_differs")]);
    value["summary"]["manifest_lock_mismatches"] = 1.into();
    value["generated_at"] = "2026-10-15T12:00:00Z".into();
    let r = repo();
    let archive = r.path().join("analysis.json");
    let bytes = serde_json::to_vec(&value).expect("report");
    let s = server(&bytes);
    let output = run(
        r.path(),
        Some(&s.origin()),
        &["--json", "--save-analysis", archive.to_str().expect("path")],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let live: Value = serde_json::from_slice(&output.stdout).expect("live JSON");
    assert_eq!(
        live["manifest_lock_mismatches"][0]["recorded_requirements"],
        json!(["^1"])
    );
    assert_eq!(live["summary"]["manifest_lock_mismatches"], 1);
    assert_eq!(live["incomplete"], false);
    let output = offline(&archive, &["--json"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let replay: Value = serde_json::from_slice(&output.stdout).expect("replay JSON");
    assert_eq!(
        replay["manifest_lock_mismatches"],
        live["manifest_lock_mismatches"]
    );
    assert_eq!(s.requests().len(), 3);
}
