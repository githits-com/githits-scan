use super::*;
use crate::test_support::jobs::{accepted, snapshot};

#[test]
fn canonical_acceptance_rejects_foreign_or_alternate_links() {
    for field in ["status_url", "events_url", "result_url"] {
        for link in [
            "https://foreign.invalid/job",
            "//foreign.invalid/job",
            "/v1/experimental/lockfile-jobs/other",
            "/v1/experimental/lockfile-jobs/../job",
        ] {
            let mut value = accepted();
            value[field] = link.into();
            assert!(matches!(
                Accepted::parse(&serde_json::to_vec(&value).expect("json")),
                Err(ApiError::Protocol { .. })
            ));
        }
    }
    for id in [
        "",
        "../events",
        "z1900000-0000-7000-8000-000000000001",
        "01900000/0000-7000-8000-000000000001",
    ] {
        let mut value = accepted();
        value["id"] = id.into();
        assert!(Accepted::parse(&serde_json::to_vec(&value).expect("json")).is_err());
    }
}

fn parse(
    value: &serde_json::Value,
    revision: &str,
    previous: Option<u64>,
) -> Result<Snapshot, ApiError> {
    let job = Accepted::parse(&serde_json::to_vec(&accepted()).expect("json")).expect("acceptance");
    Snapshot::parse(
        &serde_json::to_vec(value).expect("json"),
        revision,
        &job,
        Operation::Sbom(crate::api::OutputFormat::CycloneDx),
        previous,
    )
}

#[test]
fn equal_revisions_replace_counts_attempt_and_phase() {
    let mut first = snapshot("running", "resolving", 3);
    first["counts"] = serde_json::json!({"resolved": 10, "manifests_done": 1});
    let first = parse(&first, "3", None).expect("first");
    let mut next = snapshot("running", "enriching", 3);
    next["attempt"] = 2.into();
    next["counts"] = serde_json::json!({"coordinates_done": 0, "coordinates_total": 12, "cached": null, "future_count": "ignored"});
    let next = parse(&next, "3", Some(first.revision)).expect("equal revision");
    assert_eq!(next.progress.phase, Phase::Enriching);
    assert_eq!(next.progress.attempt, 2);
    assert_eq!(next.progress.counts.coordinates_done, Some(0));
    assert_eq!(next.progress.counts.coordinates_total, Some(12));
    assert_eq!(next.progress.counts.cached, None);
    assert_eq!(next.progress.counts.resolved, None);
}

#[test]
fn invalid_snapshot_semantics_fail_closed_without_raw_diagnostics() {
    let mutations = [
        ("state", serde_json::json!("mystery")),
        ("format", serde_json::json!("text")),
        ("kind", serde_json::json!("audit")),
        ("id", serde_json::json!("other")),
        ("attempt", serde_json::json!(-1)),
        ("revision", serde_json::json!(-1)),
        ("counts", serde_json::json!({"resolved": -1})),
        ("error", serde_json::json!("secret diagnostic")),
        ("error", serde_json::json!("execution_failed")),
        ("state", serde_json::json!("failed")),
        ("result_url", serde_json::json!("https://foreign.invalid")),
    ];
    for (field, value) in mutations {
        let mut wire = snapshot("running", "resolving", 0);
        wire[field] = value;
        let error = parse(&wire, "0", None).err().expect("invalid");
        assert!(!error.to_string().contains("secret"));
    }
    let mut failed = snapshot("failed", "failed", 0);
    assert!(parse(&failed, "0", None).is_err(), "failed with null error");
    failed["error"] = "execution_failed".into();
    let parsed = parse(&failed, "0", None).expect("valid failure");
    assert!(matches!(
        parsed.state,
        State::Failed(FailureCode::ExecutionFailed)
    ));
    let mut missing = snapshot("running", "resolving", 0);
    missing.as_object_mut().expect("object").remove("error");
    assert!(parse(&missing, "0", None).is_err());
    assert!(parse(&snapshot("running", "resolving", 1), "1", Some(2)).is_err());
    assert!(parse(&snapshot("running", "resolving", 1), "2", None).is_err());
}

#[test]
fn unfamiliar_sbom_phase_is_display_only_and_terminal_state_still_controls_completion() {
    let value = snapshot("succeeded", "future_phase", 1);
    let parsed = parse(&value, "1", None).expect("open phase");
    assert_eq!(parsed.progress.phase, Phase::Unknown);
    assert!(matches!(parsed.state, State::Succeeded));
}

#[test]
fn accepted_state_must_be_queued_even_when_response_strings_are_open() {
    for state in ["running", "succeeded", "failed", "future_state"] {
        let mut value = accepted();
        value["state"] = state.into();
        assert!(
            Accepted::parse(&serde_json::to_vec(&value).expect("json")).is_err(),
            "{state}"
        );
    }
}
