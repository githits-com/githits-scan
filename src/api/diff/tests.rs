use super::*;
use crate::api::{MAX_BODY_BYTES, UploadError, UploadFile, UploadSet, upload};

fn set(n: usize, size: usize) -> UploadSet {
    UploadSet::try_new(
        (0..n)
            .map(|i| UploadFile {
                path: format!("p{i}/Cargo.lock"),
                contents: "x".repeat(size),
            })
            .collect(),
    )
    .expect("set")
}

#[test]
fn diff_pair_allows_empty_and_cross_side_paths_but_not_side_duplicates() {
    let empty = Input::try_new(None, None, UnlockedManifests::RecordedOnly).expect("empty");
    let request: serde_json::Value = serde_json::from_str(&empty.request).expect("request");
    assert_eq!(request["base"]["state"], "empty");
    assert_eq!(request["head"]["state"], "empty");
    assert_eq!(request["selection"]["unlocked_manifests"], "recorded_only");
    assert_eq!(empty.file_count(), 0);
    assert_eq!(
        Input::try_new(Some(set(1, 1)), Some(set(1, 1)), UnlockedManifests::Resolve)
            .expect("pair")
            .file_count(),
        2
    );
    let duplicate = UploadSet::try_new(vec![
        set(1, 1).into_files().remove(0),
        set(1, 1).into_files().remove(0),
    ])
    .expect("legacy permits duplicates");
    assert!(matches!(
        Input::try_new(Some(duplicate), None, UnlockedManifests::Resolve),
        Err(UploadError::DuplicatePath { .. })
    ));
}

#[test]
fn diff_pair_enforces_aggregate_count_at_256_and_257() {
    assert_eq!(
        Input::try_new(
            Some(set(128, 1)),
            Some(set(128, 1)),
            UnlockedManifests::Resolve
        )
        .expect("256")
        .file_count(),
        256
    );
    assert!(matches!(
        Input::try_new(
            Some(set(128, 1)),
            Some(set(129, 1)),
            UnlockedManifests::Resolve
        ),
        Err(UploadError::TooManyFiles { count: 257 })
    ));
}

#[test]
fn diff_pair_full_wire_bound_is_inclusive() {
    let probe = Input::try_new(Some(set(1, 0)), Some(set(1, 0)), UnlockedManifests::Resolve)
        .expect("probe");
    let room = usize::try_from(MAX_BODY_BYTES - probe.body_bytes()).expect("fits");
    let a = room / 2;
    let b = room - a;
    let input = Input::try_new(Some(set(1, a)), Some(set(1, b)), UnlockedManifests::Resolve)
        .expect("exact");
    assert_eq!(input.body_bytes(), MAX_BODY_BYTES);
    assert!(
        matches!(Input::try_new(Some(set(1,a)),Some(set(1,b+1)),UnlockedManifests::Resolve),Err(UploadError::BodyTooLarge{estimated,..}) if estimated==MAX_BODY_BYTES+1)
    );
    assert!(upload::check_path("../Cargo.lock").is_err());
}

#[test]
fn diff_report_retains_exact_additive_and_future_json_bytes() {
    let mut value = crate::test_support::diff::report();
    value["future"] = serde_json::json!({"keep":[1,2,3]});
    value["direct_reviews"]["coverage"]["future_detail"] = "preserved".into();
    let bytes = serde_json::to_vec_pretty(&value).expect("json");
    let report = Report::from_bytes(bytes.clone()).expect("report");
    assert_eq!(report.bytes(), bytes);
    assert!(report.view().is_some());
    let bytes =
        br#" {"schema_version":99,"kind":"diff","restructured":{"all":"preserved"}} "#.to_vec();
    let report = Report::from_bytes(bytes.clone()).expect("future");
    assert_eq!(report.bytes(), bytes);
    assert!(report.view().is_none());
}

#[test]
fn diff_unknown_section_vocabulary_does_not_parse_or_claim_old_data() {
    let mut v = crate::test_support::diff::report();
    v["advisories"] = serde_json::json!({"status":"future_assessment","data":["new shape"]});
    v["direct_reviews"] = serde_json::json!({"status":"future_review","data":42});
    let report =
        Report::from_bytes(serde_json::to_vec(&v).expect("json")).expect("open vocabulary");
    assert!(
        report
            .view()
            .expect("view")
            .advisories
            .decode::<view::Advisories>()
            .expect("decode")
            .is_none()
    );
}

#[test]
fn diff_nullable_targets_preserve_null_and_reject_missing_or_wrong_types() {
    let mut v = crate::test_support::diff::report();
    v["declaration_changes"][0]["binding_transitions"][0]["base_target"] = serde_json::Value::Null;
    assert!(Report::from_bytes(serde_json::to_vec(&v).expect("json")).is_ok());
    v["declaration_changes"][0]["binding_transitions"][0]
        .as_object_mut()
        .expect("object")
        .remove("base_target");
    assert!(Report::from_bytes(serde_json::to_vec(&v).expect("json")).is_err());
}

#[test]
fn diff_invalid_report_and_known_missing_sections_fail_closed() {
    for bytes in [
        b"{}".to_vec(),
        b"[]".to_vec(),
        b"{\"schema_version\":0,\"kind\":\"diff\"}".to_vec(),
        vec![b' '; MAX_RESPONSE_BYTES + 1],
    ] {
        assert!(Report::from_bytes(bytes).is_err());
    }
    for section in ["advisories", "direct_reviews"] {
        let mut v = crate::test_support::diff::report();
        v[section] = serde_json::json!({"status":"complete"});
        assert!(Report::from_bytes(serde_json::to_vec(&v).expect("json")).is_err());
    }
}

#[test]
fn diff_additive_fields_inside_open_side_objects_are_preserved() {
    let mut v = crate::test_support::diff::report();
    v["snapshots"]["future"] = serde_json::json!({"metadata":true});
    v["changes"][0]["directness"]["future"] = serde_json::json!({"proof":"extra"});
    v["advisories"]["data"]["exposures"][0]["coverage"]["future"] = true.into();
    let bytes = serde_json::to_vec(&v).expect("json");
    let report = Report::from_bytes(bytes.clone()).expect("open objects");
    assert_eq!(report.bytes(), bytes);
}

fn explanation_projection() -> serde_json::Value {
    use serde_json::json;
    let mut v = crate::test_support::diff::report();
    let cause = json!({"code":"future_cause","message":"The producer could not link the declaration.",
        "source_key":"package-lock.json","manifest_path":"package.json",
        "declaration_id":"base:d1","dependency_name":"helper",
        "coverage_state":"incomplete","coverage_reasons":["untargeted_requirement"]});
    v["changes"][0]["before_ids"] = json!(["base:o1"]);
    v["changes"][0]["after_ids"] = json!(["head:o1"]);
    v["snapshots"]["base"]["occurrences"] = json!([{"id":"base:o1","directness":"unknown",
        "directness_reasons":[cause],"directness_proof_ids":["proof:1"]}]);
    v["snapshots"]["base"]["reachability"] = json!([{"id":"proof:1","reasons":[cause]}]);
    v["snapshots"]["base"]["bindings"] = json!([{"declaration_id":"base:d1",
        "source_key":"package-lock.json","reasons":[cause]}]);
    v["snapshots"]["base"]["coverage"]["reachability"] = json!([{"complete":false,
        "manifest_path":"package.json","source_key":"package-lock.json",
        "basis":"declaration_and_root_graph","reachability_id":"proof:1"}]);
    v["direct_reviews"]["status"] = "partial".into();
    v["direct_reviews"]["data"][0]["status"] = "unavailable".into();
    v["direct_reviews"]["data"][0]["failure"] = json!({"scope":"batch",
        "code":"future_failure","message":"The producer could not encode the review batch."});
    v
}

fn assert_explanation_projection(view: &view::View) {
    assert_eq!(view.changes[0].before_ids, ["base:o1"]);
    assert_eq!(view.changes[0].after_ids, ["head:o1"]);
    let snapshot = &view.snapshots.base;
    let row = &snapshot.occurrences[0];
    assert_eq!(row.id, "base:o1");
    assert_eq!(row.directness, "unknown");
    assert_eq!(row.directness_proof_ids, ["proof:1"]);
    let reason = &row.directness_reasons[0];
    assert_eq!(reason.code, "future_cause");
    assert_eq!(
        reason.message,
        "The producer could not link the declaration."
    );
    assert_eq!(reason.source_key, "package-lock.json");
    assert_eq!(reason.manifest_path.as_deref(), Some("package.json"));
    assert_eq!(reason.declaration_id.as_deref(), Some("base:d1"));
    assert_eq!(reason.dependency_name.as_deref(), Some("helper"));
    assert_eq!(reason.coverage_state.as_deref(), Some("incomplete"));
    assert_eq!(reason.coverage_reasons, ["untargeted_requirement"]);
    assert_eq!(snapshot.reachability[0].id.as_deref(), Some("proof:1"));
    assert_eq!(snapshot.reachability[0].reasons, row.directness_reasons);
    assert_eq!(snapshot.bindings[0].declaration_id, "base:d1");
    assert_eq!(snapshot.bindings[0].source_key, "package-lock.json");
    assert_eq!(snapshot.bindings[0].reasons, row.directness_reasons);
    let reviews = view
        .direct_reviews
        .decode::<Vec<view::Review>>()
        .expect("reviews")
        .expect("rows");
    assert_eq!(reviews[0].declaration_change_ids, ["declaration:1"]);
    let failure = reviews[0].failure.as_ref().expect("failure");
    assert_eq!(failure.scope, "batch");
    assert_eq!(failure.code, "future_failure");
    assert_eq!(
        failure.message,
        "The producer could not encode the review batch."
    );
    let coverage: view::Coverage = serde_json::from_str(snapshot.coverage.get()).expect("coverage");
    assert_eq!(
        coverage.reachability[0].reachability_id.as_deref(),
        Some("proof:1")
    );
}

#[test]
fn diff_mismatch_display_fields_validate_without_weakening_metadata() {
    use serde_json::json;
    let mut v = crate::test_support::diff::report();
    v["snapshots"]["head"]["coverage"]["mismatches"] = json!([{
        "path":"package-lock.json","declaration_path":"package.json","name":"helper",
        "requested_requirement":"^2.0","locked_versions":["1.0.0"],"reason":"locked_version_does_not_satisfy_request"}]);
    let bytes = serde_json::to_vec_pretty(&v).expect("JSON");
    let report = Report::from_bytes(bytes.clone()).expect("mismatch");
    assert_eq!(report.bytes(), bytes);
    for pointer in [
        "/snapshots/head/coverage/mismatches/0/declaration_path",
        "/snapshots/head/coverage/mismatches/0/requested_requirement",
        "/snapshots/head/coverage/mismatches/0/locked_versions",
        "/summary/changed_declarations",
        "/notices",
        "/direct_reviews/coverage/eligible",
        "/declaration_changes/0/binding_transitions/0/base_target/version",
    ] {
        let mut invalid = v.clone();
        *invalid.pointer_mut(pointer).expect("field") = json!(false);
        assert!(
            Report::from_bytes(serde_json::to_vec(&invalid).expect("JSON")).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn diff_explanation_projection_preserves_optional_fields_and_validates_shapes() {
    use serde_json::json;
    let v = explanation_projection();
    let bytes = serde_json::to_vec_pretty(&v).expect("JSON");
    let report = Report::from_bytes(bytes.clone()).expect("new explanation projection");
    assert_eq!(report.bytes(), bytes);
    assert_explanation_projection(report.view().expect("view"));
    for pointer in [
        "/snapshots/base/occurrences/0/directness_reasons",
        "/snapshots/base/occurrences/0/directness_proof_ids",
        "/snapshots/base/reachability/0/reasons",
        "/snapshots/base/bindings/0/reasons",
        "/direct_reviews/data/0/failure/message",
        "/snapshots/base/coverage/reachability/0/reachability_id",
    ] {
        let mut invalid = v.clone();
        *invalid.pointer_mut(pointer).expect("field") = json!(42);
        assert!(
            Report::from_bytes(serde_json::to_vec(&invalid).expect("JSON")).is_err(),
            "{pointer}"
        );
    }
    let legacy = crate::test_support::diff::report();
    let legacy = Report::from_bytes(serde_json::to_vec(&legacy).expect("JSON")).expect("legacy");
    assert!(
        legacy
            .view()
            .expect("view")
            .snapshots
            .base
            .occurrences
            .is_empty()
    );
    let mut optional = v;
    optional["snapshots"]["base"]["occurrences"][0] = json!({"id":"base:o1","directness":"unknown",
        "directness_reasons":[{"code":"local","message":"No associated root.",
        "source_key":"package-lock.json","dependency_name":null}]});
    optional["snapshots"]["base"]["reachability"] = json!([{}]);
    optional["snapshots"]["base"]["bindings"][0]
        .as_object_mut()
        .expect("binding")
        .remove("reasons");
    optional["direct_reviews"]["data"][0]
        .as_object_mut()
        .expect("review")
        .remove("failure");
    optional["snapshots"]["base"]["coverage"]["reachability"][0]
        .as_object_mut()
        .expect("summary")
        .remove("reachability_id");
    let optional =
        Report::from_bytes(serde_json::to_vec(&optional).expect("JSON")).expect("optional fields");
    let row = &optional.view().expect("view").snapshots.base.occurrences[0];
    assert_eq!(row.directness_proof_ids, [] as [String; 0]);
    assert!(row.directness_reasons[0].dependency_name.is_none());
}
