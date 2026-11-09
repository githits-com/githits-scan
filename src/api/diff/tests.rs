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
