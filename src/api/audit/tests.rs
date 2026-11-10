use super::*;

const FINDINGS: &[u8] = include_bytes!("../../../tests/fixtures/audit/findings.json");
const V2: &[u8] = include_bytes!("../../../tests/fixtures/audit/v2-findings.json");

fn remove_projection_key(value: &mut serde_json::Value, path: &str, key: &str) {
    value
        .pointer_mut(path)
        .expect("projection object")
        .as_object_mut()
        .expect("object")
        .remove(key);
}

fn expected_v2_projection(mut value: serde_json::Value) -> serde_json::Value {
    for key in ["schema_version", "notices", "future_marker"] {
        value.as_object_mut().expect("root object").remove(key);
    }
    remove_projection_key(&mut value, "/summary", "future_marker");
    remove_projection_key(
        &mut value,
        "/findings/vulnerabilities/0/coordinate",
        "future_marker",
    );
    remove_projection_key(
        &mut value,
        "/findings/vulnerabilities/0",
        "related_advisory_ids",
    );
    remove_projection_key(&mut value, "/findings/vulnerabilities/0", "matched_ranges");

    if let Some(remediation) = value.get_mut("remediation") {
        remove_projection_key(remediation, "/trace", "future_marker");
        remove_projection_key(remediation, "/trace/occurrences/0", "private_unused_id");
        remove_projection_key(remediation, "/limits", "memberships_checked");
    }
    value
}

fn serialize_v2_projection(bytes: &[u8]) -> Option<serde_json::Value> {
    let report = Report::from_bytes(bytes).expect("v2 report");
    let Body::V2(body) = &report.body else {
        return None;
    };
    Some(serde_json::to_value(body).expect("serialized v2 projection"))
}

#[test]
fn audit_saved_wire_projection_round_trips() {
    let remediation: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/audit/remediation.json"
    ))
    .expect("remediation fixture");
    let mut original: serde_json::Value = serde_json::from_slice(V2).expect("v2 fixture");
    original["remediation"] = remediation;
    original["future_marker"] = serde_json::json!({"ignored": true});
    original["summary"]["future_marker"] = serde_json::json!("ignored");
    original["findings"]["vulnerabilities"][0]["coordinate"]["future_marker"] =
        serde_json::json!("ignored");
    original["remediation"]["trace"]["future_marker"] = serde_json::json!("ignored");

    let expected = expected_v2_projection(original.clone());
    let serialized = serialize_v2_projection(
        &serde_json::to_vec(&original).expect("encoded v2 report with remediation"),
    )
    .expect("v2 projection with remediation");
    assert_eq!(serialized, expected);
    for path in [
        "/findings/duplicates/0/versions/1/origins/0/requested_requirement",
        "/findings/duplicates/0/versions/0/origins/0/requester/version",
        "/unknowns/resolution/0/name",
        "/unknowns/excluded_dependencies/0/version",
    ] {
        assert_eq!(
            serialized.pointer(path),
            Some(&serde_json::Value::Null),
            "{path}"
        );
    }
    for path in [
        "/findings/duplicates/0/versions/0/origins/0/attribution_basis",
        "/unknowns/resolution/0/required_path",
        "/remediation/recommendations/0/search_domain",
    ] {
        assert!(serialized.pointer(path).is_none(), "{path}");
    }

    let mut envelope = serialized.clone();
    envelope["schema_version"] = serde_json::json!(2);
    let second_projection = serialize_v2_projection(
        &serde_json::to_vec(&envelope).expect("encoded serialized projection"),
    )
    .expect("second v2 projection with remediation");
    assert_eq!(second_projection, serialized);

    let mut without_remediation: serde_json::Value =
        serde_json::from_slice(V2).expect("v2 fixture without remediation");
    without_remediation["future_marker"] = serde_json::json!("ignored");
    without_remediation["summary"]["future_marker"] = serde_json::json!("ignored");
    without_remediation["findings"]["vulnerabilities"][0]["coordinate"]["future_marker"] =
        serde_json::json!("ignored");
    let expected_without_remediation = expected_v2_projection(without_remediation.clone());
    let serialized_without_remediation = serialize_v2_projection(
        &serde_json::to_vec(&without_remediation).expect("encoded v2 report without remediation"),
    )
    .expect("v2 projection without remediation");
    assert_eq!(serialized_without_remediation, expected_without_remediation);
    assert!(serialized_without_remediation.get("remediation").is_none());
    let mut without_remediation_envelope = serialized_without_remediation.clone();
    without_remediation_envelope["schema_version"] = serde_json::json!(2);
    let second_without_remediation_projection = serialize_v2_projection(
        &serde_json::to_vec(&without_remediation_envelope)
            .expect("encoded projection without remediation"),
    )
    .expect("second v2 projection without remediation");
    assert_eq!(
        second_without_remediation_projection,
        serialized_without_remediation
    );
}

#[test]
fn audit_remediation_rejects_malformed_consumed_fields() {
    let remediation: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/audit/remediation.json"
    ))
    .expect("remediation fixture");
    for (path, invalid) in [
        ("", serde_json::Value::Null),
        ("/recommendations/0/checks", serde_json::json!([])),
        ("/recommendations/0/finding_refs", serde_json::json!(["0"])),
        ("/trace/status", serde_json::json!(7)),
    ] {
        let mut v: serde_json::Value = serde_json::from_slice(V2).expect("base");
        v["remediation"] = remediation.clone();
        *v["remediation"].pointer_mut(path).expect("path") = invalid;
        assert!(
            Report::from_bytes(&serde_json::to_vec(&v).expect("json")).is_err(),
            "{path}"
        );
    }
}

#[test]
fn audit_remediation_required_fields_and_optional_nulls_fail_closed() {
    let data: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/audit/remediation.json"
    ))
    .expect("fixture");
    for (path, field) in [
        ("", "status"),
        ("", "recommendations"),
        ("", "trace"),
        ("", "limits"),
        ("/recommendations/0", "subject"),
        ("/recommendations/0", "finding_refs"),
        ("/recommendations/0", "changes"),
        ("/recommendations/0", "blockers"),
        ("/recommendations/0", "checks"),
        ("/recommendations/0", "remaining_finding_refs"),
        ("/recommendations/0/checks", "native_resolution"),
        ("/recommendations/0/changes/0", "strategy"),
        ("/trace", "status"),
        ("/limits", "omitted_occurrences"),
    ] {
        let mut v: serde_json::Value = serde_json::from_slice(V2).expect("base");
        v["remediation"] = data.clone();
        v["remediation"]
            .pointer_mut(path)
            .expect("path")
            .as_object_mut()
            .expect("object")
            .remove(field);
        assert!(
            Report::from_bytes(&serde_json::to_vec(&v).expect("json")).is_err(),
            "{path}/{field}"
        );
    }
    for path in [
        "/recommendations/0/search_domain",
        "/recommendations/0/changes/0/availability_source",
        "/recommendations/0/changes/0/prerelease_target",
    ] {
        let mut v: serde_json::Value = serde_json::from_slice(V2).expect("base");
        v["remediation"] = data.clone();
        let (parent, field) = path.rsplit_once('/').expect("path");
        v["remediation"].pointer_mut(parent).expect("parent")[field] = serde_json::Value::Null;
        assert!(
            Report::from_bytes(&serde_json::to_vec(&v).expect("json")).is_err(),
            "{path}"
        );
    }
}

#[test]
fn audit_v1_decodes_required_nullable_fields() {
    let report = Report::from_bytes(FINDINGS).expect("v1");
    assert_eq!(report.version(), 1);
    assert!(matches!(&report.body, Body::V1(r) if r.findings.vulnerabilities.len() == 1));
    let mut value: serde_json::Value = serde_json::from_slice(FINDINGS).expect("fixture");
    value["occurrences"][0]
        .as_object_mut()
        .expect("object")
        .remove("coordinate");
    assert!(Report::from_bytes(&serde_json::to_vec(&value).expect("json")).is_err());
}

#[test]
fn audit_future_is_identified_and_bad_versions_fail_closed() {
    let report = Report::from_bytes(br#"{"schema_version":3,"future":{"summary":"opaque"}}"#)
        .expect("future");
    assert_eq!(report.version(), 3);
    assert!(matches!(report.body, Body::Future(3)));
    for bytes in [
        b"{}".as_slice(),
        br#"{"schema_version":0}"#,
        br#"{"schema_version":-1}"#,
        br#"{"schema_version":"1"}"#,
        br#"{"schema_version":1}"#,
        br#"{"schema_version":2}"#,
        b"[1]",
    ] {
        assert!(Report::from_bytes(bytes).is_err(), "{bytes:?}");
    }
}

#[test]
fn audit_objects_reject_positional_arrays_and_accept_additional_fields() {
    let mut value: serde_json::Value = serde_json::from_slice(FINDINGS).expect("fixture");
    value["occurrences"][0]["coordinate"] = serde_json::json!(["demo", "npm", "1.0.0"]);
    assert!(Report::from_bytes(&serde_json::to_vec(&value).expect("json")).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(FINDINGS).expect("fixture");
    value["summary"]["future_counter"] = 44.into();
    value["occurrences"][0]["coordinate"]["future_field"] = "ignored additional value".into();
    let report =
        Report::from_bytes(&serde_json::to_vec(&value).expect("json")).expect("additional fields");
    assert!(
        crate::audit::assess(&report, &crate::config::Audit::default())
            .expect("known")
            .unverified
            .is_empty(),
        "{:?}",
        crate::audit::assess(&report, &crate::config::Audit::default())
            .expect("known")
            .unverified
    );
}

#[test]
fn audit_v2_consumes_compact_fields_and_requires_nullable_slots() {
    let report = Report::from_bytes(V2).expect("v2");
    assert_eq!(report.version(), 2);
    let requirement = match &report.body {
        Body::V2(r) => r.findings.duplicates[0].versions[0].origins[0]
            .requested_requirement
            .as_deref(),
        _ => None,
    };
    assert_eq!(requirement, Some("^1.0.0"));
    for (path, field) in [
        ("/findings/vulnerabilities/0", "summary"),
        ("/findings/vulnerabilities/0", "severity_score"),
        ("/findings/duplicates/0/versions/0/origins/0", "requester"),
        (
            "/findings/duplicates/0/versions/0/origins/0",
            "requested_requirement",
        ),
        (
            "/findings/duplicates/0/versions/0/origins/0/requester",
            "version",
        ),
        ("/unknowns/metadata/0", "reason"),
        ("/unknowns/resolution/0", "name"),
        ("/unknowns/excluded_dependencies/0", "version"),
    ] {
        let mut v: serde_json::Value = serde_json::from_slice(V2).expect("fixture");
        v.pointer_mut(path)
            .expect("path")
            .as_object_mut()
            .expect("object")
            .remove(field);
        assert!(
            Report::from_bytes(&serde_json::to_vec(&v).expect("json")).is_err(),
            "{path}/{field}"
        );
    }
}

#[test]
fn audit_v2_rejects_wrong_containers_without_closing_additive_vocabulary() {
    for path in [
        "/summary",
        "/findings",
        "/coverage",
        "/unknowns",
        "/findings/duplicates/0/versions/0/origins/0/requester",
    ] {
        let mut v: serde_json::Value = serde_json::from_slice(V2).expect("fixture");
        *v.pointer_mut(path).expect("path") = serde_json::json!([]);
        assert!(
            Report::from_bytes(&serde_json::to_vec(&v).expect("json")).is_err(),
            "{path}"
        );
    }
    let mut v: serde_json::Value = serde_json::from_slice(V2).expect("fixture");
    v["findings"]["duplicates"][0]["versions"][0]["origins"][0]["status"] = "future_origin".into();
    v["findings"]["outdated"][0]["change_type"] = "future_delta".into();
    v["future_inventory"] = serde_json::json!({"native_id":"must not escape"});
    let report = Report::from_bytes(&serde_json::to_vec(&v).expect("json")).expect("open fields");
    assert!(
        crate::audit::assess(&report, &crate::config::Audit::default())
            .expect("known")
            .unverified
            .is_empty(),
        "{:?}",
        crate::audit::assess(&report, &crate::config::Audit::default())
            .expect("known")
            .unverified
    );
}

#[test]
fn audit_v2_optional_attribution_basis_rejects_wrong_types() {
    for basis in [
        serde_json::json!(7),
        serde_json::json!(true),
        serde_json::json!([]),
        serde_json::json!({}),
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(V2).expect("fixture");
        value["findings"]["duplicates"][0]["versions"][0]["origins"][0]["attribution_basis"] =
            basis;
        assert!(Report::from_bytes(&serde_json::to_vec(&value).expect("json")).is_err());
    }
}

#[test]
fn audit_v2_required_path_rejects_wrong_types() {
    for invalid in [
        serde_json::json!(7),
        serde_json::json!(true),
        serde_json::json!([]),
        serde_json::json!({}),
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(V2).expect("fixture");
        value["unknowns"]["resolution"] = serde_json::json!([{"path":"Cargo.toml","name":null,"reason":"required_input_not_supplied","required_path":invalid}]);
        assert!(Report::from_bytes(&serde_json::to_vec(&value).expect("json")).is_err());
    }
}

#[test]
fn audit_not_applicable_fields_reject_malformed_present_values() {
    for version in [1, 2] {
        for (field, invalid) in [
            ("not_applicable_count", serde_json::Value::Null),
            ("not_applicable_count", serde_json::json!(-1)),
            ("not_applicable_count", serde_json::json!("2")),
            ("not_applicable_registries", serde_json::Value::Null),
            ("not_applicable_registries", serde_json::json!({})),
            ("not_applicable_registries", serde_json::json!([1])),
        ] {
            let mut value = crate::test_support::audit::pypi_not_applicable(version);
            value["coverage"]["deprecation"][field] = invalid;
            assert!(
                Report::from_bytes(&serde_json::to_vec(&value).expect("JSON")).is_err(),
                "v{version} {field}"
            );
        }
    }
}
