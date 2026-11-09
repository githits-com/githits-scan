use serde_json::{Value, json};

use super::super::Reason;
use crate::api::audit::remediation::Change;

const COORDINATE: &str = r#"{"registry":"npm","name":"demo","version":"1.1.1"}"#;

fn request() -> Value {
    json!({
        "owner": {"name": "parent", "version": "2.0.0"},
        "owner_role": "third_party",
        "path": "package-lock.json",
        "kind": "dependency",
        "dependency_name": "alias",
        "requested_requirement": "<1.1",
        "requirement_status": "recorded",
        "basis": "lockfile"
    })
}

fn request_with_unconsumed_fields() -> Value {
    let mut value = request();
    value["context"] = Value::Null;
    value["declaration_ref"] = json!("ignored");
    value["dependency_occurrence_refs"] = Value::Null;
    value
}

fn change(reasons: Option<Value>) -> Value {
    let mut value = json!({
        "registry": "npm",
        "name": "demo",
        "from_version": "1.0.0",
        "target_version": "1.1.1",
        "strategy": "direct",
        "occurrence_refs": [1],
        "paths": ["package-lock.json"],
        "conflicting_target_versions": [],
        "availability_source": "registry",
        "prerelease_target": false,
        "deprecated_target": false
    });
    if let Some(reasons) = reasons {
        value["reasons"] = reasons;
    }
    value
}

#[test]
fn audit_change_reason_wire_known_variants_roundtrip_consumed_subset() {
    let reasons = json!([
        {"code":"advisory_remediation", "finding_refs":[2, 0], "occurrence_refs":"ignored", "future":"ignored"},
        {"code":"enables_dependency_target", "dependency": {"registry":"npm", "name":"demo", "version":"1.1.1"}, "path":"package-lock.json", "original_requests":[request_with_unconsumed_fields()], "replacement_requests":[request_with_unconsumed_fields()], "occurrence_refs":[3], "dependency_occurrence_refs":[4]},
        {"code":"removes_dependency_route", "dependency": {"registry":"npm", "name":"demo", "version":"1.0.0"}, "path":"package-lock.json", "original_requests":[request_with_unconsumed_fields()], "dependency_occurrence_refs":[9]},
        {"code":"unavailable", "detail":"ignored"}
    ]);

    let decoded: Vec<Reason> = serde_json::from_value(reasons).expect("known reasons decode");
    assert_eq!(
        decoded.iter().map(Reason::code).collect::<Vec<_>>(),
        [
            "advisory_remediation",
            "enables_dependency_target",
            "removes_dependency_route",
            "unavailable"
        ]
    );
    let encoded = serde_json::to_value(decoded).expect("known reasons encode");
    assert_eq!(
        encoded,
        json!([
            {"code":"advisory_remediation", "finding_refs":[2, 0]},
            {"code":"enables_dependency_target", "dependency": {"registry":"npm", "name":"demo", "version":"1.1.1"}, "path":"package-lock.json", "original_requests":[request()], "replacement_requests":[request()]},
            {"code":"removes_dependency_route", "dependency": {"registry":"npm", "name":"demo", "version":"1.0.0"}, "path":"package-lock.json", "original_requests":[request()]},
            {"code":"unavailable"}
        ])
    );
}

#[test]
fn audit_change_reason_wire_preserves_unknown_opaque_evidence() {
    let reason = json!({
        "code": "future_reason",
        "nested": {"items": [1, null, {"enabled": true}]},
        "evidence": ["opaque", 3.5]
    });
    let decoded: Reason = serde_json::from_value(reason.clone()).expect("unknown reason decode");
    assert_eq!(decoded.code(), "future_reason");
    assert_eq!(
        serde_json::to_value(decoded).expect("unknown reason encode"),
        reason
    );
}

#[test]
fn audit_change_reason_wire_preserves_absent_change_reasons() {
    let value = change(None);
    let decoded: Change = serde_json::from_value(value.clone()).expect("legacy change decode");
    let encoded = serde_json::to_value(decoded).expect("legacy change encode");
    let mut expected = value;
    expected
        .as_object_mut()
        .expect("change object")
        .remove("conflicting_target_versions");
    assert_eq!(encoded, expected);
    assert!(encoded.get("reasons").is_none());
}

#[test]
fn audit_change_reason_wire_rejects_invalid_reason_containers_and_codes() {
    for value in [
        Value::Null,
        json!("unavailable"),
        json!([]),
        json!({}),
        json!({"code": null}),
        json!({"code": 4}),
    ] {
        assert!(serde_json::from_value::<Reason>(value).is_err());
    }

    for reasons in [Value::Null, json!({"code":"unavailable"}), json!("wrong")] {
        assert!(serde_json::from_value::<Change>(change(Some(reasons))).is_err());
    }
}

#[test]
fn audit_change_reason_wire_rejects_malformed_known_payloads() {
    let malformed = [
        json!({"code":"advisory_remediation"}),
        json!({"code":"advisory_remediation", "finding_refs":"0"}),
        json!({"code":"advisory_remediation", "finding_refs":["0"]}),
        json!({"code":"advisory_remediation", "finding_refs":[-1]}),
        json!({"code":"advisory_remediation", "finding_refs":[0.5]}),
        json!({"code":"enables_dependency_target", "dependency":null, "path":"lock", "original_requests":[], "replacement_requests":[]}),
        json!({"code":"enables_dependency_target", "dependency":COORDINATE, "path":"lock", "original_requests":[], "replacement_requests":[]}),
        json!({"code":"enables_dependency_target", "dependency":{"registry":"npm", "name":"demo", "version":"1.1.1"}, "path":"lock", "original_requests":{}, "replacement_requests":[]}),
        json!({"code":"enables_dependency_target", "dependency":{"registry":"npm", "name":"demo", "version":"1.1.1"}, "path":"lock", "original_requests":[]}),
        json!({"code":"removes_dependency_route", "dependency":{"registry":"npm", "name":"demo", "version":"1.0.0"}, "path":"lock", "original_requests":null}),
        json!({"code":"enables_dependency_target", "dependency":{"registry":"npm", "name":"demo", "version":"1.1.1"}, "path":"lock", "original_requests":[{"owner":{"name":"parent"}, "owner_role":"third_party", "path":"lock", "kind":"dependency", "requested_requirement":null, "requirement_status":"recorded", "basis":"lockfile"}], "replacement_requests":[]}),
        json!({"code":"enables_dependency_target", "dependency":{"registry":"npm", "name":"demo", "version":"1.1.1"}, "path":"lock", "original_requests":[{"owner":{"name":"parent", "version":null}, "owner_role":"third_party", "path":"lock", "kind":"dependency", "requested_requirement":null, "requirement_status":"recorded", "basis":"lockfile", "dependency_name":null}], "replacement_requests":[]}),
    ];

    for value in malformed {
        assert!(
            serde_json::from_value::<Reason>(value.clone()).is_err(),
            "accepted malformed payload: {value}"
        );
    }
}

#[test]
fn audit_change_reason_wire_accepts_empty_arrays_and_optional_names() {
    let value = json!([
        {"code":"advisory_remediation", "finding_refs":[]},
        {"code":"enables_dependency_target", "dependency":{"registry":"npm", "name":"demo", "version":"1.1.1"}, "path":"lock", "original_requests":[], "replacement_requests":[]},
        {"code":"removes_dependency_route", "dependency":{"registry":"npm", "name":"demo", "version":"1.0.0"}, "path":"lock", "original_requests":[]},
        {"code":"unavailable"}
    ]);
    let decoded: Vec<Reason> = serde_json::from_value(value).expect("empty arrays are valid");
    let encoded = serde_json::to_value(decoded).expect("empty arrays encode");
    assert_eq!(encoded[0]["finding_refs"], json!([]));
    assert_eq!(encoded[1]["original_requests"], json!([]));
    assert_eq!(encoded[1]["replacement_requests"], json!([]));
    assert_eq!(encoded[2]["original_requests"], json!([]));

    let decoded: Change =
        serde_json::from_value(change(Some(json!([])))).expect("empty reasons array is valid");
    let encoded = serde_json::to_value(decoded).expect("empty reasons array encodes");
    assert_eq!(encoded["reasons"], json!([]));

    let mut request = request();
    request
        .as_object_mut()
        .expect("object")
        .remove("dependency_name");
    let reason = json!({
        "code":"removes_dependency_route",
        "dependency":{"registry":"npm", "name":"demo", "version":"1.0.0"},
        "path":"lock",
        "original_requests":[request]
    });
    let decoded: Reason = serde_json::from_value(reason).expect("missing optional name is valid");
    let encoded = serde_json::to_value(decoded).expect("request encode");
    assert!(
        encoded["original_requests"][0]
            .get("dependency_name")
            .is_none()
    );
}

#[test]
fn audit_change_reason_wire_requires_nullable_request_requirement_slot() {
    let mut incomplete_request = request();
    incomplete_request
        .as_object_mut()
        .expect("object")
        .remove("requested_requirement");
    let reason = json!({
        "code":"removes_dependency_route",
        "dependency":{"registry":"npm", "name":"demo", "version":"1.0.0"},
        "path":"lock",
        "original_requests":[incomplete_request]
    });
    assert!(serde_json::from_value::<Reason>(reason).is_err());

    let mut request = request();
    request["requested_requirement"] = json!(4);
    let reason = json!({
        "code":"removes_dependency_route",
        "dependency":{"registry":"npm", "name":"demo", "version":"1.0.0"},
        "path":"lock",
        "original_requests":[request]
    });
    assert!(serde_json::from_value::<Reason>(reason).is_err());
}
