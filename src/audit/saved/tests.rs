use super::*;
use crate::audit::test_support::{report, value};

#[test]
fn audit_saved_round_trip_preserves_facts_and_filters_new_private_properties() {
    let mut input = value();
    input["private_inventory"] = serde_json::json!({"native_id":"never-export"});
    input["remediation"]["trace"]["occurrences"][0]["private_native_id"] = "never-export".into();
    input["remediation"]["trace"]["relations"][0]["context"] =
        serde_json::json!({"private":"never-export"});
    input["remediation"]["trace"]["relations"][0]["requests"][0]["context"] =
        serde_json::json!({"private":"never-export"});
    input["remediation"]["recommendations"][0]["blockers"] = serde_json::json!([{
        "owner":{"name":"parent","version":"2.0.0"},"owner_role":"third_party",
        "path":"package-lock.json","kind":"dependency","dependency_name":"demo",
        "requested_requirement":"<1.1.0",
        "requirement_status":"recorded","basis":"lockfile","reason":"future_blocker",
        "context":{"future_information":{"value":"opaque-existing-context"}}
    }]);
    let original = report(&input);
    let bytes = encode(
        &original,
        &BTreeSet::from(["package.json".into()]),
        &crate::config::Audit::default(),
    )
    .expect("encode");
    assert!(!String::from_utf8_lossy(&bytes).contains("never-export"));
    let stored: serde_json::Value = serde_json::from_slice(&bytes).expect("archive");
    assert_eq!(
        stored["producer_report"]["remediation"]["recommendations"][0]["blockers"][0]["dependency_name"],
        "demo"
    );
    assert_eq!(
        stored["producer_report"]["remediation"]["recommendations"][0]["blockers"][0]["context"],
        input["remediation"]["recommendations"][0]["blockers"][0]["context"]
    );
    let decoded = decode(&bytes).expect("decode");
    assert_eq!(
        decoded.selected_manifests,
        BTreeSet::from(["package.json".into()])
    );
    assert_eq!(
        decoded.provenance.generated_at,
        input["generated_at"].as_str().expect("time")
    );
    assert_eq!(
        crate::audit::assess(&original, &crate::config::Audit::default())
            .expect("known")
            .attention,
        crate::audit::assess(&decoded.report, &crate::config::Audit::default())
            .expect("known")
            .attention
    );
    assert_eq!(
        encode(
            &decoded.report,
            &decoded.selected_manifests,
            &decoded.audit_policy
        )
        .expect("again"),
        bytes
    );
}

#[test]
fn audit_saved_schema_one_compatibility_and_optional_absence() {
    let analysis = decode(include_bytes!(
        "../../../tests/fixtures/audit/analysis-v1.json"
    ))
    .expect("archive v1");
    assert_eq!(analysis.provenance.writer_version, "0.2.0");
    assert_eq!(analysis.provenance.producer_schema_version, 2);
    let mut input = value();
    input.as_object_mut().expect("report").remove("remediation");
    let bytes = encode(
        &report(&input),
        &BTreeSet::new(),
        &crate::config::Audit::default(),
    )
    .expect("without remediation");
    let restored = decode(&bytes).expect("older optional absence");
    assert!(matches!(restored.report.body, Body::V2(body) if body.remediation.is_none()));
    assert!(!String::from_utf8_lossy(&bytes).contains("\"remediation\":null"));
}

#[test]
fn audit_saved_archive_errors_are_safe_and_do_not_guess_versions() {
    assert!(matches!(
        decode(br#"{"format":"githits-scan-analysis","schema_version":9}"#),
        Err(Error::Version { version: 9, .. })
    ));
    for bytes in [b"".as_slice(), b"{", b"[]", b"{}"] {
        assert!(matches!(decode(bytes), Err(Error::Invalid)));
    }
    let mut input: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/audit/analysis-v1.json"
    ))
    .expect("v1");
    input["schema_version"] = 9.into();
    input["writer_version"] = "unknown\n\u{1b}".into();
    let error = decode(&serde_json::to_vec(&input).expect("JSON"))
        .err()
        .expect("version error");
    assert!(matches!(error, Error::Version { version: 9, .. }));
    assert!(!error.to_string().contains('\n') && !error.to_string().contains('\u{1b}'));
    input["schema_version"] = 1.into();
    input["producer_report"] = serde_json::json!({"schema_version":2});
    assert!(matches!(
        decode(&serde_json::to_vec(&input).expect("bad inner")),
        Err(Error::Invalid)
    ));
}

#[test]
fn audit_saved_exact_byte_cap_and_oversize_are_distinct() {
    let mut bytes = include_bytes!("../../../tests/fixtures/audit/analysis-v1.json").to_vec();
    bytes.resize(MAX_RESPONSE_BYTES, b' ');
    assert!(decode(&bytes).is_ok());
    bytes.push(b' ');
    assert!(matches!(decode(&bytes), Err(Error::TooLarge)));
    let mut input = value();
    input["generated_at"] = "".into();
    let overhead = serde_json::to_vec(&input).expect("JSON").len();
    input["generated_at"] = "x".repeat(MAX_RESPONSE_BYTES - overhead).into();
    assert!(matches!(
        encode(
            &report(&input),
            &BTreeSet::new(),
            &crate::config::Audit::default()
        ),
        Err(Error::TooLarge)
    ));
}

#[test]
fn audit_saved_unsupported_producer_cannot_be_saved() {
    let future = Report::from_bytes(br#"{"schema_version":99}"#).expect("future");
    assert!(matches!(
        encode(&future, &BTreeSet::new(), &crate::config::Audit::default()),
        Err(Error::UnsupportedProducer)
    ));
}
