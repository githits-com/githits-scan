use crate::api::audit::Report;
use serde_json::{Value, json};

fn report(status: Option<Value>, details: Option<Value>) -> Value {
    let mut report: Value = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/audit/native-findings.json"
    ))
    .expect("report");
    report["remediation"] = serde_json::from_slice(include_bytes!(
        "../../../../../tests/fixtures/audit/remediation.json"
    ))
    .expect("remediation");
    let r = &mut report["remediation"]["recommendations"][0];
    if let Some(status) = status {
        r["search_detail_status"] = status;
    }
    if let Some(details) = details {
        r["search_details"] = details;
    }
    report
}
fn decode(value: &Value) -> Result<Report, crate::api::ApiError> {
    Report::from_bytes(&serde_json::to_vec(value).expect("bytes"))
}
fn stopped() -> Value {
    json!({"kind":"stopped", "stage":"leaf_evaluation", "reason":"phase_deadline",
        "witness":{"coordinate":null,"budget_scope":"local"}})
}
#[test]
fn audit_search_wire_forms_curate_unknown_fields_and_keep_future_vocabulary() {
    assert!(decode(&report(None, None)).is_ok());
    let details = json!([
        {"kind":"unavailable","operation":"future_operation","reasons":["future_reason"],"witness":{},"private_unused_id":"omit"},
        stopped(),
        {"kind":"future_kind","private_unused_id":"omit","witness":{"coordinate":false}}
    ]);
    let value = report(Some(json!("future_status")), Some(details));
    let decoded = decode(&value).expect("open vocabulary");
    let curated = serde_json::to_value(decoded.data).expect("facts");
    let r = &curated["remediation"]["recommendations"][0];
    assert_eq!(r["search_details"][2], json!({"kind":"future_kind"}));
    assert_eq!(r["search_details"][0]["operation"], "future_operation");
    assert_eq!(r["search_details"][0]["reasons"], json!(["future_reason"]));
    assert!(
        !serde_json::to_string(&curated)
            .expect("JSON")
            .contains("private_unused_id")
    );
    assert_eq!(r["search_details"][1]["witness"]["coordinate"], Value::Null);
    assert!(r["search_details"][1].get("used").is_none());
}
#[test]
fn audit_search_wire_rejects_malformed_known_forms_and_collection_pairs() {
    for (status, details) in [
        (Some(json!("retained")), None),
        (None, Some(json!([]))),
        (Some(Value::Null), Some(json!([]))),
        (Some(json!("retained")), Some(Value::Null)),
        (Some(json!("not_retained")), Some(json!([stopped()]))),
    ] {
        assert!(decode(&report(status, details)).is_err());
    }
    for detail in [
        Value::Null,
        json!([]),
        json!({}),
        json!({"kind":17}),
        json!({"kind":"unavailable","operation":"release","reasons":[],"witness":{}}),
        json!({"kind":"unavailable","operation":"release","reasons":[17],"witness":{}}),
        json!({"kind":"unavailable","stage":"release","reason":"lookup_failed","witness":{}}),
        json!({"kind":"stopped","stage":"leaf_evaluation","reason":"phase_deadline","witness":{"budget_scope":"local"}}),
    ] {
        assert!(decode(&report(Some(json!("retained")), Some(json!([detail])))).is_err());
    }
    for (used, allowed) in [
        (Some(json!(1)), None),
        (None, Some(json!(1))),
        (Some(json!(1)), Some(json!(0))),
        (Some(json!(-1)), Some(json!(1))),
        (Some(json!(0.5)), Some(json!(1))),
    ] {
        let mut detail = stopped();
        if let Some(used) = used {
            detail["used"] = used;
        }
        if let Some(allowed) = allowed {
            detail["allowed"] = allowed;
        }
        assert!(decode(&report(Some(json!("retained")), Some(json!([detail])))).is_err());
    }
    let mut detail = stopped();
    let mut witness: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/audit/search-witness.json"
    ))
    .expect("witness");
    witness["request_checks"][0]["clauses"][0]["effective_membership"] =
        json!({"status":"unchecked"});
    detail["witness"] = witness;
    assert!(decode(&report(Some(json!("retained")), Some(json!([detail])))).is_err());
}
