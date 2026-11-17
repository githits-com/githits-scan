use serde_json::{Value, json};

use super::SearchWitness;

#[test]
fn audit_search_witness_curates_nullable_typed_subset() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/audit/search-witness.json"
    ))
    .expect("authored witness fixture is valid JSON");
    let witness: SearchWitness = serde_json::from_value(fixture.clone())
        .expect("authored witness fixture matches the consumed subset");
    let roundtrip = serde_json::to_value(witness).expect("witness subset serializes");
    assert_eq!(roundtrip, fixture);

    let absent: SearchWitness =
        serde_json::from_value(json!({})).expect("all witness fields may be absent");
    let absent = serde_json::to_value(absent).expect("empty witness subset serializes");
    assert_eq!(absent, json!({}));

    let explicit_null: SearchWitness = serde_json::from_value(json!({"coordinate": null}))
        .expect("nullable coordinate accepts explicit null");
    assert_eq!(
        serde_json::to_value(explicit_null).expect("nullable coordinate serializes"),
        json!({"coordinate": null})
    );

    let invalid_cases = [
        (
            "nullable coordinate rejects a wrong type",
            json!({"coordinate": 17}),
        ),
        ("nonnull optional rejects null", json!({"current": null})),
        (
            "required nullable source coordinate cannot be omitted",
            json!({"source": {"path": "Cargo.lock"}}),
        ),
        (
            "nested consumed field rejects a wrong type",
            json!({"source": {"path": 17, "coordinate": null}}),
        ),
    ];
    for (case, input) in invalid_cases {
        assert!(
            serde_json::from_value::<SearchWitness>(input).is_err(),
            "{case}"
        );
    }

    let mut with_unknowns = fixture;
    with_unknowns["unconsumed_marker"] = json!("ignored");
    with_unknowns["source"]["unconsumed_marker"] = json!("ignored");
    let witness: SearchWitness = serde_json::from_value(with_unknowns)
        .expect("unconsumed root and nested fields are ignored");
    let curated = serde_json::to_value(witness).expect("curated witness serializes");
    assert!(curated.get("unconsumed_marker").is_none());
    assert!(curated["source"].get("unconsumed_marker").is_none());
}
