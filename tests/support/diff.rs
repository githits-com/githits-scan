//! Authored dependency-diff fixtures; never captured private repository data.
use serde_json::{Value, json};

pub fn files(head: bool) -> (&'static str, &'static str) {
    if head {
        (
            include_str!("../fixtures/diff/head/package.json"),
            include_str!("../fixtures/diff/head/package-lock.json"),
        )
    } else {
        (
            include_str!("../fixtures/diff/base/package.json"),
            include_str!("../fixtures/diff/base/package-lock.json"),
        )
    }
}

pub fn report() -> Value {
    let request = json!({"schema_version":1,"base":{"state":"supplied"},"head":{"state":"supplied"},
        "selection":{"groups":["all"],"unlocked_manifests":"resolve"},"analysis":{"advisories":true,"direct_reviews":true}});
    let snapshot = |side: &str| {
        json!({"side":side,"accepted_files":[],"sources":[],"resolution_units":[],
        "declarations":[{"id":format!("{side}:d1"),"declared_name":"helper","declaring_manifest":"package.json"}],
        "bindings":[],"occurrences":[],"coverage":{"scope":"selected_inputs_only","sources":[],"resolution":[],"excluded_dependencies":[]},
        "selection":{},"parser_versions":null,"reachability":[]})
    };
    let assessment = |status: &str| json!({"status":status,"occurrence_ids":[],"reasons":[]});
    let delta = |kind: &str| json!({"finding_id":"finding:1","kind":kind,"base":assessment("affected"),"head":assessment(if kind=="unchanged" {"affected"} else {"non_affecting"})});
    json!({"schema_version":1,"kind":"diff","accepted_request":request,"generated_at":"2026-11-09T12:00:00Z","outcome":"complete",
        "snapshots":{"base":snapshot("base"),"head":snapshot("head")},
        "changes":[{"id":"change:1","source_key":"package-lock.json","unit_key":["recorded_source","package-lock.json"],
            "package":{"registry":"npm","name":"minimist"},"ownership":"recorded","before_ids":[],"after_ids":[],
            "before_versions":["1.2.5"],"after_versions":["1.2.8"],"kind":"upgraded","pairing_basis":"unique_remaining_versions",
            "directness":{"base":"direct","head":"direct"},"retained":{"base":[],"head":[]},
            "retained_elsewhere":[{"source_key":"tools/package-lock.json","versions":["1.2.8"]}]}],
        "declaration_changes":[{"id":"declaration:1","kind":"changed","match_key":["package.json","helper"],"before_id":"base:d1","after_id":"head:d1",
            "binding_transitions":[{"source_key":"package-lock.json","package":{"registry":"npm","name":"minimist"},"declared_package":null,
                "base_target":{"package":{"registry":"npm","name":"minimist"},"version":"1.2.5"},
                "head_target":{"package":{"registry":"npm","name":"minimist"},"version":"1.2.8"},
                "before_versions":["1.2.5"],"after_versions":["1.2.8"],"recorded_before_versions":["1.2.5"],"resolved_before_versions":[],
                "base_status":"matched","head_status":"matched","review_eligibility":{"status":"eligible"}}]}],
        "advisories":{"status":"complete","data":{"assessments":[],
            "findings":[{"id":"finding:1","osv_id":"EXAMPLE-1","package":{"registry":"npm","name":"minimist"},"summary":"Illustrative advisory"}],
            "coordinate_transitions":[{"change_id":"change:1","deltas":[delta("fixed")]}],
            "exposures":[{"scope":{"kind":"source","source_key":"package-lock.json","qualifier":"recorded"},"deltas":[delta("fixed")],"coverage":{}},
                {"scope":{"kind":"repository_union","qualifier":"recorded"},"deltas":[delta("unchanged")],"coverage":{}}]},
            "coverage":{"coordinates":2,"checked":2,"unknown":0,"unsupported":0,"scope":"selected_inputs_only"}},
        "direct_reviews":{"status":"complete","data":[review()],"coverage":{"eligible":1,"completed":1,"returned":1,"not_assessed":0,"unavailable":0,"omitted":0}},
        "coverage":{"scope":"selected_inputs_only","partial":false},"summary":{"changed_source_package_contexts":1,"changed_declarations":1},
        "notices":["Synthetic comparison, not real package intelligence."]})
}

pub fn review() -> Value {
    json!({"id":"review:1","registry":"npm","name":"minimist","current_version":"1.2.5","target_version":"1.2.8", "declaration_change_ids":["declaration:1"],
        "source_keys":["package-lock.json"],"status":"complete","reason":null,"data":{
            "security":{"current":{"assessment_status":"affected","unknown_vulnerability_count":0},"target":{"assessment_status":"non_affecting","unknown_vulnerability_count":0}},
            "unknown_details":[],"changelog":{"entries":[{"version":"1.2.8","html_url":"https://example.invalid/releases/1.2.8","headline":"Illustrative migration note","signals":["migration"]}],
                "breaking_signals":["breaking"],"migration_signals":["migration"],"coverage":{"status":"partial","returned_entries":1,"total_entries":56,"truncated":true}}}})
}

pub fn exchanges(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut snapshot = super::jobs::snapshot("succeeded", "succeeded", 1);
    snapshot["kind"] = "diff".into();
    snapshot["format"] = "json".into();
    vec![
        super::jobs::accept_response(),
        super::jobs::events_response(&[snapshot]),
        super::response("200 OK", &[("Content-Type", "application/json")], bytes),
    ]
}
