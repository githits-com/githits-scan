use super::*;
use crate::api::diff::Report;
use crate::test_support::diff as fixture;
use serde_json::json;

fn rendered(value: &serde_json::Value, format: Format) -> String {
    let report = Report::from_bytes(serde_json::to_vec(value).expect("json")).expect("report");
    let mut out = Vec::new();
    render::write(&report, format, ("base", "head"), &mut out).expect("render");
    String::from_utf8(out).expect("text")
}

#[test]
fn diff_render_preserves_source_transition_retained_versions_and_advisory_scopes() {
    let text = rendered(&fixture::report(), Format::Human);
    for expected in [
        "File: package-lock.json",
        "1.2.5 → 1.2.8",
        "1.2.8 also appears in tools/package-lock.json",
        "minimist in package-lock.json: no longer affected",
        "the supplied project files: still affected",
        "helper in package.json",
        "may require changes to your code",
        "release notes flag migration work",
        "Release notes are incomplete",
        "release notes",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert!(!text.contains("full changelog"));
}

#[test]
fn diff_render_unknown_partial_and_nullable_evidence_is_explicit() {
    let mut value = fixture::report();
    value["outcome"] = "partial".into();
    value["changes"][0]["directness"]["base"] = "unknown".into();
    value["changes"][0]["ownership"] = "auxiliary".into();
    value["declaration_changes"][0]["binding_transitions"][0]["base_target"] =
        serde_json::Value::Null;
    value["declaration_changes"][0]["binding_transitions"][0]["review_eligibility"] =
        json!({"status":"not_applicable","reason":"base_declaration_mismatch"});
    value["advisories"] = json!({"status":"future_evidence","data":["different"]});
    let text = rendered(&value, Format::Human);
    for expected in [
        "Some checks could not be completed",
        "The service did not return its explanation",
        "secondary lockfile",
        "earlier package details do not match",
        "Security advisory checks could not be returned",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    for raw in [
        "unknown",
        "auxiliary",
        "base_declaration_mismatch",
        "future_evidence",
        "review target",
    ] {
        assert!(!text.contains(raw), "{raw}: {text}");
    }
}

#[test]
fn diff_render_keeps_all_reviews_and_distinct_service_qualifications() {
    let mut value = fixture::report();
    value["direct_reviews"]["data"] = json!(
        (0..31)
            .map(|i| {
                let mut r = fixture::review();
                r["name"] = format!("package-{i}").into();
                r
            })
            .collect::<Vec<_>>()
    );
    value["direct_reviews"]["coverage"] = json!({"eligible":31,"completed":31,"returned":31,"not_assessed":0,"unavailable":0,"omitted":0});
    value["notices"] = json!((0..16).map(|i| format!("notice-{i}")).chain([
        "Recorded input comparison, not an observed installation or solver ancestry.".into(),
        "Both sides use current shared advisory evidence; this is not historical advisory knowledge.".into(),
        "notice-15".into(),
    ]).collect::<Vec<_>>());
    let text = rendered(&value, Format::Human);
    assert!(text.contains("Upgrade review: package-30"));
    assert_eq!(text.matches("notice-15").count(), 1);
    assert_eq!(text.matches("today's security information").count(), 1);
    assert!(!text.contains("solver ancestry"));
    assert!(!text.contains("shared advisory evidence"));
    assert_eq!(
        text.matches("The earlier version is affected by security advisories")
            .count(),
        31
    );
}

#[test]
fn diff_markdown_escapes_payloads_and_keeps_only_safe_returned_links() {
    let mut value = fixture::report();
    value["changes"][0]["package"]["name"] =
        "evil|![img](https://evil.invalid) @team #12 <script> ~~hidden~~\nname".into();
    value["direct_reviews"]["data"][0]["data"]["changelog"]["entries"][0]["html_url"] =
        "https://user:password@example.invalid/leak".into();
    let text = rendered(&value, Format::Markdown);
    assert!(!text.contains("![img]"));
    assert!(!text.contains("|!["));
    assert!(!text.contains("<script>"));
    assert!(!text.contains("@team"));
    assert!(!text.contains(" #12"));
    assert!(!text.contains("password"));
    assert!(text.contains("@&#8203;team"));
    assert!(text.contains("#&#8203;12"));
    assert!(text.contains("\n  - This release&#45;note link was omitted"));
    assert!(!text.contains("~~hidden~~"));
    assert!(text.contains("&#126;&#126;hidden&#126;&#126;"));
}

#[test]
fn diff_links_preserve_queries_and_do_not_escape_returned_url_tokens() {
    let mut value = fixture::report();
    value["direct_reviews"]["data"][0]["data"]["changelog"]["entries"][0]["html_url"] =
        "https://example.invalid/entry?a=1&b=2#release".into();
    let text = rendered(&value, Format::Markdown);
    assert!(text.contains("<https://example.invalid/entry?a=1&b=2#release>"));
}

#[test]
fn diff_future_schema_human_and_markdown_decline_but_json_is_exact() {
    let bytes = br#" {"schema_version":99,"kind":"diff","new":true} "#.to_vec();
    let report = Report::from_bytes(bytes.clone()).expect("future");
    for format in [Format::Human, Format::Markdown] {
        let mut out = Vec::new();
        render::write(&report, format, ("a", "b"), &mut out).expect("render");
        let text = String::from_utf8(out).expect("text");
        assert!(text.contains("Scan cannot explain this report"));
        assert!(!text.contains("No reported"));
    }
    let mut out = Vec::new();
    render::write(&report, Format::Json, ("a", "b"), &mut out).expect("JSON");
    assert_eq!(out, bytes);
}

#[test]
fn diff_compact_changelog_keeps_flagged_entries_and_explains_display_limit() {
    let mut value = fixture::report();
    let entries=(0..7).map(|i|json!({"version":format!("1.2.{i}"),"headline":format!("entry-{i}"),"html_url":format!("https://example.invalid/{i}"),"signals":if i==6 {vec!["migration"]} else {vec![]}})).collect::<Vec<_>>();
    value["direct_reviews"]["data"][0]["data"]["changelog"]["entries"] = json!(entries);
    let text = rendered(&value, Format::Human);
    assert!(text.contains("entry-0"));
    assert!(text.contains("entry-2"));
    assert!(text.contains("entry-6"));
    assert!(!text.contains("entry-4"));
    assert!(text.contains("Additional release notes are available in the JSON report"));
}

#[test]
fn diff_markdown_keeps_all_release_notes_and_sparse_entry_identity() {
    let mut value = fixture::report();
    let headline = "safe".repeat(100);
    let entries = (0..7).map(|i| json!({
        "version": format!("1.2.{i}"), "headline": format!("entry {i}: {headline} @team <script>"),
        "html_url": format!("https://example.invalid/{i}"), "signals": []
    })).collect::<Vec<_>>();
    let changelog = &mut value["direct_reviews"]["data"][0]["data"]["changelog"];
    changelog["entries"] = json!(entries);
    changelog["coverage"]["returned_entries"] = json!(7);
    changelog["entries"][1] = json!({"version":"1.2.1","signals":["migration"]});
    changelog["entries"][6] =
        json!({"signals":[],"html_url":"https://user:secret@example.invalid"});
    changelog["entries"]
        .as_array_mut()
        .expect("entries")
        .push(json!({"signals":[]}));
    changelog["coverage"]["returned_entries"] = json!(8);
    let markdown = rendered(&value, Format::Markdown);
    for i in [0, 2, 3, 4, 5] {
        assert!(markdown.contains(&format!("entry {i}&#58; {headline}")));
        assert!(markdown.contains(&format!("<https://example.invalid/{i}>")));
    }
    assert!(markdown.contains("1&#46;2&#46;1&#58; Release&#45;note summary was not supplied"));
    assert!(markdown.contains("release version not supplied&#58; Release&#45;note summary"));
    assert!(markdown.contains("Release notes are incomplete"));
    assert!(markdown.contains("@&#8203;team &lt;script&gt;"));
    assert!(!markdown.contains("secret"));
    assert_eq!(markdown.matches("summary was not supplied").count(), 3);
    assert!(!markdown.contains("Additional release notes are available"));
    let human = rendered(&value, Format::Human);
    assert!(human.contains("1.2.1: Release-note summary was not supplied"));
    assert!(!human.contains("entry 4"));
}

#[test]
fn diff_partial_counts_name_unqualified_occurrences_and_reachability() {
    let mut value = fixture::report();
    value["outcome"] = "partial".into();
    value["advisories"]["data"]["exposures"][0]["coverage"] = json!({"base":{"inventory":"complete","assessment":"partial","checked":2,"coordinates":2,"unqualified_occurrences":1}});
    value["snapshots"]["base"]["coverage"]["reachability"] = json!([{"complete":false,"manifest_path":"Cargo.toml","source_key":"Cargo.lock","basis":"declaration_and_root_graph"}]);
    let text = rendered(&value, Format::Human);
    assert!(text.contains("some package entries could not be identified for security checks"));
    assert!(text.contains("dependencies in Cargo.toml connect to the packages in Cargo.lock"));
}

#[test]
fn diff_resolution_gap_names_the_required_input_without_guessing_missing_paths() {
    let mut value = fixture::report();
    value["snapshots"]["base"]["coverage"]["resolution"] = json!([
        {"path":"package-lock.json","reason":"required_input_not_supplied",
         "required_path":"packages/worker/package.json"},
        {"path":"other.lock","reason":"required_input_not_supplied"},
        {"path":"future.lock","reason":"future_reason","required_path":null}
    ]);
    for format in [Format::Human, Format::Markdown] {
        let text = rendered(&value, format);
        assert!(
            text.contains("was not among the files read from that revision"),
            "{text}"
        );
        assert!(text.contains("The service did not identify the missing file"));
        assert!(text.contains("this version of Scan can explain"));
        assert!(text.contains("packages/worker/package"));
        for raw in [
            "required_input_not_supplied",
            "future_reason",
            "required&#95;input",
        ] {
            assert!(!text.contains(raw));
        }
    }
}

#[test]
fn diff_added_scope_uses_head_proof_without_qualifying_absent_base() {
    let mut value = fixture::report();
    let row = &mut value["changes"][0];
    row["kind"] = "added".into();
    row["before_versions"] = json!([]);
    row["directness"] = json!({"base":"unknown","head":"transitive"});
    let text = rendered(&value, Format::Human);
    assert!(text.contains("added 1.2.8 (through another package)"));
    assert!(!text.contains("unknown → transitive"));
}

#[test]
fn diff_mismatched_binding_names_recorded_base_without_inventing_a_review_target() {
    let mut value = fixture::report();
    let b = &mut value["declaration_changes"][0]["binding_transitions"][0];
    b["before_versions"] = json!([]);
    b["base_target"] = serde_json::Value::Null;
    b["base_status"] = "version_mismatch".into();
    let text = rendered(&value, Format::Human);
    assert!(text.contains("no matching version → 1.2.8"));
    assert!(text.contains("The earlier file lists 1.2.5, but these versions could not be matched to the dependency declaration"));
}

#[test]
fn diff_unfamiliar_review_data_stays_raw_and_unassessed() {
    for changed_shape in [false, true] {
        let mut value = fixture::report();
        let r = &mut value["direct_reviews"]["data"][0];
        r["status"] = "future_review".into();
        if changed_shape {
            r["data"] = json!({"security":{"current":{"new_shape":true}}});
        }
        let text = rendered(&value, Format::Human);
        assert!(!text.contains("future_review"));
        assert!(text.contains("No usable upgrade review was returned"));
        assert!(!text.contains("Direct security target:"));
        assert!(!text.contains("changelog entry:"));
        let report = Report::from_bytes(serde_json::to_vec(&value).expect("json")).expect("report");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(report.bytes()).expect("JSON"),
            value
        );
    }
}

#[test]
fn diff_non_affecting_and_empty_advisory_rows_do_not_add_bookkeeping() {
    let mut value = fixture::report();
    value["advisories"]["data"]["coordinate_transitions"][0]["deltas"][0]["kind"] =
        "non_affecting".into();
    let text = rendered(&value, Format::Human);
    assert!(!text.contains("minimist in package-lock.json: no longer affected"));
    assert!(!text.contains("non_affecting"));
    assert!(text.contains("still affected by EXAMPLE-1"));
    value["advisories"]["data"]["coordinate_transitions"][0]["deltas"] = json!([]);
    let text = rendered(&value, Format::Human);
    assert!(!text.contains("no advisory deltas"));
    assert!(text.contains("still affected by EXAMPLE-1"));
}

#[test]
fn diff_open_review_detail_drift_preserves_json_and_qualifies_human_output() {
    let mut value = fixture::report();
    value["direct_reviews"]["data"][0]["data"]["security"]["current"] =
        json!({"assessment_status":"non_affecting","new_count_field":0});
    let bytes = serde_json::to_vec_pretty(&value).expect("json");
    let report = Report::from_bytes(bytes.clone()).expect("open review detail");
    let mut out = Vec::new();
    render::write(&report, Format::Json, ("base", "head"), &mut out).expect("json");
    assert_eq!(out, bytes);
    for format in [Format::Human, Format::Markdown] {
        let text = rendered(&value, format);
        assert!(text.contains("Scan cannot display this upgrade review"));
        assert!(!text.contains("Direct security current:"));
        assert!(!text.contains("changelog entry:"));
    }
}

#[test]
fn diff_markdown_separates_lists_summaries_and_coverage_qualifications() {
    let mut value = fixture::report();
    value["outcome"] = "partial".into();
    let text = rendered(&value, Format::Markdown);
    assert!(text.contains("### Security advisories"));
    assert!(text.contains("### Upgrade review"));
    assert!(text.contains("\n- Files"));
    assert!(text.contains("\n  - 1&#46;2&#46;8 also appears"));
    assert!(!text.contains("Review tuples"));
    assert!(!text.contains("Coordinate checks"));
}

#[test]
fn diff_excluded_dependency_keeps_its_version_and_all_source_paths() {
    let mut value = fixture::report();
    value["snapshots"]["base"]["coverage"]["excluded_dependencies"] = json!([
        {"name":"local-helper","version":"0.1.0","paths":["Cargo.lock","tools/Cargo.lock"],"reason":"non_registry_source"}
    ]);
    let text = rendered(&value, Format::Human);
    assert!(text.contains("local-helper 0.1.0"));
    assert!(text.contains("Cargo.lock, tools/Cargo.lock"));
    assert!(text.contains("comes from outside a public package registry"));
    assert!(!text.contains("non_registry_source"));
}

mod explanations;

mod friendly;

mod realistic;

#[path = "tests/git_coverage.rs"]
mod git_coverage;
