//! Reader-facing acceptance examples, authored independently of the formatter.
use super::*;

fn incomplete_usage() -> serde_json::Value {
    let mut v = fixture::report();
    v["changes"][0]["source_key"] = "bun.lock".into();
    v["changes"][0]["package"]["name"] = "@napi-rs/triples".into();
    v["changes"][0]["before_versions"] = json!(["1.1.0"]);
    v["changes"][0]["after_versions"] = json!(["1.2.0"]);
    v["changes"][0]["retained_elsewhere"] = json!([]);
    v["changes"][0]["directness"] = json!({"base":"unknown","head":"unknown"});
    v["changes"][0]["before_ids"] = json!(["same-occurrence"]);
    v["changes"][0]["after_ids"] = json!(["same-occurrence"]);
    let cause = json!({"code":"root_dependency_coverage_incomplete",
        "message":"The root's direct dependency list is incomplete: a requirement has no selected target.",
        "source_key":"bun.lock","manifest_path":"package.json","coverage_state":"incomplete",
        "coverage_reasons":["untargeted_requirement"]});
    for side in ["base", "head"] {
        v["snapshots"][side]["occurrences"] = json!([{"id":"same-occurrence","directness":"unknown",
            "directness_proof_ids":["same-proof"]}]);
        v["snapshots"][side]["reachability"] = json!([{"id":"same-proof","reasons":[cause]}]);
    }
    v["declaration_changes"] = json!([]);
    v["advisories"]["data"] = json!({"findings":[],"coordinate_transitions":[],"exposures":[]});
    v["direct_reviews"]["data"] = json!([]);
    v["notices"] = json!([]);
    v
}

#[test]
fn diff_friendly_output_explains_dependency_usage() {
    let text = rendered(&incomplete_usage(), Format::Human);
    assert_eq!(
        text,
        concat!(
            "Dependency changes: base → head\n",
            "This compares the supplied dependency files, not an observed installation.\n",
            "\nFile: bun.lock\n\n",
            "- @napi-rs/triples: 1.1.0 → 1.2.0\n",
            "- Scan could not tell whether @napi-rs/triples is used directly or through another package in either revision.\n",
            "  - Not every dependency declared in package.json could be matched to an entry in bun.lock. Review those files to confirm how the package is used.\n",
        )
    );
    let markdown = rendered(&incomplete_usage(), Format::Markdown);
    assert!(markdown.contains("### File&#58; bun&#46;lock"));
    assert!(markdown.contains("@&#8203;napi&#45;rs/triples is used directly"));
    for text in [&text, &markdown] {
        for internal in [
            "unknown",
            "root_dependency",
            "untargeted",
            "same-proof",
            "coverage",
            "target",
            "recorded",
            "1 eligible",
        ] {
            assert!(!text.contains(internal), "leaked {internal}: {text}");
        }
    }
}

#[test]
fn diff_friendly_output_groups_shared_file_reasons() {
    let mut v = incomplete_usage();
    let mut other = v["changes"][0].clone();
    other["id"] = "other-change".into();
    other["package"]["name"] = "other-package".into();
    v["changes"].as_array_mut().expect("changes").push(other);
    let text = rendered(&v, Format::Human);
    assert_eq!(text.matches("Not every dependency declared").count(), 1);
    assert!(
        text.contains("@napi-rs/triples, other-package are used directly"),
        "{text}"
    );
    assert!(!text.contains("see above"));
}

#[test]
fn diff_friendly_output_keeps_security_risks_distinct() {
    let text = rendered(&fixture::report(), Format::Human);
    assert!(text.contains("no longer affected by EXAMPLE-1"), "{text}");
    assert!(text.contains("still affected by EXAMPLE-1"), "{text}");
    for internal in [
        "repository union",
        "coordinate",
        "non_affecting",
        "Review tuples",
        "Coordinate checks",
        "1/56",
        "Breaking signals",
        "Entry signals",
    ] {
        assert!(!text.contains(internal), "leaked {internal}: {text}");
    }
    assert!(text.contains("Release notes are incomplete"));
    assert!(text.contains("may require changes to your code"));
    assert!(text.contains("Illustrative migration note"));
}

#[test]
fn diff_friendly_output_names_file_problems() {
    let mut v = incomplete_usage();
    v["snapshots"]["head"]["coverage"]["resolution"] = json!([{
        "path":"bun.lock","reason":"required_input_not_supplied","required_path":"packages/worker/package.json"}]);
    v["snapshots"]["head"]["coverage"]["mismatches"] = json!([{
        "path":"bun.lock","declaration_path":"package.json","name":"helper",
        "requested_requirement":"^2.0","locked_versions":["1.0.0"],"reason":"locked_version_does_not_satisfy_request"}]);
    let text = rendered(&v, Format::Human);
    assert!(
        text.contains(
            "packages/worker/package.json was not among the files read from that revision"
        ),
        "{text}"
    );
    assert!(text.contains("Check that it exists in that revision and is not excluded from Scan."));
    assert!(
        text.contains("helper requires ^2.0 in package.json, but bun.lock lists 1.0.0"),
        "{text}"
    );
    assert!(!text.contains("required_input_not_supplied"));
    assert!(!text.contains("locked_version_does_not_satisfy_request"));
}

#[test]
fn diff_friendly_output_preserves_multiple_file_blockers() {
    let mut v = incomplete_usage();
    v["snapshots"]["base"]["reachability"][0]["reasons"][0]["coverage_reasons"] = json!([
        "untargeted_requirement",
        "inventory_only",
        "future_native_reason"
    ]);
    let text = rendered(&v, Format::Human);
    assert!(text.contains("Not every dependency declared in package.json"));
    assert!(text.contains("without enough information about which package uses which"));
    assert!(text.contains("did not supply a further reason"));
    assert!(!text.contains("future_native_reason"));
    assert!(!text.contains("inventory_only"));
    assert!(text.contains("earlier revision"));
    assert!(text.contains("later revision"));
}

#[test]
fn diff_friendly_output_explains_review_security_limitations() {
    for (status, expected) in [
        ("affected", "is affected by security advisories"),
        (
            "unknown",
            "could not determine whether security advisories apply",
        ),
        ("not_assessed", "was not checked for security advisories"),
        ("unsupported", "the service does not support this package"),
        ("future_security", "has no usable security conclusion"),
    ] {
        let mut v = fixture::report();
        v["direct_reviews"]["data"][0]["data"]["security"]["current"]["assessment_status"] =
            status.into();
        v["direct_reviews"]["data"][0]["data"]["security"]["current"]["unknown_vulnerability_count"] =
            2.into();
        let text = rendered(&v, Format::Human);
        assert!(text.contains(expected), "{text}");
        assert!(text.contains("could not determine whether some advisories apply"));
        for raw in [
            "unknown",
            "not_assessed",
            "future_security",
            "2 unknown",
            "non_affecting",
        ] {
            assert!(!text.contains(raw), "{raw}: {text}");
        }
    }
}

#[test]
fn diff_friendly_output_explains_legacy_review_ineligibility() {
    let mut v = fixture::report();
    v["declaration_changes"][0]["binding_transitions"][0]["review_eligibility"] =
        json!({"status":"not_applicable","reason":"base_declaration_mismatch"});
    let text = rendered(&v, Format::Human);
    assert!(text.contains(
        "No upgrade review: the earlier package details do not match the dependency declaration."
    ));
    assert!(!text.contains("base_declaration_mismatch"));
    assert!(!text.contains("review target"));
}

#[test]
fn diff_friendly_output_preserves_plural_source_problems() {
    let mut v = incomplete_usage();
    v["snapshots"]["base"]["coverage"]["sources"] = json!([
        {"path":"other.lock","reasons":["dependency_scope_unknown"]},
        {"path":"third.lock","reason":"lockfile_not_supplied","reasons":["dependency_scope_unknown","dependency_scope_unknown"]}]);
    let text = rendered(&v, Format::Human);
    assert!(
        text.contains("packages from other.lock in the earlier revision belong in this comparison"),
        "{text}"
    );
    assert_eq!(text.matches("packages from third.lock").count(), 1);
    assert!(text.contains(
        "Could not check third.lock in the earlier revision because its lockfile was not read"
    ));
    assert!(!text.contains("dependency_scope_unknown"));
    assert!(!text.contains("service did not supply a reason"));
}

#[test]
fn diff_friendly_output_combines_shared_reasons_among_distinct_blockers() {
    let mut v = incomplete_usage();
    v["snapshots"]["base"]["reachability"][0]["reasons"]
        .as_array_mut()
        .expect("reasons")
        .push(json!({
        "code":"declaration_binding_missing","message":"internal diagnostic text",
        "source_key":"bun.lock","manifest_path":"package.json","dependency_name":"helper"}));
    let text = rendered(&v, Format::Human);
    assert_eq!(
        text.matches("Not every dependency declared in package.json")
            .count(),
        1
    );
    assert!(text.contains("in either revision"));
    assert!(text.contains("in the earlier revision"));
    assert!(!text.contains("in the later revision"));
    assert!(text.contains("did not return a package match for helper in package.json"));
    assert!(!text.contains("internal diagnostic text"));
}

#[test]
fn diff_friendly_output_does_not_treat_new_declarations_as_missing_matches() {
    let mut v = fixture::report();
    let declaration = &mut v["declaration_changes"][0];
    declaration["before_id"] = serde_json::Value::Null;
    declaration["kind"] = "added".into();
    let binding = &mut declaration["binding_transitions"][0];
    binding["before_versions"] = json!([]);
    binding["base_status"] = "not_recorded".into();
    binding["review_eligibility"] = json!({"status":"not_applicable","reason":"direct_addition"});
    let text = rendered(&v, Format::Human);
    assert!(text.contains("not declared → 1.2.8"), "{text}");
    assert!(text.contains("this dependency was added"));
    assert!(!text.contains("no package entry was found"));
    assert!(!text.contains("could not be matched to the dependency declaration"));
}

#[test]
fn diff_friendly_output_does_not_equate_unidentified_declarations_with_absence() {
    for kind in ["changed", "ambiguous", "future_kind"] {
        let mut v = fixture::report();
        v["declaration_changes"][0]["kind"] = kind.into();
        v["declaration_changes"][0]["before_id"] = serde_json::Value::Null;
        let binding = &mut v["declaration_changes"][0]["binding_transitions"][0];
        binding["before_versions"] = json!([]);
        binding["base_status"] = "ambiguous".into();
        binding["review_eligibility"] =
            json!({"status":"not_applicable","reason":"binding_not_matched"});
        let text = rendered(&v, Format::Human);
        assert!(
            text.contains(
                "did not identify a unique dependency declaration in the earlier revision"
            ),
            "{text}"
        );
        assert!(text.contains("matches more than one possible package entry"));
        assert!(!text.contains("not declared"));
        assert!(!text.contains("no longer declared"));
        assert!(!text.contains("future_kind"));
    }
    let mut v = fixture::report();
    v["declaration_changes"][0] = json!({"id":"ambiguous-change","kind":"ambiguous","before_id":null,"after_id":null,"binding_transitions":[]});
    let text = rendered(&v, Format::Human);
    assert!(text.contains("could not distinguish matching declarations"));
    assert!(!text.contains("Changed a dependency whose name and declaring file were not supplied"));
}

fn assert_security_section_warning_order(text: &str) {
    let heading = text.find("Security advisories").expect("heading");
    let warning = text
        .find("Some security checks could not be completed")
        .expect("warning");
    assert!(
        heading < warning,
        "warning must belong to the security section: {text}"
    );
}

#[test]
fn diff_friendly_output_keeps_security_limitations_without_findings() {
    for only_clear_rows in [false, true] {
        let mut v = fixture::report();
        v["advisories"]["status"] = "partial".into();
        v["advisories"]["reason"] = "deadline".into();
        if only_clear_rows {
            v["advisories"]["data"]["coordinate_transitions"][0]["deltas"][0]["kind"] =
                "non_affecting".into();
            v["advisories"]["data"]["exposures"] = json!([]);
        } else {
            v["advisories"]["data"] =
                json!({"findings":[],"coordinate_transitions":[],"exposures":[]});
        }
        v["advisories"]["coverage"] =
            json!({"checked":0,"coordinates":2,"unknown":1,"unsupported":1});
        let text = rendered(&v, Format::Human);
        assert!(
            text.contains(
                "Some security checks could not be completed before the comparison's time limit"
            ),
            "{text}"
        );
        assert!(text.contains("service does not support checking some package versions"));
        if only_clear_rows {
            assert_security_section_warning_order(&text);
            assert_security_section_warning_order(&rendered(&v, Format::Markdown));
        }
        for raw in [
            "unknown 1",
            "unsupported 1",
            "Advisories: partial",
            "non_affecting",
        ] {
            assert!(!text.contains(raw));
        }
    }
}

#[test]
fn diff_friendly_output_shows_joined_binding_causes_without_status_echoes() {
    let mut v = fixture::report();
    v["declaration_changes"][0]["binding_transitions"][0]["base_status"] =
        "version_mismatch".into();
    v["snapshots"]["base"]["bindings"] = json!([{"declaration_id":"base:d1","source_key":"package-lock.json","reasons":[{
        "code":"version_mismatch","message":"internal mismatch text","source_key":"package-lock.json","manifest_path":"package.json","dependency_name":"helper"}]}]);
    let text = rendered(&v, Format::Human);
    assert_eq!(
        text.matches("the listed package versions do not satisfy the declared requirement")
            .count(),
        1,
        "{text}"
    );
    assert!(text.contains("For helper in package.json"));
    v["snapshots"]["base"]["bindings"][0]["reasons"][0]["code"] =
        "authored_request_not_linked".into();
    let text = rendered(&v, Format::Human);
    assert!(text.contains("could not match helper in package.json"));
    assert!(text.contains("the listed package versions do not satisfy the declared requirement"));
}

#[test]
fn diff_friendly_output_groups_multiple_reasons_under_one_package_heading() {
    let mut v = incomplete_usage();
    for side in ["base", "head"] {
        v["snapshots"][side]["reachability"][0]["reasons"].as_array_mut().expect("reasons").push(json!({
            "code":"declaration_binding_missing","message":"internal diagnostic text","source_key":"bun.lock","manifest_path":"tools/package.json","dependency_name":"helper"}));
    }
    let text = rendered(&v, Format::Human);
    assert_eq!(
        text.matches("Scan could not tell whether @napi-rs/triples")
            .count(),
        1,
        "{text}"
    );
    assert!(text.contains("Not every dependency declared in package.json"));
    assert!(text.contains("helper in tools/package.json"));
}

#[test]
fn diff_friendly_output_does_not_assign_comparison_wide_problems_to_a_revision() {
    let mut v = incomplete_usage();
    v["coverage"] = json!({"partial":true,"resolution":[{"path":"bun.lock","reason":"required_input_not_supplied","required_path":"package.json"}],
        "reachability":[{"complete":false,"manifest_path":"package.json","source_key":"bun.lock","basis":"declaration_and_root_graph"}]});
    let text = rendered(&v, Format::Human);
    assert!(text.contains("bun.lock in this comparison"), "{text}");
    assert!(text.contains("Some dependency information was unavailable in this comparison"));
    assert!(!text.contains("compared revision."));
    assert!(!text.contains("from that revision"));
    assert!(text.contains("revision-specific explanation"));
}

#[test]
fn diff_friendly_output_does_not_blame_format_for_an_unreturned_review() {
    for (status, reason) in [
        ("not_assessed", None),
        ("unavailable", None),
        ("not_assessed", Some("future_reason")),
        ("unavailable", Some("future_reason")),
    ] {
        let mut v = fixture::report();
        v["direct_reviews"]["status"] = "partial".into();
        let review = &mut v["direct_reviews"]["data"][0];
        review["status"] = status.into();
        review["reason"] = reason.map_or(serde_json::Value::Null, serde_json::Value::from);
        review["data"] = serde_json::Value::Null;
        for format in [Format::Human, Format::Markdown] {
            let text = rendered(&v, format);
            assert!(
                text.contains("No usable upgrade review was returned"),
                "{text}"
            );
            assert!(
                text.contains("The service supplied no reason this version of Scan can display")
            );
            assert!(text.contains(
                "Review the release notes and security advisories before accepting this upgrade"
            ));
            assert!(!text.contains("format this version supports"));
            assert!(!text.contains("future_reason"));
        }
    }
}
