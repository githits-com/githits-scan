//! License policy behavior, without filesystem or network access.

use super::*;

fn policy(allow: &[&str], exceptions: &[(&str, &str)]) -> Policy {
    Policy::new(&Licenses {
        allow: allow.iter().map(|s| (*s).to_owned()).collect(),
        exceptions: exceptions
            .iter()
            .map(|(purl, reason)| Exception::Package {
                purl: (*purl).to_owned(),
                reason: (*reason).to_owned(),
            })
            .collect(),
    })
    .expect("valid policy")
}

fn document(components: &str) -> Vec<u8> {
    format!(
            r#"{{"bomFormat":"CycloneDX","specVersion":"1.7","properties":[{{"name":"githits:completeness","value":"recorded_lockfile_inventory"}}],"components":[{components}]}}"#
        )
        .into_bytes()
}

fn component(bom_ref: &str, name: &str, version: &str, purl: &str, licenses: &str) -> String {
    format!(
        r#"{{"bom-ref":"{bom_ref}","name":"{name}","version":"{version}","purl":"{purl}","licenses":[{licenses}],"properties":[{{"name":"githits:record_kind","value":"locked_package"}}]}}"#
    )
}

#[test]
fn policy_rejects_guessing_and_scoped_exceptions() {
    for entry in [
        "M1T",
        "gnu gpl v2",
        "apache",
        "MIT OR Apache-2.0",
        "Unlicense/MIT",
    ] {
        assert_eq!(
            Policy::new(&Licenses {
                allow: vec![entry.into()],
                exceptions: vec![]
            })
            .err(),
            Some(PolicyError::Allow { index: 0 })
        );
    }
    for purl in [
        "",
        "cargo/name",
        "pkg:cargo/",
        "pkg:cargo/name@1",
        "pkg:cargo/name?x=y",
        "pkg:cargo/name#part",
    ] {
        assert_eq!(
            Policy::new(&Licenses {
                allow: vec![],
                exceptions: vec![Exception::Package {
                    purl: purl.into(),
                    reason: "reviewed".into()
                }]
            })
            .err(),
            Some(PolicyError::Exception { index: 0 })
        );
    }
    let _ = policy(
        &[
            "MIT",
            "GPL-2.0+",
            "Apache-2.0 WITH LLVM-exception",
            "LicenseRef-Custom",
        ],
        &[
            ("pkg:npm/%40scope/name", "reviewed"),
            ("pkg:npm/@scope/name", "reviewed"),
        ],
    );
}

#[test]
fn explicit_license_syntax_is_never_guessed() {
    for text in [
        "gnu gpl v2",
        "apache",
        "gpl",
        "mit",
        "Unlicense/MIT",
        "MIT And Apache-2.0",
    ] {
        assert!(parse(text).is_err(), "guessed {text}");
    }
    for text in [
        "MIT",
        "MIT or Apache-2.0",
        "MIT OR Apache-2.0",
        "Apache-2.0 with LLVM-exception",
        "GPL-2.0+",
        "GPL-2.0",
        "LicenseRef-Custom",
    ] {
        assert!(parse(text).is_ok(), "rejected {text}");
    }
    let report = check(
        &document(&component(
            "custom",
            "custom",
            "1",
            "pkg:cargo/custom@1",
            r#"{"expression":"LicenseRef-Custom"}"#,
        )),
        &policy(&["LicenseRef-Custom"], &[]),
    )
    .expect("report");
    assert_eq!(report.violations, Vec::<Violation>::new());
    assert_eq!(
        check(
            &document(&component(
                "x",
                "x",
                "1",
                "pkg:cargo/x@1",
                r#"{"expression":"MIT"}"#
            )),
            &policy(&[], &[])
        )
        .expect("deny all")
        .violations
        .len(),
        1
    );
}

#[test]
fn nested_inventory_checks_all_types_and_children_of_skipped_nodes() {
    let value = serde_json::json!({"bomFormat":"CycloneDX", "specVersion":"1.4", "components":[{
        "name":"project", "properties":[{"name":"githits:record_kind","value":"manifest"}], "components":[{
            "name":"local", "properties":[{"name":"githits:source_kind","value":"LOCKED_PACKAGE_SOURCE_KIND_LOCAL"}], "components":[
                {"name":"forbidden", "type":"library", "licenses":[{"expression":"GPL-3.0-only"}]},
                {"name":"file", "type":"file"},
                {"name":"permitted", "type":"library", "licenses":[{"expression":"MIT"}]}
            ]
        }]
    }]});
    let report = check(
        &serde_json::to_vec(&value).expect("json"),
        &policy(&["MIT"], &[]),
    )
    .expect("report");
    assert_eq!((report.components, report.local_packages), (3, 1));
    assert_eq!(
        report
            .violations
            .iter()
            .map(|v| (v.name.as_str(), v.reason))
            .collect::<Vec<_>>(),
        [
            ("file", Reason::NoLicense),
            ("forbidden", Reason::NotAllowed)
        ]
    );
}

#[test]
fn malformed_nested_evidence_is_rejected_even_under_skipped_nodes() {
    for child in [
        serde_json::json!({"components":{}}),
        serde_json::json!({"components":[false]}),
        serde_json::json!({"components":[{"licenses":[{}]}]}),
    ] {
        let mut parent = child;
        parent["properties"] =
            serde_json::json!([{"name":"githits:record_kind", "value":"manifest"}]);
        let value = serde_json::json!({"bomFormat":"CycloneDX", "components":[parent]});
        assert!(matches!(
            check(
                &serde_json::to_vec(&value).expect("json"),
                &policy(&["MIT"], &[])
            ),
            Err(DocumentError::Malformed(_))
        ));
    }
}

#[test]
fn evaluates_or_and_and_with_against_the_allow_list() {
    let policy = policy(&["MIT", "Apache-2.0 WITH LLVM-exception"], &[]);
    let components = [
        component(
            "a",
            "either",
            "1",
            "pkg:cargo/either@1",
            r#"{"expression":"MIT OR GPL-3.0-only"}"#,
        ),
        component(
            "b",
            "both",
            "1",
            "pkg:cargo/both@1",
            r#"{"expression":"MIT AND GPL-3.0-only"}"#,
        ),
        component(
            "c",
            "exception",
            "1",
            "pkg:cargo/exception@1",
            r#"{"expression":"Apache-2.0 WITH LLVM-exception"}"#,
        ),
        component(
            "d",
            "bare",
            "1",
            "pkg:cargo/bare@1",
            r#"{"expression":"Apache-2.0"}"#,
        ),
        component(
            "e",
            "byid",
            "1",
            "pkg:cargo/byid@1",
            r#"{"license":{"id":"MIT"}}"#,
        ),
    ]
    .join(",");

    let report = check(&document(&components), &policy).expect("report");

    assert_eq!(report.components, 5);
    assert_eq!(
        report.completeness.as_deref(),
        Some("recorded_lockfile_inventory")
    );
    let names: Vec<(&str, Reason)> = report
        .violations
        .iter()
        .map(|v| (v.name.as_str(), v.reason))
        .collect();
    assert_eq!(
        names,
        [("bare", Reason::NotAllowed), ("both", Reason::NotAllowed)]
    );
    assert_eq!(
        report.violations[0].expression.as_deref(),
        Some("Apache-2.0")
    );
    assert_eq!(
        report.violations[0].purl.as_deref(),
        Some("pkg:cargo/bare@1")
    );
}

#[test]
fn missing_unparsable_and_free_text_evidence_are_violations() {
    let policy = policy(&["MIT"], &[]);
    let components = [
        component("a", "none", "1", "pkg:cargo/none@1", ""),
        component(
            "b",
            "broken",
            "1",
            "pkg:cargo/broken@1",
            r#"{"expression":"MIT OR"}"#,
        ),
        component(
            "c",
            "named",
            "1",
            "pkg:cargo/named@1",
            r#"{"license":{"name":"Custom Commercial"}}"#,
        ),
        component(
            "d",
            "namedspdx",
            "1",
            "pkg:cargo/namedspdx@1",
            r#"{"license":{"name":"MIT"}}"#,
        ),
        component(
            "e",
            "unknownid",
            "1",
            "pkg:cargo/unknownid@1",
            r#"{"expression":"NotAnId-1.0"}"#,
        ),
        component(
            "f",
            "several",
            "1",
            "pkg:cargo/several@1",
            r#"{"expression":"MIT"},{"license":{"id":"GPL-3.0-only"}}"#,
        ),
        component(
            "g",
            "slashed",
            "1",
            "pkg:cargo/slashed@1",
            r#"{"license":{"name":"Unlicense/MIT"}}"#,
        ),
        component(
            "h",
            "slashedexpr",
            "1",
            "pkg:cargo/slashedexpr@1",
            r#"{"expression":"Unlicense/MIT"}"#,
        ),
    ]
    .join(",");

    let report = check(&document(&components), &policy).expect("report");

    let reasons: Vec<(&str, Reason, Option<&str>)> = report
        .violations
        .iter()
        .map(|v| (v.name.as_str(), v.reason, v.expression.as_deref()))
        .collect();
    assert_eq!(
        reasons,
        [
            ("broken", Reason::UnparsableExpression, Some("MIT OR")),
            ("named", Reason::NonSpdxName, Some("Custom Commercial")),
            ("none", Reason::NoLicense, None),
            (
                "several",
                Reason::NotAllowed,
                Some("(MIT) AND (GPL-3.0-only)")
            ),
            ("slashed", Reason::NonSpdxName, Some("Unlicense/MIT")),
            (
                "slashedexpr",
                Reason::UnparsableExpression,
                Some("Unlicense/MIT")
            ),
            (
                "unknownid",
                Reason::UnparsableExpression,
                Some("NotAnId-1.0")
            ),
        ],
        "ambiguous separators are never interpreted as operators"
    );
}

#[test]
fn multi_entry_evidence_preserves_expression_grouping() {
    let empty: Value =
        serde_json::from_str(&component("empty", "empty", "1", "pkg:cargo/empty@1", ""))
            .expect("empty component");
    assert_eq!(evidence(&empty), None);

    let single: Value = serde_json::from_str(&component(
        "single",
        "single",
        "1",
        "pkg:cargo/single@1",
        r#"{"expression":"MIT OR Apache-2.0"}"#,
    ))
    .expect("single component");
    assert_eq!(evidence(&single).as_deref(), Some("MIT OR Apache-2.0"));

    let multi = component(
        "multi",
        "multi",
        "1",
        "pkg:cargo/multi@1",
        r#"{"license":{"name":"MIT OR Apache-2.0"}},{"license":{"id":"GPL-3.0-only"}}"#,
    );
    let multi_value: Value = serde_json::from_str(&multi).expect("multi component");
    assert_eq!(
        evidence(&multi_value).as_deref(),
        Some("(MIT OR Apache-2.0) AND (GPL-3.0-only)")
    );

    let report = check(&document(&multi), &policy(&["MIT"], &[])).expect("report");
    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations[0].reason, Reason::NotAllowed);
    assert_eq!(
        report.violations[0].expression.as_deref(),
        Some("(MIT OR Apache-2.0) AND (GPL-3.0-only)")
    );
}

#[test]
fn or_later_spellings_are_compared_canonically_on_both_sides() {
    let components = [
        component(
            "a",
            "plus",
            "1",
            "pkg:cargo/plus@1",
            r#"{"expression":"GPL-2.0+"}"#,
        ),
        component(
            "b",
            "later",
            "1",
            "pkg:cargo/later@1",
            r#"{"expression":"LGPL-2.1-or-later"}"#,
        ),
        component(
            "c",
            "only",
            "1",
            "pkg:cargo/only@1",
            r#"{"expression":"GPL-2.0-only"}"#,
        ),
        component(
            "d",
            "lower",
            "1",
            "pkg:cargo/lower@1",
            r#"{"expression":"MIT or GPL-3.0+"}"#,
        ),
        component(
            "e",
            "mixed",
            "1",
            "pkg:cargo/mixed@1",
            r#"{"expression":"MIT"},{"license":{"name":"Apache-2.0 with LLVM-exception"}}"#,
        ),
    ]
    .join(",");

    // The allow list uses the legacy `+` spelling and the canonical one.
    let lenient = policy(
        &[
            "GPL-2.0+",
            "LGPL-2.1-or-later",
            "MIT",
            "Apache-2.0 WITH LLVM-exception",
        ],
        &[],
    );
    let report = check(&document(&components), &lenient).expect("report");
    let names: Vec<&str> = report.violations.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, ["only"], "GPL-2.0-only is not GPL-2.0-or-later");

    // Allowing only the exact version does not cover or-later evidence.
    let strict = policy(&["GPL-2.0-only", "LGPL-2.1-only", "MIT"], &[]);
    let report = check(&document(&components), &strict).expect("report");
    let names: Vec<&str> = report.violations.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, ["later", "mixed", "plus"]);
}

#[test]
fn exceptions_match_by_purl_without_version_and_are_reported() {
    let policy = policy(&["MIT"], &[("pkg:cargo/ring", "reviewed 2026-09")]);
    let components = [
        component(
            "a",
            "ring",
            "0.17.8",
            "pkg:cargo/ring@0.17.8",
            r#"{"expression":"OpenSSL"}"#,
        ),
        component(
            "b",
            "ring",
            "0.16.20",
            "pkg:cargo/ring@0.16.20?x=y",
            r#"{"expression":"OpenSSL"}"#,
        ),
        component(
            "c",
            "ringo",
            "1",
            "pkg:cargo/ringo@1",
            r#"{"expression":"OpenSSL"}"#,
        ),
        component(
            "d",
            "fine",
            "1",
            "pkg:cargo/fine@1",
            r#"{"expression":"MIT"}"#,
        ),
    ]
    .join(",");

    let report = check(&document(&components), &policy).expect("report");

    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations[0].name, "ringo");
    assert_eq!(
        report.exceptions_applied,
        vec![Applied {
            exception: Exception::Package {
                purl: "pkg:cargo/ring".into(),
                reason: "reviewed 2026-09".into()
            },
            components: vec!["ring 0.17.8".into(), "ring 0.16.20".into()],
        }]
    );
}

#[test]
fn project_roots_and_local_packages_are_skipped_and_components_without_purl_cannot_be_excepted() {
    let policy = policy(&["MIT"], &[("pkg:cargo/x", "r")]);
    let components = [
            r#"{"bom-ref":"root","name":"my-app","properties":[{"name":"githits:record_kind","value":"manifest"}]}"#.to_owned(),
            r#"{"bom-ref":"local","name":"my-app","version":"0.1.0","properties":[{"name":"githits:record_kind","value":"locked_package"},{"name":"githits:source_kind","value":"LOCKED_PACKAGE_SOURCE_KIND_LOCAL"}]}"#.to_owned(),
            r#"{"bom-ref":"nopurl","name":"x","version":"1","licenses":[{"expression":"GPL-3.0-only"}]}"#.to_owned(),
        ]
        .join(",");

    let report = check(&document(&components), &policy).expect("report");

    assert_eq!(report.components, 1);
    assert_eq!(report.local_packages, 1);
    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations[0].purl, None);
    assert!(
        report.exceptions_applied.is_empty(),
        "{:?}",
        report.exceptions_applied
    );
}

#[test]
fn rejects_non_json_and_non_cyclonedx_documents() {
    let policy = policy(&["MIT"], &[]);
    assert!(matches!(
        check(b"SPDXVersion: SPDX-2.3\n", &policy),
        Err(DocumentError::NotJson(_))
    ));
    assert_eq!(
        check(br#"{"components":[]}"#, &policy),
        Err(DocumentError::NotCycloneDx)
    );
    let empty = check(br#"{"bomFormat":"CycloneDX"}"#, &policy).expect("report");
    assert_eq!(empty, Report::default());
}

#[test]
fn reports_projects_whose_dependencies_were_not_fully_resolved() {
    let policy = policy(&["MIT"], &[]);
    let resolutions = r#"[{"status":"complete","path":"go.mod","diagnostics":[]},{"status":"partial","path":"swift/Package.swift","diagnostics":[{"name":"","reason":"unsupported_ecosystem"},{"name":"x","reason":"unsupported_ecosystem"}]}]"#;
    let document = serde_json::json!({
        "bomFormat": "CycloneDX",
        "properties": [{"name": "githits:resolutions", "value": resolutions}],
    });
    let report = check(document.to_string().as_bytes(), &policy).expect("report");
    assert_eq!(
        report.unresolved,
        [Unresolved {
            path: "swift/Package.swift".to_owned(),
            status: "partial".to_owned(),
            reasons: vec!["unsupported_ecosystem".to_owned()],
        }]
    );

    let unreadable = serde_json::json!({
        "bomFormat": "CycloneDX",
        "properties": [{"name": "githits:resolutions", "value": "[{\"status\":\"partial\"}]"}],
    });
    assert!(matches!(
        check(unreadable.to_string().as_bytes(), &policy),
        Err(DocumentError::Malformed(_))
    ));
}

#[test]
fn rejects_documents_whose_components_or_licenses_cannot_be_evaluated() {
    let policy = policy(&["MIT"], &[]);
    for (document, detail) in [
        (
            r#"{"bomFormat":"CycloneDX","components":{}}"#,
            "`components` is not an array",
        ),
        (
            r#"{"bomFormat":"CycloneDX","components":[1]}"#,
            "component 0 is not an object",
        ),
        (
            r#"{"bomFormat":"CycloneDX","components":[{"name":"a","licenses":{}}]}"#,
            "component 0: `licenses` is not an array",
        ),
        (
            r#"{"bomFormat":"CycloneDX","components":[{"name":"a","licenses":[{"license":{"id":"MIT"}},{"license":{}}]}]}"#,
            "component 0: license entry 1 has no",
        ),
    ] {
        let result = check(document.as_bytes(), &policy);
        assert!(
            matches!(&result, Err(DocumentError::Malformed(message)) if message.starts_with(detail)),
            "{document}: {result:?}"
        );
    }
}

#[test]
fn strips_versions_qualifiers_and_subpaths_from_package_urls() {
    assert_eq!(without_version("pkg:cargo/ring@0.17.8"), "pkg:cargo/ring");
    assert_eq!(without_version("pkg:cargo/ring"), "pkg:cargo/ring");
    assert_eq!(
        without_version("pkg:npm/%40scope/name@1.2.3?repository_url=x#sub"),
        "pkg:npm/%40scope/name"
    );
    assert_eq!(
        without_version("pkg:maven/org.example/lib@1.0"),
        "pkg:maven/org.example/lib"
    );
}

fn git_component() -> Value {
    serde_json::json!({"type":"library","bom-ref":"fork","name":"grammar","version":"1.0.0",
    "properties":[
        {"name":"githits:source_kind","value":"LOCKED_PACKAGE_SOURCE_KIND_GIT"},
        {"name":"githits:source_locations","value":r#"[{"kind":"vcs_repository","owner":{"type":"source"},"url":"https://example.invalid/grammar"}]"#},
        {"name":"githits:source_revision","value":"0123456789abcdef"}
    ]})
}

fn git_policy(revision: bool) -> Policy {
    let revision = if revision {
        "rev = '0123456789abcdef'\n"
    } else {
        ""
    };
    let text = format!(
        "version = 1\n[licenses]\n[[licenses.exceptions]]\nname = 'grammar'\ngit = 'https://example.invalid/grammar'\n{revision}reason = 'Selected source reviewed'\n"
    );
    let config = crate::config::parse(std::path::Path::new("policy.toml"), &text).expect("config");
    Policy::new(&config.licenses.expect("licenses")).expect("policy")
}

fn altered_git_component(mutation: &str) -> Value {
    let mut component = git_component();
    match mutation {
                "name" => component["name"] = "different".into(),
                "kind" => component["properties"][0]["value"] = "registry".into(),
                "url" => component["properties"][1]["value"] = r#"[{"kind":"vcs_repository","owner":{"type":"source"},"url":"https://example.invalid/other"}]"#.into(),
                "owner" => component["properties"][1]["value"] = r#"[{"kind":"vcs_repository","owner":{"type":"package"},"url":"https://example.invalid/grammar"}]"#.into(),
                "malformed" => component["properties"][1]["value"] = "{".into(),
                "missing" => { component["properties"].as_array_mut().expect("properties").remove(1); },
                "ambiguous" => component["properties"][1]["value"] = r#"[{"kind":"vcs_repository","owner":{"type":"source"},"url":"https://example.invalid/grammar"},{"kind":"vcs_repository","owner":{"type":"source"},"url":"https://example.invalid/other"}]"#.into(),
                _ => unreachable!(),
            }
    component
}

#[test]
fn git_exceptions_require_exact_source_name_and_optional_revision() {
    let original = git_component();
    for revision in [false, true] {
        let policy = git_policy(revision);
        let document = |component: &Value| {
            serde_json::to_vec(
                &serde_json::json!({"bomFormat":"CycloneDX","components":[component]}),
            )
            .expect("document")
        };
        let report = check(&document(&original), &policy).expect("check");
        assert_eq!(report.violations, []);
        assert_eq!(report.components, 1);
        assert_eq!(report.exceptions_applied.len(), 1);
        assert!(original.get("licenses").is_none(), "no license fabricated");
        for mutation in [
            "name",
            "url",
            "kind",
            "owner",
            "malformed",
            "missing",
            "ambiguous",
        ] {
            let component = altered_git_component(mutation);
            assert_eq!(
                check(&document(&component), &policy)
                    .expect("check")
                    .violations
                    .len(),
                1,
                "{mutation}"
            );
        }
        for value in ["", "0123456", "other"] {
            let mut component = original.clone();
            component["properties"][2]["value"] = value.into();
            assert_eq!(
                check(&document(&component), &policy)
                    .expect("check")
                    .violations
                    .len(),
                usize::from(revision)
            );
        }
    }
}

#[test]
fn git_exceptions_validate_selectors_without_guessing_or_accepting_credentials() {
    for git in [
        "relative",
        "file:///repo",
        "https:///",
        "https://example.invalid/repo?branch=main",
        "https://example.invalid/repo#rev",
        "https://user:password@example.invalid/repo",
        "https://git@example.invalid/repo",
    ] {
        let text = format!(
            "version=1\n[licenses]\n[[licenses.exceptions]]\nname='grammar'\ngit='{git}'\nreason='reviewed'\n"
        );
        let config = crate::config::parse(std::path::Path::new("policy.toml"), &text)
            .expect("structural config");
        assert!(
            Policy::new(&config.licenses.expect("licenses")).is_err(),
            "{git}"
        );
    }
    for git in [
        "https://example.invalid/repo",
        "ssh://git@example.invalid/repo",
        "git://example.invalid/repo",
        "http://example.invalid/repo",
    ] {
        let text = format!(
            "version=1\n[licenses]\n[[licenses.exceptions]]\nname='grammar'\ngit='{git}'\nreason='reviewed'\n"
        );
        let config =
            crate::config::parse(std::path::Path::new("policy.toml"), &text).expect("config");
        assert!(
            Policy::new(&config.licenses.expect("licenses")).is_ok(),
            "{git}"
        );
    }
}

#[test]
fn git_exception_source_diagnostics_omit_unsafe_or_ambiguous_urls() {
    for locations in [
        r#"[{"kind":"vcs_repository","owner":{"type":"source"},"url":"https://user:password@example.invalid/grammar"}]"#,
        r#"[{"kind":"vcs_repository","owner":{"type":"source"},"url":"https://example.invalid/grammar"},{"kind":"vcs_repository","owner":{"type":"source"},"url":"https://example.invalid/other"}]"#,
        r#"[{"kind":"vcs_repository","owner":{"type":"source"},"url":"https://user:password@example.invalid/grammar"},{"kind":"vcs_repository","owner":{"type":"source"},"url":"https://example.invalid/grammar"}]"#,
    ] {
        let mut component = git_component();
        component["properties"][1]["value"] = locations.into();
        let bytes = serde_json::to_vec(
            &serde_json::json!({"bomFormat":"CycloneDX","components":[component]}),
        )
        .expect("document");
        let report = check(&bytes, &git_policy(false)).expect("check");
        assert_eq!(report.violations.len(), 1);
        assert!(report.violations[0].source.is_none());
    }
}
