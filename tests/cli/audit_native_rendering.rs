//! Reader-facing native scope, authority and publisher text.
use super::*;
use crate::support::audit::facet;
use serde_json::{Value, json};

fn native(kind: &str, scope: &str, registry: &str) -> Value {
    let mut v = clean();
    let version = if scope == "package" {
        Value::Null
    } else {
        json!("v1.0.0")
    };
    v["summary"]["lifecycle"] = 1.into();
    v["lifecycle"]["findings"] = json!([{
        "registry":registry,"name":"example/demo","version":version,
        "category":"withdrawal","kind":kind,"scope":scope,"source":"fixture.metadata",
        "observations":[{"source_version":"v9.0.0","observed_at":"2026-11-01T00:00:00Z",
            "reason":"Publisher says: use \"replacement\"\n\u{1b}[2J","replacement":"other/demo",
            "reason_codes":["internal_reason_code"],"affected":[{"coordinate":{
                "registry":registry,"name":"selected/alias","version":"v1.0.0"},
                "paths":["nested/lockfile"]}]}]}]);
    for check in ["deprecation", "withdrawal"] {
        v["lifecycle"]["coverage"][check] = facet(2, 2, 0, 0, 0, registry);
    }
    for check in ["registry_archival", "repository_archival"] {
        v["lifecycle"]["coverage"][check] = facet(2, 0, 0, 2, 0, registry);
    }
    v
}

#[test]
fn audit_native_positive_kinds_and_scopes_have_useful_rendering() {
    for (kind, scope, registry, label) in [
        ("deprecated", "release", "npm", "deprecated (release)"),
        ("retired", "release", "hex", "retired (release)"),
        ("yanked", "release", "crates", "yanked (release)"),
        ("unlisted", "release", "nuget", "unlisted (release)"),
        ("retracted", "release", "go", "retracted (release)"),
        ("deprecated", "package", "go", "deprecated (package-wide)"),
        (
            "abandoned",
            "package",
            "packagist",
            "abandoned (package-wide)",
        ),
        (
            "discontinued",
            "package",
            "pub",
            "discontinued (package-wide)",
        ),
        (
            "partially_yanked",
            "files",
            "pypi",
            "partly yanked (affected files only)",
        ),
        (
            "future_kind",
            "future_scope",
            "npm",
            "lifecycle warning of an unfamiliar type (scope not recognized)",
        ),
    ] {
        let root = repo();
        let mock = server(&serde_json::to_vec(&native(kind, scope, registry)).expect("native"));
        let output = run(
            root.path(),
            Some(&mock.origin()),
            &["--quiet", "--no-color", "--details"],
        );
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        let text = stdout(&output);
        for expected in [
            label,
            "Source: fixture.metadata; source version v9.0.0",
            "selected/alias@v1.0.0",
            "nested/lockfile",
            "Publisher replacement advice: other/demo (not a verified upgrade)",
            "use \"replacement\"\\n\\u{1b}[2J",
        ] {
            assert!(text.contains(expected), "{expected}: {text}");
        }
        assert!(
            !text.contains("unverified")
                && !text.contains("internal_reason_code")
                && !text.contains('\u{1b}'),
            "{text}"
        );
        assert_eq!(output.stderr, [] as [u8; 0]);
        assert_eq!(mock.requests().len(), 3);
    }
}

#[test]
fn audit_native_missing_reason_and_filtered_publisher_text_are_explicit() {
    let mut v = native("yanked", "release", "pypi");
    v["lifecycle"]["findings"][0]["observations"][0]["reason"] = Value::Null;
    v["lifecycle"]["content_safety"]["filtered"] = true.into();
    let root = repo();
    let mock = server(&serde_json::to_vec(&v).expect("native"));
    let output = run(
        root.path(),
        Some(&mock.origin()),
        &["--quiet", "--no-color"],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.contains("The source supplied no reason.")
            && text.contains("filtered some publisher text"),
        "{text}"
    );
    assert_eq!(text.matches("yanked (release)").count(), 1, "{text}");
    assert!(
        text.contains("Use --details for sources, affected files"),
        "{text}"
    );
    assert_eq!(mock.requests().len(), 3);
}

#[test]
fn audit_native_retained_warning_is_not_reclassified_or_duplicated() {
    let mut v = clean();
    v["summary"]["retained_lifecycle_warnings"] = 1.into();
    v["lifecycle"]["retained_warnings"] = json!([{"coordinate":{"registry":"nuget","name":"Demo","version":"1.0.0"},"paths":["packages.lock.json"],"classification":"legacy_unclassified","reason":"Retained publisher warning"}]);
    v["summary"]["incomplete_checks"] = 1.into();
    v["lifecycle"]["coverage"]["deprecation"] = facet(2, 1, 1, 0, 0, "nuget");
    v["lifecycle"]["unknowns"] = json!([{"coordinate":{"registry":"nuget","name":"Demo","version":"1.0.0"},"paths":["packages.lock.json"],"check":"deprecation","status":"unknown","reason":"native_evidence_unavailable"}]);
    let root = repo();
    let mock = server(&serde_json::to_vec(&v).expect("native"));
    let output = run(
        root.path(),
        Some(&mock.origin()),
        &["--quiet", "--no-color"],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    assert_eq!(text.matches("Retained publisher warning").count(), 1);
    assert!(text.contains("Use --details"), "{text}");
    assert!(
        text.contains("native classification was not retained")
            && text.contains("stored metadata does not include the native observation")
            && !text.contains("deprecated"),
        "{text}"
    );
    assert_eq!(mock.requests().len(), 3);
}
