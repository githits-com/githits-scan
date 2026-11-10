use super::*;
use serde_json::json;

fn selected(patterns: &serde_json::Value) -> BTreeSet<String> {
    let mut workspace = Workspace::new(
        "package.json".into(),
        [
            "packages/package.json",
            "packages/a/package.json",
            "packages/b/package.json",
            "packages/b/child/package.json",
            "packages/c/package.json",
            "unrelated/package.json",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    workspace.record("package.json", &json!({"workspaces":patterns}).to_string());
    workspace.members()
}

fn bun_selected(patterns: &serde_json::Value) -> BTreeSet<String> {
    let mut workspace = Workspace::bun(
        "package.json".into(),
        [
            "packages/package.json",
            "packages/a/package.json",
            "packages/b/package.json",
            "packages/c/package.json",
            "packages/pkg-1/package.json",
            "packages/pkg-a/package.json",
            "packages/pkg-b/package.json",
            "packages/sub/a/package.json",
            "packages/sub/deep/a/package.json",
            "#packages/a/package.json",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    workspace.record("package.json", &json!({"workspaces":patterns}).to_string());
    workspace.members()
}

fn paths(names: &[&str]) -> BTreeSet<String> {
    names
        .iter()
        .map(|name| format!("{name}/package.json"))
        .collect()
}

#[test]
fn npm_evidence_positive_patterns_match_native_directory_examples() {
    for (pattern, expected) in [
        ("packages/*", vec!["packages/a", "packages/b", "packages/c"]),
        ("packages/??", vec![]),
        ("packages/[ab]", vec!["packages/a", "packages/b"]),
        ("packages/[a-b]", vec!["packages/a", "packages/b"]),
        ("packages/{a,c}", vec!["packages/a", "packages/c"]),
        (
            "packages/{a,b/child}",
            vec!["packages/a", "packages/b/child"],
        ),
        (
            "packages/**",
            vec![
                "packages",
                "packages/a",
                "packages/b",
                "packages/b/child",
                "packages/c",
            ],
        ),
        (
            "packages/**/**",
            vec![
                "packages",
                "packages/a",
                "packages/b",
                "packages/b/child",
                "packages/c",
            ],
        ),
        ("packages/**/child", vec!["packages/b/child"]),
        (
            "./packages/*",
            vec!["packages/a", "packages/b", "packages/c"],
        ),
        (
            "/packages/*",
            vec!["packages/a", "packages/b", "packages/c"],
        ),
        (
            "!!packages/*",
            vec!["packages/a", "packages/b", "packages/c"],
        ),
    ] {
        assert_eq!(selected(&json!([pattern])), paths(&expected), "{pattern}");
    }
}

#[test]
fn npm_evidence_object_declarations_and_positive_union_are_deduplicated() {
    assert_eq!(
        selected(&json!({"packages":["packages/a", "packages/[ab]", "packages/a"]})),
        paths(&["packages/a", "packages/b"]),
    );
}

#[test]
fn npm_evidence_unsupported_pattern_disables_the_whole_owner() {
    for pattern in [
        "./!!foo",
        "./!foo",
        "./!*",
        "!packages/b",
        "!packages/b/**",
        "!packages/B",
        "!packages/*",
        "!packages/?",
        "!!!packages/b",
        "packages/*/",
        "packages\\a",
        "packages/@(a|b)",
        "packages/+(a|b)",
        "packages/{1..3}",
        "packages/${a,b}",
        "packages/[[:alpha:]]",
        "packages/[!a]",
        "packages/[^a]",
        "packages/{a,{b,c}}",
        "packages/{a}",
        "packages/{a,}",
        "packages/**a",
        "packages/./a",
        "packages/../a",
        "packages//a",
        "packages/[a",
        "packages/{a,b",
        "",
    ] {
        assert!(
            selected(&json!(["packages/*", pattern])).is_empty(),
            "{pattern}"
        );
    }
    assert!(selected(&json!(["!packages/b", "packages/*"])).is_empty());
    assert!(selected(&json!(["packages/*", false])).is_empty());
}

#[test]
fn npm_evidence_missing_or_malformed_declarations_add_no_members() {
    let mut workspace =
        Workspace::new("package.json".into(), ["a/package.json".into()].into_iter());
    for contents in [
        "",
        "{",
        "{}",
        r#"{"workspaces":null}"#,
        r#"{"workspaces":"a"}"#,
        r#"{"workspaces":{"packages":false}}"#,
        r#"{"private":true,"dependencies":{"a":"file:a"}}"#,
    ] {
        workspace.record("package.json", contents);
        assert!(workspace.members().is_empty(), "{contents}");
    }
}

#[test]
fn npm_evidence_only_the_owning_manifest_declares_members() {
    let mut workspace = Workspace::new(
        "app/package.json".into(),
        [
            "app/packages/a/package.json",
            "app/packages/a/child/package.json",
            "app-other/packages/b/package.json",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    workspace.record("app/packages/a/package.json", r#"{"workspaces":["child"]}"#);
    assert!(workspace.members().is_empty());
    workspace.record("app/package.json", r#"{"workspaces":["packages/*"]}"#);
    assert_eq!(
        workspace.members(),
        BTreeSet::from(["app/packages/a/package.json".into()])
    );
    workspace.record("app/packages/a/package.json", r#"{"workspaces":["child"]}"#);
    assert_eq!(
        workspace.members(),
        BTreeSet::from(["app/packages/a/package.json".into()])
    );
}

#[test]
fn npm_evidence_repeated_leading_slashes_are_native_root_relative() {
    for pattern in ["///packages/*", ".///packages/*"] {
        assert_eq!(
            selected(&json!([pattern])),
            paths(&["packages/a", "packages/b", "packages/c"]),
            "{pattern}"
        );
    }
}

#[test]
fn npm_evidence_unicode_character_patterns_require_explicit_selection() {
    let candidates = ["packages/a/package.json", "packages/é/package.json"];
    for pattern in [
        "packages/?",
        "packages/??",
        "packages/[a]",
        "packages/[é]",
        "packages/[a-é]",
    ] {
        let mut workspace = Workspace::new(
            "package.json".into(),
            candidates.into_iter().map(str::to_owned),
        );
        workspace.record(
            "package.json",
            &json!({"workspaces":["packages/*", pattern]}).to_string(),
        );
        assert!(workspace.members().is_empty(), "{pattern}");
    }
    // Non-ASCII class syntax also stays outside the qualified ASCII subset.
    assert!(selected(&json!(["packages/*", "packages/[é]"])).is_empty());
}

#[test]
fn npm_evidence_unicode_literals_and_stars_remain_supported() {
    for (pattern, expected) in [
        ("packages/é", vec!["packages/é"]),
        ("packages/*", vec!["packages/a", "packages/é"]),
    ] {
        let mut workspace = Workspace::new(
            "package.json".into(),
            ["packages/a/package.json", "packages/é/package.json"]
                .into_iter()
                .map(str::to_owned),
        );
        workspace.record("package.json", &json!({"workspaces":[pattern]}).to_string());
        assert_eq!(workspace.members(), paths(&expected), "{pattern}");
    }
}

#[test]
fn npm_evidence_chained_and_separator_spanning_ranges_require_explicit_selection() {
    for pattern in ["packages/[a-c-e]", "packages/pkg[.-0]name"] {
        let mut workspace = Workspace::new(
            "package.json".into(),
            [
                "packages/d/package.json",
                "packages/pkg.name/package.json",
                "packages/pkg/name/package.json",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        workspace.record(
            "package.json",
            &json!({"workspaces":["packages/*", pattern]}).to_string(),
        );
        assert!(workspace.members().is_empty(), "{pattern}");
    }
}

#[test]
fn npm_evidence_separate_ranges_and_edge_hyphens_keep_native_matches() {
    for (pattern, expected) in [
        (
            "packages/[a-z0-9]",
            vec![
                "packages/0",
                "packages/a",
                "packages/b",
                "packages/c",
                "packages/d",
                "packages/e",
                "packages/z",
            ],
        ),
        (
            "packages/[-a-c]",
            vec!["packages/-", "packages/a", "packages/b", "packages/c"],
        ),
        (
            "packages/[a-c-]",
            vec!["packages/-", "packages/a", "packages/b", "packages/c"],
        ),
        ("packages/[--]", vec!["packages/-"]),
    ] {
        let mut workspace = Workspace::new(
            "package.json".into(),
            ["-", "0", "a", "b", "c", "d", "e", "z"]
                .into_iter()
                .map(|name| format!("packages/{name}/package.json")),
        );
        workspace.record("package.json", &json!({"workspaces":[pattern]}).to_string());
        assert_eq!(workspace.members(), paths(&expected), "{pattern}");
    }
}

#[test]
fn npm_evidence_comments_and_literal_marker_components_match_native() {
    for (patterns, expected) in [
        (json!(["foo", "#foo"]), vec!["foo"]),
        (json!(["foo", "./#foo"]), vec!["foo"]),
        (json!(["foo", "/#foo"]), vec!["foo"]),
        (json!(["foo", "!!#foo"]), vec!["foo"]),
        (json!(["!!foo"]), vec!["foo"]),
        (json!(["packages/#foo"]), vec!["packages/#foo"]),
        (json!(["packages/!!foo"]), vec!["packages/!!foo"]),
    ] {
        let mut workspace = Workspace::new(
            "package.json".into(),
            [
                "foo/package.json",
                "#foo/package.json",
                "!foo/package.json",
                "!!foo/package.json",
                "packages/#foo/package.json",
                "packages/!!foo/package.json",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        workspace.record("package.json", &json!({"workspaces":patterns}).to_string());
        assert_eq!(workspace.members(), paths(&expected));
    }
}

#[test]
fn bun_evidence_supported_patterns_match_verified_directory_examples() {
    const DIRECT: &[&str] = &[
        "packages/a",
        "packages/b",
        "packages/c",
        "packages/pkg-1",
        "packages/pkg-a",
        "packages/pkg-b",
    ];
    const RECURSIVE: &[&str] = &[
        "packages",
        "packages/a",
        "packages/b",
        "packages/c",
        "packages/pkg-1",
        "packages/pkg-a",
        "packages/pkg-b",
        "packages/sub/a",
        "packages/sub/deep/a",
    ];
    const ENDS_A: &[&str] = &["packages/a", "packages/sub/a", "packages/sub/deep/a"];
    for (pattern, expected) in [
        ("packages/*", DIRECT),
        ("packages/**", RECURSIVE),
        ("./packages/*", DIRECT),
        ("!!packages/*", DIRECT),
        ("#packages/*", &["#packages/a"][..]),
        (
            "packages/?",
            &["packages/a", "packages/b", "packages/c"][..],
        ),
        ("packages/[ab]", &["packages/a", "packages/b"][..]),
        ("packages/[a-b]", &["packages/a", "packages/b"][..]),
        ("packages/{a,b}", &["packages/a", "packages/b"][..]),
        ("packages/**/a", ENDS_A),
        ("packages/**/**/a", ENDS_A),
    ] {
        assert_eq!(
            bun_selected(&json!([pattern])),
            paths(expected),
            "{pattern}"
        );
    }
}

#[test]
fn bun_evidence_rejects_root_slashes_brace_slashes_and_odd_negation() {
    for pattern in [
        "/packages/*",
        "packages/{a,sub/a}",
        "!packages/*",
        "!!!packages/*",
    ] {
        assert!(
            bun_selected(&json!(["packages/*", pattern])).is_empty(),
            "{pattern}"
        );
    }
}
