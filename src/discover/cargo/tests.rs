use super::*;

fn selection(root: &str, documents: &[(&str, &str)], candidates: &[&str]) -> BTreeSet<String> {
    let mut workspace = Workspace::new(root.into(), candidates.iter().map(|p| (*p).into()));
    for (path, contents) in documents {
        workspace.record(path, contents);
    }
    workspace.members()
}

#[test]
fn cargo_evidence_selects_declared_globs_with_cargo_prefix_exclusions() {
    let root = "[workspace]\nmembers = ['crates/**', 'crates/excluded/explicit']\nexclude = ['crates/excluded', 'crates/foo']\n";
    let paths = [
        "crates/a/Cargo.toml",
        "crates/deep/b/Cargo.toml",
        "crates/foo/Cargo.toml",
        "crates/foobar/Cargo.toml",
        "crates/excluded/other/Cargo.toml",
        "crates/excluded/explicit/Cargo.toml",
        "unrelated/Cargo.toml",
    ];
    assert_eq!(
        selection("Cargo.toml", &[("Cargo.toml", root)], &paths),
        BTreeSet::from([
            "crates/a/Cargo.toml".into(),
            "crates/deep/b/Cargo.toml".into(),
            "crates/foobar/Cargo.toml".into(),
            "crates/excluded/explicit/Cargo.toml".into(),
        ])
    );
}

#[test]
fn cargo_evidence_follows_root_and_recursive_used_inherited_paths() {
    let docs = [
        (
            "Cargo.toml",
            "[package]\nname='root'\nversion='1.0.0'\n[workspace]\nmembers=['app']\n[workspace.dependencies]\nshared={path='shared'}\nunused={path='unused'}\n[dependencies]\nroot_dep={path='root-dep'}\n",
        ),
        (
            "app/Cargo.toml",
            "[dependencies]\nshared={workspace=true}\n[target.'cfg(unix)'.build-dependencies]\nleaf={path='../leaf'}\n",
        ),
        (
            "shared/Cargo.toml",
            "[dev-dependencies]\nnext={path='../leaf'}\n",
        ),
        ("leaf/Cargo.toml", "[dependencies]\ncycle={path='../app'}\n"),
    ];
    let candidates = [
        "app/Cargo.toml",
        "shared/Cargo.toml",
        "unused/Cargo.toml",
        "leaf/Cargo.toml",
        "root-dep/Cargo.toml",
    ];
    assert_eq!(
        selection("Cargo.toml", &docs, &candidates),
        BTreeSet::from([
            "app/Cargo.toml".into(),
            "shared/Cargo.toml".into(),
            "leaf/Cargo.toml".into(),
            "root-dep/Cargo.toml".into(),
        ])
    );
}

#[test]
fn cargo_evidence_does_not_expand_independent_or_differently_owned_members() {
    for independent in ["[workspace]\n", "[package]\nworkspace='../other'\n"] {
        let member = format!("{independent}[dependencies]\nleaf={{path='../leaf'}}\n");
        assert_eq!(
            selection(
                "Cargo.toml",
                &[
                    ("Cargo.toml", "[workspace]\nmembers=['member']\n"),
                    ("member/Cargo.toml", &member)
                ],
                &["member/Cargo.toml", "leaf/Cargo.toml"]
            ),
            BTreeSet::from(["member/Cargo.toml".into()])
        );
    }
}

#[test]
fn cargo_evidence_preserves_original_validation_for_missing_or_invalid_workspace() {
    for contents in [
        "[dependencies]\nx={path='member'}",
        "[workspace",
        "[workspace]\nmembers=[3]",
        "[workspace]\nmembers=['member']\nexclude=3",
    ] {
        assert!(
            selection(
                "Cargo.toml",
                &[("Cargo.toml", contents)],
                &["member/Cargo.toml"]
            )
            .is_empty(),
            "{:?}",
            selection(
                "Cargo.toml",
                &[("Cargo.toml", contents)],
                &["member/Cargo.toml"]
            )
        );
    }
}

#[test]
fn cargo_evidence_never_escapes_workspace_or_selects_unadmitted_paths() {
    let contents = "[workspace]\nmembers=['../external', 'missing', 'member']\n[dependencies]\nout={path='../external'}\n[patch.crates-io]\npatched={path='patched'}\n";
    assert_eq!(
        selection(
            "project/Cargo.toml",
            &[("project/Cargo.toml", contents)],
            &[
                "external/Cargo.toml",
                "project/member/Cargo.toml",
                "project/patched/Cargo.toml"
            ]
        ),
        BTreeSet::from(["project/member/Cargo.toml".into()])
    );
}

#[test]
fn cargo_evidence_treats_braces_literally_and_supports_character_classes() {
    assert_eq!(
        selection(
            "Cargo.toml",
            &[(
                "Cargo.toml",
                "[workspace]\nmembers=['{a,b}', '[xy]', '[{]literal[}]']\n"
            )],
            &[
                "a/Cargo.toml",
                "b/Cargo.toml",
                "{a,b}/Cargo.toml",
                "x/Cargo.toml",
                "y/Cargo.toml",
                "{literal}/Cargo.toml"
            ]
        ),
        BTreeSet::from([
            "{a,b}/Cargo.toml".into(),
            "x/Cargo.toml".into(),
            "y/Cargo.toml".into(),
            "{literal}/Cargo.toml".into()
        ])
    );
}
