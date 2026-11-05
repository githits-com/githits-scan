use super::*;
use tempfile::TempDir;

fn fixture(version: &str) -> TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("changes")).unwrap();
    fs::write(
        root.path().join("Cargo.toml"),
        format!("# retain comment\n[package]\nname = \"githits-scan\"\nversion = \"{version}\"\n"),
    )
    .unwrap();
    fs::write(root.path().join("Cargo.lock"), format!("version = 4\n\n[[package]]\nname = \"githits-scan\"\nversion = \"{version}\"\n\n[[package]]\nname = \"other\"\nversion = \"1.0.0\"\n")).unwrap();
    fs::write(
        root.path().join("CHANGELOG.md"),
        "# Changelog\n\nReviewed changes.\n",
    )
    .unwrap();
    root
}

fn add(root: &Path, name: &str, impact: &str, body: &str) {
    fs::write(
        root.join("changes").join(name),
        format!("---\n\"githits-scan\": {impact}\n---\n\n{body}\n"),
    )
    .unwrap();
}

fn prepare(root: &Path) -> Result<String> {
    run(
        root,
        Command::Prepare {
            date: "2026-10-12".into(),
        },
    )
}

#[test]
fn mixed_impacts_prepare_sorted_multiline_notes_and_preserve_other_versions() {
    let root = fixture("0.1.0");
    add(
        root.path(),
        "z.changed.md",
        "minor",
        "- **Z** - Async support.\n  Continuation.",
    );
    add(root.path(), "a.changed.md", "patch", "- **A** - Bug fix.");
    add(
        root.path(),
        "maintenance.added.md",
        "none",
        "- **Maintenance** - Pipeline.",
    );
    add(
        root.path(),
        "tls.security.md",
        "patch",
        "- **TLS** - Security fix.",
    );
    fs::write(root.path().join("changes/README.md"), "not a fragment").unwrap();
    assert_eq!(prepare(root.path()).unwrap(), "Prepared v0.2.0\n");
    let snapshot = Snapshot::load(root.path()).unwrap();
    assert_eq!(snapshot.version, Version(0, 2, 0));
    assert!(
        snapshot
            .manifest
            .to_string()
            .starts_with("# retain comment")
    );
    assert!(
        snapshot
            .lock
            .to_string()
            .contains("name = \"other\"\nversion = \"1.0.0\"")
    );
    let notes = snapshot.release_notes().unwrap();
    assert_eq!(
        notes,
        "### Added\n\n- **Maintenance** - Pipeline.\n\n### Changed\n\n- **A** - Bug fix.\n- **Z** - Async support.\n  Continuation.\n\n### Security\n\n- **TLS** - Security fix."
    );
    assert!(snapshot.changelog.contains("## [0.2.0] - 2026-10-12"));
    assert!(root.path().join("changes/README.md").exists());
    assert_eq!(
        fs::read_dir(root.path().join("changes")).unwrap().count(),
        1
    );
    assert!(prepare(root.path()).is_err());
}

#[test]
fn bump_rules_and_overflow() {
    for (old, impact, expected) in [
        (Version(0, 1, 4), Impact::Patch, Version(0, 1, 5)),
        (Version(0, 1, 4), Impact::Major, Version(0, 2, 0)),
        (Version(1, 2, 4), Impact::Major, Version(2, 0, 0)),
        (Version(1, 2, 4), Impact::Minor, Version(1, 3, 0)),
    ] {
        assert_eq!(old.bump(impact).unwrap(), expected);
    }
    assert!(Version(1, 2, u64::MAX).bump(Impact::Patch).is_err());
    for invalid in ["01.2.3", "1.2", "1.2.3-beta", "1.-2.3", "1.2.3.4", "１.2.3"] {
        assert!(Version::parse(invalid).is_err());
    }
}

#[test]
fn first_release_changelog_has_exact_content_and_one_final_newline() {
    let root = fixture("0.1.0");
    add(root.path(), "a.fixed.md", "patch", "- **A** - Fix.");
    prepare(root.path()).unwrap();
    assert_eq!(
        read(&root.path().join("CHANGELOG.md")).unwrap(),
        "# Changelog\n\nReviewed changes.\n\n## [0.1.1] - 2026-10-12\n\n### Fixed\n\n- **A** - Fix.\n"
    );
}

#[test]
fn malformed_inputs_and_none_only_never_mutate_files() {
    for (name, text) in [
        (
            "a.added.md",
            "---\n\"other\": minor\n---\n\n- **A** - Change.\n",
        ),
        (
            "a.added.md",
            "---\n\"githits-scan\": unknown\n---\n\n- **A** - Change.\n",
        ),
        ("a.added.md", "---\n\"githits-scan\": minor\n---\n\n"),
        (
            "a.added.md",
            "---\n\"githits-scan\": minor\n---\n\n- **A** - Change.\n- **B** - Other.\n",
        ),
        (
            "a.Added.md",
            "---\n\"githits-scan\": minor\n---\n\n- **A** - Change.\n",
        ),
        (
            "a.unknown.md",
            "---\n\"githits-scan\": minor\n---\n\n- **A** - Change.\n",
        ),
        (
            "a.md",
            "---\n\"githits-scan\": minor\n---\n\n- **A** - Change.\n",
        ),
        (
            "a.added.md",
            "---\n\"githits-scan\": none\n---\n\n- **A** - Change.\n",
        ),
    ] {
        let root = fixture("0.1.0");
        let before = read(&root.path().join("Cargo.toml")).unwrap();
        let lock_before = read(&root.path().join("Cargo.lock")).unwrap();
        let changes_before = read(&root.path().join("CHANGELOG.md")).unwrap();
        let path = root.path().join("changes").join(name);
        fs::write(&path, text).unwrap();
        assert!(prepare(root.path()).is_err(), "{name}: {text}");
        assert_eq!(read(&root.path().join("Cargo.toml")).unwrap(), before);
        assert_eq!(read(&root.path().join("Cargo.lock")).unwrap(), lock_before);
        assert_eq!(
            read(&root.path().join("CHANGELOG.md")).unwrap(),
            changes_before
        );
        assert_eq!(read(&path).unwrap(), text);
    }
}

#[test]
fn dates_and_duplicate_or_empty_sections_fail_closed() {
    for good in ["2024-02-29", "2000-02-29", "2026-10-12"] {
        assert!(valid_date(good));
    }
    for bad in [
        "1900-02-29",
        "2026-02-29",
        "2026-04-31",
        "0000-01-01",
        "2026-00-01",
        "2026-13-01",
        "2026-01-00",
        "2026-1-01",
        "日付",
    ] {
        assert!(!valid_date(bad));
    }
    assert!(
        sections("## [0.1.0] - 2026-10-12\n\ntext\n\n## [0.1.0] - 2026-10-13\n\ntext").is_err()
    );
    assert!(sections("## [0.1.0] - 2026-10-12\n\n").is_err());
    assert!(sections("## [0.1.0] - bad\n\ntext").is_err());
    let root = fixture("0.1.0");
    add(root.path(), "a.added.md", "minor", "- **A** - Change.");
    assert!(
        run(
            root.path(),
            Command::Prepare {
                date: "2026-02-30".into()
            }
        )
        .is_err()
    );
    assert!(root.path().join("changes/a.added.md").exists());
}

#[test]
fn inserts_new_section_without_changing_old_notes() {
    let root = fixture("0.1.0");
    let old = "## [0.1.0] - 2026-10-01\n\n### Added\n\n- Older release.\n";
    fs::write(
        root.path().join("CHANGELOG.md"),
        format!("# Changelog\n\n{old}"),
    )
    .unwrap();
    add(root.path(), "a.fixed.md", "patch", "- **A** - Fix.");
    prepare(root.path()).unwrap();
    assert_eq!(
        read(&root.path().join("CHANGELOG.md")).unwrap(),
        format!("# Changelog\n\n## [0.1.1] - 2026-10-12\n\n### Fixed\n\n- **A** - Fix.\n\n{old}")
    );
}

#[test]
fn release_audit_requires_current_notes_and_no_fragments_or_lock_mismatch() {
    let root = fixture("0.1.0");
    assert!(
        run(
            root.path(),
            Command::Audit {
                release: false,
                base_ref: None
            }
        )
        .is_ok()
    );
    assert!(
        run(
            root.path(),
            Command::Audit {
                release: true,
                base_ref: None
            }
        )
        .is_err()
    );
    add(root.path(), "a.added.md", "minor", "- **A** - Change.");
    prepare(root.path()).unwrap();
    assert!(
        run(
            root.path(),
            Command::Audit {
                release: true,
                base_ref: None
            }
        )
        .is_ok()
    );
    add(root.path(), "a.fixed.md", "none", "- **A** - Change.");
    assert!(
        run(
            root.path(),
            Command::Audit {
                release: true,
                base_ref: None
            }
        )
        .is_err()
    );
    fs::write(
        root.path().join("Cargo.lock"),
        "[[package]]\nname = \"githits-scan\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    assert!(Snapshot::load(root.path()).is_err());
}

#[test]
fn invalid_manifests_and_duplicate_lock_packages_return_errors() {
    for manifest in [
        "invalid TOML [",
        "",
        "package = 1",
        "[package]\nname = \"other\"\nversion = \"0.1.0\"\n",
        "[package]\nname = \"githits-scan\"\n",
    ] {
        let root = fixture("0.1.0");
        fs::write(root.path().join("Cargo.toml"), manifest).unwrap();
        assert!(Snapshot::load(root.path()).is_err());
    }
    let root = fixture("0.1.0");
    let package = "[[package]]\nname = \"githits-scan\"\nversion = \"0.1.0\"\n";
    fs::write(
        root.path().join("Cargo.lock"),
        format!("{package}\n{package}"),
    )
    .unwrap();
    assert!(Snapshot::load(root.path()).is_err());
}

fn git_fixture(root: &Path) {
    git(root, &["init", "-b", "main"]).unwrap();
    git(root, &["config", "user.name", "Release test"]).unwrap();
    git(root, &["config", "user.email", "release@example.invalid"]).unwrap();
    git(root, &["config", "commit.gpgsign", "false"]).unwrap();
    git(root, &["config", "tag.gpgSign", "false"]).unwrap();
    fs::create_dir(root.join("empty-hooks")).unwrap();
    git(root, &["config", "core.hooksPath", "empty-hooks"]).unwrap();
    commit(root);
}

fn commit(root: &Path) {
    git(root, &["add", "."]).unwrap();
    git(root, &["commit", "-m", "fixture"]).unwrap();
}

#[test]
fn a_root_commit_has_no_base_version_but_a_missing_parent_still_fails() {
    let root = fixture("0.1.0");
    git_fixture(root.path());
    let audit = || {
        run(
            root.path(),
            Command::Audit {
                release: false,
                base_ref: Some("HEAD^".into()),
            },
        )
    };
    assert_eq!(audit().unwrap(), "Release audit passed\n");

    fs::write(root.path().join("unrelated"), "change").unwrap();
    commit(root.path());
    let shallow = tempfile::tempdir().unwrap();
    let source = root.path().to_str().unwrap();
    git(
        shallow.path(),
        &[
            "clone",
            "--quiet",
            "--no-local",
            "--depth",
            "1",
            source,
            ".",
        ],
    )
    .unwrap();
    // Git does not record the fixture's empty fragment directory.
    fs::create_dir(shallow.path().join("changes")).unwrap();
    assert_eq!(
        run(
            shallow.path(),
            Command::Audit {
                release: false,
                base_ref: Some("HEAD^".into()),
            },
        )
        .unwrap_err()
        .to_string(),
        "comparison ref is unavailable; fetch the tested commit's first parent"
    );
}

#[test]
fn tested_parent_bump_and_real_tag_membership_are_enforced() {
    let root = fixture("0.1.0");
    git_fixture(root.path());
    add(root.path(), "a.added.md", "minor", "- **A** - Change.");
    prepare(root.path()).unwrap();
    commit(root.path());
    assert!(
        run(
            root.path(),
            Command::Audit {
                release: false,
                base_ref: Some("HEAD^".into())
            }
        )
        .is_ok()
    );
    git(
        root.path(),
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    )
    .unwrap();
    let tag = || Command::VerifyTag {
        tag: "v0.2.0".into(),
    };
    assert_eq!(
        run(root.path(), tag()).unwrap_err().to_string(),
        "release tag is missing or invalid; fetch the actual version tag"
    );
    git(
        root.path(),
        &["tag", "-a", "v0.2.0", "-m", "fixture release"],
    )
    .unwrap();
    assert!(run(root.path(), tag()).is_ok());
    assert!(
        run(
            root.path(),
            Command::VerifyTag {
                tag: "v0.1.0".into()
            }
        )
        .is_err()
    );
    git(
        root.path(),
        &["update-ref", "refs/remotes/origin/main", "HEAD^"],
    )
    .unwrap();
    assert_eq!(
        run(root.path(), tag()).unwrap_err().to_string(),
        "release commit does not belong to origin/main"
    );
    git(
        root.path(),
        &["update-ref", "-d", "refs/remotes/origin/main"],
    )
    .unwrap();
    assert_eq!(
        run(root.path(), tag()).unwrap_err().to_string(),
        "cannot verify main membership; fetch full history including origin/main"
    );

    add(root.path(), "b.fixed.md", "patch", "- **B** - Change.");
    assert!(
        run(
            root.path(),
            Command::Audit {
                release: false,
                base_ref: Some("HEAD^".into())
            }
        )
        .is_err()
    );
    fs::remove_file(root.path().join("changes/b.fixed.md")).unwrap();
    fs::write(root.path().join("unrelated"), "change").unwrap();
    commit(root.path());
    git(
        root.path(),
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    )
    .unwrap();
    assert!(run(root.path(), tag()).is_err());
}
