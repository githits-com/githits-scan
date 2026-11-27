//! The live corpus must cover new cataloged inputs without spending API jobs in PR CI.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

use super::{Ecosystem, RULES, Role, classify};

#[derive(Deserialize)]
struct Fixture {
    id: String,
    ecosystem: String,
    files: BTreeMap<String, String>,
    upload_paths: Vec<String>,
    checks: BTreeMap<String, Value>,
}

#[test]
fn live_fixtures_cover_catalog_and_have_reviewed_online_baselines() {
    let cases: Vec<Fixture> =
        serde_json::from_str(include_str!("../../tests/fixtures/live/fixtures.json"))
            .expect("fixture definitions");
    let mut ecosystems = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut ids = BTreeMap::new();
    let mut revisions = BTreeMap::from([
        ("yarn-classic", ("format", "LOCKFILE_FORMAT_YARN_CLASSIC")),
        ("yarn-berry", ("format", "LOCKFILE_FORMAT_YARN_BERRY")),
        ("pnpm-v5", ("native_format_version", "5.4")),
        ("pnpm-v6", ("native_format_version", "6.0")),
        ("pnpm-v9", ("native_format_version", "9.0")),
        ("poetry-v2", ("native_format_version", "2.0")),
        ("poetry-v2-1", ("native_format_version", "2.1")),
        ("conan-v1", ("native_format_version", "0.4")),
        ("conan-v2", ("native_format_version", "0.5")),
    ]);

    for fixture in &cases {
        assert!(
            ids.insert(fixture.id.as_str(), fixture).is_none(),
            "duplicate fixture {}",
            fixture.id
        );
        for path in &fixture.upload_paths {
            assert!(fixture.files.contains_key(path), "unverified input {path}");
            let path = Path::new(path);
            let class = classify(path).expect("each fixture upload is a cataloged input");
            assert_eq!(class.ecosystem.id(), fixture.ecosystem);
            ecosystems.insert(class.ecosystem.id());
            paths.insert(path);
        }
        check_baseline(fixture, revisions.remove(fixture.id.as_str()));
    }
    assert!(
        revisions.is_empty(),
        "missing parser fixtures {revisions:?}"
    );

    for ecosystem in Ecosystem::ALL {
        assert!(
            ecosystems.contains(ecosystem.id()),
            "missing fixture for {ecosystem}"
        );
    }
    for rule in RULES
        .iter()
        .filter(|rule| matches!(rule.role, Role::Lockfile(_)))
    {
        assert!(
            paths.iter().any(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| super::matches(rule.matcher, path, name))
            }),
            "missing lockfile fixture for {:?}",
            rule.matcher
        );
    }

    for (id, path) in [
        ("yarn-classic", "yarn.lock"),
        ("yarn-berry", "yarn.lock"),
        ("swift-v1", "Package.resolved"),
        ("swift-v2", "Package.resolved"),
        ("cargo-workspace", "member/Cargo.toml"),
        ("npm-workspace", "packages/member/package.json"),
        ("bun-workspace", "packages/member/package.json"),
        ("go-workspace", "go.work"),
        ("go-workspace", "go.work.sum"),
    ] {
        assert!(
            ids.get(id)
                .is_some_and(|fixture| fixture.upload_paths.iter().any(|upload| upload == path)),
            "{id} must select {path}"
        );
    }
    // Swift's results label the family without repeating the input revision.
    assert_ne!(
        ids["swift-v1"].files["Package.resolved"],
        ids["swift-v2"].files["Package.resolved"]
    );
}

fn check_baseline(fixture: &Fixture, revision: Option<(&str, &str)>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/live/baselines")
        .join(format!("{}.json", fixture.id));
    assert!(path.is_file(), "missing baseline for {}", fixture.id);
    let bytes = std::fs::read(path).expect("read fixture baseline");
    let snapshot: BTreeMap<String, Value> =
        serde_json::from_slice(&bytes).expect("each baseline is a JSON object");
    assert!(
        fixture.checks.keys().eq(snapshot.keys()),
        "checks for {}",
        fixture.id
    );
    for check in ["sbom", "audit", "license_report"] {
        assert!(
            snapshot.contains_key(check),
            "{} is missing {check}",
            fixture.id
        );
    }
    if let Some((field, value)) = revision {
        let lockfiles = snapshot["sbom"]["stable"]["lockfiles"]
            .as_array()
            .expect("parser fixture has lockfile evidence");
        assert!(
            lockfiles.iter().any(|lockfile| lockfile[field] == value),
            "{} is missing {field} {value}",
            fixture.id
        );
    }
}
