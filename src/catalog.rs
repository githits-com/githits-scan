//! Catalog of repository files that are package evidence.
//!
//! The GitHits SBOM API recognizes files by name and content, and rejects the whole
//! upload when one file is unusable. This module therefore owns the single canonical
//! answer to "is this path a lockfile or manifest the API will accept, for which
//! ecosystem, and which manifest owns a lockfile?". It is pure data: no I/O, no
//! parsing.
//!
//! The lockfile names follow documented families or qualified live support. Each
//! lockfile names the manifest that owns it, which the service combines with it to
//! add project metadata and declared dependencies; Go modules, vcpkg, and Zig have
//! manifests only, which the service resolves from registries. See
//! `docs/implementation/package-file-catalog.md` for provenance and the deliberate
//! omissions.

use std::fmt;
use std::path::{Component, Path};

/// A package ecosystem whose lockfiles or manifests the GitHits SBOM API accepts.
///
/// Variants group the lockfile tools that share a manifest: `package.json` is the
/// companion of npm, pnpm, Yarn, and Bun lockfiles alike, so they are one ecosystem.
/// The service identifies the exact tool from the file name and contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Ecosystem {
    /// Cargo: `Cargo.lock` with `Cargo.toml`.
    Rust,
    /// npm, pnpm, Yarn, and Bun: `package-lock.json`, `npm-shrinkwrap.json`,
    /// `pnpm-lock.yaml`, `yarn.lock`, or text `bun.lock` with `package.json`.
    JavaScript,
    /// uv, Poetry, PDM, and Pipenv: `uv.lock`, `poetry.lock`, `pdm.lock`, or
    /// `Pipfile.lock`. Only uv, Poetry, and PDM locks pair with `pyproject.toml`;
    /// `Pipfile` is not cataloged.
    Python,
    /// Swift Package Manager: `Package.resolved` with `Package.swift`.
    Swift,
    /// Gradle dependency locking: cataloged Gradle lockfiles. Build scripts
    /// are separate manifest evidence, not automatic lockfile companions.
    Gradle,
    /// NuGet: `packages.lock.json` with `*.csproj`.
    DotNet,
    /// Dart and Flutter: `pubspec.lock` with `pubspec.yaml`.
    Dart,
    /// Composer: `composer.lock` with `composer.json`.
    Php,
    /// Mix: `mix.lock` with `mix.exs`.
    Elixir,
    /// Bundler: `Gemfile.lock` with `Gemfile`, or standalone `gems.locked`.
    Ruby,
    /// Rebar3: `rebar.lock` with `rebar.config`.
    Erlang,
    /// Conan: `conan.lock`. Conan recipes are not accepted as manifests, and
    /// `vcpkg.json` belongs to vcpkg.
    Conan,
    /// Go dep: `Gopkg.lock`. `go.mod` belongs to Go modules and is not paired.
    GoDep,
    /// Go modules: `go.mod`, a manifest without a lockfile. `go.sum` records
    /// checksums rather than a selection and is not uploaded.
    Go,
    /// vcpkg manifest mode: `vcpkg.json`, a manifest without a lockfile.
    Vcpkg,
    /// Zig package manager: `build.zig.zon`, a manifest without a lockfile.
    Zig,
}

impl Ecosystem {
    /// Every ecosystem, in the order the documentation lists them.
    pub const ALL: [Self; 16] = [
        Self::Rust,
        Self::JavaScript,
        Self::Python,
        Self::Swift,
        Self::Gradle,
        Self::DotNet,
        Self::Dart,
        Self::Php,
        Self::Elixir,
        Self::Ruby,
        Self::Erlang,
        Self::Conan,
        Self::GoDep,
        Self::Go,
        Self::Vcpkg,
        Self::Zig,
    ];

    /// Stable lowercase identifier used in machine-readable output and
    /// configuration. Never renamed once published.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::JavaScript => "javascript",
            Self::Python => "python",
            Self::Swift => "swift",
            Self::Gradle => "gradle",
            Self::DotNet => "dotnet",
            Self::Dart => "dart",
            Self::Php => "php",
            Self::Elixir => "elixir",
            Self::Ruby => "ruby",
            Self::Erlang => "erlang",
            Self::Conan => "conan",
            Self::GoDep => "go_dep",
            Self::Go => "go",
            Self::Vcpkg => "vcpkg",
            Self::Zig => "zig",
        }
    }

    /// Human-readable name for reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rust => "Rust",
            Self::JavaScript => "JavaScript",
            Self::Python => "Python",
            Self::Swift => "Swift",
            Self::Gradle => "Gradle",
            Self::DotNet => ".NET",
            Self::Dart => "Dart",
            Self::Php => "PHP",
            Self::Elixir => "Elixir",
            Self::Ruby => "Ruby",
            Self::Erlang => "Erlang",
            Self::Conan => "Conan",
            Self::GoDep => "Go dep",
            Self::Go => "Go",
            Self::Vcpkg => "vcpkg",
            Self::Zig => "Zig",
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Whether a catalog entry is a lockfile or a manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Records resolved versions; the primary evidence a scan looks for. The
    /// owner names the manifest the lockfile belongs to.
    Lockfile(Owner),
    /// Declares dependencies; uploaded with the lockfile it owns, or as a
    /// manifest-only project unless the run is `--lockfiles-only`.
    Manifest,
}

/// The same-directory manifest a lockfile belongs to: the file its tool writes
/// the lockfile from, and that the service can combine with it.
///
/// A lockfile is uploaded with its owner only. The owner supplies what the
/// lockfile does not record, such as the project's declared license and, for
/// some formats, its direct dependencies; any other manifest is not uploaded
/// with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Owner {
    /// The manifest with this exact name.
    Named(&'static str),
    /// The only manifest with this suffix in the directory. With several, the
    /// lockfile cannot be attributed to one of them and is ambiguous.
    OnlyWithSuffix(&'static str),
    /// No manifest the service can combine with the lockfile: its owner is not
    /// cataloged, or the service does not associate the two.
    Uncombinable,
}

/// The catalog's verdict for one repository-relative path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Classification {
    /// Ecosystem the file belongs to.
    pub ecosystem: Ecosystem,
    /// Lockfile or manifest.
    pub role: Role,
}

/// How a catalog rule matches a path.
#[derive(Debug, Clone, Copy)]
enum Matcher {
    /// The final path component equals this name (case-sensitive).
    Name(&'static str),
    /// The final path component ends with this suffix, including the leading dot.
    Suffix(&'static str),
    /// The final component ends with this suffix and the two parent components
    /// are exactly these directory names (legacy Gradle dependency locks).
    SuffixUnderDirectories(&'static str, [&'static str; 2]),
}

/// One catalog rule.
#[derive(Debug, Clone, Copy)]
struct Rule {
    matcher: Matcher,
    ecosystem: Ecosystem,
    role: Role,
}

const fn lockfile(name: &'static str, ecosystem: Ecosystem, owner: Owner) -> Rule {
    Rule {
        matcher: Matcher::Name(name),
        ecosystem,
        role: Role::Lockfile(owner),
    }
}

const fn manifest(name: &'static str, ecosystem: Ecosystem) -> Rule {
    Rule {
        matcher: Matcher::Name(name),
        ecosystem,
        role: Role::Manifest,
    }
}

/// Cataloged name of the Cargo package and workspace manifest.
const CARGO_MANIFEST: &str = "Cargo.toml";

const CARGO_LOCKFILE: &str = "Cargo.lock";
const NPM_PACKAGE_LOCKFILE: &str = "package-lock.json";
const BUN_LOCKFILE: &str = "bun.lock";
const NPM_SHRINKWRAP_LOCKFILE: &str = "npm-shrinkwrap.json";
/// Cataloged name of the npm package and workspace manifest.
const NPM_MANIFEST: &str = "package.json";

const PACKAGE_JSON: Owner = Owner::Named(NPM_MANIFEST);
const PYPROJECT: Owner = Owner::Named("pyproject.toml");

/// Legacy Gradle dependency locks live two directories below their project.
const LEGACY_GRADLE_LOCK_DIRECTORIES: [&str; 2] = ["gradle", "dependency-locks"];

/// Every file the scanner may upload. Order is irrelevant for the outcome: no two
/// rules that can match the same path disagree on ecosystem or role.
const RULES: &[Rule] = &[
    lockfile(
        CARGO_LOCKFILE,
        Ecosystem::Rust,
        Owner::Named(CARGO_MANIFEST),
    ),
    manifest(CARGO_MANIFEST, Ecosystem::Rust),
    lockfile(NPM_PACKAGE_LOCKFILE, Ecosystem::JavaScript, PACKAGE_JSON),
    lockfile(NPM_SHRINKWRAP_LOCKFILE, Ecosystem::JavaScript, PACKAGE_JSON),
    lockfile("pnpm-lock.yaml", Ecosystem::JavaScript, PACKAGE_JSON),
    lockfile("yarn.lock", Ecosystem::JavaScript, PACKAGE_JSON),
    lockfile(BUN_LOCKFILE, Ecosystem::JavaScript, PACKAGE_JSON),
    manifest(NPM_MANIFEST, Ecosystem::JavaScript),
    lockfile("uv.lock", Ecosystem::Python, PYPROJECT),
    lockfile("poetry.lock", Ecosystem::Python, PYPROJECT),
    lockfile("pdm.lock", Ecosystem::Python, PYPROJECT),
    // Owned by `Pipfile`, which the service does not accept as a manifest.
    lockfile("Pipfile.lock", Ecosystem::Python, Owner::Uncombinable),
    manifest("pyproject.toml", Ecosystem::Python),
    lockfile(
        "Package.resolved",
        Ecosystem::Swift,
        Owner::Named("Package.swift"),
    ),
    manifest("Package.swift", Ecosystem::Swift),
    // The service does not associate Gradle build scripts with dependency locks.
    lockfile("gradle.lockfile", Ecosystem::Gradle, Owner::Uncombinable),
    lockfile(
        "buildscript-gradle.lockfile",
        Ecosystem::Gradle,
        Owner::Uncombinable,
    ),
    lockfile(
        "settings-gradle.lockfile",
        Ecosystem::Gradle,
        Owner::Uncombinable,
    ),
    Rule {
        matcher: Matcher::SuffixUnderDirectories(".lockfile", LEGACY_GRADLE_LOCK_DIRECTORIES),
        ecosystem: Ecosystem::Gradle,
        role: Role::Lockfile(Owner::Uncombinable),
    },
    manifest("build.gradle", Ecosystem::Gradle),
    manifest("build.gradle.kts", Ecosystem::Gradle),
    lockfile(
        "packages.lock.json",
        Ecosystem::DotNet,
        Owner::OnlyWithSuffix(".csproj"),
    ),
    Rule {
        matcher: Matcher::Suffix(".csproj"),
        ecosystem: Ecosystem::DotNet,
        role: Role::Manifest,
    },
    lockfile(
        "pubspec.lock",
        Ecosystem::Dart,
        Owner::Named("pubspec.yaml"),
    ),
    manifest("pubspec.yaml", Ecosystem::Dart),
    lockfile(
        "composer.lock",
        Ecosystem::Php,
        Owner::Named("composer.json"),
    ),
    manifest("composer.json", Ecosystem::Php),
    lockfile("mix.lock", Ecosystem::Elixir, Owner::Named("mix.exs")),
    manifest("mix.exs", Ecosystem::Elixir),
    lockfile("Gemfile.lock", Ecosystem::Ruby, Owner::Named("Gemfile")),
    // Owned by `gems.rb`, which the service does not accept as a manifest.
    lockfile("gems.locked", Ecosystem::Ruby, Owner::Uncombinable),
    manifest("Gemfile", Ecosystem::Ruby),
    lockfile(
        "rebar.lock",
        Ecosystem::Erlang,
        Owner::Named("rebar.config"),
    ),
    manifest("rebar.config", Ecosystem::Erlang),
    lockfile("conan.lock", Ecosystem::Conan, Owner::Uncombinable),
    lockfile("Gopkg.lock", Ecosystem::GoDep, Owner::Uncombinable),
    manifest("go.mod", Ecosystem::Go),
    manifest("vcpkg.json", Ecosystem::Vcpkg),
    manifest("build.zig.zon", Ecosystem::Zig),
];

/// Directory names under which package files are installed copies rather than
/// project evidence. These are hard skips; fixture selection is owned by config.
///
/// Hidden directories (`.tox`, `.bundle`, `.dart_tool`, ...) are excluded by the
/// walker's hidden-file policy and do not need to be listed here.
///
/// Matching is exact-case on purpose: these names are created by package managers
/// or reserved by a toolchain in this exact spelling, and a differently cased
/// directory is a project choice.
const EXCLUDED_COMPONENTS: &[&str] = &[
    "node_modules",
    "vendor",
    "site-packages",
    "deps",
    "_build",
    "_checkouts",
];

/// The exact lockfile names the scanner looks for, in catalog order.
///
/// Meant for messages that tell a user what a scan would have accepted. Pattern
/// rules (legacy Gradle dependency locks) are not names and are not listed.
pub fn lockfile_names() -> impl Iterator<Item = &'static str> {
    RULES
        .iter()
        .filter_map(|rule| match (rule.role, rule.matcher) {
            (Role::Lockfile(_), Matcher::Name(name)) => Some(name),
            _ => None,
        })
}

/// A lockfile family whose manifest declarations can describe workspace members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceFamily {
    /// Cargo workspaces declared in `Cargo.toml`.
    Cargo,
    /// npm workspaces declared in `package.json`.
    Npm,
    /// Bun workspaces declared in `package.json`.
    Bun,
}

/// Identify the cataloged lockfile family that supports workspace expansion.
pub(crate) fn workspace_family(relative_path: &str) -> Option<WorkspaceFamily> {
    match Path::new(relative_path).file_name()?.to_str()? {
        CARGO_LOCKFILE => Some(WorkspaceFamily::Cargo),
        NPM_PACKAGE_LOCKFILE | NPM_SHRINKWRAP_LOCKFILE => Some(WorkspaceFamily::Npm),
        BUN_LOCKFILE => Some(WorkspaceFamily::Bun),
        _ => None,
    }
}

/// Classify a repository-relative path.
///
/// Returns `None` for files outside the supported catalog, and for files
/// that live under an installed-dependency directory such as `node_modules`.
/// Matching is exact and case-sensitive, like the service's own recognition.
#[must_use]
pub fn classify(relative_path: &Path) -> Option<Classification> {
    let file_name = relative_path.file_name()?.to_str()?;
    if is_under_excluded_directory(relative_path) {
        return None;
    }
    RULES
        .iter()
        .find(|rule| matches(rule.matcher, relative_path, file_name))
        .map(|rule| Classification {
            ecosystem: rule.ecosystem,
            role: rule.role,
        })
}

/// Explain a recognized package format that Scan does not yet upload.
/// Matching follows the same installed-dependency exclusions as supported evidence.
#[must_use]
pub fn unsupported_hint(path: &Path) -> Option<&'static str> {
    if is_under_excluded_directory(path) {
        return None;
    }
    match path.file_name()?.to_str()? {
        "requirements.txt" => Some(
            "use a supported Python lockfile (uv, Poetry, PDM or Pipenv), or pyproject.toml for manifest resolution",
        ),
        "deno.lock" => {
            Some("githits-scan does not upload Deno lockfiles; see README: What gets uploaded")
        }
        "pom.xml" => {
            Some("githits-scan does not upload Maven manifests; see README: What gets uploaded")
        }
        _ => None,
    }
}

/// The directory whose manifests own a lockfile at `relative_path`: its own
/// directory, or the project directory two levels up for a legacy Gradle
/// dependency lock. `None` for a path without a parent.
#[must_use]
pub fn owning_directory(relative_path: &Path) -> Option<&Path> {
    let directory = relative_path.parent()?;
    let file_name = relative_path.file_name()?.to_str()?;
    let legacy = Matcher::SuffixUnderDirectories(".lockfile", LEGACY_GRADLE_LOCK_DIRECTORIES);
    if matches(legacy, relative_path, file_name) {
        return directory.parent()?.parent();
    }
    Some(directory)
}

fn matches(matcher: Matcher, path: &Path, file_name: &str) -> bool {
    match matcher {
        Matcher::Name(expected) => file_name == expected,
        Matcher::Suffix(expected) => has_stem_and_suffix(file_name, expected),
        Matcher::SuffixUnderDirectories(expected, directories) => {
            has_stem_and_suffix(file_name, expected) && parent_directories(path) == directories
        }
    }
}

fn has_stem_and_suffix(file_name: &str, suffix: &str) -> bool {
    file_name.len() > suffix.len() && file_name.ends_with(suffix)
}

/// The names of the two directories closest to the file, outermost first.
fn parent_directories(path: &Path) -> [&str; 2] {
    let mut names = path
        .components()
        .rev()
        .skip(1)
        .filter_map(|component| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        });
    let nearest = names.next().unwrap_or_default();
    let outer = names.next().unwrap_or_default();
    [outer, nearest]
}

fn is_under_excluded_directory(path: &Path) -> bool {
    path.parent().is_some_and(is_excluded_directory)
}

/// Whether a directory path contains an installed-dependency directory.
pub(crate) fn is_excluded_directory(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(name) => name
            .to_str()
            .is_some_and(|name| EXCLUDED_COMPONENTS.contains(&name)),
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classification(path: &str) -> Option<Classification> {
        classify(Path::new(path))
    }

    /// The ecosystem of `path` when the catalog classifies it as a lockfile.
    fn lockfile_ecosystem(path: &str) -> Option<Ecosystem> {
        classification(path)
            .filter(|c| matches!(c.role, Role::Lockfile(_)))
            .map(|c| c.ecosystem)
    }

    fn owner(path: &str) -> Option<Owner> {
        match classification(path)?.role {
            Role::Lockfile(owner) => Some(owner),
            Role::Manifest => None,
        }
    }

    const fn manifest_of(ecosystem: Ecosystem) -> Classification {
        Classification {
            ecosystem,
            role: Role::Manifest,
        }
    }

    #[test]
    fn recognizes_every_cataloged_lockfile_family() {
        let cases = [
            ("Cargo.lock", Ecosystem::Rust),
            ("package-lock.json", Ecosystem::JavaScript),
            ("npm-shrinkwrap.json", Ecosystem::JavaScript),
            ("pnpm-lock.yaml", Ecosystem::JavaScript),
            ("yarn.lock", Ecosystem::JavaScript),
            ("bun.lock", Ecosystem::JavaScript),
            ("uv.lock", Ecosystem::Python),
            ("poetry.lock", Ecosystem::Python),
            ("pdm.lock", Ecosystem::Python),
            ("Pipfile.lock", Ecosystem::Python),
            ("Package.resolved", Ecosystem::Swift),
            ("gradle.lockfile", Ecosystem::Gradle),
            ("buildscript-gradle.lockfile", Ecosystem::Gradle),
            ("settings-gradle.lockfile", Ecosystem::Gradle),
            ("packages.lock.json", Ecosystem::DotNet),
            ("pubspec.lock", Ecosystem::Dart),
            ("composer.lock", Ecosystem::Php),
            ("mix.lock", Ecosystem::Elixir),
            ("Gemfile.lock", Ecosystem::Ruby),
            ("gems.locked", Ecosystem::Ruby),
            ("rebar.lock", Ecosystem::Erlang),
            ("conan.lock", Ecosystem::Conan),
            ("Gopkg.lock", Ecosystem::GoDep),
        ];
        let paths = cases.iter().flat_map(|&(file, ecosystem)| {
            [
                (file.to_owned(), ecosystem),
                (format!("services/api/{file}"), ecosystem),
            ]
        });
        for (path, ecosystem) in paths {
            assert_eq!(lockfile_ecosystem(&path), Some(ecosystem), "{path}");
        }
    }

    #[test]
    fn recognizes_every_cataloged_manifest() {
        let cases = [
            ("Cargo.toml", Ecosystem::Rust),
            ("package.json", Ecosystem::JavaScript),
            ("pyproject.toml", Ecosystem::Python),
            ("Package.swift", Ecosystem::Swift),
            ("build.gradle", Ecosystem::Gradle),
            ("build.gradle.kts", Ecosystem::Gradle),
            ("App.csproj", Ecosystem::DotNet),
            ("pubspec.yaml", Ecosystem::Dart),
            ("composer.json", Ecosystem::Php),
            ("mix.exs", Ecosystem::Elixir),
            ("Gemfile", Ecosystem::Ruby),
            ("rebar.config", Ecosystem::Erlang),
            ("go.mod", Ecosystem::Go),
            ("vcpkg.json", Ecosystem::Vcpkg),
            ("build.zig.zon", Ecosystem::Zig),
        ];
        for (file, ecosystem) in cases {
            assert_eq!(classification(file), Some(manifest_of(ecosystem)), "{file}");
        }
    }

    #[test]
    fn recognizes_legacy_gradle_dependency_locks_only_under_their_directory() {
        assert_eq!(
            lockfile_ecosystem("app/gradle/dependency-locks/compileClasspath.lockfile"),
            Some(Ecosystem::Gradle)
        );
        assert_eq!(
            classification("app/dependency-locks/compileClasspath.lockfile"),
            None
        );
        assert_eq!(classification("gradle/dependency-locks/.lockfile"), None);
        assert_eq!(classification("app/compileClasspath.lockfile"), None);
    }

    #[test]
    fn requires_a_stem_before_an_extension_match() {
        assert_eq!(classification(".csproj"), None);
        assert_eq!(
            classification("a.csproj"),
            Some(manifest_of(Ecosystem::DotNet))
        );
        assert_eq!(
            classification("src/Web.csproj"),
            Some(manifest_of(Ecosystem::DotNet))
        );
    }

    #[test]
    fn matching_is_case_sensitive() {
        assert_eq!(classification("cargo.lock"), None);
        assert_eq!(classification("PACKAGE-LOCK.JSON"), None);
        assert_eq!(classification("gemfile"), None);
        assert_eq!(classification("Bun.lock"), None);
        assert_eq!(classification("BUN.LOCK"), None);
        assert_eq!(classification("Go.mod"), None);
        assert_eq!(classification("VCPKG.json"), None);
    }

    #[test]
    fn rejects_uncataloged_and_unsupported_files() {
        for path in [
            "bun.lock.bak",
            "bun.lockb",
            "go.sum",
            "go.work",
            "build.zig",
            "vcpkg-configuration.json",
            "conanfile.txt",
            "pom.xml",
            "requirements.txt",
            "Pipfile",
            "Cartfile.resolved",
            "paket.lock",
            "flake.lock",
            "README.md",
            "Cargo.lock.bak",
        ] {
            assert_eq!(classification(path), None, "{path}");
        }
    }

    #[test]
    fn ignores_installed_dependency_directories() {
        for path in [
            "node_modules/left-pad/package.json",
            "node_modules/left-pad/package-lock.json",
            "node_modules/left-pad/bun.lock",
            "vendor/bundle/Gemfile.lock",
            "deps/plug/mix.lock",
            "_build/dev/lib/plug/mix.lock",
            "_checkouts/dep/rebar.lock",
            "venv/lib/python3.12/site-packages/pkg/pyproject.toml",
            "vendor/github.com/pkg/errors/go.mod",
        ] {
            assert_eq!(classification(path), None, "{path}");
        }
        // A directory merely named like an install location is not one.
        assert_eq!(
            lockfile_ecosystem("vendors/Cargo.lock"),
            Some(Ecosystem::Rust)
        );
        assert_eq!(
            classification("TestData/go.mod"),
            Some(manifest_of(Ecosystem::Go))
        );
        assert_eq!(
            classification("testdata/go.mod"),
            Some(manifest_of(Ecosystem::Go))
        );
    }

    #[test]
    fn every_ecosystem_has_a_unique_identifier_and_name() {
        let ids: std::collections::BTreeSet<_> = Ecosystem::ALL.iter().map(|e| e.id()).collect();
        assert_eq!(ids.len(), Ecosystem::ALL.len());
        let names: std::collections::BTreeSet<_> =
            Ecosystem::ALL.iter().map(|e| e.name()).collect();
        assert_eq!(names.len(), Ecosystem::ALL.len());
        for ecosystem in Ecosystem::ALL {
            let id = ecosystem.id();
            assert!(
                id.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{id}"
            );
            assert_eq!(ecosystem.to_string(), ecosystem.name());
        }
    }

    #[test]
    fn lockfile_names_are_exactly_the_named_lockfile_rules() {
        let names: Vec<_> = lockfile_names().collect();
        assert_eq!(names.first(), Some(&"Cargo.lock"));
        assert_eq!(names.last(), Some(&"Gopkg.lock"));
        assert_eq!(names.len(), 23);
        assert!(names.contains(&"bun.lock"));
        for name in &names {
            assert!(lockfile_ecosystem(name).is_some(), "{name}");
        }
    }

    #[test]
    fn npm_evidence_catalog_workspace_families() {
        let supported_lockfiles = [
            "Cargo.lock",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "bun.lock",
        ];
        for (path, expected) in [
            ("Cargo.lock", Some(WorkspaceFamily::Cargo)),
            ("package-lock.json", Some(WorkspaceFamily::Npm)),
            ("npm-shrinkwrap.json", Some(WorkspaceFamily::Npm)),
            ("bun.lock", Some(WorkspaceFamily::Bun)),
            ("services/api/bun.lock", Some(WorkspaceFamily::Bun)),
            ("services/api/Cargo.lock", Some(WorkspaceFamily::Cargo)),
            ("services/api/package-lock.json", Some(WorkspaceFamily::Npm)),
            (
                "services/api/npm-shrinkwrap.json",
                Some(WorkspaceFamily::Npm),
            ),
        ] {
            assert_eq!(workspace_family(path), expected, "{path}");
        }

        for file_name in lockfile_names().filter(|name| !supported_lockfiles.contains(name)) {
            assert_eq!(workspace_family(file_name), None, "{file_name}");
        }

        for path in [
            "Cargo.toml",
            "package.json",
            "cargo.toml",
            "PACKAGE.JSON",
            "cargo.lock",
            "PACKAGE-LOCK.JSON",
            "npm-SHRINKWRAP.json",
            "package-lock.json.bak",
            "README.md",
            "app/gradle/dependency-locks/compileClasspath.lockfile",
        ] {
            assert_eq!(workspace_family(path), None, "{path}");
        }
    }

    #[test]
    fn every_lockfile_names_the_manifest_that_owns_it() {
        let cases = [
            ("Cargo.lock", Owner::Named("Cargo.toml")),
            ("package-lock.json", Owner::Named("package.json")),
            ("npm-shrinkwrap.json", Owner::Named("package.json")),
            ("pnpm-lock.yaml", Owner::Named("package.json")),
            ("yarn.lock", Owner::Named("package.json")),
            ("bun.lock", Owner::Named("package.json")),
            ("uv.lock", Owner::Named("pyproject.toml")),
            ("poetry.lock", Owner::Named("pyproject.toml")),
            ("pdm.lock", Owner::Named("pyproject.toml")),
            ("Pipfile.lock", Owner::Uncombinable),
            ("Package.resolved", Owner::Named("Package.swift")),
            ("gradle.lockfile", Owner::Uncombinable),
            ("buildscript-gradle.lockfile", Owner::Uncombinable),
            ("settings-gradle.lockfile", Owner::Uncombinable),
            (
                "gradle/dependency-locks/compileClasspath.lockfile",
                Owner::Uncombinable,
            ),
            ("packages.lock.json", Owner::OnlyWithSuffix(".csproj")),
            ("pubspec.lock", Owner::Named("pubspec.yaml")),
            ("composer.lock", Owner::Named("composer.json")),
            ("mix.lock", Owner::Named("mix.exs")),
            ("Gemfile.lock", Owner::Named("Gemfile")),
            ("gems.locked", Owner::Uncombinable),
            ("rebar.lock", Owner::Named("rebar.config")),
            ("conan.lock", Owner::Uncombinable),
            ("Gopkg.lock", Owner::Uncombinable),
        ];
        for (path, expected) in cases {
            assert_eq!(owner(path), Some(expected), "{path}");
        }
        assert_eq!(
            cases.len(),
            lockfile_names().count() + 1,
            "every lockfile rule"
        );
    }

    #[test]
    fn owners_are_cataloged_manifests_of_the_lockfile_ecosystem() {
        let owned = RULES.iter().filter_map(|rule| match rule.role {
            Role::Lockfile(Owner::Named(name)) => Some((rule, name.to_owned())),
            Role::Lockfile(Owner::OnlyWithSuffix(suffix)) => Some((rule, format!("App{suffix}"))),
            Role::Lockfile(Owner::Uncombinable) | Role::Manifest => None,
        });
        for (rule, owner) in owned {
            let manifest = classification(&owner);
            assert_eq!(
                manifest,
                Some(Classification {
                    ecosystem: rule.ecosystem,
                    role: Role::Manifest,
                }),
                "{owner}"
            );
        }
    }

    #[test]
    fn a_legacy_gradle_lock_is_owned_by_the_project_two_levels_up() {
        let owning = |path: &str| owning_directory(Path::new(path)).map(Path::to_path_buf);
        assert_eq!(
            owning("app/gradle/dependency-locks/compileClasspath.lockfile"),
            Some("app".into())
        );
        assert_eq!(
            owning("gradle/dependency-locks/compileClasspath.lockfile"),
            Some("".into())
        );
        assert_eq!(owning("app/gradle.lockfile"), Some("app".into()));
        assert_eq!(owning("Cargo.lock"), Some("".into()));
    }

    #[test]
    fn handles_paths_without_a_file_name() {
        assert_eq!(classification(""), None);
        assert_eq!(classification(".."), None);
    }
}
