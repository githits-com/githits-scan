//! Repository discovery: walk a directory tree and pair lockfiles with the
//! manifests that own them.
//!
//! This is the only module that reads the filesystem during a scan. It consults
//! [`catalog`] for every file name decision and produces an
//! [`Inventory`] whose paths are repository-relative with forward slashes, which
//! is the form the API expects in upload filenames. [`scan`] reads metadata only.
//! Upload preparation uses [`read_file`] for bounded cataloged contents and the
//! pure workspace selectors to interpret already-read member declarations.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read as _};
use std::path::{Component, Path, PathBuf};

use ignore::WalkBuilder;
use thiserror::Error;

use crate::catalog::{self, Ecosystem, Owner, Role};

#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only native upload selection"
)]
pub(crate) mod cargo;
#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only native upload selection"
)]
pub(crate) mod npm;

/// The manifest that owns a lockfile, uploaded with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Companion {
    /// Path relative to the scan root, with forward slashes.
    pub path: String,
    /// File size from metadata.
    pub bytes: u64,
}

/// A lockfile found in the scanned tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockfile {
    /// Path relative to the scan root, with forward slashes.
    pub path: String,
    /// Ecosystem the lockfile belongs to.
    pub ecosystem: Ecosystem,
    /// File size from metadata.
    pub bytes: u64,
    /// The owning manifest from the lockfile's project directory, as the
    /// catalog names it. Empty when the owner is absent (a lockfile committed
    /// without its manifest) or cannot be combined with the lockfile.
    pub manifests: Vec<Companion>,
}

/// A manifest that no lockfile covers: its directory and every ancestor hold no
/// lockfile of its ecosystem, or its directory's lockfile is ambiguous.
///
/// Such a project is uploaded unless the run is `--lockfiles-only`, and the
/// service resolves its dependencies from the declared constraints. That is
/// less exact than a recorded inventory, so the summary names every such
/// project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestOnly {
    /// Path relative to the scan root, with forward slashes.
    pub path: String,
    /// Ecosystem the manifest belongs to.
    pub ecosystem: Ecosystem,
    /// File size from metadata.
    pub bytes: u64,
}

/// A manifest near a lockfile it does not own.
///
/// Either the nearest ancestor directory holds a lockfile of its ecosystem,
/// or its own directory holds one that it does not own or cannot be combined
/// with, such as `pyproject.toml` beside `Pipfile.lock`.
///
/// Classification is purely path-based and establishes neither workspace
/// membership nor recorded dependency coverage. Cargo and supported npm members can
/// be selected during upload preparation; other candidates require configuration. Service
/// parsing owns their final association with recorded lock evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoveredManifest {
    /// Path relative to the scan root, with forward slashes.
    pub path: String,
    /// Ecosystem the manifest belongs to.
    pub ecosystem: Ecosystem,
    /// File size from metadata.
    pub bytes: u64,
    /// The covering lockfile of the same ecosystem (the first by path when
    /// that directory holds several).
    pub lockfile: String,
}

/// A lockfile that more than one manifest could own, such as one
/// `packages.lock.json` beside several `.csproj` files.
///
/// The lockfile cannot be attributed to one project, so it is not uploaded and
/// its candidate owners are manifest-only projects instead. Excluding the
/// lockfile records that decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguousLockfile {
    /// Path relative to the scan root, with forward slashes.
    pub path: String,
    /// Ecosystem the lockfile belongs to.
    pub ecosystem: Ecosystem,
    /// File size from metadata.
    pub bytes: u64,
    /// The manifests that could own it, sorted by path.
    pub manifests: Vec<String>,
}

/// A recognized but unsupported file, reported without reading its contents.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UnsupportedFile {
    /// Repository-relative display path; non-UTF-8 names use replacement characters.
    pub path: String,
    /// Actionable format limitation or alternative.
    pub hint: &'static str,
}

/// Everything a scan found, sorted by path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    /// Recognized unsupported formats; never selected for upload.
    pub unsupported: Vec<UnsupportedFile>,
    /// Lockfiles with their owning manifests.
    pub lockfiles: Vec<Lockfile>,
    /// Manifests below a lockfile of the same ecosystem in an ancestor directory.
    pub nested: Vec<CoveredManifest>,
    /// Manifests beside a lockfile of their ecosystem that they do not own or
    /// cannot be combined with.
    pub uncombined: Vec<CoveredManifest>,
    /// Lockfiles that several manifests could own; not uploaded.
    pub ambiguous: Vec<AmbiguousLockfile>,
    /// Manifests that no lockfile covers.
    pub manifest_only: Vec<ManifestOnly>,
}

impl Inventory {
    /// Number of distinct ecosystems among the lockfiles.
    #[must_use]
    pub fn ecosystem_count(&self) -> usize {
        let mut ecosystems: Vec<_> = self.lockfiles.iter().map(|l| l.ecosystem).collect();
        ecosystems.sort_unstable();
        ecosystems.dedup();
        ecosystems.len()
    }
}

/// Why a scan could not complete.
#[derive(Debug, Error)]
pub enum DiscoverError {
    /// The scan root does not exist or is not a directory.
    #[error("{} is not a directory", path.display())]
    NotADirectory {
        /// The path as given by the caller.
        path: PathBuf,
    },
    /// The walker could not read part of the tree (for example a directory
    /// without read permission). The scan stops rather than report a partial
    /// inventory as complete.
    #[error(
        "cannot read the directory tree; check permissions or pass --exclude 'relative-directory/**' (relative to the scan root, without './')"
    )]
    Walk {
        /// The walker's error, which names the path.
        #[source]
        source: ignore::Error,
    },
    /// Metadata for a cataloged file could not be read.
    #[error("cannot read metadata of {path}")]
    Metadata {
        /// Repository-relative path.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// A cataloged file cannot be named as a relative UTF-8 path, which every
    /// upload filename must be (for example, a directory name that is not
    /// valid UTF-8).
    #[error("cannot express {} as a relative UTF-8 path", path.display())]
    InvalidPath {
        /// The offending path as the OS reports it.
        path: PathBuf,
    },
    /// A file selected for upload could not be read.
    #[error("cannot read {path}")]
    Read {
        /// Repository-relative path.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// A file selected for upload is not valid UTF-8; the service would reject
    /// the whole upload as `invalid_utf8`.
    #[error("{path} is not valid UTF-8")]
    NotUtf8 {
        /// Repository-relative path.
        path: String,
    },
    /// A file selected for upload is larger than the caller's bound at read
    /// time. The inventory size was within the bound, so the file grew after
    /// the scan, for example because a package manager rewrote it.
    #[error("{path} is larger than {limit} bytes; it changed after the scan")]
    FileTooLarge {
        /// Repository-relative path.
        path: String,
        /// The bound the caller passed.
        limit: u64,
    },
}

/// A cataloged file before pairing.
struct Candidate {
    path: String,
    bytes: u64,
}

/// A cataloged lockfile before pairing.
struct LockCandidate {
    file: Candidate,
    owner: Owner,
}

/// Files of one ecosystem in one project directory. Lockfiles are grouped by
/// the directory whose manifests own them, manifests by their own directory.
#[derive(Default)]
struct Group {
    lockfiles: Vec<LockCandidate>,
    manifests: Vec<Candidate>,
}

/// Scan `root` for package evidence.
///
/// The walk honors `.gitignore`, `.git/info/exclude`, and the global git excludes
/// whether or not `root` is inside a git repository, skips hidden entries, and
/// never follows symbolic links. Files under installed-dependency directories
/// are excluded by the catalog. The result is sorted by path so output is
/// deterministic across platforms.
///
/// # Errors
///
/// Returns [`DiscoverError::NotADirectory`] for a root that is not a directory,
/// and stops at the first unreadable directory, unreadable cataloged file, or
/// path that cannot be expressed as a relative UTF-8 string.
pub fn scan(root: &Path) -> Result<Inventory, DiscoverError> {
    scan_filtered(root, |_| true)
}

/// Walk with a repository-relative directory predicate evaluated before descent.
pub(crate) fn scan_filtered(
    root: &Path,
    include_directory: impl Fn(&Path) -> bool + Send + Sync + 'static,
) -> Result<Inventory, DiscoverError> {
    require_directory(root)?;
    let filter_root = root.to_path_buf();
    let mut groups: BTreeMap<(String, Ecosystem), Group> = BTreeMap::new();
    let mut unsupported = Vec::new();
    let walker = WalkBuilder::new(root)
        .hidden(true)
        .ignore(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .require_git(false)
        .follow_links(false)
        .filter_entry(move |entry| {
            if entry.depth() == 0 || !entry.file_type().is_some_and(|t| t.is_dir()) {
                return true;
            }
            let Ok(relative) = entry.path().strip_prefix(&filter_root) else {
                return true;
            };
            include_directory(relative) && !catalog::is_excluded_directory(relative)
        })
        .build();
    for entry in walker {
        let entry = entry.map_err(|source| DiscoverError::Walk { source })?;
        // The walker attaches ignore-file processing errors to the directory
        // entry instead of failing the iteration.
        if let Some(source) = entry.error() {
            return Err(DiscoverError::Walk {
                source: source.clone(),
            });
        }
        if !entry.file_type().is_some_and(|kind| kind.is_file()) {
            continue;
        }
        // Every entry lies below the root the walker was built with; a path
        // that does not is never reported under a made-up name.
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| DiscoverError::InvalidPath {
                path: entry.path().to_path_buf(),
            })?;
        if let Some(hint) = catalog::unsupported_hint(relative) {
            unsupported.push(UnsupportedFile {
                // Diagnostic paths never select uploads, so native names can be displayed lossily.
                path: relative
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/"),
                hint,
            });
            continue;
        }
        let Some(classification) = catalog::classify(relative) else {
            continue;
        };
        let path = relative_string(relative)?;
        let bytes = std::fs::metadata(entry.path())
            .map_err(|source| DiscoverError::Metadata {
                path: path.clone(),
                source,
            })?
            .len();
        let candidate = Candidate { path, bytes };
        match classification.role {
            Role::Lockfile(owner) => {
                let directory = catalog::owning_directory(relative)
                    .map(relative_string)
                    .transpose()?
                    .unwrap_or_default();
                groups
                    .entry((directory, classification.ecosystem))
                    .or_default()
                    .lockfiles
                    .push(LockCandidate {
                        file: candidate,
                        owner,
                    });
            }
            Role::Manifest => groups
                .entry((directory_of(&candidate.path), classification.ecosystem))
                .or_default()
                .manifests
                .push(candidate),
        }
    }
    unsupported.sort_by(|a, b| a.path.cmp(&b.path));
    let mut inventory = pair(&groups);
    inventory.unsupported = unsupported;
    Ok(inventory)
}

/// Read one inventory file as UTF-8 text for upload, reading at most `limit`
/// bytes.
///
/// `relative` is a forward-slash path from the inventory; the upload set has
/// already accepted it and its metadata size. The read is bounded anyway so a
/// file that grew between the scan and the read cannot exhaust memory; the
/// caller passes the API's per-file limit.
///
/// # Errors
///
/// Returns [`DiscoverError::Read`] when the file cannot be read,
/// [`DiscoverError::FileTooLarge`] when it holds more than `limit` bytes, and
/// [`DiscoverError::NotUtf8`] when its contents are not UTF-8.
pub fn read_file(root: &Path, relative: &str, limit: u64) -> Result<String, DiscoverError> {
    let read_error = |source| DiscoverError::Read {
        path: relative.to_owned(),
        source,
    };
    let file = File::open(root.join(relative)).map_err(read_error)?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(read_error)?;
    if bytes.len() as u64 > limit {
        return Err(DiscoverError::FileTooLarge {
            path: relative.to_owned(),
            limit,
        });
    }
    String::from_utf8(bytes).map_err(|_| DiscoverError::NotUtf8 {
        path: relative.to_owned(),
    })
}

/// Distinguish "not a directory" (a usage error) from a metadata failure such
/// as a permission problem (an execution error a retry may fix).
pub(crate) fn require_directory(root: &Path) -> Result<(), DiscoverError> {
    match std::fs::metadata(root) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(DiscoverError::NotADirectory {
            path: root.to_path_buf(),
        }),
        Err(source)
            if matches!(
                source.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Err(DiscoverError::NotADirectory {
                path: root.to_path_buf(),
            })
        }
        Err(source) => Err(DiscoverError::Metadata {
            path: root.display().to_string(),
            source,
        }),
    }
}

/// Turn grouped candidates into the inventory. Each lockfile is uploaded with
/// the manifest that owns it; an ambiguous lockfile is set aside and its
/// candidate owners become manifest-only. Remaining manifests are uncombined
/// when their directory holds a lockfile of their ecosystem, nested under an
/// ancestor lockfile, or, failing both, manifest-only projects.
fn pair(groups: &BTreeMap<(String, Ecosystem), Group>) -> Inventory {
    let mut inventory = Inventory::default();
    let mut covering: BTreeMap<(&str, Ecosystem), &str> = BTreeMap::new();
    let mut pending: Vec<(&str, Ecosystem, &Candidate)> = Vec::new();
    for ((directory, ecosystem), group) in groups {
        let paired = pair_lockfiles(&mut inventory, *ecosystem, group);
        if let Some(first) = paired.first {
            covering.insert((directory.as_str(), *ecosystem), first);
        }
        for manifest in &group.manifests {
            match paired.placement(&manifest.path) {
                Placement::Owned => (),
                Placement::Displaced => inventory
                    .manifest_only
                    .push(manifest_only(manifest, *ecosystem)),
                Placement::Beside(lockfile) => inventory
                    .uncombined
                    .push(covered(manifest, *ecosystem, lockfile)),
                Placement::Elsewhere => pending.push((directory.as_str(), *ecosystem, manifest)),
            }
        }
    }
    for (directory, ecosystem, manifest) in pending {
        match ancestor_lockfile(&covering, directory, ecosystem) {
            Some(lockfile) => inventory
                .nested
                .push(covered(manifest, ecosystem, lockfile)),
            None => inventory
                .manifest_only
                .push(manifest_only(manifest, ecosystem)),
        }
    }
    inventory.lockfiles.sort_by(|a, b| a.path.cmp(&b.path));
    inventory.nested.sort_by(|a, b| a.path.cmp(&b.path));
    inventory.uncombined.sort_by(|a, b| a.path.cmp(&b.path));
    inventory.ambiguous.sort_by(|a, b| a.path.cmp(&b.path));
    inventory.manifest_only.sort_by(|a, b| a.path.cmp(&b.path));
    inventory
}

/// What pairing one group's lockfiles decided about its manifests.
struct Paired<'a> {
    /// Manifests uploaded with a lockfile.
    owned: Vec<&'a str>,
    /// Candidate owners of an ambiguous lockfile.
    displaced: Vec<&'a str>,
    /// The first lockfile by path, used to describe nearby uncombined manifests.
    first: Option<&'a str>,
}

/// Where a manifest of a paired group goes.
enum Placement<'a> {
    Owned,
    Displaced,
    Beside(&'a str),
    Elsewhere,
}

impl<'a> Paired<'a> {
    fn placement(&self, path: &str) -> Placement<'a> {
        if self.owned.contains(&path) {
            Placement::Owned
        } else if self.displaced.contains(&path) {
            Placement::Displaced
        } else {
            self.first.map_or(Placement::Elsewhere, Placement::Beside)
        }
    }
}

/// Record the group's lockfiles with their owners, setting ambiguous ones
/// aside.
fn pair_lockfiles<'a>(
    inventory: &mut Inventory,
    ecosystem: Ecosystem,
    group: &'a Group,
) -> Paired<'a> {
    let mut paired = Paired {
        owned: Vec::new(),
        displaced: Vec::new(),
        first: None,
    };
    for lock in &group.lockfiles {
        let owners = owners(lock.owner, &group.manifests);
        if owners.len() > 1 {
            paired
                .displaced
                .extend(owners.iter().map(|m| m.path.as_str()));
            inventory.ambiguous.push(AmbiguousLockfile {
                path: lock.file.path.clone(),
                ecosystem,
                bytes: lock.file.bytes,
                manifests: sorted_paths(&owners),
            });
            continue;
        }
        let path = lock.file.path.as_str();
        paired.first = Some(paired.first.map_or(path, |first| first.min(path)));
        paired.owned.extend(owners.iter().map(|m| m.path.as_str()));
        inventory.lockfiles.push(Lockfile {
            path: lock.file.path.clone(),
            ecosystem,
            bytes: lock.file.bytes,
            manifests: owners.iter().map(|m| companion(m)).collect(),
        });
    }
    paired
}

/// The manifests among `manifests` that `owner` names.
fn owners(owner: Owner, manifests: &[Candidate]) -> Vec<&Candidate> {
    manifests
        .iter()
        .filter(|manifest| {
            let name = manifest.path.rsplit('/').next().unwrap_or_default();
            match owner {
                Owner::Named(expected) => name == expected,
                Owner::OnlyWithSuffix(suffix) => name.ends_with(suffix),
                Owner::Uncombinable => false,
            }
        })
        .collect()
}

fn sorted_paths(manifests: &[&Candidate]) -> Vec<String> {
    let mut paths: Vec<String> = manifests.iter().map(|m| m.path.clone()).collect();
    paths.sort();
    paths
}

fn companion(manifest: &Candidate) -> Companion {
    Companion {
        path: manifest.path.clone(),
        bytes: manifest.bytes,
    }
}

fn manifest_only(manifest: &Candidate, ecosystem: Ecosystem) -> ManifestOnly {
    ManifestOnly {
        path: manifest.path.clone(),
        ecosystem,
        bytes: manifest.bytes,
    }
}

fn covered(manifest: &Candidate, ecosystem: Ecosystem, lockfile: &str) -> CoveredManifest {
    CoveredManifest {
        path: manifest.path.clone(),
        ecosystem,
        bytes: manifest.bytes,
        lockfile: lockfile.to_owned(),
    }
}

/// The first lockfile of `ecosystem` in the nearest strict ancestor of
/// `directory`, if any.
fn ancestor_lockfile<'a>(
    covering: &BTreeMap<(&str, Ecosystem), &'a str>,
    directory: &str,
    ecosystem: Ecosystem,
) -> Option<&'a str> {
    let mut current = directory;
    while !current.is_empty() {
        current = current.rsplit_once('/').map_or("", |(parent, _)| parent);
        if let Some(lockfile) = covering.get(&(current, ecosystem)) {
            return Some(lockfile);
        }
    }
    None
}

/// Join the normal components of a relative path with forward slashes.
///
/// The walker only yields paths below the root, so every component is a normal
/// one; anything else would mean the walker's contract changed and is rejected
/// rather than silently uploaded under a wrong name.
fn relative_string(relative: &Path) -> Result<String, DiscoverError> {
    let mut joined = String::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(DiscoverError::InvalidPath {
                path: relative.to_path_buf(),
            });
        };
        let Some(name) = name.to_str() else {
            return Err(DiscoverError::InvalidPath {
                path: relative.to_path_buf(),
            });
        };
        if !joined.is_empty() {
            joined.push('/');
        }
        joined.push_str(name);
    }
    Ok(joined)
}

/// The directory part of a forward-slash path; empty for the root.
fn directory_of(path: &str) -> String {
    path.rsplit_once('/')
        .map(|(directory, _)| directory.to_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    /// Write empty files at the given relative paths, creating directories.
    fn repository(files: &[&str]) -> TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for file in files {
            write(dir.path(), file, "");
        }
        dir
    }

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, contents).expect("write file");
    }

    fn lockfile_paths(inventory: &Inventory) -> Vec<&str> {
        inventory
            .lockfiles
            .iter()
            .map(|l| l.path.as_str())
            .collect()
    }

    fn companion_paths(lockfile: &Lockfile) -> Vec<&str> {
        lockfile.manifests.iter().map(|m| m.path.as_str()).collect()
    }

    fn manifest_only_paths(inventory: &Inventory) -> Vec<&str> {
        inventory
            .manifest_only
            .iter()
            .map(|m| m.path.as_str())
            .collect()
    }

    #[test]
    fn pairs_a_lockfile_with_its_same_directory_manifest() {
        let repo = repository(&["Cargo.lock", "Cargo.toml", "src/main.rs"]);
        write(repo.path(), "Cargo.lock", "# lock\n");

        let inventory = scan(repo.path()).expect("scan");

        assert_eq!(
            inventory.lockfiles,
            vec![Lockfile {
                path: "Cargo.lock".into(),
                ecosystem: Ecosystem::Rust,
                bytes: 7,
                manifests: vec![Companion {
                    path: "Cargo.toml".into(),
                    bytes: 0,
                }],
            }]
        );
        assert!(
            inventory.manifest_only.is_empty(),
            "{:?}",
            inventory.manifest_only
        );
        assert_eq!(inventory.ecosystem_count(), 1);
    }

    #[test]
    fn bun_pairs_same_directory_manifests_and_covers_nested_workspaces() {
        let repo = repository(&[
            "bun.lock",
            "package.json",
            "packages/core/package.json",
            "tools/bun.lock",
            "tools/package.json",
            "tools/packages/plugin/package.json",
            "standalone/bun.lock",
        ]);

        let inventory = scan(repo.path()).expect("scan Bun projects");

        assert_eq!(
            lockfile_paths(&inventory),
            ["bun.lock", "standalone/bun.lock", "tools/bun.lock"]
        );
        assert_eq!(companion_paths(&inventory.lockfiles[0]), ["package.json"]);
        assert!(
            inventory.lockfiles[1].manifests.is_empty(),
            "{:?}",
            inventory.lockfiles[1].manifests
        );
        assert_eq!(
            companion_paths(&inventory.lockfiles[2]),
            ["tools/package.json"]
        );
        assert!(
            inventory
                .lockfiles
                .iter()
                .all(|lock| lock.ecosystem == Ecosystem::JavaScript)
        );
        assert_eq!(
            inventory
                .nested
                .iter()
                .map(|m| (m.path.as_str(), m.lockfile.as_str()))
                .collect::<Vec<_>>(),
            [
                ("packages/core/package.json", "bun.lock"),
                ("tools/packages/plugin/package.json", "tools/bun.lock"),
            ]
        );
        assert!(
            inventory.manifest_only.is_empty(),
            "{:?}",
            inventory.manifest_only
        );
    }

    #[test]
    fn reports_manifests_without_a_lockfile_separately() {
        let repo = repository(&["Cargo.lock", "services/legacy/package.json"]);

        let inventory = scan(repo.path()).expect("scan");

        assert_eq!(lockfile_paths(&inventory), ["Cargo.lock"]);
        assert_eq!(
            inventory.manifest_only,
            vec![ManifestOnly {
                path: "services/legacy/package.json".into(),
                ecosystem: Ecosystem::JavaScript,
                bytes: 0,
            }]
        );
    }

    #[test]
    fn does_not_pair_manifests_of_a_different_ecosystem() {
        let repo = repository(&["Cargo.lock", "package.json"]);

        let inventory = scan(repo.path()).expect("scan");

        assert!(
            inventory.lockfiles[0].manifests.is_empty(),
            "{:?}",
            inventory.lockfiles[0].manifests
        );
        assert_eq!(manifest_only_paths(&inventory), ["package.json"]);
    }

    #[test]
    fn go_vcpkg_and_zig_manifests_are_manifest_only_beside_other_tools_lockfiles() {
        let repo = repository(&[
            "Cargo.lock",
            "cpp/conan.lock",
            "cpp/vcpkg.json",
            "legacy/Gopkg.lock",
            "legacy/go.mod",
            "legacy/tools/go.mod",
            "zig/build.zig.zon",
            "go.mod",
            "go.sum",
            "vendor/github.com/pkg/errors/go.mod",
        ]);

        let inventory = scan(repo.path()).expect("scan");

        assert_eq!(
            lockfile_paths(&inventory),
            ["Cargo.lock", "cpp/conan.lock", "legacy/Gopkg.lock"]
        );
        assert!(inventory.lockfiles.iter().all(|l| l.manifests.is_empty()));
        assert!(inventory.nested.is_empty(), "{:?}", inventory.nested);
        assert_eq!(
            inventory
                .manifest_only
                .iter()
                .map(|m| (m.path.as_str(), m.ecosystem))
                .collect::<Vec<_>>(),
            [
                ("cpp/vcpkg.json", Ecosystem::Vcpkg),
                ("go.mod", Ecosystem::Go),
                ("legacy/go.mod", Ecosystem::Go),
                ("legacy/tools/go.mod", Ecosystem::Go),
                ("zig/build.zig.zon", Ecosystem::Zig),
            ]
        );
    }

    #[test]
    fn manifests_under_an_ancestor_lockfile_are_nested_not_manifest_only() {
        let repo = repository(&[
            "Cargo.lock",
            "Cargo.toml",
            "crates/core/Cargo.toml",
            "crates/core/deep/Cargo.toml",
            "web/package-lock.json",
            "web/yarn.lock",
            "web/packages/ui/package.json",
        ]);

        let inventory = scan(repo.path()).expect("scan");

        assert_eq!(companion_paths(&inventory.lockfiles[0]), ["Cargo.toml"]);
        assert_eq!(
            inventory.nested,
            vec![
                CoveredManifest {
                    path: "crates/core/Cargo.toml".into(),
                    ecosystem: Ecosystem::Rust,
                    bytes: 0,
                    lockfile: "Cargo.lock".into(),
                },
                CoveredManifest {
                    path: "crates/core/deep/Cargo.toml".into(),
                    ecosystem: Ecosystem::Rust,
                    bytes: 0,
                    lockfile: "Cargo.lock".into(),
                },
                CoveredManifest {
                    path: "web/packages/ui/package.json".into(),
                    ecosystem: Ecosystem::JavaScript,
                    bytes: 0,
                    lockfile: "web/package-lock.json".into(),
                },
            ]
        );
        assert!(
            inventory.manifest_only.is_empty(),
            "{:?}",
            inventory.manifest_only
        );
    }

    #[test]
    fn the_nearest_ancestor_lockfile_covers_a_nested_manifest() {
        let repo = repository(&[
            "Cargo.lock",
            "tools/Cargo.lock",
            "tools/plugin/Cargo.toml",
            "tools/plugin/package.json",
        ]);

        let inventory = scan(repo.path()).expect("scan");

        assert_eq!(inventory.nested.len(), 1);
        assert_eq!(inventory.nested[0].lockfile, "tools/Cargo.lock");
        assert_eq!(
            manifest_only_paths(&inventory),
            ["tools/plugin/package.json"]
        );
    }

    #[test]
    fn several_lockfiles_share_the_manifest_that_owns_them() {
        let repo = repository(&[
            "web/package-lock.json",
            "web/yarn.lock",
            "web/bun.lock",
            "web/package.json",
            "net/packages.lock.json",
            "net/Web.csproj",
        ]);

        let inventory = scan(repo.path()).expect("scan");

        assert_eq!(
            lockfile_paths(&inventory),
            [
                "net/packages.lock.json",
                "web/bun.lock",
                "web/package-lock.json",
                "web/yarn.lock"
            ]
        );
        assert_eq!(companion_paths(&inventory.lockfiles[0]), ["net/Web.csproj"]);
        for lockfile in &inventory.lockfiles[1..] {
            assert_eq!(companion_paths(lockfile), ["web/package.json"]);
        }
        assert_eq!(inventory.ecosystem_count(), 2);
    }

    #[test]
    fn a_lockfile_several_manifests_could_own_is_set_aside_for_its_manifests() {
        let repo = repository(&[
            "net/packages.lock.json",
            "net/Web.csproj",
            "net/Api.csproj",
            "net/src/Lib.csproj",
        ]);

        let inventory = scan(repo.path()).expect("scan");

        assert!(inventory.lockfiles.is_empty(), "{:?}", inventory.lockfiles);
        assert_eq!(
            inventory.ambiguous,
            vec![AmbiguousLockfile {
                path: "net/packages.lock.json".into(),
                ecosystem: Ecosystem::DotNet,
                bytes: 0,
                manifests: vec!["net/Api.csproj".into(), "net/Web.csproj".into()],
            }]
        );
        // The set-aside lockfile covers nothing, below it either.
        assert_eq!(
            manifest_only_paths(&inventory),
            ["net/Api.csproj", "net/Web.csproj", "net/src/Lib.csproj"]
        );
        assert!(inventory.nested.is_empty(), "{:?}", inventory.nested);
    }

    #[test]
    fn owners_of_an_ambiguous_lockfile_stay_manifest_only_under_an_ancestor_lockfile() {
        let repo = repository(&[
            "packages.lock.json",
            "Root.csproj",
            "shared/packages.lock.json",
            "shared/A.csproj",
            "shared/B.csproj",
        ]);

        let inventory = scan(repo.path()).expect("scan");

        assert_eq!(lockfile_paths(&inventory), ["packages.lock.json"]);
        assert_eq!(companion_paths(&inventory.lockfiles[0]), ["Root.csproj"]);
        assert_eq!(
            manifest_only_paths(&inventory),
            ["shared/A.csproj", "shared/B.csproj"]
        );
        assert!(inventory.nested.is_empty(), "{:?}", inventory.nested);
    }

    #[test]
    fn manifests_beside_a_lockfile_they_do_not_own_are_uncombined() {
        let repo = repository(&[
            "py/Pipfile.lock",
            "py/pyproject.toml",
            "jvm/gradle.lockfile",
            "jvm/build.gradle.kts",
            "jvm/app/build.gradle",
            "rb/gems.locked",
            "rb/Gemfile",
            "both/uv.lock",
            "both/Pipfile.lock",
            "both/pyproject.toml",
        ]);

        let inventory = scan(repo.path()).expect("scan");

        let uncombined: Vec<(&str, &str)> = inventory
            .uncombined
            .iter()
            .map(|m| (m.path.as_str(), m.lockfile.as_str()))
            .collect();
        assert_eq!(
            uncombined,
            [
                ("jvm/build.gradle.kts", "jvm/gradle.lockfile"),
                ("py/pyproject.toml", "py/Pipfile.lock"),
                ("rb/Gemfile", "rb/gems.locked"),
            ]
        );
        assert!(
            inventory
                .lockfiles
                .iter()
                .filter(|l| !l.path.starts_with("both/"))
                .all(|l| l.manifests.is_empty())
        );
        let both: Vec<_> = inventory
            .lockfiles
            .iter()
            .filter(|l| l.path.starts_with("both/"))
            .map(|l| (l.path.as_str(), companion_paths(l)))
            .collect();
        assert_eq!(
            both,
            [
                ("both/Pipfile.lock", vec![]),
                ("both/uv.lock", vec!["both/pyproject.toml"]),
            ]
        );
        assert_eq!(
            inventory
                .nested
                .iter()
                .map(|m| (m.path.as_str(), m.lockfile.as_str()))
                .collect::<Vec<_>>(),
            [("jvm/app/build.gradle", "jvm/gradle.lockfile")]
        );
        assert!(
            inventory.manifest_only.is_empty(),
            "{:?}",
            inventory.manifest_only
        );
    }

    #[test]
    fn a_legacy_gradle_lock_covers_the_build_script_of_its_project() {
        let repo = repository(&[
            "app/build.gradle",
            "app/gradle/dependency-locks/compileClasspath.lockfile",
        ]);

        let inventory = scan(repo.path()).expect("scan");

        assert_eq!(
            lockfile_paths(&inventory),
            ["app/gradle/dependency-locks/compileClasspath.lockfile"]
        );
        assert_eq!(
            inventory
                .uncombined
                .iter()
                .map(|m| (m.path.as_str(), m.lockfile.as_str()))
                .collect::<Vec<_>>(),
            [(
                "app/build.gradle",
                "app/gradle/dependency-locks/compileClasspath.lockfile"
            )]
        );
        assert!(
            inventory.manifest_only.is_empty(),
            "{:?}",
            inventory.manifest_only
        );
    }

    #[test]
    fn honors_gitignore_without_a_git_repository() {
        let repo = repository(&[
            "Cargo.lock",
            "examples/big/Cargo.lock",
            "fixtures/Gemfile.lock",
        ]);
        write(
            repo.path(),
            ".gitignore",
            "/examples/\nfixtures/Gemfile.lock\n",
        );

        let inventory = scan(repo.path()).expect("scan");

        assert_eq!(lockfile_paths(&inventory), ["Cargo.lock"]);
    }

    #[test]
    fn skips_hidden_and_installed_dependency_directories() {
        let repo = repository(&[
            "Cargo.lock",
            ".cargo/registry/Cargo.lock",
            "node_modules/dep/package-lock.json",
            "vendor/bundle/Gemfile.lock",
            ".git/Cargo.lock",
        ]);

        let inventory = scan(repo.path()).expect("scan");

        assert_eq!(lockfile_paths(&inventory), ["Cargo.lock"]);
        assert!(
            inventory.manifest_only.is_empty(),
            "{:?}",
            inventory.manifest_only
        );
    }

    #[test]
    fn returns_an_empty_inventory_for_a_tree_without_package_files() {
        let repo = repository(&["README.md", "src/lib.rs"]);

        let inventory = scan(repo.path()).expect("scan");

        assert_eq!(inventory, Inventory::default());
        assert_eq!(inventory.ecosystem_count(), 0);
    }

    #[test]
    fn output_is_sorted_by_path() {
        let repo = repository(&[
            "z/Cargo.lock",
            "a/Cargo.lock",
            "m/pubspec.lock",
            "b/package.json",
            "a/pyproject.toml",
        ]);

        let inventory = scan(repo.path()).expect("scan");

        assert_eq!(
            lockfile_paths(&inventory),
            ["a/Cargo.lock", "m/pubspec.lock", "z/Cargo.lock"]
        );
        assert_eq!(
            manifest_only_paths(&inventory),
            ["a/pyproject.toml", "b/package.json"]
        );
    }

    #[test]
    fn rejects_a_root_that_is_not_a_directory() {
        let repo = repository(&["Cargo.lock"]);

        let error = scan(&repo.path().join("Cargo.lock")).expect_err("file root");
        assert!(matches!(error, DiscoverError::NotADirectory { .. }));

        let error = scan(&repo.path().join("missing")).expect_err("missing root");
        assert!(matches!(error, DiscoverError::NotADirectory { .. }));

        let error = scan(&repo.path().join("Cargo.lock/child")).expect_err("below a file");
        assert!(
            matches!(error, DiscoverError::NotADirectory { .. }),
            "{error:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn does_not_follow_symbolic_links() {
        let outside = repository(&["Cargo.lock", "Cargo.toml"]);
        let repo = repository(&["web/package-lock.json"]);
        std::os::unix::fs::symlink(outside.path(), repo.path().join("linked"))
            .expect("symlink directory");
        std::os::unix::fs::symlink(
            outside.path().join("Cargo.lock"),
            repo.path().join("Cargo.lock"),
        )
        .expect("symlink file");

        let inventory = scan(repo.path()).expect("scan");

        assert_eq!(lockfile_paths(&inventory), ["web/package-lock.json"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_root_whose_metadata_cannot_be_read_is_an_execution_error() {
        use std::os::unix::fs::PermissionsExt;

        let repo = repository(&["locked/inner/Cargo.lock"]);
        let locked = repo.path().join("locked");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("chmod");

        let result = scan(&locked.join("inner"));

        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).expect("restore");
        assert!(
            matches!(result, Err(DiscoverError::Metadata { .. })),
            "{result:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_component_cannot_become_an_upload_name() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let path = Path::new(OsStr::from_bytes(b"caf\xe9/Cargo.lock"));

        let error = relative_string(path).expect_err("non-UTF-8 component");

        assert!(
            matches!(error, DiscoverError::InvalidPath { .. }),
            "{error:?}"
        );
    }

    // macOS (APFS) rejects non-UTF-8 names at the filesystem level; only Linux
    // can hold such a directory.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_cataloged_file_below_a_non_utf8_directory_is_an_invalid_path() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let repo = repository(&["Cargo.lock"]);
        let odd = repo.path().join(OsStr::from_bytes(b"caf\xe9"));
        fs::create_dir(&odd).expect("create non-UTF-8 directory");
        fs::write(odd.join("Cargo.lock"), "").expect("write lockfile");

        let error = scan(repo.path()).expect_err("non-UTF-8 component");

        assert!(
            matches!(error, DiscoverError::InvalidPath { .. }),
            "{error:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fails_when_a_directory_cannot_be_read() {
        use std::os::unix::fs::PermissionsExt;

        let repo = repository(&["Cargo.lock", "locked/Cargo.lock"]);
        let locked = repo.path().join("locked");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("chmod");

        let result = scan(repo.path());

        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).expect("restore");
        assert!(
            matches!(result, Err(DiscoverError::Walk { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn reads_inventory_files_as_utf8_text() {
        let repo = repository(&["web/package.json"]);
        write(repo.path(), "web/package.json", "{\"name\": \"x\"}");
        fs::write(repo.path().join("web/binary.lock"), [0xff, 0xfe]).expect("write binary");

        assert_eq!(
            read_file(repo.path(), "web/package.json", 1024).expect("read"),
            "{\"name\": \"x\"}"
        );
        let error = read_file(repo.path(), "web/binary.lock", 1024).expect_err("binary");
        assert!(matches!(error, DiscoverError::NotUtf8 { ref path } if path == "web/binary.lock"));
        let error = read_file(repo.path(), "web/missing.lock", 1024).expect_err("missing");
        assert!(
            matches!(error, DiscoverError::Read { ref path, .. } if path == "web/missing.lock")
        );
    }

    #[test]
    fn reads_are_bounded_by_the_caller_limit() {
        let repo = repository(&["Cargo.lock"]);
        write(repo.path(), "Cargo.lock", "0123456789");

        assert_eq!(
            read_file(repo.path(), "Cargo.lock", 10).expect("at limit"),
            "0123456789"
        );
        let error = read_file(repo.path(), "Cargo.lock", 9).expect_err("over limit");
        assert!(
            matches!(error, DiscoverError::FileTooLarge { ref path, limit: 9 } if path == "Cargo.lock"),
            "{error:?}"
        );
    }

    #[test]
    fn relative_strings_use_forward_slashes_on_every_platform() {
        let path: PathBuf = ["gradle", "dependency-locks", "compileClasspath.lockfile"]
            .iter()
            .collect();
        assert_eq!(
            relative_string(&path).expect("utf-8"),
            "gradle/dependency-locks/compileClasspath.lockfile"
        );
        assert_eq!(directory_of("a/b/c.lock"), "a/b");
        assert_eq!(directory_of("c.lock"), "");
    }
}
