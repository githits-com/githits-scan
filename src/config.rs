//! The configuration file `githits-scan.toml`.
//!
//! One file makes every command strict: the lockfile inventory is compared
//! against it (drift fails the run), listed manifests are uploaded without a
//! lockfile, and the license policy drives `license check`. This module owns
//! the schema, loading, the evaluation of an inventory against it, and the
//! format-preserving save that `detect --save` performs. Paths in the file
//! are relative to the scanned directory, with forward slashes, whatever
//! directory the file itself lives in.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use thiserror::Error;
use toml_edit::{Array, DocumentMut, Item, Value};

use crate::api::upload::{PathRule, check_path};
use crate::discover::{Inventory, Lockfile};

/// Default file name, looked up in the scanned directory.
pub const FILE_NAME: &str = "githits-scan.toml";
/// The only schema version this build understands.
pub const VERSION: u32 = 1;
/// Origin used in messages when an `--exclude` glob cannot be compiled.
pub const CLI_EXCLUDE: &str = "--exclude";

/// License policy for `license check`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Licenses {
    /// SPDX identifiers and `<id> WITH <exception>` strings that are allowed.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Packages exempted from the allow list, each with a reason.
    #[serde(default)]
    pub exceptions: Vec<Exception>,
}

mod policy;

pub use policy::{AdvisoryIgnore, Audit, Exception};

/// The file as written, before validation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    version: u32,
    #[serde(default)]
    lockfiles: RawLockfiles,
    licenses: Option<Licenses>,
    #[serde(default)]
    audit: Audit,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLockfiles {
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    manifests: Vec<String>,
}

/// A validated configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Where the file was read from, for messages.
    pub path: PathBuf,
    /// Exact lockfile paths that form the inventory.
    pub include: Vec<String>,
    /// Glob patterns for lockfiles deliberately left out.
    pub exclude: Vec<String>,
    /// Manifests uploaded without a lockfile.
    pub manifests: Vec<String>,
    /// License policy, when present.
    pub licenses: Option<Licenses>,
    /// Local advisory ignores, independent of evidence assessment.
    pub audit: Audit,
    excluded: GlobSet,
}

impl Config {
    /// Whether a repository-relative path matches an `exclude` pattern.
    #[must_use]
    pub fn is_excluded(&self, path: &str) -> bool {
        self.excluded.is_match(path)
    }
}

/// Compile `exclude` globs. `origin` is the configuration path or [`CLI_EXCLUDE`].
///
/// # Errors
///
/// Returns [`ConfigError::InvalidGlob`] when a pattern is not a valid glob.
pub fn exclude_set(patterns: &[String], origin: &Path) -> Result<GlobSet, ConfigError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .map_err(|error| ConfigError::InvalidGlob {
                path: origin.to_path_buf(),
                pattern: pattern.clone(),
                message: error.kind().to_string(),
            })?;
        builder.add(glob);
    }
    builder.build().map_err(|error| ConfigError::InvalidGlob {
        path: origin.to_path_buf(),
        pattern: String::new(),
        message: error.kind().to_string(),
    })
}

/// File `exclude` entries followed by `--exclude` patterns that are not already listed.
#[must_use]
pub fn merge_exclude_patterns(file: &[String], extra: &[String]) -> Vec<String> {
    let mut patterns = file.to_vec();
    for pattern in extra {
        if !patterns.contains(pattern) {
            patterns.push(pattern.clone());
        }
    }
    patterns
}

/// Whether a repository-relative path is under a default fixture directory.
///
/// Exact directory components, matched ASCII case-insensitively. Explicit
/// inventory entries override this policy; invocation excludes always win.
#[must_use]
pub fn is_default_excluded(path: &str) -> bool {
    path.rsplit_once('/').is_some_and(|(directory, _)| {
        directory.split('/').any(|part| {
            [
                "fixtures",
                "__fixtures__",
                "testdata",
                "test-data",
                "test_data",
            ]
            .iter()
            .any(|name| part.eq_ignore_ascii_case(name))
        })
    })
}

/// Standing of the inventory against an optional configuration and invocation
/// excludes.
///
/// `None` when no configuration, invocation patterns, or default fixture
/// exclusions apply. Every lockfile and eligible manifest-only project is then in play.
///
/// # Errors
///
/// Returns [`ConfigError::InvalidGlob`] when an `--exclude` pattern is invalid.
pub fn inventory_evaluation(
    config: Option<&Config>,
    invocation_patterns: &[String],
    inventory: &Inventory,
    include_manifests: bool,
) -> Result<Option<Evaluation>, ConfigError> {
    let invocation = exclude_set(invocation_patterns, Path::new(CLI_EXCLUDE))?;
    let evaluation = evaluate(config, &invocation, inventory, include_manifests);
    if config.is_none()
        && invocation_patterns.is_empty()
        && !evaluation
            .statuses
            .values()
            .any(|status| *status == Status::Excluded)
    {
        return Ok(None);
    }
    Ok(Some(evaluation))
}

/// Why the file could not be used.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file could not be read (including a missing explicit path).
    #[error("cannot read {}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The file is not valid TOML or does not match the schema (unknown keys
    /// are errors so a typo cannot silently widen policy).
    #[error("{}: {message}", path.display())]
    Parse {
        /// The file.
        path: PathBuf,
        /// The parser's message, with line and column when available.
        message: String,
    },
    /// The file declares a schema version this build does not understand.
    #[error("{}: version {version} is not supported; this build understands version {VERSION}", path.display())]
    UnsupportedVersion {
        /// The file.
        path: PathBuf,
        /// The declared version.
        version: u32,
    },
    /// An `exclude` entry is not a valid glob.
    #[error("{}: exclude pattern {pattern:?} is invalid: {message}", path.display())]
    InvalidGlob {
        /// The file.
        path: PathBuf,
        /// The pattern.
        pattern: String,
        /// The glob parser's message.
        message: String,
    },
    /// An `include` or `manifests` entry is not a repository-relative path.
    #[error("{}: {entry:?} is not a repository-relative path: {reason}", path.display())]
    InvalidPath {
        /// The file.
        path: PathBuf,
        /// The entry.
        entry: String,
        /// Which rule it breaks.
        reason: PathRule,
    },
    /// The file could not be written.
    #[error("cannot write {}", path.display())]
    Write {
        /// The file.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
}

/// Load the configuration at `path`. A missing file is `Ok(None)`; the caller
/// decides whether configuration is required, as it is for `license check`.
///
/// # Errors
///
/// Returns a [`ConfigError`] when the file exists but cannot be read or is
/// invalid. Use [`load_required`] for explicit user selections.
pub fn load(path: &Path) -> Result<Option<Config>, ConfigError> {
    match load_required(path) {
        Err(ConfigError::Read { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            Ok(None)
        }
        result => result.map(Some),
    }
}

/// Load an explicitly selected configuration; absence is an error.
///
/// # Errors
///
/// Returns [`ConfigError::Read`] when missing or unreadable, or a validation error.
pub fn load_required(path: &Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    parse(path, &text)
}

/// Parse and validate configuration text; `path` is used in messages only.
///
/// # Errors
///
/// Returns [`ConfigError::Parse`] for invalid TOML or unknown keys,
/// [`ConfigError::UnsupportedVersion`], [`ConfigError::InvalidGlob`], or
/// [`ConfigError::InvalidPath`].
pub fn parse(path: &Path, text: &str) -> Result<Config, ConfigError> {
    let raw: RawConfig = toml_edit::de::from_str(text).map_err(|error| ConfigError::Parse {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    if raw.version != VERSION {
        return Err(ConfigError::UnsupportedVersion {
            path: path.to_path_buf(),
            version: raw.version,
        });
    }
    for entry in raw.lockfiles.include.iter().chain(&raw.lockfiles.manifests) {
        check_path(entry).map_err(|reason| ConfigError::InvalidPath {
            path: path.to_path_buf(),
            entry: entry.clone(),
            reason,
        })?;
    }
    raw.audit.validate().map_err(|message| ConfigError::Parse {
        path: path.to_path_buf(),
        message,
    })?;
    let excluded = exclude_set(&raw.lockfiles.exclude, path)?;
    Ok(Config {
        path: path.to_path_buf(),
        include: raw.lockfiles.include,
        exclude: raw.lockfiles.exclude,
        manifests: raw.lockfiles.manifests,
        licenses: raw.licenses,
        audit: raw.audit,
        excluded,
    })
}

/// A detected file's standing against the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Listed; part of the upload.
    Included,
    /// Matches an `exclude` pattern; deliberately left out.
    Excluded,
    /// Detected but not listed. Drift for a lockfile and for a manifest-only
    /// project that the run includes; informational otherwise.
    Unlisted,
}

impl Status {
    /// Stable identifier for machine-readable output.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Included => "included",
            Self::Excluded => "excluded",
            Self::Unlisted => "unlisted",
        }
    }
}

/// The inventory compared against the configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evaluation {
    /// Status of lockfiles, manifest-only projects, selected/excluded companions,
    /// covered manifests with an explicit status, excluded ambiguous lockfiles,
    /// and absent listed paths deliberately excluded by the invocation.
    pub statuses: BTreeMap<String, Status>,
    /// Detected lockfiles, and manifest-only projects the run includes, that
    /// are neither listed nor excluded: drift.
    pub unlisted: Vec<String>,
    /// Listed paths that were not detected: drift.
    pub missing: Vec<String>,
}

impl Evaluation {
    /// Whether the inventory differs from the configuration.
    #[must_use]
    pub const fn has_drift(&self) -> bool {
        !self.unlisted.is_empty() || !self.missing.is_empty()
    }

    /// Status of a detected path, if it has one.
    #[must_use]
    pub fn status(&self, path: &str) -> Option<Status> {
        self.statuses.get(path).copied()
    }
}

/// Compare an inventory with an optional configuration and invocation excludes.
///
/// An explicit file `include` or `manifests` entry beats a file `exclude`
/// pattern and default fixture exclusions. `--exclude` globs win over those
/// lists, so a one-off run can omit a listed lockfile without editing the file. Without a configuration, every
/// detected lockfile, and every manifest-only project when `include_manifests`
/// is set, is included unless an invocation glob or default fixture rule
/// matches it. With one, an
/// unlisted manifest-only project is drift when `include_manifests` is set, like
/// an unlisted lockfile, and informational otherwise.
/// Entries are matched by role: an `include` entry must name a detected
/// lockfile; a `manifests` entry must name a manifest-only manifest, a nested
/// or uncombined manifest, or a companion of an included lockfile (unless
/// excluded). Anything else listed is missing, so a path in the wrong list, a companion of an excluded lockfile, or an ambiguous lockfile,
/// which is never uploaded, is drift rather than a silent no-op. An exclude
/// that matches an ambiguous lockfile marks it excluded, which acknowledges
/// that it is not uploaded.
#[must_use]
pub fn evaluate(
    config: Option<&Config>,
    invocation_excludes: &GlobSet,
    inventory: &Inventory,
    include_manifests: bool,
) -> Evaluation {
    let include: BTreeSet<&str> = config
        .map(|config| config.include.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let manifests: BTreeSet<&str> = config
        .map(|config| config.manifests.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let mut evaluation = Evaluation::default();
    let mut lockfiles_found: BTreeSet<&str> = BTreeSet::new();
    let mut manifests_found: BTreeSet<&str> = BTreeSet::new();
    for lockfile in &inventory.lockfiles {
        let path = lockfile.path.as_str();
        lockfiles_found.insert(path);
        let status = detected_status(
            path,
            &include,
            config,
            invocation_excludes,
            Status::Included,
        );
        manifests_found.extend(
            lockfile
                .manifests
                .iter()
                .filter(|_| status == Status::Included)
                .map(|m| m.path.as_str()),
        );
        record_companions(
            &mut evaluation.statuses,
            companion_statuses(
                lockfile,
                status,
                &manifests,
                config,
                invocation_excludes,
                include.contains(path),
            ),
        );
        if status == Status::Unlisted {
            evaluation.unlisted.push(path.to_owned());
        }
        evaluation.statuses.insert(path.to_owned(), status);
    }
    for manifest in &inventory.manifest_only {
        let path = manifest.path.as_str();
        manifests_found.insert(path);
        let unconfigured = if include_manifests {
            Status::Included
        } else {
            Status::Unlisted
        };
        let status = detected_status(path, &manifests, config, invocation_excludes, unconfigured);
        if status == Status::Unlisted && include_manifests {
            evaluation.unlisted.push(path.to_owned());
        }
        evaluation.statuses.insert(path.to_owned(), status);
    }
    for ambiguous in &inventory.ambiguous {
        let path = ambiguous.path.as_str();
        let excluded = invocation_excludes.is_match(path)
            || config.is_some_and(|config| config.is_excluded(path))
            || is_default_excluded(path);
        if excluded {
            evaluation
                .statuses
                .insert(path.to_owned(), Status::Excluded);
        }
    }
    for covered in inventory.nested.iter().chain(&inventory.uncombined) {
        let path = covered.path.as_str();
        manifests_found.insert(path);
        let status = detected_status(
            path,
            &manifests,
            config,
            invocation_excludes,
            Status::Unlisted,
        );
        if status != Status::Unlisted {
            evaluation.statuses.insert(path.to_owned(), status);
        }
    }
    for path in include
        .iter()
        .chain(&manifests)
        .filter(|p| invocation_excludes.is_match(p))
    {
        evaluation
            .statuses
            .insert((*path).to_owned(), Status::Excluded);
    }
    evaluation.missing = include
        .difference(&lockfiles_found)
        .chain(manifests.difference(&manifests_found))
        .filter(|entry| !invocation_excludes.is_match(entry))
        .map(|entry| (*entry).to_owned())
        .collect();
    evaluation
}

// A shared owner stays selected when any included sibling lock retains it.
// Authored path exclusions are identical for every sibling decision.
fn record_companions(
    statuses: &mut BTreeMap<String, Status>,
    companions: impl IntoIterator<Item = (String, Status)>,
) {
    for (path, status) in companions {
        if statuses.get(&path) == Some(&Status::Included) {
            continue;
        }
        statuses.insert(path, status);
    }
}

fn companion_statuses<'a>(
    lockfile: &'a Lockfile,
    lock_status: Status,
    listed: &'a BTreeSet<&str>,
    config: Option<&'a Config>,
    invocation: &'a GlobSet,
    explicit_lock: bool,
) -> impl Iterator<Item = (String, Status)> + 'a {
    lockfile
        .manifests
        .iter()
        .map(move |companion| {
            let status =
                companion_status(&companion.path, listed, config, invocation, explicit_lock);
            (companion.path.clone(), status)
        })
        .filter(move |(_, status)| lock_status == Status::Included || *status == Status::Excluded)
}

fn companion_status(
    path: &str,
    listed: &BTreeSet<&str>,
    config: Option<&Config>,
    invocation: &GlobSet,
    explicit_lock: bool,
) -> Status {
    if invocation.is_match(path) {
        return Status::Excluded;
    }
    if !listed.contains(path)
        && ((!explicit_lock && is_default_excluded(path))
            || config.is_some_and(|c| c.is_excluded(path)))
    {
        return Status::Excluded;
    }
    Status::Included
}

/// Directory patterns whose complete subtrees can be omitted before traversal.
/// Other globs still apply to discovered files, without guessing their descendants.
pub(crate) fn directory_patterns(patterns: &[String]) -> Vec<String> {
    patterns
        .iter()
        .filter(|p| p.ends_with("/**"))
        .cloned()
        .collect()
}

/// Compile a pure directory filter. File-level inclusion overrides preserve the
/// ancestors needed to discover those files; invocation exclusions always win.
pub(crate) fn directory_filter(
    config: Option<&Config>,
    invocation: &[String],
) -> Result<impl Fn(&Path) -> bool + Send + Sync + 'static, ConfigError> {
    let compile = |patterns: &[String], origin: &Path| {
        let roots: Vec<_> = directory_patterns(patterns)
            .iter()
            .flat_map(|p| [p.clone(), p.strip_suffix("/**").unwrap_or(p).to_owned()])
            .collect();
        exclude_set(&roots, origin)
    };
    // Validate all patterns, including those which cannot prune directories.
    exclude_set(invocation, Path::new(CLI_EXCLUDE))?;
    let cli = compile(invocation, Path::new(CLI_EXCLUDE))?;
    let file = compile(
        config.map_or(&[], |c| c.exclude.as_slice()),
        config.map_or_else(|| Path::new(FILE_NAME), |c| c.path.as_path()),
    )?;
    let included: Vec<_> = config
        .into_iter()
        .flat_map(|c| c.include.iter().chain(&c.manifests))
        .cloned()
        .collect();
    Ok(move |path: &Path| {
        let path = path
            .components()
            .map(|part| part.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if cli.is_match(&path) {
            return false;
        }
        !file.is_match(&path) || included.iter().any(|p| p.starts_with(&format!("{path}/")))
    })
}

fn detected_status(
    path: &str,
    listed: &BTreeSet<&str>,
    config: Option<&Config>,
    invocation_excludes: &GlobSet,
    unconfigured: Status,
) -> Status {
    if invocation_excludes.is_match(path) {
        return Status::Excluded;
    }
    if listed.contains(path) {
        return Status::Included;
    }
    if is_default_excluded(path) || config.is_some_and(|config| config.is_excluded(path)) {
        Status::Excluded
    } else if config.is_some() {
        Status::Unlisted
    } else {
        unconfigured
    }
}

/// What a save did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SaveOutcome {
    /// The file did not exist and was created.
    pub created: bool,
    /// Paths added to `include` or `manifests`, and `exclude` patterns when
    /// those were written.
    pub added: Vec<String>,
    /// Paths removed from `include` or `manifests`, and `exclude` patterns
    /// dropped when that list was rewritten.
    pub removed: Vec<String>,
    /// Whether the file's bytes changed. A repeated save is a no-op.
    pub changed: bool,
}

/// Header of a file created by `detect --save`.
const TEMPLATE: &str = r#"# githits-scan configuration. Paths are relative to the scanned directory
# and use forward slashes, whatever directory this file lives in.
#
# `githits-scan detect --save` keeps `include` and `manifests` current.
# `--exclude` patterns are merged into `exclude`. Everything else survives a save.

version = 1

[lockfiles]
# Every lockfile the scan uploads. A detected lockfile that is not listed
# here, or a listed one that is not found, is drift and fails the run
# unless --no-check is passed.
include = []
# Globs for lockfiles and manifests that are intentionally not part of the
# inventory. Matches are reported as excluded, never as drift.
exclude = []
# Manifests to upload without a lockfile; the service resolves their
# dependencies from the declared constraints. A detected project without a
# lockfile that is missing here is drift, unless the run is --lockfiles-only.
manifests = []

# Uncomment to enable `githits-scan license check`.
# [licenses]
# allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-3-Clause", "ISC"]
#
# [[licenses.exceptions]]
# purl = "pkg:cargo/example"
# reason = "reviewed 2026-09"
#
# # Or except a named Git source; copy the full URL/revision from license check --json.
# [[licenses.exceptions]]
# name = "grammar"
# git = "https://example.invalid/grammar"
# rev = "0123456789abcdef0123456789abcdef01234567" # optional; exact match
# reason = "Selected source reviewed"
#
# # Ignored advisories stay visible and do not cause failure themselves.
# [[audit.ignore]]
# id = "RUSTSEC-2024-0436"
# reason = "Reviewed for this deployment"
"#;

/// Write `include` and `manifests` to the file at `path`.
///
/// A missing file is created from the template. An existing file keeps
/// everything but the rewritten arrays byte for byte: comments, key order,
/// and `[licenses]` survive. `exclude` is rewritten only when `exclude` is
/// `Some`. Nothing is written when the result equals the current contents.
///
/// # Errors
///
/// Returns [`ConfigError::Read`], [`ConfigError::Parse`] for an existing file
/// that is not valid TOML, or [`ConfigError::Write`].
pub fn save(
    path: &Path,
    include: &[String],
    manifests: &[String],
    exclude: Option<&[String]>,
) -> Result<SaveOutcome, ConfigError> {
    let existing = match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(source) if source.kind() == io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let created = existing.is_none();
    let text = existing.as_deref().unwrap_or(TEMPLATE);
    let mut document: DocumentMut =
        text.parse()
            .map_err(|error: toml_edit::TomlError| ConfigError::Parse {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;
    let table = document
        .entry("lockfiles")
        .or_insert(toml_edit::table())
        .as_table_mut()
        .ok_or_else(|| ConfigError::Parse {
            path: path.to_path_buf(),
            message: "`lockfiles` must be a table".to_owned(),
        })?;
    let mut outcome = SaveOutcome {
        created,
        ..SaveOutcome::default()
    };
    let before_include = string_array(table.get("include"));
    let before_manifests = string_array(table.get("manifests"));
    let before_exclude = string_array(table.get("exclude"));
    set_array(table, "include", include);
    if !manifests.is_empty() || table.contains_key("manifests") {
        set_array(table, "manifests", manifests);
    }
    let mut added: Vec<String> = difference(include, &before_include)
        .chain(difference(manifests, &before_manifests))
        .collect();
    let mut removed: Vec<String> = difference(&before_include, include)
        .chain(difference(&before_manifests, manifests))
        .collect();
    if let Some(exclude) = exclude {
        set_array(table, "exclude", exclude);
        added.extend(difference(exclude, &before_exclude));
        removed.extend(difference(&before_exclude, exclude));
    }
    outcome.added = added;
    outcome.removed = removed;
    let rendered = document.to_string();
    outcome.changed = created || rendered != text;
    if outcome.changed {
        std::fs::write(path, rendered).map_err(|source| ConfigError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(outcome)
}

/// Replace the value in place when the key exists so the comments attached to
/// the key survive; `Table::insert` would create a fresh, undecorated key.
fn set_array(table: &mut toml_edit::Table, key: &str, paths: &[String]) {
    match table.get_mut(key) {
        Some(item) => *item = path_array(paths),
        None => {
            table.insert(key, path_array(paths));
        }
    }
}

fn string_array(item: Option<&Item>) -> Vec<String> {
    item.and_then(Item::as_array)
        .map(|array| {
            array
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Paths in `left` that are not in `right`, in `left`'s order.
fn difference<'a>(left: &'a [String], right: &'a [String]) -> impl Iterator<Item = String> + 'a {
    left.iter()
        .filter(move |path| !right.contains(path))
        .cloned()
}

/// One path per line for a non-empty list, `[]` otherwise.
fn path_array(paths: &[String]) -> Item {
    let mut array = Array::new();
    for path in paths {
        let mut value = Value::from(path.as_str());
        value.decor_mut().set_prefix("\n    ");
        value.decor_mut().set_suffix("");
        array.push_formatted(value);
    }
    if !paths.is_empty() {
        array.set_trailing_comma(true);
        array.set_trailing("\n");
    }
    toml_edit::value(array)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::discover;
    use globset::GlobSet;

    fn parsed(text: &str) -> Config {
        parse(Path::new("githits-scan.toml"), text).expect("valid config")
    }

    fn no_invocation() -> GlobSet {
        exclude_set(&[], Path::new("test")).expect("empty globset")
    }

    fn repository(files: &[&str]) -> TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for file in files {
            let path = dir.path().join(file);
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(path, "").expect("write");
        }
        dir
    }

    #[test]
    fn parses_every_documented_key() {
        let config = parsed(
            r#"
version = 1

[lockfiles]
include = ["Cargo.lock", "web/package-lock.json"]
exclude = ["examples/**", "benches/fixtures/**"]
manifests = ["services/legacy/package.json"]

[licenses]
allow = ["MIT", "Apache-2.0 WITH LLVM-exception"]

[[licenses.exceptions]]
purl = "pkg:cargo/ring"
reason = "reviewed"

[[licenses.exceptions]]
name = "grammar"
git = "https://example.invalid/grammar"
rev = "0123456789abcdef"
reason = "reviewed source"

[[audit.ignore]]
id = "RUSTSEC-2024-0436"
reason = "reviewed advisory"
"#,
        );

        assert_eq!(config.include, ["Cargo.lock", "web/package-lock.json"]);
        assert_eq!(config.exclude, ["examples/**", "benches/fixtures/**"]);
        assert_eq!(config.manifests, ["services/legacy/package.json"]);
        assert!(config.is_excluded("examples/demo/Cargo.lock"));
        assert!(!config.is_excluded("Cargo.lock"));
        let licenses = config.licenses.expect("licenses");
        assert_eq!(licenses.allow, ["MIT", "Apache-2.0 WITH LLVM-exception"]);
        assert!(
            matches!(&licenses.exceptions[0], Exception::Package { purl, .. } if purl == "pkg:cargo/ring")
        );
        assert!(
            matches!(&licenses.exceptions[1], Exception::Git { name, git, rev, .. }
            if name == "grammar" && git == "https://example.invalid/grammar" && rev.as_deref() == Some("0123456789abcdef"))
        );
        assert_eq!(config.audit.ignore[0].id, "RUSTSEC-2024-0436");
        assert_eq!(config.audit.ignore[0].reason, "reviewed advisory");
    }

    #[test]
    fn a_minimal_file_defaults_every_list() {
        let config = parsed("version = 1\n");

        assert!(config.include.is_empty(), "{:?}", config.include);
        assert!(config.exclude.is_empty(), "{:?}", config.exclude);
        assert!(config.manifests.is_empty(), "{:?}", config.manifests);
        assert!(config.licenses.is_none());
    }

    #[test]
    fn unknown_keys_and_wrong_shapes_are_parse_errors() {
        for text in [
            "version = 1\n[lockfiles]\ninclud = []\n",
            "version = 1\n[lockfile]\ninclude = []\n",
            "version = 1\n[licenses]\nallowed = []\n",
            "version = 1\n[[licenses.exceptions]]\npurl = \"x\"\n",
            "[lockfiles]\ninclude = []\n",
            "version = 1\n[lockfiles]\ninclude = \"Cargo.lock\"\n",
            "version = 1\n[lockfiles\n",
        ] {
            let error = parse(Path::new("c.toml"), text).expect_err(text);
            assert!(
                matches!(error, ConfigError::Parse { .. }),
                "{text}: {error}"
            );
            assert!(error.to_string().starts_with("c.toml: "), "{error}");
        }
    }

    #[test]
    fn rejects_other_versions_bad_globs_and_bad_paths() {
        let error = parse(Path::new("c.toml"), "version = 2\n").expect_err("version");
        assert!(matches!(
            error,
            ConfigError::UnsupportedVersion { version: 2, .. }
        ));

        let error = parse(
            Path::new("c.toml"),
            "version = 1\n[lockfiles]\nexclude = [\"[\"]\n",
        )
        .expect_err("glob");
        assert!(matches!(error, ConfigError::InvalidGlob { ref pattern, .. } if pattern == "["));

        let error = parse(
            Path::new("c.toml"),
            "version = 1\n[lockfiles]\ninclude = [\"../Cargo.lock\"]\n",
        )
        .expect_err("path");
        assert!(matches!(
            error,
            ConfigError::InvalidPath {
                reason: PathRule::ParentSegment,
                ..
            }
        ));
    }

    #[test]
    fn globs_do_not_cross_directories_unless_doubled() {
        let config =
            parsed("version = 1\n[lockfiles]\nexclude = [\"*/Cargo.lock\", \"vendor/**\"]\n");

        assert!(config.is_excluded("a/Cargo.lock"));
        assert!(!config.is_excluded("a/b/Cargo.lock"));
        assert!(config.is_excluded("vendor/x/y/Gemfile.lock"));
    }

    #[test]
    fn load_returns_none_for_a_missing_file() {
        let repo = repository(&[]);
        assert!(load(&repo.path().join(FILE_NAME)).expect("load").is_none());
    }

    #[test]
    fn evaluates_statuses_and_drift() {
        let repo = repository(&[
            "Cargo.lock",
            "Cargo.toml",
            "examples/demo/Cargo.lock",
            "web/package-lock.json",
            "legacy/package.json",
            "old/package.json",
            "crates/core/Cargo.toml",
        ]);
        let inventory = discover::scan(repo.path()).expect("scan");
        let config = parsed(
            r#"
version = 1
[lockfiles]
include = ["Cargo.lock", "gone/Cargo.lock"]
exclude = ["examples/**", "old/**"]
manifests = ["legacy/package.json", "crates/core/Cargo.toml", "Cargo.toml", "gone/package.json"]
"#,
        );

        let evaluation = evaluate(Some(&config), &no_invocation(), &inventory, true);

        assert_eq!(evaluation.status("Cargo.lock"), Some(Status::Included));
        assert_eq!(
            evaluation.status("examples/demo/Cargo.lock"),
            Some(Status::Excluded)
        );
        assert_eq!(
            evaluation.status("web/package-lock.json"),
            Some(Status::Unlisted)
        );
        assert_eq!(
            evaluation.status("legacy/package.json"),
            Some(Status::Included)
        );
        assert_eq!(
            evaluation.status("old/package.json"),
            Some(Status::Excluded)
        );
        assert_eq!(
            evaluation.status("crates/core/Cargo.toml"),
            Some(Status::Included)
        );
        assert_eq!(
            evaluation.status("Cargo.toml"),
            Some(Status::Included),
            "companions share canonical selection status"
        );
        assert_eq!(evaluation.unlisted, ["web/package-lock.json"]);
        assert_eq!(evaluation.missing, ["gone/Cargo.lock", "gone/package.json"]);
        assert!(evaluation.has_drift());
    }

    #[test]
    fn an_explicit_entry_beats_an_exclude_pattern_and_a_match_is_no_drift() {
        let repo = repository(&["examples/Cargo.lock", "tools/package.json"]);
        let inventory = discover::scan(repo.path()).expect("scan");
        let config = parsed(
            "version = 1\n[lockfiles]\ninclude = [\"examples/Cargo.lock\"]\nexclude = [\"examples/**\", \"tools/**\"]\n",
        );

        let evaluation = evaluate(Some(&config), &no_invocation(), &inventory, true);

        assert_eq!(
            evaluation.status("examples/Cargo.lock"),
            Some(Status::Included)
        );
        assert_eq!(
            evaluation.status("tools/package.json"),
            Some(Status::Excluded)
        );
        assert!(!evaluation.has_drift());
    }

    #[test]
    fn entries_in_the_wrong_list_are_missing_not_silently_satisfied() {
        let repo = repository(&[
            "Cargo.lock",
            "Cargo.toml",
            "crates/core/Cargo.toml",
            "docs/pyproject.toml",
            "examples/demo/Cargo.lock",
            "examples/demo/Cargo.toml",
        ]);
        let inventory = discover::scan(repo.path()).expect("scan");
        let config = parsed(
            r#"
version = 1
[lockfiles]
include = ["Cargo.lock", "docs/pyproject.toml", "crates/core/Cargo.toml", "Cargo.toml"]
exclude = ["examples/**"]
manifests = ["examples/demo/Cargo.toml", "Cargo.lock", "Cargo.toml"]
"#,
        );

        let evaluation = evaluate(Some(&config), &no_invocation(), &inventory, true);

        assert_eq!(
            evaluation.missing,
            [
                // `include` entries that are not lockfiles.
                "Cargo.toml",
                "crates/core/Cargo.toml",
                "docs/pyproject.toml",
                // `manifests` entries that are a lockfile or the companion of an
                // excluded lockfile; `Cargo.toml` is the companion of an included
                // lockfile and is therefore found.
                "Cargo.lock",
                "examples/demo/Cargo.toml",
            ]
        );
        assert!(evaluation.has_drift());
    }

    #[test]
    fn save_refuses_a_lockfiles_key_that_is_not_a_table() {
        let repo = repository(&[]);
        let path = repo.path().join(FILE_NAME);
        fs::write(&path, "version = 1\nlockfiles = \"oops\"\n").expect("write");

        let error = save(&path, &["Cargo.lock".into()], &[], None).expect_err("not a table");

        assert!(
            matches!(error, ConfigError::Parse { ref message, .. } if message.contains("table")),
            "{error}"
        );
        assert_eq!(
            fs::read_to_string(&path).expect("file"),
            "version = 1\nlockfiles = \"oops\"\n"
        );
    }

    #[test]
    fn save_creates_a_commented_file_that_parses_and_round_trips() {
        let repo = repository(&[]);
        let path = repo.path().join(FILE_NAME);

        let outcome = save(
            &path,
            &["Cargo.lock".into(), "web/package-lock.json".into()],
            &[],
            None,
        )
        .expect("save");

        assert!(outcome.created && outcome.changed);
        assert_eq!(outcome.added, ["Cargo.lock", "web/package-lock.json"]);
        assert!(outcome.removed.is_empty(), "{:?}", outcome.removed);
        let text = fs::read_to_string(&path).expect("file");
        assert!(text.starts_with("# githits-scan configuration."), "{text}");
        assert!(
            text.contains("# unless --no-check is passed.\ninclude = [\n    \"Cargo.lock\",\n    \"web/package-lock.json\",\n]\n"),
            "the comment above include survives:\n{text}"
        );
        assert!(text.contains("manifests = []\n"), "{text}");
        assert!(text.contains("# [licenses]\n"), "{text}");
        let config = load(&path).expect("load").expect("present");
        assert_eq!(config.include, ["Cargo.lock", "web/package-lock.json"]);
        assert!(config.licenses.is_none());

        let again = save(
            &path,
            &["Cargo.lock".into(), "web/package-lock.json".into()],
            &[],
            None,
        )
        .expect("save again");
        assert!(!again.changed && !again.created);
        assert!(again.added.is_empty() && again.removed.is_empty());
        assert_eq!(fs::read_to_string(&path).expect("file"), text);
    }

    #[test]
    fn save_rewrites_only_the_two_arrays_and_preserves_everything_else() {
        let repo = repository(&[]);
        let path = repo.path().join(FILE_NAME);
        let original = r#"# my notes
version = 1

[licenses]   # policy first, on purpose
allow = ["MIT"]

[lockfiles]
exclude = ["examples/**"]  # keep
# the inventory
include = ["old/Cargo.lock", "Cargo.lock"]
manifests = ["legacy/package.json"]
"#;
        fs::write(&path, original).expect("write");

        let outcome = save(
            &path,
            &["Cargo.lock".into(), "web/yarn.lock".into()],
            &["legacy/package.json".into(), "tools/package.json".into()],
            None,
        )
        .expect("save");

        assert!(!outcome.created && outcome.changed);
        assert_eq!(outcome.added, ["web/yarn.lock", "tools/package.json"]);
        assert_eq!(outcome.removed, ["old/Cargo.lock"]);
        let text = fs::read_to_string(&path).expect("file");
        let expected = r#"# my notes
version = 1

[licenses]   # policy first, on purpose
allow = ["MIT"]

[lockfiles]
exclude = ["examples/**"]  # keep
# the inventory
include = [
    "Cargo.lock",
    "web/yarn.lock",
]
manifests = [
    "legacy/package.json",
    "tools/package.json",
]
"#;
        assert_eq!(text, expected);
    }

    #[test]
    fn save_does_not_add_an_empty_manifests_key_to_an_existing_file() {
        let repo = repository(&[]);
        let path = repo.path().join(FILE_NAME);
        fs::write(&path, "version = 1\n\n[lockfiles]\ninclude = []\n").expect("write");

        save(&path, &["Cargo.lock".into()], &[], None).expect("save");

        let text = fs::read_to_string(&path).expect("file");
        assert_eq!(
            text,
            "version = 1\n\n[lockfiles]\ninclude = [\n    \"Cargo.lock\",\n]\n"
        );
    }

    #[test]
    fn save_refuses_an_unparsable_existing_file() {
        let repo = repository(&[]);
        let path = repo.path().join(FILE_NAME);
        fs::write(&path, "version = [\n").expect("write");

        let error = save(&path, &[], &[], None).expect_err("parse error");

        assert!(matches!(error, ConfigError::Parse { .. }), "{error}");
        assert_eq!(fs::read_to_string(&path).expect("file"), "version = [\n");
    }

    #[test]
    fn invocation_excludes_beat_an_include_entry_and_are_not_drift() {
        let repo = repository(&["examples/Cargo.lock", "Cargo.lock"]);
        let inventory = discover::scan(repo.path()).expect("scan");
        let config = parsed(
            "version = 1\n[lockfiles]\ninclude = [\"examples/Cargo.lock\", \"Cargo.lock\"]\n",
        );
        let invocation = exclude_set(&["examples/**".into()], Path::new(CLI_EXCLUDE)).unwrap();

        let evaluation = evaluate(Some(&config), &invocation, &inventory, true);

        assert_eq!(
            evaluation.status("examples/Cargo.lock"),
            Some(Status::Excluded)
        );
        assert_eq!(evaluation.status("Cargo.lock"), Some(Status::Included));
        assert!(!evaluation.has_drift());
    }

    #[test]
    fn without_a_file_invocation_excludes_are_not_drift() {
        let repo = repository(&["Cargo.lock", "web/yarn.lock"]);
        let inventory = discover::scan(repo.path()).expect("scan");
        let invocation = exclude_set(&["web/**".into()], Path::new(CLI_EXCLUDE)).unwrap();

        let evaluation = evaluate(None, &invocation, &inventory, true);

        assert_eq!(evaluation.status("Cargo.lock"), Some(Status::Included));
        assert_eq!(evaluation.status("web/yarn.lock"), Some(Status::Excluded));
        assert!(!evaluation.has_drift());
    }

    #[test]
    fn without_a_file_manifest_only_is_included_unless_lockfiles_only() {
        let repo = repository(&["Cargo.lock", "legacy/package.json", "vendor/x/go.mod"]);
        let inventory = discover::scan(repo.path()).expect("scan");
        let invocation = exclude_set(&["vendor/**".into()], Path::new(CLI_EXCLUDE)).unwrap();

        let default = evaluate(None, &invocation, &inventory, true);
        let lockfiles_only = evaluate(None, &invocation, &inventory, false);

        assert_eq!(default.status("Cargo.lock"), Some(Status::Included));
        assert_eq!(
            default.status("legacy/package.json"),
            Some(Status::Included)
        );
        assert_eq!(
            lockfiles_only.status("legacy/package.json"),
            Some(Status::Unlisted)
        );
        assert!(!default.has_drift() && !lockfiles_only.has_drift());
    }

    #[test]
    fn an_unlisted_manifest_only_project_is_drift_unless_lockfiles_only() {
        let repo = repository(&["Cargo.lock", "legacy/package.json", "tools/go.mod"]);
        let inventory = discover::scan(repo.path()).expect("scan");
        let config = parsed(
            "version = 1\n[lockfiles]\ninclude = [\"Cargo.lock\"]\nmanifests = [\"tools/go.mod\"]\n",
        );

        let default = evaluate(Some(&config), &no_invocation(), &inventory, true);
        let lockfiles_only = evaluate(Some(&config), &no_invocation(), &inventory, false);

        assert_eq!(default.unlisted, ["legacy/package.json"]);
        assert_eq!(default.status("tools/go.mod"), Some(Status::Included));
        assert!(!lockfiles_only.has_drift());
        assert_eq!(
            lockfiles_only.status("legacy/package.json"),
            Some(Status::Unlisted)
        );
        assert_eq!(
            lockfiles_only.status("tools/go.mod"),
            Some(Status::Included)
        );
    }

    #[test]
    fn an_exclude_acknowledges_an_ambiguous_lockfile_and_an_include_entry_is_missing() {
        let repo = repository(&["net/packages.lock.json", "net/A.csproj", "net/B.csproj"]);
        let inventory = discover::scan(repo.path()).expect("scan");
        let none = exclude_set(&[], Path::new(CLI_EXCLUDE)).unwrap();
        let listed = parsed("version = 1\n[lockfiles]\ninclude = [\"net/packages.lock.json\"]\n");
        let excluded = parsed("version = 1\n[lockfiles]\nexclude = [\"net/packages.lock.json\"]\n");

        let unacknowledged = evaluate(None, &none, &inventory, true);
        let missing = evaluate(Some(&listed), &none, &inventory, true);
        let acknowledged = evaluate(Some(&excluded), &none, &inventory, true);

        assert_eq!(unacknowledged.status("net/packages.lock.json"), None);
        assert!(!unacknowledged.has_drift());
        assert_eq!(missing.missing, ["net/packages.lock.json"]);
        assert_eq!(
            acknowledged.status("net/packages.lock.json"),
            Some(Status::Excluded)
        );
        // Its projects are manifest-only, which a configuration must list.
        assert_eq!(acknowledged.unlisted, ["net/A.csproj", "net/B.csproj"]);
        assert!(
            acknowledged.missing.is_empty(),
            "{:?}",
            acknowledged.missing
        );
    }

    #[test]
    fn an_uncombined_manifest_can_be_listed_like_a_nested_one() {
        let repo = repository(&["jvm/gradle.lockfile", "jvm/build.gradle"]);
        let inventory = discover::scan(repo.path()).expect("scan");
        let none = exclude_set(&[], Path::new(CLI_EXCLUDE)).unwrap();
        let config = parsed(
            "version = 1\n[lockfiles]\ninclude = [\"jvm/gradle.lockfile\"]\nmanifests = [\"jvm/build.gradle\"]\n",
        );

        let evaluation = evaluate(Some(&config), &none, &inventory, true);

        assert_eq!(
            evaluation.status("jvm/build.gradle"),
            Some(Status::Included)
        );
        assert!(!evaluation.has_drift());
    }

    #[test]
    fn invocation_excludes_give_nested_manifests_an_excluded_status() {
        let repo = repository(&["Cargo.lock", "crates/core/Cargo.toml"]);
        let inventory = discover::scan(repo.path()).expect("scan");
        let config = parsed(
            "version = 1\n[lockfiles]\ninclude = [\"Cargo.lock\"]\nmanifests = [\"crates/core/Cargo.toml\"]\n",
        );
        let invocation = exclude_set(&["crates/**".into()], Path::new(CLI_EXCLUDE)).unwrap();

        let evaluation = evaluate(Some(&config), &invocation, &inventory, true);

        assert_eq!(
            evaluation.status("crates/core/Cargo.toml"),
            Some(Status::Excluded)
        );
    }

    #[test]
    fn save_merges_exclude_patterns_when_asked() {
        let repo = repository(&[]);
        let path = repo.path().join(FILE_NAME);
        fs::write(
            &path,
            "version = 1\n\n[lockfiles]\ninclude = []\nexclude = [\"examples/**\"]\n",
        )
        .expect("write");

        let outcome = save(
            &path,
            &["Cargo.lock".into()],
            &[],
            Some(&["examples/**".into(), "tests/**".into()][..]),
        )
        .expect("save");

        assert!(outcome.changed);
        assert_eq!(outcome.added, ["Cargo.lock", "tests/**"]);
        let loaded = load(&path).expect("load").expect("present");
        assert_eq!(loaded.include, ["Cargo.lock"]);
        assert_eq!(loaded.exclude, ["examples/**", "tests/**"]);
    }

    #[test]
    fn fixture_defaults_match_exact_directory_components_only() {
        for directory in [
            "fixtures",
            "__fixtures__",
            "testdata",
            "test-data",
            "test_data",
        ] {
            assert!(is_default_excluded(&format!("{directory}/Cargo.lock")));
            assert!(is_default_excluded(&format!(
                "{}/Cargo.lock",
                directory.to_ascii_uppercase()
            )));
            assert!(is_default_excluded(&format!(
                "tests/{directory}/deep/Cargo.lock"
            )));
            assert!(
                !is_default_excluded(directory),
                "filename alone is not a directory"
            );
        }
        for path in [
            "Cargo.lock",
            "tests/Cargo.lock",
            "fixtures-app/Cargo.lock",
            "mytruth/Cargo.lock",
            "truth/Cargo.lock",
        ] {
            assert!(!is_default_excluded(path), "{path}");
        }
    }

    #[test]
    fn explicit_loading_requires_a_file_but_default_loading_allows_absence() {
        let repo = repository(&[]);
        let path = repo.path().join(FILE_NAME);
        assert!(load(&path).expect("optional default").is_none());
        let error = load_required(&path).expect_err("explicit path required");
        assert!(
            matches!(error, ConfigError::Read { source, .. } if source.kind() == io::ErrorKind::NotFound)
        );
    }
}
