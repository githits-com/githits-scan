//! `githits-scan detect`: preview locally selected package evidence.
//!
//! No token and no network. The human report leads with the outcome and lists
//! every lockfile with its owning manifest and every manifest-only project a
//! scan would upload; skipped ones (`--lockfiles-only`, or not listed in the
//! configuration) are listed separately with that reason. With a configuration
//! file every entry carries a status and drift is a finding; `--save` accepts the detected inventory into the file.
//! `--json` emits the same information losslessly.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

use serde::Serialize;

use super::{
    Error, Outcome, Selection, ambiguous_warnings, config_path, manifest_selection, plural,
};
use crate::catalog;
use crate::config::{self, Config, Evaluation, SaveOutcome, Status};
use crate::discover::{
    self, AmbiguousLockfile, Companion, CoveredManifest, Inventory, Lockfile, ManifestOnly,
};
use crate::style::Palette;

/// Version of the JSON report. Additive changes keep it; removals or renames
/// bump it.
const SCHEMA_VERSION: u32 = 2;

/// What to do when the inventory differs from the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftPolicy {
    /// Report it and exit with findings (the default; what a pipeline wants).
    Fail,
    /// Report it and succeed (`--no-check`).
    Report,
    /// Write the detected inventory to the configuration file (`--save`).
    Accept,
}

/// What the caller asked for.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// Directory to scan.
    pub root: &'a Path,
    /// Configuration file; defaults to `githits-scan.toml` in `root`.
    pub config: Option<&'a Path>,
    /// Count manifest-only projects as part of the inventory (the default;
    /// `--lockfiles-only` clears it).
    pub include_manifests: bool,
    /// Invocation `--exclude` globs; same language as `lockfiles.exclude`.
    pub exclude: &'a [String],
    /// Emit JSON instead of the human report.
    pub json: bool,
    /// How to treat drift.
    pub drift: DriftPolicy,
    /// Suppress save-success notes, preserving the inventory report.
    pub quiet: bool,
    /// Report destination.
    pub output: super::sbom::Output,
}

/// Scan and write the report.
///
/// Returns [`Outcome::Findings`] when the inventory is empty (no lockfile was
/// found and no manifest-only project was included) or when it drifts from
/// the configuration under [`DriftPolicy::Fail`]. The report is still written
/// in both cases so the caller sees what the scan considered.
///
/// # Errors
///
/// Returns the discovery or configuration error when the scan cannot
/// complete, a typed upload-preparation error after writing the inventory with
/// an unavailable preview, or [`Error::Output`] when the report cannot be written.
pub fn run(
    request: &Request<'_>,
    stdout: &mut dyn Write,
    palette: Palette,
) -> Result<Outcome, Error> {
    discover::require_directory(request.root)?;
    let path = config_path(request.root, request.config);
    let mut config = if request.drift == DriftPolicy::Accept {
        config::load(&path)?
    } else {
        super::load_config(request.root, request.config)?
    };
    let inventory = discover::scan_filtered(
        request.root,
        config::directory_filter(config.as_ref(), request.exclude)?,
    )?;
    let mut saved = None;
    if request.drift == DriftPolicy::Accept {
        let (include, manifests) = desired_lists(
            &inventory,
            config.as_ref(),
            request.include_manifests,
            request.exclude,
        )?;
        let persist_exclude = if request.exclude.is_empty() {
            None
        } else {
            Some(config::merge_exclude_patterns(
                config
                    .as_ref()
                    .map_or(&[], |config| config.exclude.as_slice()),
                request.exclude,
            ))
        };
        saved = Some(config::save(
            &path,
            &include,
            &manifests,
            persist_exclude.as_deref(),
        )?);
        config = config::load(&path)?;
    }
    let evaluation = config::inventory_evaluation(
        config.as_ref(),
        request.exclude,
        &inventory,
        request.include_manifests,
    )?;
    let preview = super::upload::preview(
        request.root,
        &inventory,
        evaluation.as_ref(),
        request.include_manifests,
    );
    let (upload_paths, upload_error) = match preview {
        Ok(paths) => (paths, None),
        Err(error) => (BTreeSet::new(), Some(error)),
    };
    let directory_exclusions = config::directory_patterns(&config::merge_exclude_patterns(
        config.as_ref().map_or(&[], |c| c.exclude.as_slice()),
        request.exclude,
    ));
    let view = View {
        upload_paths,
        upload_error: upload_error.as_ref(),
        directory_exclusions,
        request,
        inventory: &inventory,
        config: config.as_ref(),
        evaluation: evaluation.as_ref(),
        saved: saved.as_ref(),
        unsupported: super::unsupported_files(&inventory, config.as_ref(), request.exclude)?,
    };
    super::write_report(&request.output, stdout, palette, |out, palette| {
        if request.json {
            write_json(&view, out)
        } else {
            write_human(&view, out, palette).map_err(Error::Output)
        }
    })?;
    let outcome = view.outcome();
    if let Some(error) = upload_error {
        stdout.flush().map_err(Error::Output)?;
        return Err(error);
    }
    Ok(outcome)
}

/// The inventory `--save` writes: every eligible detected lockfile, respecting
/// explicit configuration overrides and invocation exclusions, and listed manifests that still
/// exist, plus every non-excluded manifest-only project unless the run is
/// `--lockfiles-only`.
fn desired_lists(
    inventory: &Inventory,
    config: Option<&Config>,
    include_manifests: bool,
    extra_exclude: &[String],
) -> Result<(Vec<String>, Vec<String>), config::ConfigError> {
    let excluded = config::exclude_set(extra_exclude, Path::new(config::CLI_EXCLUDE))?;
    let evaluation = config::evaluate(config, &excluded, inventory, include_manifests);
    let omitted = |path: &str| evaluation.status(path) == Some(Status::Excluded);
    let include: Vec<String> = inventory
        .lockfiles
        .iter()
        .filter(|lockfile| !omitted(&lockfile.path))
        .map(|lockfile| lockfile.path.clone())
        .collect();
    let mut manifests: BTreeSet<String> = BTreeSet::new();
    if let Some(config) = config {
        manifests.extend(
            config
                .manifests
                .iter()
                .filter(|path| !evaluation.missing.contains(path) && !omitted(path))
                .cloned(),
        );
    }
    if include_manifests {
        manifests.extend(
            inventory
                .manifest_only
                .iter()
                .filter(|manifest| !omitted(&manifest.path))
                .map(|manifest| manifest.path.clone()),
        );
    }
    Ok((include, manifests.into_iter().collect()))
}

/// Everything the renderers need.
struct View<'a> {
    upload_paths: BTreeSet<String>,
    upload_error: Option<&'a Error>,
    directory_exclusions: Vec<String>,
    request: &'a Request<'a>,
    inventory: &'a Inventory,
    config: Option<&'a Config>,
    evaluation: Option<&'a Evaluation>,
    saved: Option<&'a SaveOutcome>,
    unsupported: Vec<&'a discover::UnsupportedFile>,
}

impl View<'_> {
    /// Findings when a scan would upload nothing, judged by the same selection
    /// `sbom generate` makes, or on drift under [`DriftPolicy::Fail`].
    fn outcome(&self) -> Outcome {
        let lockfile = self
            .inventory
            .lockfiles
            .iter()
            .any(|l| self.selected_lock(&l.path));
        let manifest = self.manifest_only(Selection::Upload).next().is_some();
        let listed = self
            .inventory
            .nested
            .iter()
            .chain(&self.inventory.uncombined)
            .any(|m| self.status(&m.path) == Some(Status::Included));
        if !lockfile && !manifest && !listed {
            return Outcome::Findings;
        }
        let drift = self.evaluation.is_some_and(Evaluation::has_drift);
        if drift && self.request.drift == DriftPolicy::Fail {
            Outcome::Findings
        } else {
            Outcome::Success
        }
    }

    /// Manifest-only projects that `selection` applies to.
    fn manifest_only(&self, selection: Selection) -> impl Iterator<Item = &ManifestOnly> {
        self.inventory.manifest_only.iter().filter(move |m| {
            manifest_selection(self.status(&m.path), self.request.include_manifests) == selection
        })
    }

    fn selected_lock(&self, path: &str) -> bool {
        self.evaluation.is_none() || self.status(path) == Some(Status::Included)
    }

    fn suggest_path(&self, path: &str) -> bool {
        if self.upload_error.is_some() {
            return self.status(path) != Some(Status::Excluded);
        }
        self.upload_paths.contains(path)
    }

    fn status(&self, path: &str) -> Option<Status> {
        self.evaluation
            .and_then(|evaluation| evaluation.status(path))
    }

    fn config_display(&self) -> String {
        self.config
            .map(|config| super::safe_path(&config.path))
            .unwrap_or_default()
    }
}

#[derive(Serialize)]
struct Report<'a> {
    schema_version: u32,
    upload_paths: Option<&'a BTreeSet<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upload_error: Option<String>,
    excluded_directory_patterns: &'a [String],
    root: String,
    lockfiles_only: bool,
    unsupported: &'a [&'a discover::UnsupportedFile],
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<String>,
    lockfiles: Vec<LockfileEntry<'a>>,
    nested: Vec<CoveredEntry<'a>>,
    uncombined: Vec<CoveredEntry<'a>>,
    ambiguous: Vec<AmbiguousEntry<'a>>,
    manifest_only: Vec<ManifestOnlyEntry<'a>>,
    test_paths: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    drift: Option<DriftEntry<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    saved: Option<SavedEntry<'a>>,
}

#[derive(Serialize)]
struct LockfileEntry<'a> {
    path: &'a str,
    ecosystem: &'static str,
    bytes: u64,
    manifests: Vec<CompanionEntry<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'static str>,
}

#[derive(Serialize)]
struct CompanionEntry<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'static str>,
    path: &'a str,
    bytes: u64,
}

impl<'a> CompanionEntry<'a> {
    fn new(companion: &'a Companion, status: Option<Status>) -> Self {
        Self {
            status: status.map(Status::id),
            path: &companion.path,
            bytes: companion.bytes,
        }
    }
}

#[derive(Serialize)]
struct CoveredEntry<'a> {
    path: &'a str,
    ecosystem: &'static str,
    bytes: u64,
    lockfile: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'static str>,
}

#[derive(Serialize)]
struct AmbiguousEntry<'a> {
    path: &'a str,
    ecosystem: &'static str,
    bytes: u64,
    manifests: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'static str>,
}

#[derive(Serialize)]
struct ManifestOnlyEntry<'a> {
    path: &'a str,
    ecosystem: &'static str,
    bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'static str>,
}

#[derive(Serialize)]
struct DriftEntry<'a> {
    unlisted: &'a [String],
    missing: &'a [String],
}

#[derive(Serialize)]
struct SavedEntry<'a> {
    created: bool,
    changed: bool,
    added: &'a [String],
    removed: &'a [String],
}

fn write_json(view: &View<'_>, out: &mut dyn Write) -> Result<(), Error> {
    let inventory = view.inventory;
    let status = |path: &str| view.status(path).map(Status::id);
    let report = Report {
        upload_paths: view.upload_error.is_none().then_some(&view.upload_paths),
        upload_error: view.upload_error.map(ToString::to_string),
        excluded_directory_patterns: &view.directory_exclusions,
        schema_version: SCHEMA_VERSION,
        root: view.request.root.display().to_string(),
        lockfiles_only: !view.request.include_manifests,
        unsupported: &view.unsupported,
        config: view.config.map(|config| config.path.display().to_string()),
        lockfiles: inventory
            .lockfiles
            .iter()
            .map(|l| LockfileEntry {
                path: &l.path,
                ecosystem: l.ecosystem.id(),
                bytes: l.bytes,
                manifests: l
                    .manifests
                    .iter()
                    .map(|m| CompanionEntry::new(m, view.status(&m.path)))
                    .collect(),
                status: status(&l.path),
            })
            .collect(),
        nested: inventory
            .nested
            .iter()
            .map(|n| covered_entry(n, status(&n.path)))
            .collect(),
        uncombined: inventory
            .uncombined
            .iter()
            .map(|u| covered_entry(u, status(&u.path)))
            .collect(),
        ambiguous: inventory
            .ambiguous
            .iter()
            .map(|a| AmbiguousEntry {
                path: &a.path,
                ecosystem: a.ecosystem.id(),
                bytes: a.bytes,
                manifests: &a.manifests,
                status: status(&a.path),
            })
            .collect(),
        manifest_only: inventory
            .manifest_only
            .iter()
            .map(|m| ManifestOnlyEntry {
                path: &m.path,
                ecosystem: m.ecosystem.id(),
                bytes: m.bytes,
                status: status(&m.path),
            })
            .collect(),
        test_paths: test_paths(view),
        drift: view
            .config
            .and(view.evaluation)
            .map(|evaluation| DriftEntry {
                unlisted: &evaluation.unlisted,
                missing: &evaluation.missing,
            }),
        saved: view.saved.map(|saved| SavedEntry {
            created: saved.created,
            changed: saved.changed,
            added: &saved.added,
            removed: &saved.removed,
        }),
    };
    serde_json::to_writer_pretty(&mut *out, &report)?;
    writeln!(out).map_err(Error::Output)
}

fn covered_entry<'a>(
    manifest: &'a CoveredManifest,
    status: Option<&'static str>,
) -> CoveredEntry<'a> {
    CoveredEntry {
        path: &manifest.path,
        ecosystem: manifest.ecosystem.id(),
        bytes: manifest.bytes,
        lockfile: &manifest.lockfile,
        status,
    }
}

/// One line of the inventory table, unstyled.
struct Row {
    path: String,
    ecosystem: &'static str,
    size: String,
    companion: String,
    manifest_only: bool,
    status: Option<Status>,
}

impl Row {
    fn lockfile(
        lockfile: &Lockfile,
        status: Option<Status>,
        selected: Option<&BTreeSet<String>>,
    ) -> Self {
        let companion = if lockfile.manifests.is_empty() {
            "-".to_owned()
        } else {
            lockfile
                .manifests
                .iter()
                .map(|m| companion_label(m, selected))
                .collect::<Vec<_>>()
                .join(", ")
        };
        Self {
            path: lockfile.path.clone(),
            ecosystem: lockfile.ecosystem.name(),
            size: thousands(lockfile.bytes),
            companion,
            manifest_only: false,
            status,
        }
    }

    fn manifest_only(
        manifest: &ManifestOnly,
        inventory: &Inventory,
        status: Option<Status>,
    ) -> Self {
        let displaced = inventory
            .ambiguous
            .iter()
            .any(|lock| lock.manifests.contains(&manifest.path));
        let companion = if displaced {
            "(ambiguous lockfile)"
        } else {
            "(no lockfile)"
        };
        Self {
            path: manifest.path.clone(),
            ecosystem: manifest.ecosystem.name(),
            size: thousands(manifest.bytes),
            companion: companion.to_owned(),
            manifest_only: true,
            status,
        }
    }

    fn covered(manifest: &CoveredManifest, status: Option<Status>) -> Self {
        Self {
            path: manifest.path.clone(),
            ecosystem: manifest.ecosystem.name(),
            size: thousands(manifest.bytes),
            companion: format!("lockfile: {}", manifest.lockfile),
            manifest_only: false,
            status,
        }
    }

    fn ambiguous(lockfile: &AmbiguousLockfile, status: Option<Status>) -> Self {
        Self {
            path: lockfile.path.clone(),
            ecosystem: lockfile.ecosystem.name(),
            size: thousands(lockfile.bytes),
            companion: format!("could be owned by {}", lockfile.manifests.join(", ")),
            manifest_only: true,
            status,
        }
    }
}

fn companion_label(manifest: &Companion, selected: Option<&BTreeSet<String>>) -> String {
    if selected.is_some_and(|paths| !paths.contains(&manifest.path)) {
        format!("{} (not uploaded)", manifest.path)
    } else {
        manifest.path.clone()
    }
}

fn write_directory_patterns(view: &View<'_>, out: &mut dyn Write) -> std::io::Result<()> {
    if view.directory_exclusions.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "\nDirectory exclusion patterns (configuration inclusions may preserve paths; CLI excludes always win):"
    )?;
    for pattern in &view.directory_exclusions {
        writeln!(out, "  {}", super::safe(pattern))?;
    }
    Ok(())
}

fn write_human(view: &View<'_>, out: &mut dyn Write, palette: Palette) -> std::io::Result<()> {
    let inventory = view.inventory;
    let with_status = view.evaluation.is_some();
    writeln!(out, "{}", palette.bold(&summary(view)))?;
    if let Some(error) = view.upload_error {
        writeln!(
            out,
            "Upload preview unavailable: {}",
            super::diagnostic(&error.to_string())
        )?;
    }
    if let Some(saved) = view.saved.filter(|_| !view.request.quiet) {
        writeln!(out, "{}", save_note(saved, &view.config_display()))?;
    }
    let mut rows: Vec<Row> = inventory
        .lockfiles
        .iter()
        .map(|l| {
            Row::lockfile(
                l,
                view.status(&l.path),
                view.upload_error.is_none().then_some(&view.upload_paths),
            )
        })
        .collect();
    rows.extend(
        view.manifest_only(Selection::Upload)
            .chain(view.manifest_only(Selection::Ignore))
            .map(|m| Row::manifest_only(m, inventory, view.status(&m.path))),
    );
    writeln!(out)?;
    if rows.is_empty() {
        let names: Vec<_> = catalog::lockfile_names().collect();
        writeln!(out, "Supported lockfiles: {}", names.join(", "))?;
    } else {
        write_table(&rows, with_status, out, palette)?;
    }
    let skipped: Vec<Row> = view
        .manifest_only(Selection::Skip)
        .map(|m| Row::manifest_only(m, inventory, view.status(&m.path)))
        .collect();
    if !skipped.is_empty() {
        writeln!(out)?;
        let heading = if view.request.include_manifests {
            format!(
                "Manifest-only projects not listed in {} (not uploaded):",
                view.config_display()
            )
        } else {
            "Manifest-only projects (not uploaded with --lockfiles-only):".to_owned()
        };
        writeln!(out, "{}", palette.warning(&heading))?;
        let rows = skipped;
        write_table(&rows, with_status, out, palette)?;
    }
    write_directory_patterns(view, out)?;
    write_automatic(view, out, palette)?;
    write_nested(view, with_status, out, palette)?;
    write_unsupported(view, out)?;
    if inventory
        .uncombined
        .iter()
        .any(|m| !view.upload_paths.contains(&m.path))
    {
        writeln!(out)?;
        writeln!(
            out,
            "{}",
            palette.dim(
                "Manifests beside a lockfile they do not own (cannot be combined; not uploaded unless the configuration lists them):"
            )
        )?;
        let rows: Vec<Row> = inventory
            .uncombined
            .iter()
            .filter(|m| !view.upload_paths.contains(&m.path))
            .map(|u| Row::covered(u, view.status(&u.path)))
            .collect();
        write_table(&rows, with_status, out, palette)?;
    }
    if !inventory.ambiguous.is_empty() {
        writeln!(out)?;
        writeln!(
            out,
            "{}",
            palette.warning(
                "Lockfiles several manifests could own (not uploaded; those manifests are manifest-only):"
            )
        )?;
        let rows: Vec<Row> = inventory
            .ambiguous
            .iter()
            .map(|a| Row::ambiguous(a, view.status(&a.path)))
            .collect();
        write_table(&rows, with_status, out, palette)?;
    }
    write_test_paths(view, out)?;
    write_missing(view, out, palette)
}

/// Informational annotations never change selection; configuration owns that policy.
fn test_paths<'a>(view: &'a View<'_>) -> Vec<&'a str> {
    let inventory = view.inventory;
    let paths = inventory
        .lockfiles
        .iter()
        .flat_map(|lock| {
            std::iter::once(lock.path.as_str()).chain(
                lock.manifests
                    .iter()
                    .filter(|_| view.selected_lock(&lock.path))
                    .map(|m| m.path.as_str()),
            )
        })
        .chain(inventory.manifest_only.iter().map(|m| m.path.as_str()))
        .chain(
            inventory
                .nested
                .iter()
                .chain(&inventory.uncombined)
                .map(|m| m.path.as_str()),
        )
        .chain(inventory.ambiguous.iter().map(|m| m.path.as_str()));
    paths
        .filter(|path| is_test_path(path) && view.suggest_path(path))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn is_test_path(path: &str) -> bool {
    if config::is_default_excluded(path) {
        return true;
    }
    let Some((directory, _)) = path.rsplit_once('/') else {
        return false;
    };
    directory.split('/').any(|part| {
        ["test", "tests", "eval", "evals", "truth"]
            .iter()
            .any(|name| part.eq_ignore_ascii_case(name))
            || part.to_ascii_lowercase().ends_with("_eval")
    })
}

fn write_test_paths(view: &View<'_>, out: &mut dyn Write) -> std::io::Result<()> {
    let paths = test_paths(view);
    if paths.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "\nTest-looking paths (review selection; use --exclude GLOB to omit):"
    )?;
    for path in paths.iter().take(10) {
        writeln!(out, "  {}", super::safe(path))?;
    }
    if paths.len() > 10 {
        writeln!(
            out,
            "  ... {} more; use --json for the complete list",
            paths.len() - 10
        )?;
    }
    Ok(())
}

fn write_unsupported(view: &View<'_>, out: &mut dyn Write) -> std::io::Result<()> {
    let mut groups: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for file in &view.unsupported {
        groups.entry(file.hint).or_default().push(&file.path);
    }
    if groups.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "\nUnsupported formats (not supported yet; not uploaded):"
    )?;
    for (hint, paths) in groups {
        writeln!(out, "  {hint}")?;
        for path in paths {
            writeln!(out, "    {}", super::safe(path))?;
        }
    }
    Ok(())
}

fn write_automatic(view: &View<'_>, out: &mut dyn Write, palette: Palette) -> std::io::Result<()> {
    for explicit in [false, true] {
        let rows: Vec<_> = view
            .inventory
            .nested
            .iter()
            .chain(&view.inventory.uncombined)
            .filter(|m| view.upload_paths.contains(&m.path))
            .filter(|m| view.config.is_some_and(|c| c.manifests.contains(&m.path)) == explicit)
            .map(|m| Row::covered(m, Some(Status::Included)))
            .collect();
        if rows.is_empty() {
            continue;
        }
        let heading = if explicit {
            "Manifests included by configuration:"
        } else {
            "Workspace manifests included automatically:"
        };
        writeln!(out, "\n{heading}")?;
        write_table(&rows, true, out, palette)?;
    }
    Ok(())
}

fn write_nested(
    view: &View<'_>,
    with_status: bool,
    out: &mut dyn Write,
    palette: Palette,
) -> std::io::Result<()> {
    for ecosystem in catalog::Ecosystem::ALL {
        let rows: Vec<_> = view
            .inventory
            .nested
            .iter()
            .filter(|m| m.ecosystem == ecosystem && !view.upload_paths.contains(&m.path))
            .map(|m| Row::covered(m, view.status(&m.path)))
            .collect();
        if rows.is_empty() {
            continue;
        }
        let note = if view.upload_error.is_some() {
            "upload selection unavailable; fix the preparation error"
        } else {
            "not uploaded; list explicitly in configuration to include"
        };
        writeln!(
            out,
            "\n{}",
            palette.dim(&format!(
                "{} manifests below an ancestor lockfile ({note}):",
                ecosystem.name()
            ))
        )?;
        write_table(&rows, with_status, out, palette)?;
    }
    Ok(())
}

fn write_missing(view: &View<'_>, out: &mut dyn Write, palette: Palette) -> std::io::Result<()> {
    let Some(evaluation) = view.evaluation else {
        return Ok(());
    };
    if evaluation.missing.is_empty() {
        return Ok(());
    }
    writeln!(out)?;
    let heading = format!("Listed in {} but not found:", view.config_display());
    writeln!(out, "{}", palette.warning(&heading))?;
    for path in &evaluation.missing {
        writeln!(out, "  {}", super::safe(path))?;
    }
    Ok(())
}

fn summary(view: &View<'_>) -> String {
    let inventory = view.inventory;
    let selected: Vec<_> = inventory
        .lockfiles
        .iter()
        .filter(|l| view.selected_lock(&l.path))
        .collect();
    let lockfiles = selected.len();
    let ecosystems = selected
        .iter()
        .map(|l| l.ecosystem)
        .collect::<BTreeSet<_>>()
        .len();
    let excluded = inventory
        .lockfiles
        .iter()
        .filter(|l| view.status(&l.path) == Some(Status::Excluded))
        .count();
    let included = view.manifest_only(Selection::Upload).count();
    let skipped = view.manifest_only(Selection::Skip).count();
    let additional = inventory
        .nested
        .iter()
        .chain(&inventory.uncombined)
        .filter(|m| view.upload_paths.contains(&m.path))
        .count();
    if lockfiles == 0 && included == 0 && additional == 0 {
        return empty_summary(view, skipped, excluded);
    }
    let mut text = if lockfiles == 0 {
        "no lockfiles".to_owned()
    } else {
        format!(
            "{} in {}",
            plural(lockfiles, "lockfile"),
            plural(ecosystems, "ecosystem")
        )
    };
    if excluded > 0 {
        let _ = write!(text, ", {} excluded", plural(excluded, "lockfile"));
    }
    if included > 0 {
        let _ = write!(
            text,
            ", {} included",
            plural(included, "manifest-only project")
        );
    }
    if skipped > 0 {
        let _ = write!(
            text,
            ", {} not included",
            plural(skipped, "manifest-only project")
        );
    }
    if additional > 0 {
        let _ = write!(
            text,
            ", {} included",
            plural(additional, "additional manifest")
        );
    }
    for (candidates, label) in [
        (&inventory.nested, "nested candidate"),
        (&inventory.uncombined, "adjacent candidate"),
    ] {
        let omitted = candidates
            .iter()
            .filter(|m| !view.upload_paths.contains(&m.path))
            .count();
        if omitted > 0 && view.upload_error.is_none() {
            let _ = write!(text, ", {} not uploaded", plural(omitted, label));
        }
    }
    let warnings = ambiguous_warnings(inventory, view.evaluation).len();
    if warnings > 0 {
        let _ = write!(
            text,
            ", {} not uploaded",
            plural(warnings, "ambiguous lockfile")
        );
    }
    append_drift(view, &mut text);
    text
}

fn empty_summary(view: &View<'_>, skipped: usize, excluded: usize) -> String {
    let inventory = view.inventory;
    let request = view.request;
    let mut text = format!(
        "no lockfiles {} in {}",
        if inventory.lockfiles.is_empty() && view.directory_exclusions.is_empty() {
            "found"
        } else {
            "selected"
        },
        super::safe_path(request.root)
    );
    if skipped > 0 {
        let _ = write!(
            text,
            " ({} not included)",
            plural(skipped, "manifest-only project")
        );
    }
    let warnings = ambiguous_warnings(inventory, view.evaluation).len();
    if warnings > 0 {
        let _ = write!(
            text,
            ", {} not uploaded",
            plural(warnings, "ambiguous lockfile")
        );
    }
    if excluded > 0 {
        let _ = write!(text, ", {} excluded", plural(excluded, "lockfile"));
    }
    append_drift(view, &mut text);
    text
}

fn append_drift(view: &View<'_>, text: &mut String) {
    if let Some(evaluation) = view
        .evaluation
        .filter(|_| view.config.is_some() && !view.saved.is_some_and(|s| s.created))
    {
        let _ = write!(
            text,
            ", {}",
            drift_summary(evaluation, &view.config_display())
        );
    }
}

fn drift_summary(evaluation: &Evaluation, config: &str) -> String {
    if !evaluation.has_drift() {
        return format!("inventory matches {config}");
    }
    let mut parts = Vec::new();
    if !evaluation.unlisted.is_empty() {
        parts.push(format!("{} unlisted", evaluation.unlisted.len()));
    }
    if !evaluation.missing.is_empty() {
        parts.push(format!("{} missing", evaluation.missing.len()));
    }
    format!("drift against {config}: {}", parts.join(", "))
}

fn save_note(saved: &SaveOutcome, config: &str) -> String {
    if !saved.changed {
        return format!("{config} is up to date");
    }
    if saved.created {
        return format!(
            "created {config} with {}",
            plural(saved.added.len(), "entry")
        );
    }
    format!(
        "saved {config}: added {}, removed {}",
        saved.added.len(),
        saved.removed.len()
    )
}

fn write_table(
    rows: &[Row],
    with_status: bool,
    out: &mut dyn Write,
    palette: Palette,
) -> std::io::Result<()> {
    let path_width = rows
        .iter()
        .map(|r| super::safe(&r.path).len())
        .max()
        .unwrap_or(0)
        .max(4);
    let ecosystem_width = rows
        .iter()
        .map(|r| r.ecosystem.len())
        .max()
        .unwrap_or(0)
        .max(9);
    let size_width = rows.iter().map(|r| r.size.len()).max().unwrap_or(0).max(5);
    let companion_width = rows
        .iter()
        .map(|r| super::safe(&r.companion).len())
        .max()
        .unwrap_or(0)
        .max(9);
    let mut header = format!(
        "  {:<path_width$}  {:<ecosystem_width$}  {:>size_width$}  {:<companion_width$}",
        "PATH", "ECOSYSTEM", "BYTES", "COMPANION"
    );
    if with_status {
        header.push_str("  STATUS");
    }
    writeln!(out, "{}", palette.dim(header.trim_end()))?;
    for row in rows {
        let companion_text = super::safe(&row.companion);
        let companion = if row.manifest_only {
            palette.warning(&companion_text)
        } else {
            companion_text.as_str().into()
        };
        let padding = " ".repeat(companion_width - companion_text.len());
        let mut line = format!(
            "  {:<path_width$}  {:<ecosystem_width$}  {:>size_width$}  {companion}{padding}",
            super::safe(&row.path),
            row.ecosystem,
            row.size
        );
        if with_status {
            let _ = write!(line, "  {}", status_cell(row.status, palette));
        }
        writeln!(out, "{}", line.trim_end())?;
    }
    Ok(())
}

fn status_cell(status: Option<Status>, palette: Palette) -> String {
    match status {
        Some(Status::Included) => "included".to_owned(),
        Some(Status::Excluded) => "excluded".to_owned(),
        Some(Status::Unlisted) => palette.warning("unlisted").into_owned(),
        None => "-".to_owned(),
    }
}

/// Format a byte count with thousands separators, e.g. `1,234,567`.
fn thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::*;
    use crate::commands::ErrorKind;

    fn repository(files: &[(&str, &str)]) -> TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for (relative, contents) in files {
            write_file(&dir.path().join(relative), contents);
        }
        dir
    }

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, contents).expect("write file");
    }

    fn request(root: &Path) -> Request<'_> {
        Request {
            root,
            config: None,
            include_manifests: false,
            exclude: &[],
            json: false,
            drift: DriftPolicy::Fail,
            quiet: false,
            output: super::super::sbom::Output::Stdout,
        }
    }

    fn detect(request: &Request<'_>) -> (Outcome, String) {
        let mut out = Vec::new();
        let outcome = run(request, &mut out, Palette::PLAIN).expect("detect");
        (outcome, String::from_utf8(out).expect("utf-8 report"))
    }

    #[test]
    fn human_report_lists_lockfiles_with_companions_and_manifest_only_projects() {
        let repo = repository(&[
            ("Cargo.lock", "# 1234567\n"),
            ("Cargo.toml", ""),
            ("crates/core/Cargo.toml", "x"),
            ("web/yarn.lock", ""),
            ("web/package.json", ""),
            ("legacy/package.json", ""),
        ]);

        let (outcome, report) = detect(&request(repo.path()));

        assert_eq!(outcome, Outcome::Success);
        let expected = "\
2 lockfiles in 2 ecosystems, 1 manifest-only project not included, 1 nested candidate not uploaded

  PATH           ECOSYSTEM   BYTES  COMPANION
  Cargo.lock     Rust           10  Cargo.toml
  web/yarn.lock  JavaScript      0  web/package.json

Manifest-only projects (not uploaded with --lockfiles-only):
  PATH                 ECOSYSTEM   BYTES  COMPANION
  legacy/package.json  JavaScript      0  (no lockfile)

Rust manifests below an ancestor lockfile (not uploaded; list explicitly in configuration to include):
  PATH                    ECOSYSTEM  BYTES  COMPANION
  crates/core/Cargo.toml  Rust           1  lockfile: Cargo.lock
";
        assert_eq!(report, expected);
    }

    #[test]
    fn human_report_explains_uncombined_manifests_and_ambiguous_lockfiles() {
        let repo = repository(&[
            ("jvm/gradle.lockfile", "x"),
            ("jvm/build.gradle", "y"),
            ("net/packages.lock.json", "{}"),
            ("net/App.csproj", ""),
            ("net/Tool.csproj", ""),
        ]);

        let (outcome, report) = detect(&request(repo.path()));

        assert_eq!(outcome, Outcome::Success);
        let expected = "\
1 lockfile in 1 ecosystem, 2 manifest-only projects not included, 1 adjacent candidate not uploaded, 1 ambiguous lockfile not uploaded

  PATH                 ECOSYSTEM  BYTES  COMPANION
  jvm/gradle.lockfile  Gradle         1  -

Manifest-only projects (not uploaded with --lockfiles-only):
  PATH             ECOSYSTEM  BYTES  COMPANION
  net/App.csproj   .NET           0  (ambiguous lockfile)
  net/Tool.csproj  .NET           0  (ambiguous lockfile)

Manifests beside a lockfile they do not own (cannot be combined; not uploaded unless the configuration lists them):
  PATH              ECOSYSTEM  BYTES  COMPANION
  jvm/build.gradle  Gradle         1  lockfile: jvm/gradle.lockfile

Lockfiles several manifests could own (not uploaded; those manifests are manifest-only):
  PATH                    ECOSYSTEM  BYTES  COMPANION
  net/packages.lock.json  .NET           2  could be owned by net/App.csproj, net/Tool.csproj
";
        assert_eq!(report, expected);
    }

    #[test]
    fn include_manifests_moves_manifest_only_projects_into_the_inventory() {
        let repo = repository(&[("Cargo.lock", ""), ("legacy/package.json", "")]);

        let (outcome, report) = detect(&Request {
            include_manifests: true,
            ..request(repo.path())
        });

        assert_eq!(outcome, Outcome::Success);
        let expected = "\
1 lockfile in 1 ecosystem, 1 manifest-only project included

  PATH                 ECOSYSTEM   BYTES  COMPANION
  Cargo.lock           Rust            0  -
  legacy/package.json  JavaScript      0  (no lockfile)
";
        assert_eq!(report, expected);
    }

    #[test]
    fn empty_inventory_is_a_finding_and_names_the_supported_lockfiles() {
        let repo = repository(&[("README.md", "")]);

        let (outcome, report) = detect(&request(repo.path()));

        assert_eq!(outcome, Outcome::Findings);
        let root = repo.path().display();
        assert!(
            report.starts_with(&format!("no lockfiles found in {root}\n\n")),
            "{report}"
        );
        assert!(report.contains("Supported lockfiles: Cargo.lock, package-lock.json"));
        assert!(report.trim_end().ends_with("Gopkg.lock"), "{report}");
    }

    #[test]
    fn manifest_only_projects_alone_are_a_finding_unless_included() {
        let repo = repository(&[("package.json", "")]);

        let (outcome, report) = detect(&request(repo.path()));
        assert_eq!(outcome, Outcome::Findings);
        let root = repo.path().display();
        let expected = format!(
            "\
no lockfiles found in {root} (1 manifest-only project not included)

Supported lockfiles: {}

Manifest-only projects (not uploaded with --lockfiles-only):
  PATH          ECOSYSTEM   BYTES  COMPANION
  package.json  JavaScript      0  (no lockfile)
",
            catalog::lockfile_names().collect::<Vec<_>>().join(", ")
        );
        assert_eq!(report, expected);

        let (outcome, report) = detect(&Request {
            include_manifests: true,
            ..request(repo.path())
        });
        assert_eq!(outcome, Outcome::Success);
        assert!(
            report.starts_with("no lockfiles, 1 manifest-only project included\n"),
            "{report}"
        );
    }

    #[test]
    fn json_report_is_lossless_and_versioned() {
        let repo = repository(&[
            ("Cargo.lock", "abc"),
            ("Cargo.toml", ""),
            ("crates/core/Cargo.toml", "x"),
            ("legacy/package.json", "{}"),
            ("tools/Pipfile.lock", "{}"),
            ("tools/pyproject.toml", "[x]"),
            ("net/packages.lock.json", "{}"),
            ("net/Api.csproj", "<a/>"),
            ("net/Web.csproj", "<w/>"),
        ]);

        let (outcome, report) = detect(&Request {
            json: true,
            ..request(repo.path())
        });

        assert_eq!(outcome, Outcome::Success);
        let value: serde_json::Value = serde_json::from_str(&report).expect("json");
        assert_eq!(
            value,
            serde_json::json!({
                "schema_version": 2,
                "upload_paths": ["Cargo.lock", "Cargo.toml", "tools/Pipfile.lock"],
                "excluded_directory_patterns": [],
                "test_paths": [],
                "root": repo.path().display().to_string(),
                "lockfiles_only": true,
                "unsupported": [],
                "lockfiles": [
                    { "path": "Cargo.lock", "ecosystem": "rust", "bytes": 3, "manifests": [{ "path": "Cargo.toml", "bytes": 0 }] },
                    { "path": "tools/Pipfile.lock", "ecosystem": "python", "bytes": 2, "manifests": [] }
                ],
                "nested": [
                    { "path": "crates/core/Cargo.toml", "ecosystem": "rust", "bytes": 1, "lockfile": "Cargo.lock" }
                ],
                "uncombined": [
                    { "path": "tools/pyproject.toml", "ecosystem": "python", "bytes": 3, "lockfile": "tools/Pipfile.lock" }
                ],
                "ambiguous": [
                    { "path": "net/packages.lock.json", "ecosystem": "dotnet", "bytes": 2, "manifests": ["net/Api.csproj", "net/Web.csproj"] }
                ],
                "manifest_only": [
                    { "path": "legacy/package.json", "ecosystem": "javascript", "bytes": 2 },
                    { "path": "net/Api.csproj", "ecosystem": "dotnet", "bytes": 4 },
                    { "path": "net/Web.csproj", "ecosystem": "dotnet", "bytes": 4 }
                ]
            })
        );
        assert!(report.ends_with('\n'));
    }

    #[test]
    fn json_report_is_written_for_findings_too() {
        let repo = repository(&[]);

        let (outcome, report) = detect(&Request {
            json: true,
            ..request(repo.path())
        });

        assert_eq!(outcome, Outcome::Findings);
        let value: serde_json::Value = serde_json::from_str(&report).expect("json");
        assert_eq!(value["lockfiles"], serde_json::json!([]));
        assert_eq!(value["nested"], serde_json::json!([]));
        assert_eq!(value["uncombined"], serde_json::json!([]));
        assert_eq!(value["ambiguous"], serde_json::json!([]));
        assert_eq!(value["manifest_only"], serde_json::json!([]));
    }

    #[test]
    fn a_missing_root_is_a_usage_error() {
        let root = PathBuf::from("definitely/missing/root");
        let mut out = Vec::new();

        let error = run(&request(&root), &mut out, Palette::PLAIN).expect_err("missing root");

        assert_eq!(error.kind(), ErrorKind::Usage);
        assert!(out.is_empty(), "nothing is written on failure");
    }

    const CONFIG: &str = "\
version = 1

[lockfiles]
include = [\"Cargo.lock\", \"gone/Cargo.lock\"]
exclude = [\"examples/**\"]
manifests = [\"legacy/package.json\"]
";

    fn configured_repository() -> TempDir {
        repository(&[
            ("githits-scan.toml", CONFIG),
            ("Cargo.lock", ""),
            ("Cargo.toml", ""),
            ("examples/demo/Cargo.lock", ""),
            ("web/yarn.lock", ""),
            ("legacy/package.json", ""),
            ("tools/package.json", ""),
        ])
    }

    #[test]
    fn with_a_config_every_row_has_a_status_and_drift_is_a_finding() {
        let repo = configured_repository();

        let (outcome, report) = detect(&request(repo.path()));

        assert_eq!(outcome, Outcome::Findings);
        let config = repo.path().join("githits-scan.toml").display().to_string();
        let expected = format!(
            "\
1 lockfile in 1 ecosystem, 1 manifest-only project included, 1 manifest-only project not included, drift against {config}: 1 unlisted, 1 missing

  PATH                 ECOSYSTEM   BYTES  COMPANION      STATUS
  Cargo.lock           Rust            0  Cargo.toml     included
  web/yarn.lock        JavaScript      0  -              unlisted
  legacy/package.json  JavaScript      0  (no lockfile)  included

Manifest-only projects (not uploaded with --lockfiles-only):
  PATH                ECOSYSTEM   BYTES  COMPANION      STATUS
  tools/package.json  JavaScript      0  (no lockfile)  unlisted

Directory exclusion patterns (configuration inclusions may preserve paths; CLI excludes always win):
  examples/**

Listed in {config} but not found:
  gone/Cargo.lock
"
        );
        assert_eq!(report, expected);
    }

    #[test]
    fn no_check_reports_drift_without_failing() {
        let repo = configured_repository();

        let (outcome, report) = detect(&Request {
            drift: DriftPolicy::Report,
            ..request(repo.path())
        });

        assert_eq!(outcome, Outcome::Success);
        assert!(report.contains("drift against"), "{report}");
    }

    #[test]
    fn a_matching_inventory_succeeds_and_says_so() {
        let repo = repository(&[
            (
                "githits-scan.toml",
                "version = 1\n[lockfiles]\ninclude = [\"Cargo.lock\"]\n",
            ),
            ("Cargo.lock", ""),
        ]);

        let (outcome, report) = detect(&request(repo.path()));

        assert_eq!(outcome, Outcome::Success);
        assert!(
            report.starts_with(&format!(
                "1 lockfile in 1 ecosystem, inventory matches {}\n",
                repo.path().join("githits-scan.toml").display()
            )),
            "{report}"
        );
    }

    #[test]
    fn json_report_carries_statuses_and_drift_with_a_config() {
        let repo = configured_repository();

        let (_, report) = detect(&Request {
            json: true,
            ..request(repo.path())
        });

        let value: serde_json::Value = serde_json::from_str(&report).expect("json");
        assert_eq!(
            value["config"],
            repo.path().join("githits-scan.toml").display().to_string()
        );
        assert_eq!(value["lockfiles"][0]["status"], "included");
        assert_eq!(value["lockfiles"][1]["status"], "unlisted");
        assert_eq!(
            value["excluded_directory_patterns"],
            serde_json::json!(["examples/**"])
        );
        assert_eq!(value["manifest_only"][0]["status"], "included");
        assert_eq!(value["manifest_only"][1]["status"], "unlisted");
        assert_eq!(
            value["drift"]["unlisted"],
            serde_json::json!(["web/yarn.lock"])
        );
        assert_eq!(
            value["drift"]["missing"],
            serde_json::json!(["gone/Cargo.lock"])
        );
        assert!(value.get("saved").is_none());
    }

    #[test]
    fn a_config_override_is_honored() {
        let repo = repository(&[("Cargo.lock", "")]);
        let elsewhere = tempfile::tempdir().expect("tempdir");
        let config = elsewhere.path().join("custom.toml");
        fs::write(
            &config,
            "version = 1\n[lockfiles]\ninclude = [\"Cargo.lock\"]\n",
        )
        .expect("write");

        let (outcome, report) = detect(&Request {
            config: Some(&config),
            ..request(repo.path())
        });

        assert_eq!(outcome, Outcome::Success);
        assert!(
            report.contains(&format!("inventory matches {}", config.display())),
            "{report}"
        );
    }

    #[test]
    fn an_invalid_config_is_a_usage_error() {
        let repo = repository(&[
            ("githits-scan.toml", "version = 1\n[lockfiles]\nincl = []\n"),
            ("Cargo.lock", ""),
        ]);
        let mut out = Vec::new();

        let error = run(&request(repo.path()), &mut out, Palette::PLAIN).expect_err("config");

        assert_eq!(error.kind(), ErrorKind::Usage);
        assert!(error.to_string().contains("incl"), "{error}");
    }

    #[test]
    fn save_creates_the_config_and_the_inventory_then_matches() {
        let repo = repository(&[
            ("Cargo.lock", ""),
            ("web/yarn.lock", ""),
            ("legacy/package.json", ""),
        ]);

        let (outcome, report) = detect(&Request {
            drift: DriftPolicy::Accept,
            ..request(repo.path())
        });

        assert_eq!(outcome, Outcome::Success);
        let config = repo.path().join("githits-scan.toml");
        assert!(
            report.starts_with(&format!(
                "2 lockfiles in 2 ecosystems, 1 manifest-only project not included\ncreated {0} with 2 entries\n",
                config.display()
            )),
            "{report}"
        );
        let loaded = config::load(&config).expect("load").expect("created");
        assert_eq!(loaded.include, ["Cargo.lock", "web/yarn.lock"]);
        assert!(loaded.manifests.is_empty(), "{:?}", loaded.manifests);

        let (outcome, report) = detect(&Request {
            drift: DriftPolicy::Accept,
            ..request(repo.path())
        });
        assert_eq!(outcome, Outcome::Success);
        assert!(
            report.contains(&format!("{} is up to date\n", config.display())),
            "{report}"
        );
    }

    #[test]
    fn save_with_include_manifests_lists_manifest_only_projects() {
        let repo = repository(&[("Cargo.lock", ""), ("legacy/package.json", "")]);

        let (outcome, _) = detect(&Request {
            drift: DriftPolicy::Accept,
            include_manifests: true,
            ..request(repo.path())
        });

        assert_eq!(outcome, Outcome::Success);
        let loaded = config::load(&repo.path().join("githits-scan.toml"))
            .expect("load")
            .expect("created");
        assert_eq!(loaded.manifests, ["legacy/package.json"]);
    }

    #[test]
    fn save_accepts_drift_and_keeps_excludes_and_existing_manifests() {
        let repo = configured_repository();

        let (outcome, report) = detect(&Request {
            drift: DriftPolicy::Accept,
            ..request(repo.path())
        });

        assert_eq!(outcome, Outcome::Success);
        let config = repo.path().join("githits-scan.toml");
        assert!(
            report.contains(&format!(
                "inventory matches {0}\nsaved {0}: added 1, removed 1\n",
                config.display()
            )),
            "{report}"
        );
        let loaded = config::load(&config).expect("load").expect("present");
        assert_eq!(loaded.include, ["Cargo.lock", "web/yarn.lock"]);
        assert_eq!(loaded.exclude, ["examples/**"]);
        assert_eq!(loaded.manifests, ["legacy/package.json"]);
    }

    #[test]
    fn save_reports_in_json() {
        let repo = repository(&[("Cargo.lock", "")]);

        let (_, report) = detect(&Request {
            drift: DriftPolicy::Accept,
            json: true,
            ..request(repo.path())
        });

        let value: serde_json::Value = serde_json::from_str(&report).expect("json");
        assert_eq!(
            value["saved"],
            serde_json::json!({ "created": true, "changed": true, "added": ["Cargo.lock"], "removed": [] })
        );
        assert_eq!(
            value["drift"],
            serde_json::json!({ "unlisted": [], "missing": [] })
        );
    }

    #[test]
    fn exclude_marks_matching_lockfiles_and_save_writes_the_patterns() {
        let repo = repository(&[("Cargo.lock", ""), ("web/yarn.lock", "")]);
        let exclude = ["web/**".to_string()];

        let (outcome, report) = detect(&Request {
            exclude: &exclude,
            ..request(repo.path())
        });

        assert_eq!(outcome, Outcome::Success);
        assert!(report.contains("Directory exclusion patterns"), "{report}");
        assert!(report.contains("web/**"), "{report}");
        assert!(!report.contains("web/yarn.lock"), "{report}");

        let (outcome, _) = detect(&Request {
            exclude: &exclude,
            drift: DriftPolicy::Accept,
            ..request(repo.path())
        });

        assert_eq!(outcome, Outcome::Success);
        let loaded = config::load(&repo.path().join("githits-scan.toml"))
            .expect("load")
            .expect("created");
        assert_eq!(loaded.include, ["Cargo.lock"]);
        assert_eq!(loaded.exclude, ["web/**"]);
    }

    #[test]
    fn save_drops_manifests_that_match_invocation_excludes() {
        let repo = configured_repository();
        let exclude = ["legacy/**".to_string()];

        let (outcome, _) = detect(&Request {
            exclude: &exclude,
            drift: DriftPolicy::Accept,
            ..request(repo.path())
        });

        assert_eq!(outcome, Outcome::Success);
        let loaded = config::load(&repo.path().join("githits-scan.toml"))
            .expect("load")
            .expect("present");
        assert!(
            !loaded
                .manifests
                .iter()
                .any(|path| path.starts_with("legacy/"))
        );
        assert!(loaded.exclude.contains(&"legacy/**".to_string()));
    }

    #[test]
    fn formats_byte_counts_with_thousands_separators() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }
}
