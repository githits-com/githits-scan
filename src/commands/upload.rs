//! Canonical command-layer inventory selection and bounded upload preparation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

use super::{
    Error, Selection, ambiguous_warnings, config_path, drift_lines, manifest_selection, plural,
};
use crate::api::{self, UploadFile, UploadSet};
use crate::catalog::{self, WorkspaceFamily};
use crate::config::{self, Evaluation, Status};
use crate::discover::{self, CoveredManifest, Inventory, Lockfile, cargo, npm};
use crate::style::Palette;

pub(super) struct Options<'a> {
    pub root: &'a Path,
    pub config: Option<&'a Path>,
    pub no_check: bool,
    pub include_manifests: bool,
    pub exclude: &'a [String],
    pub progress: bool,
}

pub(super) struct Prepared {
    pub upload: UploadSet,
    pub summary: String,
    pub manifests: Vec<String>,
    pub audit_policy: config::Audit,
}

pub(super) fn prepare(
    options: &Options<'_>,
    stderr: &mut dyn Write,
    palette: Palette,
) -> Result<Option<Prepared>, Error> {
    discover::require_directory(options.root)?;
    if options.progress {
        super::progress::message("scanning repository...", stderr).map_err(Error::Output)?;
    }
    let path = config_path(options.root, options.config);
    let config = super::load_config(options.root, options.config)?;
    let inventory = discover::scan_filtered(
        options.root,
        config::directory_filter(config.as_ref(), options.exclude)?,
    )?;
    let mut unsupported: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for file in super::unsupported_files(&inventory, config.as_ref(), options.exclude)? {
        unsupported.entry(file.hint).or_default().push(&file.path);
    }
    for (hint, files) in unsupported {
        writeln!(
            stderr,
            "warning: {} {} not supported yet; {hint}; example: {}; run `githits-scan detect` to list paths",
            plural(files.len(), "file"),
            if files.len() == 1 { "is" } else { "are" },
            super::safe(files[0])
        )
        .map_err(Error::Output)?;
    }
    let evaluation = config::inventory_evaluation(
        config.as_ref(),
        options.exclude,
        &inventory,
        options.include_manifests,
    )?;
    if let Some(evaluation) = evaluation
        .as_ref()
        .filter(|e| e.has_drift() && !options.no_check)
    {
        for line in drift_lines(evaluation, &path) {
            writeln!(stderr, "{line}").map_err(Error::Output)?;
        }
        return Ok(None);
    }
    for warning in ambiguous_warnings(&inventory, evaluation.as_ref()) {
        writeln!(stderr, "{}", palette.warning(&warning)).map_err(Error::Output)?;
    }
    let mut plan = Plan::new(&inventory, evaluation.as_ref(), options.include_manifests);
    if plan.files.is_empty() {
        let message = if inventory.lockfiles.is_empty() {
            let patterns = config::merge_exclude_patterns(
                config.as_ref().map_or(&[], |c| c.exclude.as_slice()),
                options.exclude,
            );
            empty_message(
                options.root,
                &plan,
                !config::directory_patterns(&patterns).is_empty(),
            )
        } else {
            omitted_message(options.root, &plan)
        };
        writeln!(stderr, "{message}").map_err(Error::Output)?;
        return Ok(None);
    }
    api::upload::check_plan(plan.entries())?;
    if options.progress {
        super::progress::message("preparing upload...", stderr).map_err(Error::Output)?;
    }
    let files = read_within_limits(options.root, &mut plan, &inventory, evaluation.as_ref())?;
    let upload = UploadSet::try_new(files)?;
    if options.progress {
        super::progress::message(
            &format!(
                "submitting {} and {}...",
                plural(plan.lockfiles, "lockfile"),
                plural(plan.manifests.len(), "manifest")
            ),
            stderr,
        )
        .map_err(Error::Output)?;
    }
    Ok(Some(Prepared {
        upload,
        summary: plan.summary(palette),
        manifests: plan.manifests,
        audit_policy: config.map(|config| config.audit).unwrap_or_default(),
    }))
}

/// Select Git evidence using the normal inventory policy and workspace expansion.
pub(super) fn from_inventory(
    inventory: &Inventory,
    include_manifests: bool,
    exclude: &[String],
    read: impl FnMut(&str) -> Result<String, Error>,
) -> Result<Option<UploadSet>, Error> {
    let evaluation = config::inventory_evaluation(None, exclude, inventory, include_manifests)?;
    let mut plan = Plan::new(inventory, evaluation.as_ref(), include_manifests);
    if plan.files.is_empty() {
        return Ok(None);
    }
    api::upload::check_plan(plan.entries())?;
    let files = read_selected(&mut plan, inventory, evaluation.as_ref(), read)?;
    Ok(Some(UploadSet::try_new(files)?))
}

/// Use the upload preparation path offline so preview cannot disagree with submission.
pub(super) fn preview(
    root: &Path,
    inventory: &Inventory,
    evaluation: Option<&Evaluation>,
    include_manifests: bool,
) -> Result<BTreeSet<String>, Error> {
    let mut plan = Plan::new(inventory, evaluation, include_manifests);
    if plan.files.is_empty() {
        return Ok(BTreeSet::new());
    }
    api::upload::check_plan(plan.entries())?;
    read_within_limits(root, &mut plan, inventory, evaluation)?;
    Ok(plan.files.into_keys().collect())
}

/// Read the planned files, keeping memory within the body limit even when a
/// file grew after the scan: each read is capped at the per-file limit, and
/// the expanded plan is checked with the sizes seen so far before the next
/// file is read. Supported workspace declarations can add admitted member evidence.
fn read_within_limits(
    root: &Path,
    plan: &mut Plan,
    inventory: &Inventory,
    evaluation: Option<&Evaluation>,
) -> Result<Vec<UploadFile>, Error> {
    read_selected(plan, inventory, evaluation, |path| {
        discover::read_file(root, path, api::MAX_FILE_BYTES).map_err(Error::from)
    })
}

fn read_selected(
    plan: &mut Plan,
    inventory: &Inventory,
    evaluation: Option<&Evaluation>,
    mut read: impl FnMut(&str) -> Result<String, Error>,
) -> Result<Vec<UploadFile>, Error> {
    let initial_manifests = plan.manifests.len();
    let mut workspaces = workspaces(inventory, evaluation, plan);
    let candidates: BTreeMap<_, _> = inventory
        .nested
        .iter()
        .map(|m| (m.path.as_str(), m.bytes))
        .collect();
    let mut files = BTreeMap::new();
    while let Some(path) = plan
        .files
        .keys()
        .find(|path| !files.contains_key(*path))
        .cloned()
    {
        let contents = read(&path)?;
        plan.files.insert(path.clone(), contents.len() as u64);
        for workspace in &mut workspaces {
            workspace.record(&path, &contents);
            add_members(plan, workspace, &candidates);
        }

        // Includes actual sizes already read and metadata for every newly selected member.
        // Failure here prevents another read or a network submission.
        check_expanded_plan(plan, initial_manifests)?;
        files.insert(path.clone(), UploadFile { path, contents });
    }
    plan.manifests.sort();
    Ok(files.into_values().collect())
}

fn check_expanded_plan(plan: &Plan, initial_manifests: usize) -> Result<(), Error> {
    let Err(source) = api::upload::check_plan(plan.entries()) else {
        return Ok(());
    };
    // Expansion only adds manifests; explicitly selected inputs retain the usual error.
    let automatic_manifests = plan.manifests.len() - initial_manifests;
    match source {
        api::UploadError::TooManyFiles { count } if automatic_manifests > 0 => {
            let exclusions = plan.manifests[initial_manifests..]
                .iter()
                .take(3)
                .map(|path| {
                    format!(
                        "--exclude '{}'",
                        globset::escape(path).replace('\'', "'\\''")
                    )
                })
                .collect::<Vec<_>>()
                .join(" or ");
            Err(Error::WorkspaceMemberLimit {
                files: count,
                automatic_manifests,
                exclusions,
            })
        }
        source => Err(Error::Upload(source)),
    }
}

fn add_members(plan: &mut Plan, workspace: &Workspace, candidates: &BTreeMap<&str, u64>) {
    for member in workspace.members() {
        if plan.files.contains_key(&member) {
            continue;
        }
        if let Some(bytes) = candidates.get(member.as_str()) {
            plan.files.insert(member.clone(), *bytes);
            plan.manifests.push(member);
        }
    }
}

fn workspaces(
    inventory: &Inventory,
    evaluation: Option<&Evaluation>,
    plan: &Plan,
) -> Vec<Workspace> {
    inventory
        .lockfiles
        .iter()
        .filter(|lock| plan.files.contains_key(&lock.path))
        .filter_map(|lock| catalog::workspace_family(&lock.path).map(|family| (lock, family)))
        .flat_map(|(lock, family)| {
            lock.manifests
                .iter()
                .filter(|root| plan.files.contains_key(&root.path))
                .map(move |root| (lock, family, root))
        })
        .map(|(lock, family, root)| {
            let candidates = inventory
                .nested
                .iter()
                .filter(|m| candidate_owned(m, lock, family))
                .filter(|m| evaluation.and_then(|e| e.status(&m.path)) != Some(Status::Excluded))
                .map(|m| m.path.clone());
            match family {
                WorkspaceFamily::Cargo => {
                    Workspace::Cargo(cargo::Workspace::new(root.path.clone(), candidates))
                }
                WorkspaceFamily::Npm => {
                    Workspace::Npm(npm::Workspace::new(root.path.clone(), candidates))
                }
            }
        })
        .collect()
}

fn candidate_owned(member: &CoveredManifest, lock: &Lockfile, family: WorkspaceFamily) -> bool {
    if member.ecosystem != lock.ecosystem {
        return false;
    }
    match family {
        WorkspaceFamily::Cargo => member.lockfile == lock.path,
        // Several JavaScript locks can share an owner; discovery names just one representative.
        WorkspaceFamily::Npm => {
            catalog::owning_directory(Path::new(&member.lockfile))
                == catalog::owning_directory(Path::new(&lock.path))
        }
    }
}

enum Workspace {
    Cargo(cargo::Workspace),
    Npm(npm::Workspace),
}

impl Workspace {
    fn record(&mut self, path: &str, contents: &str) {
        match self {
            Self::Cargo(workspace) => workspace.record(path, contents),
            Self::Npm(workspace) => workspace.record(path, contents),
        }
    }

    fn members(&self) -> BTreeSet<String> {
        match self {
            Self::Cargo(workspace) => workspace.members(),
            Self::Npm(workspace) => workspace.members(),
        }
    }
}

/// The files selected for upload, deduplicated and sorted by path, with the
/// counts the summary reports.
struct Plan {
    files: BTreeMap<String, u64>,
    lockfiles: usize,
    manifests: Vec<String>,
    skipped_manifest_only: Vec<String>,
    include_manifests: bool,
}

impl Plan {
    /// Build initial selection; bounded reads later add supported workspace member evidence.
    /// Without a configuration: every lockfile with its
    /// owning manifest, plus every manifest-only project unless the run is
    /// `--lockfiles-only`. With a configuration: included lockfiles with their
    /// owning manifests and the manifests the file lists (manifest-only,
    /// nested, or uncombined); an unlisted manifest-only project is drift, and
    /// like an unlisted lockfile it is not uploaded even under `--no-check`.
    /// Invocation `--exclude` globs omit matching lockfiles even when they
    /// are listed in `include`. Excluded files are never uploaded and never
    /// reported as skipped: they are a deliberate choice.
    fn new(
        inventory: &Inventory,
        evaluation: Option<&Evaluation>,
        include_manifests: bool,
    ) -> Self {
        let status = |path: &str| evaluation.and_then(|e| e.status(path));
        let lockfiles: Vec<&Lockfile> = inventory
            .lockfiles
            .iter()
            .filter(|l| evaluation.is_none() || status(&l.path) == Some(Status::Included))
            .collect();
        let mut manifests: BTreeMap<String, u64> = lockfiles
            .iter()
            .flat_map(|lockfile| lockfile.manifests.iter())
            .filter(|m| status(&m.path) != Some(Status::Excluded))
            .map(|manifest| (manifest.path.clone(), manifest.bytes))
            .collect();
        let mut files: BTreeMap<String, u64> = lockfiles
            .iter()
            .map(|lockfile| (lockfile.path.clone(), lockfile.bytes))
            .collect();
        let mut additional = Vec::new();
        let mut skipped_manifest_only = Vec::new();
        for manifest in &inventory.manifest_only {
            match manifest_selection(status(&manifest.path), include_manifests) {
                Selection::Upload => additional.push((&manifest.path, manifest.bytes)),
                Selection::Skip => skipped_manifest_only.push(manifest.path.clone()),
                Selection::Ignore => (),
            }
        }
        additional.extend(
            inventory
                .nested
                .iter()
                .chain(&inventory.uncombined)
                .filter(|covered| status(&covered.path) == Some(Status::Included))
                .map(|covered| (&covered.path, covered.bytes)),
        );
        manifests.extend(
            additional
                .into_iter()
                .map(|(path, bytes)| (path.clone(), bytes)),
        );
        files.extend(manifests.iter().map(|(path, bytes)| (path.clone(), *bytes)));
        Self {
            files,
            lockfiles: lockfiles.len(),
            manifests: manifests.into_keys().collect(),
            skipped_manifest_only,
            include_manifests,
        }
    }

    fn entries(&self) -> impl Iterator<Item = (&str, u64)> {
        self.files
            .iter()
            .map(|(path, bytes)| (path.as_str(), *bytes))
    }

    /// Why manifest-only projects were left out: the run is lockfile-only,
    /// or the configuration does not list them.
    const fn skip_reason(&self) -> &'static str {
        if self.include_manifests {
            "not listed in the configuration"
        } else {
            "--lockfiles-only"
        }
    }

    fn summary(&self, palette: Palette) -> String {
        let mut text = format!(
            "uploaded {} and {}",
            plural(self.lockfiles, "lockfile"),
            plural(self.manifests.len(), "manifest")
        );
        let paths = self
            .manifests
            .iter()
            .map(|p| p.escape_debug().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        if !paths.is_empty() && text.chars().count() + paths.chars().count() + 3 <= 100 {
            let _ = write!(text, " ({paths})");
        }
        if !self.skipped_manifest_only.is_empty() {
            let reason = self.skip_reason();
            let note = format!(
                "{} not uploaded ({}; {reason})",
                plural(self.skipped_manifest_only.len(), "manifest-only project"),
                super::safe_names(&self.skipped_manifest_only)
            );
            let _ = write!(text, "; {}", palette.warning(&note));
        }
        text
    }
}

fn empty_message(root: &Path, plan: &Plan, directory_exclusions: bool) -> String {
    let mut text = format!(
        "no lockfiles {} in {}; run `githits-scan detect` to see what was considered",
        if directory_exclusions {
            "selected"
        } else {
            "found"
        },
        super::safe_path(root)
    );
    if directory_exclusions {
        text.push_str("; excluded directory contents are not inspected");
    }
    push_skipped(&mut text, plan);
    text
}

fn omitted_message(root: &Path, plan: &Plan) -> String {
    let mut text = format!(
        "nothing to upload from {}; every lockfile is excluded (run `githits-scan detect` to see statuses)",
        super::safe_path(root)
    );
    push_skipped(&mut text, plan);
    text
}

/// Name the manifest-only projects an empty plan left out, with the reason.
fn push_skipped(text: &mut String, plan: &Plan) {
    if plan.skipped_manifest_only.is_empty() {
        return;
    }
    let _ = write!(
        text,
        "\n{} not uploaded ({}): {}",
        plural(plan.skipped_manifest_only.len(), "manifest-only project"),
        plan.skip_reason(),
        super::safe_names(&plan.skipped_manifest_only)
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::ErrorKind;
    use crate::test_support::repository;
    use std::fs;
    #[test]
    fn files_that_grew_past_the_body_limit_after_the_scan_fail_before_more_reads() {
        // Two files planned at 0 bytes are rewritten to 4 MiB each before the
        // reads happen. Together they exceed the 8,000,000-byte body limit,
        // which must be detected after the second read at the latest.
        let repo = repository(&[("a/Cargo.lock", ""), ("b/Cargo.lock", "")]);
        let inventory = discover::scan(repo.path()).expect("scan");
        let big = "x".repeat(4 * 1024 * 1024);
        fs::write(repo.path().join("a/Cargo.lock"), &big).expect("grow a");
        fs::write(repo.path().join("b/Cargo.lock"), &big).expect("grow b");
        let mut plan = Plan::new(&inventory, None, false);

        let error =
            read_within_limits(repo.path(), &mut plan, &inventory, None).expect_err("body limit");

        assert_eq!(error.kind(), ErrorKind::Usage);
        assert!(
            error.to_string().starts_with("the upload would be about "),
            "{error}"
        );
    }

    #[test]
    fn a_shrunk_file_does_not_count_at_its_planned_size_when_another_grows() {
        // `a` is planned at 4 MiB and shrinks to nothing; `b` is planned at
        // 3 MiB and grows to 4 MiB. The real total fits; the stale plan
        // (4 MiB + 4 MiB) would not.
        let repo = repository(&[("a/Cargo.lock", ""), ("b/Cargo.lock", "")]);
        fs::write(
            repo.path().join("a/Cargo.lock"),
            "x".repeat(4 * 1024 * 1024),
        )
        .expect("a");
        fs::write(
            repo.path().join("b/Cargo.lock"),
            "x".repeat(3 * 1024 * 1024),
        )
        .expect("b");
        let inventory = discover::scan(repo.path()).expect("scan");
        fs::write(repo.path().join("a/Cargo.lock"), "").expect("shrink a");
        fs::write(
            repo.path().join("b/Cargo.lock"),
            "x".repeat(4 * 1024 * 1024),
        )
        .expect("grow b");
        let mut plan = Plan::new(&inventory, None, false);

        let files = read_within_limits(repo.path(), &mut plan, &inventory, None).expect("fits");

        assert_eq!(files.len(), 2);
        assert_eq!(files[0].contents.len(), 0);
        assert_eq!(files[1].contents.len(), 4 * 1024 * 1024);
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use crate::commands::ErrorKind;
    use crate::test_support::repository;
    use std::fs;

    #[test]
    fn npm_evidence_expansion_checks_limits_before_reading_members() {
        for (count, bytes, message) in [
            (255, 0, "256-file upload limit"),
            (1, api::MAX_FILE_BYTES + 1, "over the"),
            (2, 4_000_000, "upload would be about"),
        ] {
            assert_npm_expansion_limit(count, bytes, message);
        }
    }

    fn assert_npm_expansion_limit(count: usize, bytes: u64, message: &str) {
        let repo = repository(&[
            ("package-lock.json", "{}"),
            ("package.json", r#"{"workspaces":["packages/*"]}"#),
        ]);
        let mut paths = Vec::new();
        for index in 0..count {
            let path = repo
                .path()
                .join(format!("packages/member{index}/package.json"));
            fs::create_dir_all(path.parent().expect("parent")).expect("directory");
            fs::File::create(&path)
                .expect("file")
                .set_len(bytes)
                .expect("length");
            paths.push(path);
        }
        let inventory = discover::scan(repo.path()).expect("inventory");
        for path in paths {
            fs::remove_file(path).expect("remove before-read probe");
        }
        let mut plan = Plan::new(&inventory, None, false);
        let error = read_within_limits(repo.path(), &mut plan, &inventory, None)
            .expect_err("expanded limit precedes member read");
        assert_eq!(error.kind(), ErrorKind::Usage, "{error}");
        assert!(error.to_string().contains(message), "{error}");
    }

    #[test]
    fn cargo_evidence_selection_honors_inventory_and_member_policy() {
        const EXCLUDED: &str = "version=1\n[lockfiles]\ninclude=['Cargo.lock']\nmanifests=[]\nexclude=['crates/b/**']\n";
        const LISTED: &str = "version=1\n[lockfiles]\ninclude=['Cargo.lock']\nmanifests=['crates/b/Cargo.toml']\nexclude=['crates/b/**']\n";
        for (config, cli_excluded, include_b) in [
            (None, false, true),
            (Some(EXCLUDED), false, false),
            (Some(LISTED), false, true),
            (Some(LISTED), true, false),
        ] {
            assert_member_policy(config, cli_excluded, include_b);
        }
    }

    fn assert_member_policy(config: Option<&str>, cli_excluded: bool, include_b: bool) {
        let repo = repository(&[
            ("Cargo.lock", ""),
            ("Cargo.toml", "[workspace]\nmembers=['crates/**']\n"),
            ("crates/a/Cargo.toml", "[package]\nname='a'\n"),
            ("crates/b/Cargo.toml", "[package]\nname='b'\n"),
            ("crates/ignored/Cargo.toml", "[package]\nname='ignored'\n"),
            ("crates/.hidden/Cargo.toml", "[package]\nname='hidden'\n"),
            ("crates/locked/Cargo.lock", ""),
            ("crates/locked/Cargo.toml", "[workspace]\n"),
            (
                "crates/locked/child/Cargo.toml",
                "[package]\nname='child'\n",
            ),
            ("unrelated/Cargo.toml", "[package]\nname='unrelated'\n"),
            (".gitignore", "crates/ignored/\n"),
        ]);
        if let Some(config) = config {
            fs::write(repo.path().join("githits-scan.toml"), config).expect("configuration");
        }
        let mut exclude = vec!["crates/locked/Cargo.lock".into()];
        if cli_excluded {
            exclude.push("crates/b/**".into());
        }
        let options = Options {
            root: repo.path(),
            config: None,
            no_check: false,
            include_manifests: false,
            exclude: &exclude,
            progress: false,
        };
        let prepared = prepare(&options, &mut Vec::new(), Palette::PLAIN)
            .expect("preparation")
            .expect("upload");
        let paths: Vec<_> = prepared
            .upload
            .files()
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        let expected = if include_b {
            vec![
                "Cargo.lock",
                "Cargo.toml",
                "crates/a/Cargo.toml",
                "crates/b/Cargo.toml",
            ]
        } else {
            vec!["Cargo.lock", "Cargo.toml", "crates/a/Cargo.toml"]
        };
        assert_eq!(
            paths, expected,
            "config={config:?}, CLI exclude={cli_excluded}"
        );
    }

    #[test]
    fn cargo_evidence_expansion_checks_every_limit_before_reading_members() {
        for (count, bytes, message) in [
            (api::MAX_FILES - 1, 0, "256-file upload limit"),
            (1, api::MAX_FILE_BYTES + 1, "over the"),
            (2, 4_000_000, "upload would be about"),
        ] {
            assert_expansion_limit(count, bytes, message);
        }
    }

    fn assert_expansion_limit(count: usize, bytes: u64, message: &str) {
        let repo = repository(&[
            ("Cargo.lock", ""),
            ("Cargo.toml", "[workspace]\nmembers=['crates/*']\n"),
        ]);
        let mut paths = Vec::new();
        for index in 0..count {
            let path = repo.path().join(format!("crates/member{index}/Cargo.toml"));
            fs::create_dir_all(path.parent().expect("parent")).expect("directory");
            fs::File::create(&path)
                .expect("file")
                .set_len(bytes)
                .expect("length");
            paths.push(path);
        }
        let inventory = discover::scan(repo.path()).expect("inventory");
        // A member read would now fail with an execution error. Metadata admission
        // must instead reject the whole expansion with the corresponding usage error.
        for path in paths {
            fs::remove_file(path).expect("remove read probe");
        }
        let mut plan = Plan::new(&inventory, None, false);
        let error = read_within_limits(repo.path(), &mut plan, &inventory, None)
            .expect_err("expanded limit");
        assert_eq!(error.kind(), ErrorKind::Usage, "{error}");
        assert!(error.to_string().contains(message), "{error}");
    }
}
