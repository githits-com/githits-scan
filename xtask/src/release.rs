//! Canonical release policy over the root manifest, lockfile, fragments and changelog.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command as Git,
};

use clap::Subcommand;
use toml_edit::{DocumentMut, value};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
/// Invalid release input or a filesystem/process failure.
#[expect(
    clippy::redundant_pub_crate,
    reason = "parent-only binary boundary; Rust unreachable_pub rejects broader visibility"
)]
pub(super) enum Error {
    /// A release policy invariant did not hold.
    #[error("{0}")]
    Invalid(String),
    /// Reading, writing, or launching Git failed.
    #[error("{path}: {source}")]
    Io {
        /// The affected repository path.
        path: PathBuf,
        /// The underlying operating-system error.
        source: std::io::Error,
    },
}

#[derive(Subcommand)]
/// Maintainer operations over one repository.
#[expect(
    clippy::redundant_pub_crate,
    reason = "parent-only binary boundary; Rust unreachable_pub rejects broader visibility"
)]
pub(super) enum Command {
    /// Print the root application's version.
    Version,
    /// Validate fragments and manifest/lock consistency; enforce release invariants on a bump.
    Audit {
        /// Require consolidated notes and no pending fragments.
        #[arg(long)]
        release: bool,
        /// Compare the root version to this Git ref (CI uses the tested commit's first parent).
        #[arg(long)]
        base_ref: Option<String>,
    },
    /// Consume fragments, bump root versions and insert a dated changelog entry.
    Prepare {
        /// UTC release date, YYYY-MM-DD.
        #[arg(long)]
        date: String,
    },
    /// Print the current version's changelog section, or unreleased fragments.
    Notes {
        /// Render pending fragments for a development rehearsal.
        #[arg(long)]
        unreleased: bool,
    },
    /// Require a complete release commit that belongs to origin/main.
    VerifyMain,
    /// Require an actual tag pointing at this complete release commit on origin/main.
    VerifyTag {
        /// Stable version tag, vX.Y.Z.
        #[arg(long)]
        tag: String,
    },
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.into(),
        source,
    })
}

fn document(text: &str, label: &str) -> Result<DocumentMut> {
    text.parse()
        .map_err(|_| invalid(format!("invalid TOML in {label}")))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Version(u64, u64, u64);

impl Version {
    fn parse(text: &str) -> Result<Self> {
        let parts = text.split('.').collect::<Vec<_>>();
        if parts.len() != 3
            || parts.iter().any(|s| {
                s.is_empty()
                    || (s.len() > 1 && s.starts_with('0'))
                    || !s.bytes().all(|b| b.is_ascii_digit())
            })
        {
            return Err(invalid(
                "version must be stable X.Y.Z without leading zeros",
            ));
        }
        let numbers = parts
            .iter()
            .map(|s| {
                s.parse::<u64>()
                    .map_err(|_| invalid("version component overflow"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self(numbers[0], numbers[1], numbers[2]))
    }

    fn bump(self, impact: Impact) -> Result<Self> {
        let next = |n: u64| {
            n.checked_add(1)
                .ok_or_else(|| invalid("version component overflow"))
        };
        match impact {
            Impact::None => Err(invalid("no release: fragments have no version impact")),
            Impact::Patch => Ok(Self(self.0, self.1, next(self.2)?)),
            Impact::Minor => Ok(Self(self.0, next(self.1)?, 0)),
            Impact::Major if self.0 == 0 => Ok(Self(0, next(self.1)?, 0)),
            Impact::Major => Ok(Self(next(self.0)?, 0, 0)),
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Impact {
    None,
    Patch,
    Minor,
    Major,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Category {
    Added,
    Changed,
    Deprecated,
    Removed,
    Fixed,
    Security,
}

impl Category {
    const ALL: [Self; 6] = [
        Self::Added,
        Self::Changed,
        Self::Deprecated,
        Self::Removed,
        Self::Fixed,
        Self::Security,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Added => "Added",
            Self::Changed => "Changed",
            Self::Deprecated => "Deprecated",
            Self::Removed => "Removed",
            Self::Fixed => "Fixed",
            Self::Security => "Security",
        }
    }
}

struct Fragment {
    path: PathBuf,
    category: Category,
    impact: Impact,
    body: String,
}

fn fragment(path: PathBuf) -> Result<Fragment> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| invalid("fragment filename is not UTF-8"))?;
    let Some((slug, category)) = name.strip_suffix(".md").and_then(|s| s.rsplit_once('.')) else {
        return Err(invalid(format!("invalid fragment filename: {name}")));
    };
    if slug.is_empty()
        || !slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(invalid(format!("invalid fragment slug: {name}")));
    }
    let category = Category::ALL
        .into_iter()
        .find(|c| c.name().to_ascii_lowercase() == category)
        .ok_or_else(|| invalid(format!("unknown fragment category: {name}")))?;
    let text = read(&path)?;
    let normalized = text.replace("\r\n", "\n");
    let Some(rest) = normalized.strip_prefix("---\n") else {
        return Err(invalid(format!("missing frontmatter: {name}")));
    };
    let Some((header, body)) = rest.split_once("\n---\n") else {
        return Err(invalid(format!("invalid frontmatter: {name}")));
    };
    let impact = match header {
        "\"githits-scan\": none" => Impact::None,
        "\"githits-scan\": patch" => Impact::Patch,
        "\"githits-scan\": minor" => Impact::Minor,
        "\"githits-scan\": major" => Impact::Major,
        _ => return Err(invalid(format!("invalid package or impact: {name}"))),
    };
    let body = body.trim();
    let mut lines = body.lines();
    let first = lines
        .next()
        .ok_or_else(|| invalid(format!("empty fragment: {name}")))?;
    let valid_first = first
        .strip_prefix("- **")
        .and_then(|s| s.split_once("** - "))
        .is_some_and(|(title, description)| {
            !title.trim().is_empty() && !description.trim().is_empty()
        });
    if !valid_first || lines.any(|line| !line.is_empty() && !line.starts_with("  ")) {
        return Err(invalid(format!(
            "fragment must contain one titled bullet with indented continuations: {name}"
        )));
    }
    Ok(Fragment {
        path,
        category,
        impact,
        body: body.into(),
    })
}

fn fragments(root: &Path) -> Result<Vec<Fragment>> {
    let directory = root.join("changes");
    let entries = fs::read_dir(&directory).map_err(|source| Error::Io {
        path: directory,
        source,
    })?;
    let mut paths = entries
        .map(|e| {
            e.map(|e| e.path()).map_err(|source| Error::Io {
                path: root.join("changes"),
                source,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    paths.sort();
    paths
        .into_iter()
        .filter(|p| p.file_name().is_none_or(|n| n != "README.md"))
        .map(fragment)
        .collect()
}

fn render(fragments: &[Fragment]) -> String {
    let mut output = String::new();
    for category in Category::ALL {
        let entries = fragments
            .iter()
            .filter(|f| f.category == category)
            .collect::<Vec<_>>();
        if entries.is_empty() {
            continue;
        }
        output.push_str("### ");
        output.push_str(category.name());
        output.push_str("\n\n");
        for entry in entries {
            output.push_str(&entry.body);
            output.push('\n');
        }
        output.push('\n');
    }
    output
}

fn manifest_version(manifest: &DocumentMut) -> Result<Version> {
    let package = manifest
        .get("package")
        .and_then(toml_edit::Item::as_table_like)
        .ok_or_else(|| invalid("missing root package table"))?;
    if package.get("name").and_then(toml_edit::Item::as_str) != Some("githits-scan") {
        return Err(invalid("root manifest must be the githits-scan package"));
    }
    Version::parse(
        package
            .get("version")
            .and_then(toml_edit::Item::as_str)
            .ok_or_else(|| invalid("missing root package version"))?,
    )
}

fn valid_date(date: &str) -> bool {
    let bytes = date.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(i, b)| i != 4 && i != 7 && !b.is_ascii_digit())
    {
        return false;
    }
    let Ok(year) = date[..4].parse::<u32>() else {
        return false;
    };
    let Ok(month) = date[5..7].parse::<usize>() else {
        return false;
    };
    let Ok(day) = date[8..].parse::<u32>() else {
        return false;
    };
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    year > 0 && month > 0 && month <= 12 && day > 0 && day <= days[month - 1]
}

struct Snapshot {
    manifest: DocumentMut,
    lock: DocumentMut,
    lock_index: usize,
    version: Version,
    changelog: String,
    fragments: Vec<Fragment>,
}

impl Snapshot {
    fn load(root: &Path) -> Result<Self> {
        let manifest = document(&read(&root.join("Cargo.toml"))?, "Cargo.toml")?;
        let version = manifest_version(&manifest)?;
        let lock = document(&read(&root.join("Cargo.lock"))?, "Cargo.lock")?;
        let packages = lock
            .get("package")
            .and_then(toml_edit::Item::as_array_of_tables)
            .ok_or_else(|| invalid("missing Cargo.lock packages"))?;
        let indices = packages
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                p.get("name").and_then(toml_edit::Item::as_str) == Some("githits-scan")
            })
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        let [lock_index] = indices.as_slice() else {
            return Err(invalid(
                "Cargo.lock must contain exactly one githits-scan package",
            ));
        };
        let package = packages
            .get(*lock_index)
            .ok_or_else(|| invalid("missing root lock package"))?;
        if package.get("version").and_then(toml_edit::Item::as_str)
            != Some(version.to_string().as_str())
        {
            return Err(invalid("Cargo.toml and Cargo.lock root versions differ"));
        }
        let changelog = read(&root.join("CHANGELOG.md"))?;
        sections(&changelog)?;
        Ok(Self {
            manifest,
            lock,
            lock_index: *lock_index,
            version,
            changelog,
            fragments: fragments(root)?,
        })
    }

    fn release_notes(&self) -> Result<String> {
        if !self.fragments.is_empty() {
            return Err(invalid("release has unconsumed fragments"));
        }
        sections(&self.changelog)?
            .into_iter()
            .find(|(version, _)| *version == self.version)
            .map(|(_, body)| body.to_owned())
            .ok_or_else(|| invalid("current version has no dated changelog section"))
    }

    fn prepare(mut self, root: &Path, date: &str) -> Result<String> {
        if !valid_date(date) {
            return Err(invalid("release date must be a valid YYYY-MM-DD"));
        }
        let impact = self
            .fragments
            .iter()
            .map(|f| f.impact)
            .max()
            .unwrap_or(Impact::None);
        let version = self.version.bump(impact)?;
        if sections(&self.changelog)?
            .iter()
            .any(|(v, _)| *v == version)
        {
            return Err(invalid("next version already exists in CHANGELOG.md"));
        }
        let section = format!("## [{version}] - {date}\n\n{}", render(&self.fragments));
        let insertion = self
            .changelog
            .find("\n## [")
            .map_or(self.changelog.len(), |i| i + 1);
        let prefix = self.changelog[..insertion].trim_end();
        let suffix = &self.changelog[insertion..];
        let section = if suffix.is_empty() {
            format!("{}\n", section.trim_end())
        } else {
            section
        };
        self.changelog = format!("{prefix}\n\n{section}{suffix}");
        self.manifest["package"]["version"] = value(version.to_string());
        let packages = self.lock["package"]
            .as_array_of_tables_mut()
            .ok_or_else(|| invalid("missing Cargo.lock packages"))?;
        let package = packages
            .get_mut(self.lock_index)
            .ok_or_else(|| invalid("missing root lock package"))?;
        package["version"] = value(version.to_string());
        // All content is validated before the first mutation. I/O errors leave a
        // reviewable partial diff; no hidden rollback or fragment recovery state.
        write(&root.join("Cargo.toml"), &self.manifest.to_string())?;
        write(&root.join("Cargo.lock"), &self.lock.to_string())?;
        write(&root.join("CHANGELOG.md"), &self.changelog)?;
        for fragment in self.fragments {
            fs::remove_file(&fragment.path).map_err(|source| Error::Io {
                path: fragment.path,
                source,
            })?;
        }
        Ok(format!("Prepared v{version}\n"))
    }
}

fn write(path: &Path, text: &str) -> Result<()> {
    fs::write(path, text).map_err(|source| Error::Io {
        path: path.into(),
        source,
    })
}

fn sections(changelog: &str) -> Result<Vec<(Version, &str)>> {
    let mut headings = Vec::new();
    let mut offset = 0;
    for line in changelog.split_inclusive('\n') {
        let position = offset;
        offset += line.len();
        let Some(rest) = line.trim_end().strip_prefix("## [") else {
            continue;
        };
        let (version, date) = rest
            .split_once("] - ")
            .ok_or_else(|| invalid("invalid changelog heading"))?;
        let version = Version::parse(version)?;
        if !valid_date(date) || headings.iter().any(|(v, _, _)| *v == version) {
            return Err(invalid("invalid date or duplicate changelog version"));
        }
        headings.push((version, position, offset));
    }
    headings
        .iter()
        .enumerate()
        .map(|(i, (version, _, start))| {
            let end = headings
                .get(i + 1)
                .map_or(changelog.len(), |(_, position, _)| *position);
            let body = changelog[*start..end].trim();
            if body.is_empty() {
                return Err(invalid("empty changelog version section"));
            }
            Ok((*version, body))
        })
        .collect()
}

fn git(root: &Path, arguments: &[&str]) -> Result<String> {
    let output = Git::new("git")
        .current_dir(root)
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_DIR")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .args(arguments)
        .output()
        .map_err(|source| Error::Io {
            path: root.into(),
            source,
        })?;
    if !output.status.success() {
        return Err(git_failure(arguments, output.status.code()));
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().into())
        .map_err(|_| invalid("Git output is not UTF-8"))
}

fn git_failure(arguments: &[&str], status: Option<i32>) -> Error {
    // Authored diagnostics preserve context without echoing Git's stderr or
    // configuration, which this tool does not own or credential-audit.
    match arguments {
        ["merge-base", "--is-ancestor", ..] if status == Some(1) => {
            invalid("release commit does not belong to origin/main")
        }
        ["merge-base", ..] => {
            invalid("cannot verify main membership; fetch full history including origin/main")
        }
        ["rev-parse", "--verify", ..] => {
            invalid("release tag is missing or invalid; fetch the actual version tag")
        }
        ["show", ..] => {
            invalid("comparison ref is unavailable; fetch the tested commit's first parent")
        }
        _ => invalid("Git command failed"),
    }
}

/// The base ref's `Cargo.toml`, or `None` when HEAD is the repository's root
/// commit in a complete checkout: a first commit has no earlier version to
/// compare. A shallow checkout keeps the error, so a parent that was simply not
/// fetched is never mistaken for a root commit.
fn base_manifest(root: &Path, reference: &str) -> Result<Option<String>> {
    let error = match git(root, &["show", &format!("{reference}:Cargo.toml")]) {
        Ok(previous) => return Ok(Some(previous)),
        Err(error) => error,
    };
    let shallow = git(root, &["rev-parse", "--is-shallow-repository"])? == "true";
    let commit_and_parents = git(root, &["rev-list", "--parents", "-n", "1", "HEAD"])?;
    if shallow || commit_and_parents.split_whitespace().count() > 1 {
        return Err(error);
    }
    Ok(None)
}

fn verify_main(root: &Path, snapshot: &Snapshot) -> Result<()> {
    snapshot.release_notes()?;
    git(
        root,
        &["merge-base", "--is-ancestor", "HEAD", "origin/main"],
    )?;
    Ok(())
}

/// Execute an operation and return its stdout document or status line.
///
/// # Errors
/// Returns an error for malformed inputs, inconsistent release metadata, failed
/// Git verification, or filesystem failures. Preparation validates before writes.
#[expect(
    clippy::redundant_pub_crate,
    reason = "parent-only binary boundary; Rust unreachable_pub rejects broader visibility"
)]
pub(super) fn run(root: &Path, command: Command) -> Result<String> {
    let snapshot = Snapshot::load(root)?;
    match command {
        Command::Version => Ok(format!("{}\n", snapshot.version)),
        Command::Prepare { date } => snapshot.prepare(root, &date),
        Command::Notes { unreleased: true } => Ok(render(&snapshot.fragments)),
        Command::Notes { unreleased: false } => Ok(format!("{}\n", snapshot.release_notes()?)),
        Command::Audit { release, base_ref } => {
            let changed = match base_ref {
                Some(reference) => match base_manifest(root, &reference)? {
                    Some(previous) => {
                        manifest_version(&document(&previous, "base Cargo.toml")?)?
                            != snapshot.version
                    }
                    None => false,
                },
                None => false,
            };
            if release || changed {
                snapshot.release_notes()?;
            }
            Ok("Release audit passed\n".into())
        }
        Command::VerifyMain => {
            verify_main(root, &snapshot)?;
            Ok("Release commit belongs to main\n".into())
        }
        Command::VerifyTag { tag } => {
            if tag != format!("v{}", snapshot.version) {
                return Err(invalid("tag must match the root package version"));
            }
            let tagged = git(
                root,
                &[
                    "rev-parse",
                    "--verify",
                    &format!("refs/tags/{tag}^{{commit}}"),
                ],
            )?;
            if tagged != git(root, &["rev-parse", "HEAD"])? {
                return Err(invalid("release tag does not point at HEAD"));
            }
            verify_main(root, &snapshot)?;
            Ok("Release tag verified\n".into())
        }
    }
}

#[cfg(test)]
mod tests;
