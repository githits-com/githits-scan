//! Immutable Git enumeration and bounded package-evidence reads for dependency diff.
use std::collections::BTreeMap;
use std::io::{self, BufRead as _, BufReader, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use thiserror::Error;

use crate::{api, catalog, config, discover};

/// Failure to obtain an immutable repository input; raw Git diagnostics are never displayed.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid repository state or revision.
    #[error("{0}")]
    Input(&'static str),
    /// Local process or file I/O failed.
    #[error(
        "cannot read Git package evidence; ensure Git is installed and objects are available locally"
    )]
    Io(#[from] io::Error),
    /// A required object is unavailable, including missing partial-clone blobs.
    #[error(
        "Git object unavailable locally; fetch the required revision and package blobs before diffing"
    )]
    Object,
    /// Invalid upload path or size.
    #[error(transparent)]
    Upload(#[from] api::UploadError),
    /// Filesystem evidence could not be read.
    #[error(transparent)]
    Discover(#[from] discover::DiscoverError),
}

pub(crate) struct Snapshot {
    root: PathBuf,
    pub label: String,
    pub files: BTreeMap<String, u64>,
    blobs: BTreeMap<String, String>,
    pub has_config: bool,
    excluded: globset::GlobSet,
}

impl Snapshot {
    pub(crate) fn open(
        root: &Path,
        revision: Option<&str>,
        excluded: &globset::GlobSet,
    ) -> Result<Self, Error> {
        let prefix = capture(root, &["rev-parse", "--show-prefix"], api::MAX_PATH_BYTES).map_err(
            |error| match error {
                Error::Object => Error::Input("diff PATH must be a readable Git repository root"),
                error => error,
            },
        )?;
        if !prefix.iter().all(u8::is_ascii_whitespace) {
            return Err(Error::Input(
                "diff PATH must be a readable Git repository root",
            ));
        }
        let mut snapshot = Self {
            root: root.to_path_buf(),
            label: "working-tree".into(),
            files: BTreeMap::new(),
            blobs: BTreeMap::new(),
            has_config: false,
            excluded: excluded.clone(),
        };
        if let Some(revision) = revision {
            let commit = capture(
                root,
                &[
                    "rev-parse",
                    "--verify",
                    "--end-of-options",
                    &format!("{revision}^{{commit}}"),
                ],
                128,
            )
            .map_err(|_| Error::Input("cannot resolve Git revision to a local commit"))?;
            String::from_utf8(commit)
                .map_err(|_| Error::Object)?
                .trim()
                .clone_into(&mut snapshot.label);
            records(
                root,
                &["ls-tree", "-r", "-z", &snapshot.label.clone()],
                |record| snapshot.tree_entry(record),
            )?;
            snapshot.size_blobs()?;
        } else {
            records(
                root,
                &[
                    "ls-files",
                    "-t",
                    "-c",
                    "-o",
                    "--deduplicate",
                    "--exclude-standard",
                    "-z",
                ],
                |record| snapshot.working_entry(record),
            )?;
        }
        Ok(snapshot)
    }

    fn eligible(&mut self, path: &str) -> bool {
        if path == config::FILE_NAME {
            self.has_config = true;
        }
        if config::is_default_excluded(path) || self.excluded.is_match(path) {
            return false;
        }
        if path.split('/').any(|part| part.starts_with('.')) {
            return false;
        }
        let path = Path::new(path);
        catalog::classify(path).is_some() || catalog::unsupported_hint(path).is_some()
    }

    fn tree_entry(&mut self, record: &str) -> Result<(), Error> {
        let (header, path) = record.split_once('\t').ok_or(Error::Object)?;
        let mut fields = header.split_whitespace();
        let mode = fields.next().ok_or(Error::Object)?;
        let kind = fields.next().ok_or(Error::Object)?;
        let oid = fields.next().ok_or(Error::Object)?;
        if !matches!(mode, "100644" | "100755") || kind != "blob" || !self.eligible(path) {
            return Ok(());
        }
        api::upload::check_path(path).map_err(|reason| api::UploadError::InvalidPath {
            path: path.into(),
            reason,
        })?;
        self.files.insert(path.into(), 0);
        if catalog::classify(Path::new(path)).is_none() {
            return Ok(());
        }
        self.blobs.insert(path.into(), oid.into());
        Ok(())
    }

    fn size_blobs(&mut self) -> Result<(), Error> {
        let entries: Vec<_> = self.blobs.iter().collect();
        // Each batch's input and maximum metadata output fit below a 4 KiB pipe,
        // so writing before reading cannot deadlock on supported platforms.
        for chunk in entries.chunks(32) {
            let mut child = git(&self.root, &["cat-file", "--batch-check"])
                .stdin(Stdio::piped())
                .spawn()?;
            let mut input = child.stdin.take().ok_or(Error::Object)?;
            let written = chunk
                .iter()
                .try_for_each(|(_, oid)| writeln!(input, "{oid}"));
            drop(input);
            let result = collect(&mut child, 4096);
            written?;
            let bytes = result?;
            apply_sizes(&mut self.files, chunk, &bytes)?;
        }
        Ok(())
    }

    fn working_entry(&mut self, record: &str) -> Result<(), Error> {
        if record.starts_with("S ") {
            return Err(Error::Input(
                "sparse working tree cannot be compared; pass --head HEAD",
            ));
        }
        if record.starts_with("M ") {
            return Err(Error::Input(
                "resolve unmerged Git paths before comparing the working tree",
            ));
        }
        let path = record.get(2..).ok_or(Error::Object)?;
        if path.ends_with('/') || !self.eligible(path) {
            return Ok(());
        }
        api::upload::check_path(path).map_err(|reason| api::UploadError::InvalidPath {
            path: path.into(),
            reason,
        })?;
        let Some(bytes) = regular_file(&self.root, path)? else {
            return Ok(());
        };
        self.files.insert(path.into(), bytes);
        Ok(())
    }

    pub(crate) fn read(&self, path: &str) -> Result<String, Error> {
        let Some(oid) = self.blobs.get(path) else {
            return self.read_working(path);
        };
        let bytes = capture(
            &self.root,
            &["cat-file", "blob", oid],
            usize::try_from(api::MAX_FILE_BYTES).map_err(|_| Error::Object)?,
        )?;
        String::from_utf8(bytes)
            .map_err(|_| discover::DiscoverError::NotUtf8 { path: path.into() }.into())
    }
    fn read_working(&self, path: &str) -> Result<String, Error> {
        if regular_file(&self.root, path)?.is_none() {
            return Err(Error::Input(
                "selected working-tree file is no longer a regular file",
            ));
        }
        Ok(discover::read_file(&self.root, path, api::MAX_FILE_BYTES)?)
    }
}

fn apply_sizes(
    files: &mut BTreeMap<String, u64>,
    entries: &[(&String, &String)],
    bytes: &[u8],
) -> Result<(), Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Object)?;
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != entries.len() {
        return Err(Error::Object);
    }
    for ((path, oid), line) in entries.iter().zip(lines) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 3 || fields[0] != *oid || fields[1] != "blob" {
            return Err(Error::Object);
        }
        files.insert(
            (*path).clone(),
            fields[2].parse().map_err(|_| Error::Object)?,
        );
    }
    Ok(())
}

fn regular_file(root: &Path, relative: &str) -> Result<Option<u64>, Error> {
    let mut path = root.to_path_buf();
    for part in Path::new(relative).components() {
        path.push(part);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(Error::Io(error)),
        };
        if metadata.is_symlink() {
            return Ok(None);
        }
    }
    let metadata = std::fs::metadata(path)?;
    Ok(metadata.is_file().then_some(metadata.len()))
}

fn git(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command
        .args(["--no-replace-objects", "-c", "core.fsmonitor=false", "-C"])
        .arg(root)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_remove("GITHITS_API_TOKEN")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ] {
        command.env_remove(name);
    }
    command
}

fn capture(root: &Path, args: &[&str], limit: usize) -> Result<Vec<u8>, Error> {
    let mut child = git(root, args).spawn()?;
    collect(&mut child, limit)
}

fn collect(child: &mut std::process::Child, limit: usize) -> Result<Vec<u8>, Error> {
    let result = (|| {
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .ok_or(Error::Object)?
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(Error::Input("Git evidence exceeds its bounded read limit"));
        }
        Ok(bytes)
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(Error::Object);
    }
    result
}

fn records(
    root: &Path,
    args: &[&str],
    mut visit: impl FnMut(&str) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut child = git(root, args).spawn()?;
    let result = child
        .stdout
        .take()
        .ok_or(Error::Object)
        .and_then(|stdout| visit_records(BufReader::new(stdout), &mut visit));
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    result?;
    if !status.success() {
        return Err(Error::Input(
            "cannot enumerate Git repository; ensure PATH is a readable root",
        ));
    }
    Ok(())
}

fn visit_records(
    mut reader: impl io::BufRead,
    visit: &mut impl FnMut(&str) -> Result<(), Error>,
) -> Result<(), Error> {
    loop {
        let mut record = Vec::new();
        let count = reader
            .by_ref()
            .take((api::MAX_PATH_BYTES + 256) as u64)
            .read_until(0, &mut record)?;
        if count == 0 {
            return Ok(());
        }
        if record.pop() != Some(0) {
            return Err(Error::Input("Git path exceeds its bounded metadata limit"));
        }
        visit_record(&record, visit)?;
    }
}

fn visit_record(
    record: &[u8],
    visit: &mut impl FnMut(&str) -> Result<(), Error>,
) -> Result<(), Error> {
    let Ok(text) = std::str::from_utf8(record) else {
        let lossy = String::from_utf8_lossy(record);
        let path = lossy
            .split_once('\t')
            .map_or_else(|| lossy.get(2..).unwrap_or_default(), |(_, path)| path);
        if catalog::classify(Path::new(path)).is_some()
            || catalog::unsupported_hint(Path::new(path)).is_some()
        {
            return Err(Error::Input("Git package path is not UTF-8"));
        }
        return Ok(());
    };
    visit(text)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_non_utf8_records_ignore_unrelated_names_but_reject_package_paths() {
        let mut visited = Vec::new();
        visit_record(b"100644 blob abc\todd\xff.bin", &mut |text| {
            visited.push(text.to_owned());
            Ok(())
        })
        .expect("unrelated");
        assert_eq!(visited.len(), 0);
        let error = visit_record(b"100644 blob abc\todd\xff/Cargo.lock", &mut |_| Ok(()))
            .expect_err("package path");
        assert!(matches!(
            error,
            Error::Input("Git package path is not UTF-8")
        ));
    }
}
