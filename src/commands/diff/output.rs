//! Diff-only destination selection and preflight; shared writers own file writes.
use super::{Error, Format, Output, sbom};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub(super) fn reports(output: &Output) -> impl Iterator<Item = (Format, &sbom::Output)> {
    let reports = match output {
        Output::Single {
            format,
            destination,
        } => [Some((*format, destination)), None],
        Output::JsonAndMarkdown { json, markdown } => [
            Some((Format::Json, json)),
            Some((Format::Markdown, markdown)),
        ],
    };
    reports.into_iter().flatten()
}

pub(super) fn validate(output: &Output) -> Result<(), Error> {
    let Output::JsonAndMarkdown { json, markdown } = output else {
        return Ok(());
    };
    match (json, markdown) {
        (sbom::Output::Stdout, sbom::Output::Stdout) => Err(Error::DiffOutputConflict),
        (sbom::Output::File(a), sbom::Output::File(b)) => {
            let a = destination(a)?;
            let b = destination(b)?;
            if a == b {
                return Err(Error::DiffOutputConflict);
            }
            #[cfg(unix)]
            if hardlink_alias(&a, &b)? {
                return Err(Error::DiffOutputConflict);
            }
            Ok(())
        }
        (sbom::Output::File(path), _) | (_, sbom::Output::File(path)) => {
            destination(path).map(|_| ())
        }
    }
}

fn output_error(path: &Path, source: io::Error) -> Error {
    Error::OutputFile {
        path: path.to_path_buf(),
        source,
    }
}

/// Resolve existing aliases without opening or truncating any output.
fn destination(path: &Path) -> Result<PathBuf, Error> {
    match fs::canonicalize(path) {
        Ok(resolved) => {
            let metadata = fs::metadata(&resolved).map_err(|e| output_error(path, e))?;
            if metadata.is_dir() {
                return Err(output_error(
                    path,
                    io::Error::from(io::ErrorKind::IsADirectory),
                ));
            }
            Ok(resolved)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A dangling symlink cannot safely be compared by its own filename.
            if fs::symlink_metadata(path).is_ok() {
                return Err(output_error(path, error));
            }
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let parent = fs::canonicalize(parent).map_err(|e| output_error(path, e))?;
            let name = path.file_name().ok_or_else(|| output_error(path, error))?;
            Ok(parent.join(name))
        }
        Err(error) => Err(output_error(path, error)),
    }
}

#[cfg(unix)]
fn hardlink_alias(a: &Path, b: &Path) -> Result<bool, Error> {
    use std::os::unix::fs::MetadataExt;
    let metadata = |path| match fs::metadata(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(output_error(path, error)),
    };
    let (Some(a), Some(b)) = (metadata(a)?, metadata(b)?) else {
        return Ok(false);
    };
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}
