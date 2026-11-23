//! Bounded, local observation of a selected Go module's package declarations.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use ignore::DirEntry;

use crate::catalog;

use super::{directory_of, relative_string, repository_walker};

const SOURCE_PREFIX_BYTES: u64 = 8_192;

/// Observe an unconditional production package main within one selected module.
pub(crate) fn has_main_package(
    root: &Path,
    manifest: &str,
    include_directory: impl Fn(&Path) -> bool + Send + Sync + 'static,
    include_file: impl Fn(&str) -> bool,
) -> bool {
    let module = root.join(directory_of(manifest));
    let scope = root.to_path_buf();
    let walker = repository_walker(&module)
        .filter_entry(move |entry| source_walk_entry(entry, &scope, &include_directory))
        .build();
    let mut packages = BTreeMap::<PathBuf, bool>::new();
    for entry in walker {
        let Ok(entry) = entry else {
            return false;
        };
        if entry.error().is_some() {
            return false;
        }
        if let Some((directory, main)) = observe_source(&entry, root, &include_file) {
            packages
                .entry(directory.into())
                .and_modify(|all_main| *all_main &= main)
                .or_insert(main);
        }
    }
    packages.into_values().any(|main| main)
}

fn source_walk_entry(
    entry: &DirEntry,
    root: &Path,
    include_directory: &impl Fn(&Path) -> bool,
) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_some_and(|kind| kind.is_dir()) {
        return true;
    }
    let Ok(relative) = entry.path().strip_prefix(root) else {
        return false;
    };
    entry.file_name().to_str().is_some_and(catalog::is_go_source_directory)
        && !catalog::is_excluded_directory(relative)
        && include_directory(relative)
        // Even an ignored or excluded go.mod is a module boundary.
        && fs::symlink_metadata(entry.path().join(catalog::GO_MANIFEST))
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
}

fn observe_source<'a>(
    entry: &'a DirEntry,
    root: &Path,
    include_file: &impl Fn(&str) -> bool,
) -> Option<(&'a Path, bool)> {
    if !entry.file_type().is_some_and(|kind| kind.is_file())
        || !entry
            .file_name()
            .to_str()
            .is_some_and(catalog::is_go_source)
    {
        return None;
    }
    let path = entry.path();
    let relative = relative_string(path.strip_prefix(root).ok()?).ok()?;
    if !include_file(&relative) {
        return None;
    }
    // A file with a build constraint cannot conflict with unconditional
    // observations. An unreadable or unrecognized eligible file can.
    let observation = read_prefix(path)
        .as_deref()
        .and_then(prefix_text)
        .map_or(Some(false), |(source, eof)| package_main(source, eof));
    Some((path.parent()?, observation?))
}

fn read_prefix(path: &Path) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(SOURCE_PREFIX_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

fn prefix_text(bytes: &[u8]) -> Option<(&str, bool)> {
    let eof = (bytes.len() as u64) < SOURCE_PREFIX_BYTES;
    match std::str::from_utf8(bytes) {
        Ok(source) => Some((source, eof)),
        // The byte bound can cut off a code point after a complete package clause.
        Err(error) if !eof && error.error_len().is_none() => {
            std::str::from_utf8(&bytes[..error.valid_up_to()])
                .ok()
                .map(|source| (source, false))
        }
        Err(_) => None,
    }
}

// None is a build-constrained source. False includes an ambiguous or missing clause.
fn package_main(source: &str, eof: bool) -> Option<bool> {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let code = leading_code(source)?;
    let Some(rest) = code.strip_prefix("package") else {
        return Some(false);
    };
    if !rest.starts_with([' ', '\t', '\r', '\n', '/']) {
        return Some(false);
    }
    Some(
        leading_code(rest)?
            .strip_prefix("main")
            .is_some_and(|rest| ends_package_clause(rest, eof)),
    )
}

fn leading_code(mut source: &str) -> Option<&str> {
    loop {
        source = source.trim_start_matches([' ', '\t', '\r', '\n']);
        if let Some(comment) = source.strip_prefix("//") {
            source = after_line_comment(comment)?;
        } else if let Some(comment) = source.strip_prefix("/*") {
            source = comment.split_once("*/").map_or("", |(_, rest)| rest);
        } else {
            return Some(source);
        }
    }
}

fn after_line_comment(line: &str) -> Option<&str> {
    let (comment, rest) = line.split_once('\n').unwrap_or((line, ""));
    (!comment.starts_with("go:build") && !comment.trim_start().starts_with("+build"))
        .then_some(rest)
}

fn ends_package_clause(mut rest: &str, eof: bool) -> bool {
    loop {
        rest = rest.trim_start_matches([' ', '\t', '\r']);
        if rest.is_empty() {
            return eof;
        }
        if rest.starts_with(['\n', ';']) || rest.starts_with("//") {
            return true;
        }
        let Some((comment, remaining)) = rest
            .strip_prefix("/*")
            .and_then(|comment| comment.split_once("*/"))
        else {
            return false;
        };
        if comment.contains('\n') {
            return true;
        }
        rest = remaining;
    }
}
