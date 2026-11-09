//! The validated upload: the one place that checks the service's limits.
//!
//! [`check_plan`] validates the initial metadata plan before reading contents,
//! then validates native evidence expansions and observed sizes before another
//! read. [`UploadSet::try_new`] validates the final actual contents, so the type
//! proves the request the HTTP client builds is within limits.

use std::fmt;

use thiserror::Error;

use super::{MAX_BODY_BYTES, MAX_FILE_BYTES, MAX_FILES, MAX_PATH_BYTES};

/// One file to upload: its repository-relative path and UTF-8 contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadFile {
    /// Forward-slash path relative to the scan root; the multipart filename.
    pub path: String,
    /// File contents. UTF-8 by construction, as the service requires.
    pub contents: String,
}

/// Files that passed every limit and path rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadSet {
    files: Vec<UploadFile>,
}

impl UploadSet {
    /// Validate `files` against the service's limits.
    ///
    /// # Errors
    ///
    /// Returns the first [`UploadError`] found, in the order: no files, too
    /// many files, an invalid path, a file over the size limit, a body over
    /// the size limit.
    pub fn try_new(files: Vec<UploadFile>) -> Result<Self, UploadError> {
        check_plan(
            files
                .iter()
                .map(|file| (file.path.as_str(), file.contents.len() as u64)),
        )?;
        Ok(Self { files })
    }

    /// The validated files, in the order given.
    #[must_use]
    pub fn files(&self) -> &[UploadFile] {
        &self.files
    }

    /// Consume the set for building the request body.
    #[must_use]
    pub fn into_files(self) -> Vec<UploadFile> {
        self.files
    }

    /// Number of files.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether the set is empty; never true for a validated set.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// Why a planned upload is outside the service's limits.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UploadError {
    /// Nothing was selected.
    #[error("nothing to upload")]
    NoFiles,
    /// Two file parts in the same side have the same logical path.
    #[error("duplicate upload filename: {}", path.escape_debug())]
    DuplicatePath {
        /// Repeated repository-relative path.
        path: String,
    },
    /// More files than one request may carry.
    #[error(
        "{count} files exceed the limit of {MAX_FILES} files per upload; use --exclude GLOB to omit unrelated projects, --lockfiles-only to skip manifest-only projects, or `githits-scan detect --save --exclude GLOB` to save a narrower inventory"
    )]
    TooManyFiles {
        /// Number of files selected.
        count: usize,
    },
    /// A path the service would reject as a filename.
    #[error("{} cannot be an upload filename: {reason}", path.escape_debug())]
    InvalidPath {
        /// The offending path.
        path: String,
        /// Which rule it breaks.
        reason: PathRule,
    },
    /// One file over the per-file limit.
    #[error("{} is {bytes} bytes, over the {MAX_FILE_BYTES}-byte limit per file", path.escape_debug())]
    FileTooLarge {
        /// The offending path.
        path: String,
        /// Its size.
        bytes: u64,
    },
    /// The multipart body would exceed the request limit.
    #[error(
        "the upload would be about {estimated} bytes, over the {MAX_BODY_BYTES}-byte limit; largest files: {}; scan a smaller tree",
        largest.iter().map(|value| value.escape_debug().to_string()).collect::<Vec<_>>().join(", ")
    )]
    BodyTooLarge {
        /// Estimated body size including multipart framing.
        estimated: u64,
        /// Up to three largest files as `path (bytes)`.
        largest: Vec<String>,
    },
}

/// Filename rules from the service's contract, plus one client rule.
///
/// The client rule rejects a double quote: the multipart `filename` attribute
/// is quote-delimited and the service is not documented to accept escapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRule {
    /// Empty path.
    Empty,
    /// Over `MAX_PATH_BYTES` UTF-8 bytes.
    TooLong,
    /// Starts with a slash.
    Absolute,
    /// Contains an empty segment (`a//b` or a trailing slash).
    EmptySegment,
    /// Contains a `.` segment.
    DotSegment,
    /// Contains a `..` segment.
    ParentSegment,
    /// Contains a backslash.
    Backslash,
    /// Contains an ASCII control character.
    ControlCharacter,
    /// Contains a double quote.
    Quote,
}

impl fmt::Display for PathRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "it is empty",
            Self::TooLong => "it is longer than 1,024 bytes",
            Self::Absolute => "it is absolute",
            Self::EmptySegment => "it contains an empty segment",
            Self::DotSegment => "it contains a `.` segment",
            Self::ParentSegment => "it contains a `..` segment",
            Self::Backslash => "it contains a backslash",
            Self::ControlCharacter => "it contains a control character",
            Self::Quote => "it contains a double quote",
        })
    }
}

/// Length of the boundary `reqwest` generates: four 16-digit hexadecimal
/// groups joined by dashes. A test in `tests/api_http.rs` checks the estimate
/// against the real `Content-Length`.
const BOUNDARY_BYTES: u64 = 67;
const PART_HEAD: &str = "Content-Disposition: form-data; name=\"files[]\"; filename=\"";
const PART_TYPE: &str = "\"\r\nContent-Type: application/octet-stream\r\n\r\n";

/// Bytes one part adds beyond its contents: boundary line, headers, and the
/// trailing line break.
const fn part_overhead(path: &str) -> u64 {
    named_part_overhead("files[]", path)
}

const fn named_part_overhead(field: &str, path: &str) -> u64 {
    2 + BOUNDARY_BYTES + 2 + PART_HEAD.len() as u64 - "files[]".len() as u64
        + field.len() as u64
        + path.len() as u64
        + PART_TYPE.len() as u64
        + 2
}

/// Multipart accounting shared by paired uploads and the single-side format.
pub(super) fn estimate_named_body<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a str, u64)>,
    text: Option<(&str, u64)>,
) -> u64 {
    let parts: u64 = entries
        .into_iter()
        .map(|(field, path, bytes)| named_part_overhead(field, path) + bytes)
        .sum();
    let text = text.map_or(0, |(field, bytes)| {
        2 + BOUNDARY_BYTES
            + 2
            + "Content-Disposition: form-data; name=\"\"\r\n\r\n".len() as u64
            + field.len() as u64
            + bytes
            + 2
    });
    parts + text + 2 + BOUNDARY_BYTES + 4
}

/// Estimated multipart body size for `(path, bytes)` entries.
#[must_use]
pub fn estimate_body<'a>(entries: impl IntoIterator<Item = (&'a str, u64)>) -> u64 {
    let parts: u64 = entries
        .into_iter()
        .map(|(path, bytes)| part_overhead(path) + bytes)
        .sum();
    parts + 2 + BOUNDARY_BYTES + 4
}

/// Validate `(path, bytes)` entries against every limit and path rule.
///
/// # Errors
///
/// Returns the first [`UploadError`] found; see [`UploadSet::try_new`] for
/// the order.
pub fn check_plan<'a>(
    entries: impl IntoIterator<Item = (&'a str, u64)>,
) -> Result<(), UploadError> {
    let entries: Vec<(&str, u64)> = entries.into_iter().collect();
    if entries.is_empty() {
        return Err(UploadError::NoFiles);
    }
    if entries.len() > MAX_FILES {
        return Err(UploadError::TooManyFiles {
            count: entries.len(),
        });
    }
    for &(path, bytes) in &entries {
        if let Err(reason) = check_path(path) {
            return Err(UploadError::InvalidPath {
                path: path.to_owned(),
                reason,
            });
        }
        if bytes > MAX_FILE_BYTES {
            return Err(UploadError::FileTooLarge {
                path: path.to_owned(),
                bytes,
            });
        }
    }
    let estimated = estimate_body(entries.iter().copied());
    if estimated > MAX_BODY_BYTES {
        let mut sorted = entries;
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        let largest = sorted
            .iter()
            .take(3)
            .map(|(path, bytes)| format!("{path} ({bytes} bytes)"))
            .collect();
        return Err(UploadError::BodyTooLarge { estimated, largest });
    }
    Ok(())
}

/// Check one path against the filename rules.
///
/// # Errors
///
/// Returns the first [`PathRule`] the path breaks.
pub fn check_path(path: &str) -> Result<(), PathRule> {
    if path.is_empty() {
        return Err(PathRule::Empty);
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(PathRule::TooLong);
    }
    if path.starts_with('/') {
        return Err(PathRule::Absolute);
    }
    if path.contains('\\') {
        return Err(PathRule::Backslash);
    }
    if path.chars().any(char::is_control) {
        return Err(PathRule::ControlCharacter);
    }
    if path.contains('"') {
        return Err(PathRule::Quote);
    }
    for segment in path.split('/') {
        match segment {
            "" => return Err(PathRule::EmptySegment),
            "." => return Err(PathRule::DotSegment),
            ".." => return Err(PathRule::ParentSegment),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_too_large(error: UploadError) -> Option<(u64, Vec<String>)> {
        match error {
            UploadError::BodyTooLarge { estimated, largest } => Some((estimated, largest)),
            _ => None,
        }
    }

    fn file(path: &str, bytes: usize) -> UploadFile {
        UploadFile {
            path: path.to_owned(),
            contents: "x".repeat(bytes),
        }
    }

    #[test]
    fn accepts_one_file_and_the_maximum_file_count() {
        let one = UploadSet::try_new(vec![file("Cargo.lock", 1)]).expect("one file");
        assert_eq!(one.len(), 1);
        assert!(!one.is_empty(), "expected a non-empty value");

        let files: Vec<_> = (0..MAX_FILES)
            .map(|i| file(&format!("p{i}/Cargo.lock"), 1))
            .collect();
        assert_eq!(UploadSet::try_new(files).expect("256 files").len(), 256);
    }

    #[test]
    fn rejects_no_files_and_one_file_too_many() {
        assert_eq!(
            UploadSet::try_new(vec![]).unwrap_err(),
            UploadError::NoFiles
        );

        let files: Vec<_> = (0..=MAX_FILES)
            .map(|i| file(&format!("p{i}/Cargo.lock"), 1))
            .collect();
        assert_eq!(
            UploadSet::try_new(files).unwrap_err(),
            UploadError::TooManyFiles { count: 257 }
        );
    }

    #[test]
    fn checks_the_per_file_limit_exactly() {
        let at_limit = usize::try_from(MAX_FILE_BYTES).expect("fits in usize");
        assert!(check_plan([("big.lock", MAX_FILE_BYTES)]).is_ok());
        assert_eq!(
            check_plan([("big.lock", MAX_FILE_BYTES + 1)]).unwrap_err(),
            UploadError::FileTooLarge {
                path: "big.lock".into(),
                bytes: MAX_FILE_BYTES + 1
            }
        );
        // The same rule applies to actual contents.
        assert!(UploadSet::try_new(vec![file("big.lock", at_limit)]).is_ok());
    }

    #[test]
    fn checks_the_body_limit_from_the_multipart_framing() {
        let single = ("Cargo.lock", 0);
        assert_eq!(
            estimate_body([single]),
            part_overhead("Cargo.lock") + 2 + 67 + 4
        );

        // Two files of 4 MiB each fit per file but not per body.
        let big = 4 * 1024 * 1024;
        let error =
            check_plan([("a/Cargo.lock", big), ("b/Cargo.lock", big), ("c.lock", 10)]).unwrap_err();
        let (estimated, largest) = body_too_large(error).expect("body too large");
        assert!(estimated > MAX_BODY_BYTES);
        assert_eq!(
            largest,
            [
                format!("a/Cargo.lock ({big} bytes)"),
                format!("b/Cargo.lock ({big} bytes)"),
                "c.lock (10 bytes)".to_owned()
            ]
        );

        // Exactly at the limit passes; one byte more fails. Two files keep
        // each under the per-file limit.
        let room = MAX_BODY_BYTES - estimate_body([("x", 0), ("y", 0)]);
        let (first, second) = (room / 2, room - room / 2);
        assert!(check_plan([("x", first), ("y", second)]).is_ok());
        assert!(matches!(
            check_plan([("x", first), ("y", second + 1)]),
            Err(UploadError::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn enforces_every_path_rule() {
        let long = "a".repeat(MAX_PATH_BYTES);
        assert!(check_path(&long).is_ok());
        let too_long = format!("{long}b");
        let cases = [
            ("", PathRule::Empty),
            (too_long.as_str(), PathRule::TooLong),
            ("/abs/Cargo.lock", PathRule::Absolute),
            ("a//Cargo.lock", PathRule::EmptySegment),
            ("a/Cargo.lock/", PathRule::EmptySegment),
            ("./Cargo.lock", PathRule::DotSegment),
            ("a/../Cargo.lock", PathRule::ParentSegment),
            ("a\\Cargo.lock", PathRule::Backslash),
            ("a\u{7}/Cargo.lock", PathRule::ControlCharacter),
            ("a\n/Cargo.lock", PathRule::ControlCharacter),
            ("we\"ird/Cargo.lock", PathRule::Quote),
        ];
        for (path, rule) in cases {
            assert_eq!(check_path(path), Err(rule), "{path:?}");
        }
        assert_eq!(
            check_plan([("../Cargo.lock", 1)]).unwrap_err(),
            UploadError::InvalidPath {
                path: "../Cargo.lock".into(),
                reason: PathRule::ParentSegment
            }
        );
        assert!(check_path("résumé/Cargo.lock").is_ok());
        assert!(check_path("with space/Cargo.lock").is_ok());
    }
}
