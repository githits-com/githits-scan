//! The two side namespaces and required request controls form one bounded upload.
use std::collections::BTreeSet;

use super::super::{MAX_BODY_BYTES, MAX_FILES, UploadError, UploadSet, upload};

/// How the service handles selected manifests without recorded lock evidence.
#[derive(Debug, Clone, Copy)]
pub enum UnlockedManifests {
    /// Resolve selected manifest-only projects.
    Resolve,
    /// Retain only recorded evidence without solving manifests.
    RecordedOnly,
}

/// Validated paired files; absent sets represent explicit empty sides.
pub struct Input {
    pub(in crate::api) base: Option<UploadSet>,
    pub(in crate::api) head: Option<UploadSet>,
    pub(in crate::api) request: String,
}

impl Input {
    /// Validate aggregate limits and per-side uniqueness before credentials or HTTP.
    ///
    /// # Errors
    /// Returns the existing upload error for excessive input or duplicate filenames.
    pub fn try_new(
        base: Option<UploadSet>,
        head: Option<UploadSet>,
        mode: UnlockedManifests,
    ) -> Result<Self, UploadError> {
        let count =
            base.as_ref().map_or(0, UploadSet::len) + head.as_ref().map_or(0, UploadSet::len);
        if count > MAX_FILES {
            return Err(UploadError::TooManyFiles { count });
        }
        unique_paths(base.as_ref())?;
        unique_paths(head.as_ref())?;
        let request = serde_json::json!({
            "schema_version":1,
            "base":{"state":if base.is_some() {"supplied"} else {"empty"}},
            "head":{"state":if head.is_some() {"supplied"} else {"empty"}},
            "selection":{"groups":["all"],"unlocked_manifests":match mode {
                UnlockedManifests::Resolve=>"resolve", UnlockedManifests::RecordedOnly=>"recorded_only"}},
            "analysis":{"advisories":true,"direct_reviews":true}
        }).to_string();
        let input = Self {
            base,
            head,
            request,
        };
        let estimated = input.body_bytes();
        if estimated > MAX_BODY_BYTES {
            return Err(UploadError::BodyTooLarge {
                estimated,
                largest: input.largest_files(),
            });
        }
        Ok(input)
    }

    pub(super) fn body_bytes(&self) -> u64 {
        upload::estimate_named_body(
            self.base
                .iter()
                .flat_map(UploadSet::files)
                .map(|f| ("base_files[]", f.path.as_str(), f.contents.len() as u64))
                .chain(
                    self.head
                        .iter()
                        .flat_map(UploadSet::files)
                        .map(|f| ("head_files[]", f.path.as_str(), f.contents.len() as u64)),
                ),
            Some(("request", self.request.len() as u64)),
        )
    }

    fn largest_files(&self) -> Vec<String> {
        let mut files: Vec<_> = self
            .base
            .iter()
            .flat_map(UploadSet::files)
            .map(|f| ("base", f))
            .chain(
                self.head
                    .iter()
                    .flat_map(UploadSet::files)
                    .map(|f| ("head", f)),
            )
            .collect();
        files.sort_by(|a, b| {
            b.1.contents
                .len()
                .cmp(&a.1.contents.len())
                .then(a.1.path.cmp(&b.1.path))
        });
        files
            .iter()
            .take(3)
            .map(|(side, f)| format!("{side}:{} ({} bytes)", f.path, f.contents.len()))
            .collect()
    }

    /// The number of selected file parts in both namespaces.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.base.as_ref().map_or(0, UploadSet::len) + self.head.as_ref().map_or(0, UploadSet::len)
    }
}

fn unique_paths(set: Option<&UploadSet>) -> Result<(), UploadError> {
    let mut seen = BTreeSet::new();
    for file in set.into_iter().flat_map(UploadSet::files) {
        if !seen.insert(&file.path) {
            return Err(UploadError::DuplicatePath {
                path: file.path.clone(),
            });
        }
    }
    Ok(())
}
