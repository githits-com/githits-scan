//! Bounded terminal previews; source evidence remains in the JSON representation.

use std::io::{self, Write};

use crate::commands::{Escape, push_safe};

pub(super) const DETAIL: usize = 240;
pub(super) const GROUP: usize = 48;
pub(super) const PACKAGE: usize = 160;
pub(super) const LICENSE: usize = 80;
pub(super) const PACKAGE_PADDING: usize = 48;
pub(super) const LICENSE_PADDING: usize = 32;
const QUALIFIERS: usize = 64;

/// Return whether the partial-inventory warning was emitted, so callers can
/// omit a redundant inventory summary.
pub(super) fn warn_incomplete(
    completeness: Option<&str>,
    stderr: &mut dyn Write,
) -> io::Result<bool> {
    let incomplete = completeness == Some("partial_manifest_inventory");
    if incomplete {
        writeln!(stderr, "warning: dependency resolution is incomplete")?;
    }
    Ok(incomplete)
}

pub(super) fn completeness(value: &str) -> String {
    let value = match value {
        "partial_manifest_inventory" => "incomplete dependency resolution",
        "resolved_manifest_inventory" => "resolved from manifests",
        "recorded_lockfile_inventory" => "recorded lockfile inventory",
        "mixed_dependency_inventory" => "recorded and resolved dependencies",
        "not reported" => "not reported",
        _ => "unrecognized inventory evidence (retained in JSON)",
    };
    Text::new(value, DETAIL).value
}

/// Human explanations of authored evidence codes; wire values remain in JSON.
pub(super) fn evidence_code(value: &str) -> &'static str {
    match value {
        "manifest_resolution" => "manifest dependency resolution",
        "missing_identity_facets" => "package identity is incomplete",
        "unsupported_registry" => "registry is not supported",
        "invalid_coordinate" => "package coordinate is invalid",
        "not_recorded" => "not recorded",
        "withheld" => "withheld",
        "branch" => "branch",
        "tag" => "tag",
        "commit" => "commit",
        "non_public_registry_source" => "non-public registry source",
        "source_substitution" => "registry metadata may not apply to substituted source",
        "uploaded_declaration" => "uploaded declaration",
        "not_eligible" => "not eligible for registry metadata",
        "not_checked" => "not checked",
        "selected_only" => "selected statements only",
        "deprecated" => "deprecated license identifier",
        "registry_name_version" => "registry name and version lookup",
        "resolution_failed" => "dependency resolution failed",
        "vcpkg_baseline_not_applied" => "catalog baseline was not applied",
        "version_mismatch" => "declared and locked versions differ",
        "associated" => "associated",
        "unassociated" => "not associated with a manifest",
        "matched" => "matched",
        "recorded" => "recorded",
        "manifest_declared" => "uploaded manifest",
        "registry_declared" => "registry declaration",
        "manifest" => "manifest",
        "release" => "release",
        "package" => "package",
        "repository" => "repository",
        "lockfile_records_and_manifest_resolution" => "recorded lockfiles and manifest resolution",
        "library_assumed_from_inventory" => "library classification assumed from inventory",
        "current_public_catalog" => "current public catalog",
        "LOCKED_PACKAGE_SOURCE_KIND_GIT" => "Git source",
        "LOCKFILE_COMPLETENESS_PACKAGE_ENTRIES_ONLY" => {
            "package entries only; relationships may be incomplete"
        }
        "LOCKFILE_COMPLETENESS_PACKAGE_ENTRIES_AND_RECORDED_RELATIONSHIPS" => {
            "package entries and recorded relationships"
        }
        "expression" => "recognized license expression",
        "absent" => "not reported",
        "ambiguous" => "ambiguous license evidence",
        "contextual_statements_only" => "context only; no release license statement",
        "publisher_release_metadata" => "publisher release metadata",
        "missing_input" => "required input was not supplied",
        "invalid_token" => "unrecognized text in license expression",
        "partial" => "partially resolved",
        "timeout" => "resolution timed out",
        "max_iterations" => "resolution iteration limit reached",
        "complete" => "complete",
        "incomplete" => "incomplete",
        "failed" => "failed",
        "excluded" => "excluded",
        "pending" => "pending",
        "unavailable" => "unavailable",
        "not_found" => "not found",
        "not_requested" => "not requested",
        "not_supported" => "not supported",
        "unknown" => "unknown",
        _ => crate::commands::evidence::reason(value)
            .unwrap_or("unrecognized evidence (retained in JSON)"),
    }
}

pub(super) struct Text {
    pub value: String,
    pub shortened: bool,
}

impl Text {
    pub(super) fn new(value: &str, limit: usize) -> Self {
        build(value.chars(), limit, false, Escape::Text)
    }

    pub(super) fn prose(value: &str, limit: usize) -> Self {
        build(value.chars(), limit, true, Escape::Text)
    }

    pub(super) fn parts<'a>(values: impl IntoIterator<Item = &'a str>, limit: usize) -> Self {
        build(
            values.into_iter().flat_map(str::chars),
            limit,
            false,
            Escape::Text,
        )
    }

    pub(super) fn displayed(value: &str, limit: usize) -> Self {
        build(value.chars(), limit, false, Escape::Path)
    }

    pub(super) fn prose_parts<'a>(values: impl IntoIterator<Item = &'a str>, limit: usize) -> Self {
        build(
            values.into_iter().flat_map(str::chars),
            limit,
            true,
            Escape::Text,
        )
    }
}

fn build(chars: impl Iterator<Item = char>, limit: usize, fold: bool, mode: Escape) -> Text {
    let mut value = String::new();
    // Retain scalar boundaries so reserving the ellipsis cannot split an escape.
    let mut boundaries = Vec::new();
    let mut used = 0;
    let mut scalar = String::new();
    let mut space = true;
    for ch in chars {
        if fold && ch.is_whitespace() && space {
            continue;
        }
        let ch = if fold && ch.is_whitespace() {
            space = true;
            ' '
        } else {
            space = false;
            ch
        };
        scalar.clear();
        push_safe(&mut scalar, ch, mode);
        let width = scalar.chars().count();
        if used + width > limit {
            trim_preview(&mut value, &mut boundaries, &mut used, limit);
            value.push_str(&"..."[..limit.min(3)]);
            return Text {
                value,
                shortened: true,
            };
        }
        boundaries.push((value.len(), used));
        value.push_str(&scalar);
        used += width;
    }
    if fold {
        value.truncate(value.trim_end_matches(' ').len());
    }
    Text {
        value,
        shortened: false,
    }
}

fn trim_preview(
    value: &mut String,
    boundaries: &mut Vec<(usize, usize)>,
    used: &mut usize,
    limit: usize,
) {
    while *used > limit.saturating_sub(3) {
        let Some((bytes, count)) = boundaries.pop() else {
            break;
        };
        value.truncate(bytes);
        *used = count;
    }
}

pub(super) struct Identity {
    pub text: Text,
    pub continuation: Option<(&'static str, Text)>,
}

pub(super) fn purl_base(purl: &str) -> &str {
    purl.split(['?', '#']).next().unwrap_or(purl)
}

pub(super) fn identity(
    name: &str,
    version: Option<&str>,
    purl: Option<&str>,
    marker: &str,
    distinguish: bool,
    groups: Option<&str>,
) -> Identity {
    let raw_suffix = purl
        .and_then(|value| value.find(['?', '#']).map(|at| &value[at..]))
        .unwrap_or("");
    let suffix = Text::new(raw_suffix, QUALIFIERS);
    let suffix_width = suffix.value.chars().count();
    let groups = groups.map(|value| Text::parts([" [", value, "]"], GROUP));
    let group_width = groups.as_ref().map_or(0, |text| text.value.chars().count());
    let overhead = marker.chars().count()
        + group_width
        + suffix_width
        + usize::from(!marker.is_empty())
        + usize::from(suffix_width > 0);
    let base = Text::parts(coordinate(name, version), PACKAGE - overhead);
    let identity_shortened = base.shortened || suffix.shortened;
    let shortened = identity_shortened || groups.as_ref().is_some_and(|text| text.shortened);
    let mut value = base.value;
    if !marker.is_empty() {
        value.push(' ');
        value.push_str(marker);
    }
    if let Some(groups) = groups {
        value.push_str(&groups.value);
    }
    if !suffix.value.is_empty() {
        value.push(' ');
        value.push_str(&suffix.value);
    }
    let continuation = (identity_shortened || distinguish).then(|| {
        purl.map_or_else(
            || ("identity", Text::parts(coordinate(name, version), DETAIL)),
            |url| ("package URL", Text::new(url, DETAIL)),
        )
    });
    Identity {
        text: Text { value, shortened },
        continuation,
    }
}

fn coordinate<'a>(name: &'a str, version: Option<&'a str>) -> [&'a str; 3] {
    [
        name,
        if version.is_some() { " " } else { "" },
        version.unwrap_or(""),
    ]
}

pub(super) fn continuation(out: &mut dyn Write, identity: &Identity) -> io::Result<()> {
    if let Some((label, text)) = &identity.continuation {
        writeln!(out, "  {label}: {}", text.value)?;
    }
    Ok(())
}

/// Atomic fields keep URLs/paths copyable; prose wraps only between words.
pub(super) fn field(
    out: &mut dyn Write,
    prefix: &str,
    value: &str,
    prose: bool,
) -> io::Result<bool> {
    if value.trim().is_empty() {
        return Ok(false);
    }
    let text = if prose {
        Text::prose(value, DETAIL)
    } else {
        Text::new(value, DETAIL)
    };
    if !prose {
        writeln!(out, "{prefix}{}", text.value)?;
        return Ok(text.shortened);
    }
    write!(out, "{prefix}")?;
    let mut width = prefix.chars().count();
    for (index, word) in text.value.split(' ').enumerate() {
        let n = word.chars().count();
        if index > 0 && width + n + 1 > 100 {
            write!(out, "\n    ")?;
            width = 4;
        } else if index > 0 {
            write!(out, " ")?;
            width += 1;
        }
        write!(out, "{word}")?;
        width += n;
    }
    writeln!(out)?;
    Ok(text.shortened)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_text_preserves_scalars_and_marks_omission() {
        for (raw, limit, expected) in [
            ("abc", 3, "abc"),
            ("abcdef", 5, "ab..."),
            ("éééé", 3, "..."),
            ("\u{1b}suffix", 8, "..."),
            ("abc", 0, ""),
        ] {
            let text = Text::new(raw, limit);
            assert_eq!(text.value, expected);
            assert!(text.value.chars().count() <= limit);
            assert!(!text.value.contains('\u{1b}'));
        }
        assert_eq!(
            Text::prose("  full\n\tlicense  text\n", 80).value,
            "full license text"
        );
    }

    #[test]
    fn preview_stops_reading_once_the_rendered_budget_is_exhausted() {
        let read = std::cell::Cell::new(0);
        let input = std::iter::repeat_n('a', 100_000).inspect(|_| read.set(read.get() + 1));
        let text = build(input, LICENSE, false, Escape::Text);
        assert_eq!(text.value, format!("{}...", "a".repeat(77)));
        assert!(read.get() <= 81);
    }

    #[test]
    fn long_identity_cannot_hide_ordinary_platform_qualifiers() {
        let name = "a".repeat(300);
        let id = identity(
            &name,
            Some("1"),
            Some("pkg:gem/a@1?platform=arm64-darwin"),
            "",
            false,
            None,
        );
        assert!(id.text.value.ends_with("?platform=arm64-darwin"));
        assert!(id.text.value.chars().count() <= PACKAGE);
        assert!(id.text.shortened);
        assert_eq!(
            id.continuation.as_ref().expect("source URL").1.value,
            "pkg:gem/a@1?platform=arm64-darwin"
        );
    }
}
