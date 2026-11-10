//! Bounded package declaration hints over admitted paths, without lock parsing or I/O.
use std::collections::{BTreeMap, BTreeSet};
use std::str::Chars;

use globset::{GlobBuilder, GlobMatcher};
use serde_json::Value;

/// One selected package owner's declaration and already admitted candidate paths.
pub(crate) struct Workspace {
    root: String,
    candidates: BTreeMap<String, String>,
    members: BTreeSet<String>,
    dialect: Dialect,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Npm,
    Bun,
}

impl Workspace {
    /// Candidates have passed discovery/selection and share this owner's lock directory.
    pub(crate) fn new(root: String, candidates: impl Iterator<Item = String>) -> Self {
        let base = directory(&root);
        let candidates = candidates
            .filter_map(|path| {
                let relative = relative_directory(directory(&path), base)?;
                Some((relative.to_owned(), path))
            })
            .collect();
        Self {
            root,
            candidates,
            members: BTreeSet::new(),
            dialect: Dialect::Npm,
        }
    }

    /// Interpret a Bun package manifest with its verified workspace glob rules.
    pub(crate) fn bun(root: String, candidates: impl Iterator<Item = String>) -> Self {
        let mut workspace = Self::new(root, candidates);
        workspace.dialect = Dialect::Bun;
        workspace
    }

    /// Interpret only the owning manifest; member manifests never recursively expand.
    pub(crate) fn record(&mut self, path: &str, contents: &str) {
        if path == self.root {
            self.members = self.select(contents).unwrap_or_default();
        }
    }

    /// Declared members that are present in the admitted candidate inventory.
    pub(crate) fn members(&self) -> BTreeSet<String> {
        self.members.clone()
    }

    fn select(&self, contents: &str) -> Option<BTreeSet<String>> {
        let document: Value = serde_json::from_str(contents).ok()?;
        let declaration = document.get("workspaces")?;
        let patterns = declaration
            .as_array()
            .or_else(|| declaration.get("packages")?.as_array())?;
        let patterns = patterns
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()?;
        // Keep the existing conservative Unicode boundary for both dialects:
        // globset counts bytes for ?/classes, while npm counts characters.
        if patterns.iter().any(|pattern| pattern.contains(['?', '[']))
            && (patterns.iter().any(|pattern| !pattern.is_ascii())
                || self.candidates.keys().any(|path| !path.is_ascii()))
        {
            return None;
        }
        let globs = patterns
            .iter()
            .map(|pattern| matchers(pattern, self.dialect))
            .collect::<Option<Vec<_>>>()?;
        Some(
            self.candidates
                .iter()
                .filter(|(directory, _)| {
                    globs.iter().flatten().any(|glob| glob.is_match(directory))
                })
                .map(|(_, path)| path.clone())
                .collect(),
        )
    }
}

fn relative_directory<'a>(directory: &'a str, base: &str) -> Option<&'a str> {
    if base.is_empty() {
        return Some(directory);
    }
    directory.strip_prefix(base)?.strip_prefix('/')
}

fn directory(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(directory, _)| directory)
}

fn matchers(pattern: &str, dialect: Dialect) -> Option<Vec<GlobMatcher>> {
    let bangs = pattern.bytes().take_while(|&b| b == b'!').count();
    if bangs % 2 != 0 {
        return None;
    }
    let pattern = &pattern[bangs..];
    let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
    let pattern = match dialect {
        Dialect::Npm => pattern.trim_start_matches('/'),
        Dialect::Bun if pattern.starts_with('/') => return None,
        Dialect::Bun => pattern,
    };
    let mut parts: Vec<_> = pattern.split('/').collect();
    if pattern.starts_with('!')
        || parts
            .iter()
            .any(|p| matches!(*p, "" | "." | "..") || p.contains("**") && *p != "**")
        || !syntax_supported(pattern, dialect)
    {
        return None;
    }
    // Native npm's member filter ignores supported positive comment patterns.
    if dialect == Dialect::Npm && pattern.starts_with('#') {
        return Some(Vec::new());
    }
    // Globset's trailing /** requires a slash; both dialects include its base directory.
    parts.dedup_by(|a, b| *a == "**" && *b == "**");
    let pattern = parts.join("/");
    let mut globs = vec![compile(&pattern)?];
    if let Some(base) = pattern.strip_suffix("/**") {
        globs.push(compile(base)?);
    }
    Some(globs)
}

fn compile(pattern: &str) -> Option<GlobMatcher> {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .case_insensitive(false)
        .build()
        .ok()
        .map(|glob| glob.compile_matcher())
}

fn syntax_supported(pattern: &str, dialect: Dialect) -> bool {
    if pattern.contains("${") || pattern.chars().any(char::is_control) {
        return false;
    }
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        let valid = match ch {
            '[' => group(&mut chars, ']').is_some_and(|inner| class_supported(&inner)),
            '{' => group(&mut chars, '}').is_some_and(|inner| {
                inner.contains(',')
                    && inner
                        .split(',')
                        .all(|alternative| literal_alternative(alternative, dialect))
            }),
            ']' | '}' | '(' | ')' | '\\' => false,
            _ => true,
        };
        if !valid {
            return false;
        }
    }
    true
}

// Globset reopens completed ranges after another hyphen and allows ranges
// spanning '/'. Neither form has npm's single-segment class semantics.
fn class_supported(inner: &str) -> bool {
    if inner.is_empty()
        || inner.starts_with(['!', '^'])
        || inner.contains(['[', '{', '}', '/', '\\'])
    {
        return false;
    }
    // A leading or trailing hyphen is a literal in both matchers.
    let mut chars = inner.strip_prefix('-').unwrap_or(inner).chars().peekable();
    while let Some(start) = chars.next() {
        if start == '-' {
            return chars.peek().is_none();
        }
        if chars.next_if_eq(&'-').is_none() {
            continue;
        }
        let Some(end) = chars.next() else {
            return true;
        };
        if end == '-' || (start..=end).contains(&'/') {
            return false;
        }
    }
    true
}

fn group(chars: &mut Chars<'_>, closing: char) -> Option<String> {
    let mut inner = String::new();
    for ch in chars.by_ref() {
        if ch == closing {
            return Some(inner);
        }
        inner.push(ch);
    }
    None
}

fn literal_alternative(value: &str, dialect: Dialect) -> bool {
    (dialect == Dialect::Npm || !value.contains('/'))
        && !value.is_empty()
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
        && value.chars().all(|ch| !"*?![]{}()\\".contains(ch))
}

#[cfg(test)]
mod tests;
