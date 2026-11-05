//! Native Cargo member hints over admitted paths, never a resolver or filesystem walk.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use globset::{GlobBuilder, GlobMatcher};
use toml_edit::{DocumentMut, Item, TableLike};

/// Selection state for one selected lock-owning manifest and its admitted candidates.
/// Parsed documents are retained only for bounded upload inputs, each read once.
pub(crate) struct Workspace {
    root: String,
    candidates: BTreeMap<String, String>,
    documents: BTreeMap<String, DocumentMut>,
}

impl Workspace {
    /// Candidates have already passed discovery and selection policy, and share this lock.
    pub(crate) fn new(root: String, candidates: impl Iterator<Item = String>) -> Self {
        Self {
            root,
            candidates: candidates
                .map(|path| (directory(&path).into(), path))
                .collect(),
            documents: BTreeMap::new(),
        }
    }

    /// Observe admitted upload contents without validating Cargo input on the service's behalf.
    pub(crate) fn record(&mut self, path: &str, contents: &str) {
        if path != self.root && !self.candidates.values().any(|candidate| candidate == path) {
            return;
        }
        if let Ok(document) = contents.parse() {
            self.documents.insert(path.into(), document);
        }
    }

    /// Required candidates known from the root and the member documents read so far.
    pub(crate) fn members(&self) -> BTreeSet<String> {
        let Some(root) = self.documents.get(&self.root) else {
            return BTreeSet::new();
        };
        let Some(workspace) = root.get("workspace").and_then(Item::as_table_like) else {
            return BTreeSet::new();
        };
        let Some(members) = strings(workspace.get("members")) else {
            return BTreeSet::new();
        };
        let Some(excludes) = strings(workspace.get("exclude")) else {
            return BTreeSet::new();
        };
        let base = directory(&self.root);
        let member_paths: Vec<_> = members.iter().filter_map(|p| relative(base, p)).collect();
        let exclude_paths: Vec<_> = excludes.iter().filter_map(|p| relative(base, p)).collect();
        let globs: Vec<_> = member_paths.iter().filter_map(|p| member_glob(p)).collect();
        let allowed =
            |dir: &str| within(dir, base) && !excluded(dir, &member_paths, &exclude_paths);
        let mut selected = BTreeSet::from([self.root.clone()]);
        selected.extend(
            self.candidates
                .iter()
                .filter(|(dir, _)| {
                    allowed(dir) && globs.iter().any(|pattern| pattern.is_match(dir))
                })
                .map(|(_, path)| path.clone()),
        );
        self.path_members(workspace, &allowed, &mut selected);
        selected.remove(&self.root);
        selected
    }

    fn path_members(
        &self,
        workspace: &dyn TableLike,
        allowed: &dyn Fn(&str) -> bool,
        selected: &mut BTreeSet<String>,
    ) {
        let mut visited = BTreeSet::new();
        while let Some(path) = selected.difference(&visited).next().cloned() {
            visited.insert(path.clone());
            let paths = self.member_dependency_paths(workspace, &path);
            selected.extend(
                paths
                    .into_iter()
                    .filter(|dir| allowed(dir))
                    .filter_map(|dir| self.candidates.get(&dir).cloned()),
            );
        }
    }
    fn member_dependency_paths(&self, workspace: &dyn TableLike, path: &str) -> Vec<String> {
        let Some(doc) = self.documents.get(path) else {
            return Vec::new();
        };
        if !belongs(doc, path, &self.root) {
            return Vec::new();
        }
        dependency_paths(doc, workspace, directory(&self.root), directory(path))
    }
}

fn directory(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(directory, _)| directory)
}

fn within(path: &str, prefix: &str) -> bool {
    Path::new(path).starts_with(prefix)
}

/// Normalize declarations, not filesystem paths: only inventory matches can be selected.
fn relative(base: &str, path: &str) -> Option<String> {
    let mut parts: Vec<_> = base
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    for part in Path::new(path).components() {
        match part {
            Component::CurDir => (),
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::Normal(value) => parts.push(value.to_str()?.to_owned()),
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(parts.join("/"))
}

fn strings(item: Option<&Item>) -> Option<Vec<&str>> {
    let Some(item) = item else {
        return Some(Vec::new());
    };
    item.as_array()?
        .iter()
        .map(toml_edit::Value::as_str)
        .collect()
}

fn member_glob(pattern: &str) -> Option<GlobMatcher> {
    // Cargo uses glob, whose braces are literal; globset otherwise treats them as alternatives.
    let pattern = pattern
        .replace('\\', "\\\\")
        .replace('{', "\\{")
        .replace('}', "\\}");
    GlobBuilder::new(&pattern)
        .literal_separator(true)
        .backslash_escape(true)
        .build()
        .ok()
        .map(|glob| glob.compile_matcher())
}

fn excluded(directory: &str, members: &[String], excludes: &[String]) -> bool {
    !members.iter().any(|p| within(directory, p)) && excludes.iter().any(|p| within(directory, p))
}

fn belongs(doc: &DocumentMut, path: &str, root: &str) -> bool {
    if path != root && doc.contains_key("workspace") {
        return false;
    }
    let declared = doc
        .get("package")
        .and_then(Item::as_table_like)
        .and_then(|p| p.get("workspace"))
        .and_then(Item::as_str);
    declared
        .is_none_or(|value| relative(directory(path), value).as_deref() == Some(directory(root)))
}

fn dependency_tables(doc: &DocumentMut) -> Vec<&dyn TableLike> {
    let mut tables = tables(doc.as_table());
    let targets = doc.get("target").and_then(Item::as_table_like);
    for (_, target) in targets.into_iter().flat_map(TableLike::iter) {
        if let Some(target) = target.as_table_like() {
            tables.extend(self::tables(target));
        }
    }
    tables
}

fn tables(table: &dyn TableLike) -> Vec<&dyn TableLike> {
    ["dependencies", "dev-dependencies", "build-dependencies"]
        .iter()
        .filter_map(|name| table.get(name).and_then(Item::as_table_like))
        .collect()
}

fn dependency_paths(
    doc: &DocumentMut,
    workspace: &dyn TableLike,
    base: &str,
    directory: &str,
) -> Vec<String> {
    dependency_tables(doc)
        .into_iter()
        .flat_map(TableLike::iter)
        .filter_map(|(name, value)| dependency_path(name, value, workspace, base, directory))
        .collect()
}

fn dependency_path(
    name: &str,
    value: &Item,
    workspace: &dyn TableLike,
    base: &str,
    directory: &str,
) -> Option<String> {
    let value = value.as_table_like()?;
    if value.get("workspace").and_then(Item::as_bool) != Some(true) {
        return relative(directory, value.get("path")?.as_str()?);
    }
    let inherited = workspace
        .get("dependencies")?
        .as_table_like()?
        .get(name)?
        .as_table_like()?;
    relative(base, inherited.get("path")?.as_str()?)
}

#[cfg(test)]
mod tests;
