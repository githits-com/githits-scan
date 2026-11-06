//! Pure repository-wide inventory comparison; source-local direct transitions stay separate.
use crate::api::{
    Document,
    audit::{Body, Report as AuditReport},
    upgrade,
};
use crate::commands::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

type Set = BTreeSet<String>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct Key {
    pub registry: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct Package {
    pub versions: Set,
    pub paths: Set,
    pub direct: BTreeMap<String, Set>,
    pub direct_unknown: Set,
    pub scope_unknown: bool,
}

impl Package {
    pub(crate) fn scope(&self) -> &'static str {
        if !self.direct.is_empty() {
            "direct"
        } else if self.scope_unknown || !self.direct_unknown.is_empty() {
            "unknown"
        } else {
            "transitive"
        }
    }
}

#[derive(Default)]
pub(crate) struct Inventory {
    pub packages: BTreeMap<Key, Package>,
    pub notices: Vec<String>,
}

#[derive(Deserialize)]
struct Agreement {
    name: String,
    path: String,
    declaration_path: String,
    status: String,
    #[serde(default)]
    matched_versions: Vec<Option<String>>,
}

#[derive(Deserialize)]
struct Declaration {
    name: String,
    manifest_path: String,
    source_type: String,
}

impl Inventory {
    pub(crate) fn decode(document: &Document) -> Result<Self, Error> {
        let value: Value = serde_json::from_slice(&document.bytes)
            .map_err(|_| Error::Diff("invalid CycloneDX inventory"))?;
        if value.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX") {
            return Err(Error::Diff("expected CycloneDX inventory"));
        }
        let mut inventory = Self::default();
        inventory.components(&value)?;
        if !matches!(
            property(&value, "githits:completeness"),
            Some(
                "recorded_lockfile_inventory"
                    | "resolved_manifest_inventory"
                    | "mixed_dependency_inventory"
            )
        ) {
            inventory
                .notices
                .push("inventory completeness is partial or unavailable".into());
        }
        inventory.directness(&value)?;
        if inventory
            .packages
            .values()
            .any(|p| p.scope_unknown || !p.direct_unknown.is_empty())
        {
            inventory
                .notices
                .push("direct/transitive scope is unavailable for some packages".into());
        }
        Ok(inventory)
    }

    fn components(&mut self, value: &Value) -> Result<(), Error> {
        let Some(components) = value.get("components") else {
            return Ok(());
        };
        for component in components
            .as_array()
            .ok_or(Error::Diff("invalid component array"))?
        {
            self.component(component)?;
        }
        Ok(())
    }

    fn component(&mut self, component: &Value) -> Result<(), Error> {
        self.components(component)?;
        if property(component, "githits:record_kind") == Some("manifest") {
            return Ok(());
        }
        let name = component
            .get("name")
            .and_then(Value::as_str)
            .ok_or(Error::Diff("component name unavailable"))?;
        let registry = match property(component, "githits:source_kind") {
            Some("LOCKED_PACKAGE_SOURCE_KIND_REGISTRY") => property(component, "githits:registry"),
            None if property(component, "githits:record_kind") == Some("resolved_package") => {
                property(component, "githits:registry")
            }
            _ => None,
        }
        .map(str::to_owned);
        let key = Key {
            registry,
            name: name.into(),
        };
        if key.registry.is_none() {
            self.notices
                .push(format!("registry identity unavailable for {name}"));
        }
        let package = self.packages.entry(key).or_default();
        if let Some(version) = component.get("version").and_then(Value::as_str) {
            package.versions.insert(version.into());
        } else {
            self.notices.push(format!("version unavailable for {name}"));
        }
        if let Some(path) = property(component, "githits:lockfile_path") {
            package.paths.insert(path.into());
        }
        if let Some(paths) = property(component, "githits:manifest_paths") {
            let paths: Vec<String> =
                serde_json::from_str(paths).map_err(|_| Error::Diff("invalid manifest paths"))?;
            package.paths.extend(paths);
        }
        Ok(())
    }

    fn directness(&mut self, value: &Value) -> Result<(), Error> {
        let agreements: Vec<Agreement> =
            structured(value, "githits:declaration_agreement")?.unwrap_or_default();
        let declarations: Vec<Declaration> =
            structured(value, "githits:declarations")?.unwrap_or_default();
        let registry_declarations: BTreeSet<_> = declarations
            .iter()
            .filter(|d| d.source_type == "registry")
            .map(|d| (d.manifest_path.as_str(), d.name.as_str()))
            .collect();
        let covered: BTreeSet<_> = agreements
            .iter()
            .map(|a| (a.declaration_path.as_str(), a.name.as_str()))
            .collect();
        let missing: Vec<_> = registry_declarations
            .difference(&covered)
            .copied()
            .collect();
        let known_paths: Set = agreements.iter().map(|a| a.path.clone()).collect();
        for package in self.packages.values_mut() {
            package.scope_unknown =
                package.paths.is_empty() || !package.paths.is_subset(&known_paths);
        }
        for (source, name) in missing {
            self.missing_declaration(source, name);
        }
        for agreement in agreements {
            let declared = registry_declarations
                .contains(&(agreement.declaration_path.as_str(), agreement.name.as_str()));
            self.agreement(&agreement, declared);
        }
        Ok(())
    }

    fn missing_declaration(&mut self, source: &str, name: &str) {
        self.notices
            .push(format!("direct agreement unavailable: {name} in {source}"));
        for (key, package) in &mut self.packages {
            mark_unknown(package, source, key.name == name);
        }
    }

    fn agreement(&mut self, agreement: &Agreement, declared: bool) {
        let versions: Set = agreement
            .matched_versions
            .iter()
            .flatten()
            .cloned()
            .collect();
        let candidates: Vec<_> = self
            .packages
            .iter()
            .filter(|(key, package)| {
                key.name == agreement.name
                    && key.registry.is_some()
                    && package.paths.contains(&agreement.path)
            })
            .map(|(key, _)| key.clone())
            .collect();
        let exact = declared
            && agreement.status == "matched"
            && !versions.is_empty()
            && candidates.len() == 1
            && candidates
                .first()
                .and_then(|key| self.packages.get(key))
                .is_some_and(|p| versions.is_subset(&p.versions));
        if !exact {
            self.unknown_agreement(agreement);
            return;
        }
        let Some(package) = candidates
            .first()
            .and_then(|key| self.packages.get_mut(key))
        else {
            return;
        };
        package
            .direct
            .entry(agreement.declaration_path.clone())
            .or_default()
            .extend(versions);
    }

    fn unknown_agreement(&mut self, agreement: &Agreement) {
        self.notices.push(format!(
            "direct version unknown: {} in {} ({})",
            agreement.name, agreement.declaration_path, agreement.status
        ));
        for (key, package) in self
            .packages
            .iter_mut()
            .filter(|(_, p)| p.paths.contains(&agreement.path))
        {
            mark_unknown(
                package,
                &agreement.declaration_path,
                key.name == agreement.name && key.registry.is_some(),
            );
        }
    }
}

fn mark_unknown(package: &mut Package, source: &str, candidate: bool) {
    package.scope_unknown = true;
    if candidate {
        package.direct_unknown.insert(source.into());
    }
}

fn property<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    value
        .get("properties")?
        .as_array()?
        .iter()
        .find(|p| p.get("name").and_then(Value::as_str) == Some(name))?
        .get("value")?
        .as_str()
}

fn structured<T: serde::de::DeserializeOwned>(
    value: &Value,
    name: &str,
) -> Result<Option<T>, Error> {
    property(value, name)
        .map(|text| {
            serde_json::from_str(text)
                .map_err(|_| Error::Diff("invalid structured inventory evidence"))
        })
        .transpose()
}

#[derive(Default)]
pub(crate) struct Audit {
    findings: BTreeMap<Key, Set>,
    unknown: BTreeSet<Key>,
    unsupported: Set,
    pub available: bool,
    pub incomplete: bool,
}

impl Audit {
    pub(crate) fn empty() -> Self {
        Self {
            available: true,
            ..Self::default()
        }
    }

    pub(crate) fn project(report: &AuditReport, inventory: &Inventory) -> Result<Self, Error> {
        let assessment =
            crate::audit::assess(report).ok_or(Error::Diff("unsupported audit schema version"))?;
        let mut audit = Self {
            available: assessment.unverified.is_empty(),
            incomplete: assessment.incomplete,
            ..Self::default()
        };
        match &report.body {
            Body::V1(r) => {
                audit.available &= r.unknowns.sources.is_empty();
                audit.unsupported.clone_from(
                    &r.coverage
                        .vulnerabilities
                        .unsupported_registries
                        .iter()
                        .cloned()
                        .collect(),
                );
                audit.record_findings(
                    r.findings
                        .vulnerabilities
                        .iter()
                        .map(|v| (&v.coordinate, v.advisory_id.as_str())),
                    inventory,
                );
                audit.unknown.extend(
                    r.unknowns
                        .vulnerabilities
                        .iter()
                        .map(|v| key(&v.coordinate)),
                );
            }
            Body::V2(r) => {
                audit.available &=
                    r.unknowns.sources.is_empty() && r.unknowns.resolution.is_empty();
                audit.unsupported = r
                    .coverage
                    .vulnerabilities
                    .unsupported_registries
                    .iter()
                    .cloned()
                    .collect();
                audit.record_findings(
                    r.findings
                        .vulnerabilities
                        .iter()
                        .map(|v| (&v.coordinate, v.advisory_id.as_str())),
                    inventory,
                );
                audit.unknown.extend(
                    r.unknowns
                        .vulnerabilities
                        .iter()
                        .map(|v| key(&v.coordinate)),
                );
            }
            Body::Future(_) => return Err(Error::Diff("unsupported audit schema version")),
        }
        let coordinates: usize = inventory
            .packages
            .iter()
            .filter(|(key, _)| key.registry.is_some())
            .map(|(_, p)| p.versions.len())
            .sum();
        if assessment.summary.dependencies != coordinates as u64 {
            audit.available = false;
            audit.incomplete = true;
        }
        Ok(audit)
    }

    fn record_findings<'a>(
        &mut self,
        findings: impl Iterator<Item = (&'a crate::api::audit::wire::Coordinate, &'a str)>,
        inventory: &Inventory,
    ) {
        for (coordinate, id) in findings {
            self.finding(coordinate, id, inventory);
        }
    }

    fn finding(
        &mut self,
        coordinate: &crate::api::audit::wire::Coordinate,
        id: &str,
        inventory: &Inventory,
    ) {
        let key = key(coordinate);
        if !inventory
            .packages
            .get(&key)
            .is_some_and(|p| p.versions.contains(&coordinate.version))
        {
            self.available = false;
            self.incomplete = true;
        }
        self.findings.entry(key).or_default().insert(id.into());
    }

    fn checked(&self, key: &Key) -> bool {
        self.available
            && key
                .registry
                .as_ref()
                .is_some_and(|r| !self.unsupported.contains(r))
            && !self.unknown.contains(key)
    }
}

fn key(coordinate: &crate::api::audit::wire::Coordinate) -> Key {
    Key {
        registry: Some(coordinate.registry.clone()),
        name: coordinate.name.clone(),
    }
}

#[derive(Serialize)]
pub(crate) struct Delta {
    pub fixed: Option<Set>,
    pub introduced: Option<Set>,
    pub unchanged: Option<Set>,
    pub base_observed: Set,
    pub head_observed: Set,
    pub assessed: bool,
}

#[derive(Serialize)]
pub(crate) struct Change {
    #[serde(flatten)]
    pub key: Key,
    pub kind: &'static str,
    pub base: Option<Package>,
    pub head: Option<Package>,
    pub base_scope: Option<&'static str>,
    pub head_scope: Option<&'static str>,
    pub vulnerabilities: Delta,
    pub upgrade_reviews: Vec<upgrade::Review>,
    pub review_gaps: Vec<String>,
}

#[derive(Serialize)]
pub(crate) struct Report {
    pub schema_version: u8,
    pub comparison_scope: &'static str,
    pub base: String,
    pub head: String,
    pub analysis_performed: bool,
    pub incomplete: bool,
    pub notices: Vec<String>,
    pub changes: Vec<Change>,
}

pub(crate) fn compare(base: &Inventory, head: &Inventory, audits: (&Audit, &Audit)) -> Vec<Change> {
    let keys: BTreeSet<_> = base.packages.keys().chain(head.packages.keys()).collect();
    keys.into_iter()
        .filter_map(|key| change(key, base.packages.get(key), head.packages.get(key), audits))
        .collect()
}

fn change(
    key: &Key,
    old: Option<&Package>,
    new: Option<&Package>,
    audits: (&Audit, &Audit),
) -> Option<Change> {
    if let (Some(a), Some(b)) = (old, new) {
        let scope_change = !a.scope_unknown
            && !b.scope_unknown
            && a.direct_unknown.is_empty()
            && b.direct_unknown.is_empty()
            && a.direct != b.direct;
        if a.versions == b.versions && !scope_change {
            return None;
        }
    }
    let before = audits.0.findings.get(key).cloned().unwrap_or_default();
    let after = audits.1.findings.get(key).cloned().unwrap_or_default();
    let assessed = audits.0.checked(key) && audits.1.checked(key);
    Some(Change {
        key: key.clone(),
        kind: kind(old, new),
        base: old.cloned(),
        head: new.cloned(),
        base_scope: old.map(Package::scope),
        head_scope: new.map(Package::scope),
        vulnerabilities: Delta {
            fixed: assessed.then(|| before.difference(&after).cloned().collect()),
            introduced: assessed.then(|| after.difference(&before).cloned().collect()),
            unchanged: assessed.then(|| before.intersection(&after).cloned().collect()),
            assessed,
            base_observed: before,
            head_observed: after,
        },
        upgrade_reviews: Vec::new(),
        review_gaps: Vec::new(),
    })
}

fn kind(base: Option<&Package>, head: Option<&Package>) -> &'static str {
    let (Some(base), Some(head)) = (base, head) else {
        return if base.is_none() { "added" } else { "removed" };
    };
    let old: Vec<_> = base.versions.difference(&head.versions).collect();
    let new: Vec<_> = head.versions.difference(&base.versions).collect();
    if old.is_empty() && new.is_empty() {
        return "scope_changed";
    }
    if old.len() != 1 || new.len() != 1 {
        return "changed";
    }
    let (Some(old), Some(new)) = (numeric_version(old[0]), numeric_version(new[0])) else {
        return "changed";
    };
    match old.cmp(&new) {
        std::cmp::Ordering::Less => "upgraded",
        std::cmp::Ordering::Greater => "downgraded",
        std::cmp::Ordering::Equal => "changed",
    }
}

fn numeric_version(version: &str) -> Option<[u64; 3]> {
    let parts: Vec<_> = version.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|p| {
            p.is_empty()
                || !p.bytes().all(|b| b.is_ascii_digit())
                || (p.len() > 1 && p.starts_with('0'))
        })
    {
        return None;
    }
    Some([
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ])
}

pub(crate) fn transitions(change: &mut Change) -> Vec<upgrade::Package> {
    let Some(head) = &change.head else {
        return Vec::new();
    };
    let mut transitions = BTreeSet::new();
    for (source, target) in &head.direct {
        let current = change
            .base
            .as_ref()
            .and_then(|p| p.direct.get(source))
            .cloned()
            .unwrap_or_default();
        let old: Vec<_> = current.difference(target).collect();
        let new: Vec<_> = target.difference(&current).collect();
        if new.is_empty() {
            continue;
        }
        let Some(registry) = &change.key.registry else {
            continue;
        };
        if old.len() != 1 || new.len() != 1 {
            change.review_gaps.push(format!("{source}: no unique previous/target direct version; additions and ambiguous transitions cannot be reviewed"));
            continue;
        }
        let package = upgrade::Package {
            registry: registry.clone(),
            name: change.key.name.clone(),
            current_version: old[0].clone(),
            target_version: new[0].clone(),
        };
        if package.supported() {
            transitions.insert(package);
        } else {
            change.review_gaps.push(format!(
                "{source}: registry or version unsupported by upgrade review"
            ));
        }
    }
    transitions.into_iter().collect()
}

#[cfg(test)]
mod tests;
