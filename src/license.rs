//! License policy evaluation over a CycloneDX document.
//!
//! Pure: a document's bytes and a [`Policy`] in, a [`Report`] out. Every
//! component's license evidence is evaluated as an SPDX expression against
//! the allow list: `OR` passes if any operand is allowed, `AND` needs every
//! operand, `WITH` needs the full `<id> WITH <exception>` string to be
//! allowed. Only explicit SPDX identifiers and upper-/lower-case operators
//! are interpreted; names and slash-separated text are never guessed. Formal
//! GNU postfix-plus notation is canonicalized. Missing or unrecognized evidence
//! is a violation. Package-wide exceptions require versionless package URLs.
//! Project-root and local-source markers exclude their own node, not descendants.
//! A local source marker describes location, not proof of first-party ownership.

use std::collections::BTreeSet;

use serde_json::Value;
use thiserror::Error;

use crate::config::{Exception, Licenses};

/// The allow list and exceptions from the configuration, ready to evaluate.
#[derive(Debug, Clone)]
pub struct Policy {
    allowed: BTreeSet<String>,
    exceptions: Vec<Exception>,
}

impl Policy {
    /// Validate the configured allow list and package-wide exceptions.
    ///
    /// Formal GNU postfix-plus notation is canonicalized, so `GPL-2.0+` and
    /// `GPL-2.0-or-later` match the same requirement. An empty list denies all.
    ///
    /// # Errors
    /// Returns [`PolicyError`] for ambiguous/compound requirements or an exception
    /// URL whose scope would be discarded during package matching.
    pub fn new(licenses: &Licenses) -> Result<Self, PolicyError> {
        let allowed = licenses
            .allow
            .iter()
            .enumerate()
            .map(|(index, entry)| canonical_requirement(entry).ok_or(PolicyError::Allow { index }))
            .collect::<Result<BTreeSet<_>, _>>()?;
        validate_exceptions(&licenses.exceptions)?;
        Ok(Self {
            allowed,
            exceptions: licenses.exceptions.clone(),
        })
    }

    /// Whether one requirement (`MIT`, `GPL-2.0-or-later`, `Apache-2.0 WITH
    /// LLVM-exception`) is allowed, compared as its canonical SPDX string.
    fn allows(&self, requirement: &spdx::LicenseReq) -> bool {
        self.allowed.contains(&requirement.to_string())
    }

    fn exception_for(&self, purl: Option<&str>) -> Option<&Exception> {
        let purl = without_version(purl?);
        self.exceptions
            .iter()
            .find(|exception| without_version(&exception.purl) == purl)
    }
}

fn validate_exceptions(exceptions: &[Exception]) -> Result<(), PolicyError> {
    for (index, exception) in exceptions.iter().enumerate() {
        if !is_unscoped_package(&exception.purl) {
            return Err(PolicyError::Exception { index });
        }
    }
    Ok(())
}

fn is_unscoped_package(purl: &str) -> bool {
    let identity = purl
        .strip_prefix("pkg:")
        .and_then(|url| url.split_once('/'));
    identity
        .is_some_and(|(kind, name)| !kind.is_empty() && !name.is_empty() && !name.ends_with('/'))
        && without_version(purl) == purl
}

/// A configured license policy cannot be applied without guessing its meaning.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// An allow-list entry is not one explicit SPDX requirement.
    #[error(
        "licenses.allow[{index}] must be one explicit SPDX requirement, such as MIT or Apache-2.0 WITH LLVM-exception"
    )]
    Allow {
        /// Zero-based entry index.
        index: usize,
    },
    /// An exception is not an unscoped package identity.
    #[error(
        "licenses.exceptions[{index}].purl must be a package URL without version, qualifiers or subpath; exceptions apply to all versions"
    )]
    Exception {
        /// Zero-based exception index.
        index: usize,
    },
}

/// Why a component violates the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The expression parsed but the allow list does not satisfy it.
    NotAllowed,
    /// The component carries no license evidence at all.
    NoLicense,
    /// The evidence is a free-text name that is not an SPDX expression.
    NonSpdxName,
    /// The evidence claims to be an expression but does not parse.
    UnparsableExpression,
}

impl Reason {
    /// Stable identifier for machine-readable output.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::NotAllowed => "not_allowed",
            Self::NoLicense => "no_license",
            Self::NonSpdxName => "non_spdx_name",
            Self::UnparsableExpression => "unparsable_expression",
        }
    }

    /// Short human wording.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::NotAllowed => "not allowed",
            Self::NoLicense => "license not reported",
            Self::NonSpdxName => "not an SPDX expression",
            Self::UnparsableExpression => "unparsable expression",
        }
    }
}

/// A component the policy rejects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The document's identity for the component.
    pub bom_ref: String,
    /// Package name.
    pub name: String,
    /// Package version, when the document has one.
    pub version: Option<String>,
    /// Package URL, when the document has one.
    pub purl: Option<String>,
    /// The license evidence as written: one entry stays verbatim; several
    /// entries are parenthesized and joined with ` AND ` as a derived
    /// conjunction, not a publisher expression. `None` when there is none.
    pub expression: Option<String>,
    /// Why it is a violation.
    pub reason: Reason,
}

/// An exception that suppressed at least one violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The exception's package URL as configured.
    pub purl: String,
    /// The configured reason.
    pub reason: String,
    /// The components it covered, as `name version`.
    pub components: Vec<String>,
}

/// The outcome of a check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Number of inventory components evaluated, of every component type.
    /// Nodes marked as project roots or local sources do not count.
    pub components: usize,
    /// Local packages (workspace members, path dependencies) that were
    /// excluded by their source marker, regardless of authorship.
    pub local_packages: usize,
    /// Violations, sorted by name, version, and identity.
    pub violations: Vec<Violation>,
    /// Applied exceptions, in inventory encounter order.
    pub exceptions_applied: Vec<Applied>,
    /// The document's `githits:completeness`, when present.
    pub completeness: Option<String>,
    /// Manifest-only projects whose dependencies the service could not fully
    /// resolve, from `githits:resolutions`; their packages were not evaluated.
    pub unresolved: Vec<Unresolved>,
}

/// A project whose dependencies were not fully resolved, so their licenses
/// were never seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    /// The manifest path, relative to the scanned directory.
    pub path: String,
    /// The resolution status the service reported, such as `partial`.
    pub status: String,
    /// Distinct diagnostic reasons, such as `unsupported_ecosystem`.
    pub reasons: Vec<String>,
}

/// Why the bytes could not be checked.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DocumentError {
    /// Not JSON.
    #[error("the document is not JSON: {0}")]
    NotJson(String),
    /// JSON, but not a CycloneDX document.
    #[error(
        "the document is not a CycloneDX bill of materials (bomFormat is missing or not \"CycloneDX\")"
    )]
    NotCycloneDx,
    /// CycloneDX, but a field the check relies on has the wrong shape, so some
    /// packages or license evidence could not be evaluated.
    #[error("the CycloneDX document is malformed: {0}")]
    Malformed(String),
}

/// Evaluate the component inventory and all nested assemblies in CycloneDX JSON.
///
/// # Errors
///
/// Returns [`DocumentError`] when `document` is not a CycloneDX JSON document.
pub fn check(document: &[u8], policy: &Policy) -> Result<Report, DocumentError> {
    let value: Value = serde_json::from_slice(document)
        .map_err(|error| DocumentError::NotJson(error.to_string()))?;
    if value.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX") {
        return Err(DocumentError::NotCycloneDx);
    }
    let mut report = Report {
        completeness: property(&value, "githits:completeness").map(str::to_owned),
        unresolved: unresolved(&value)?,
        ..Report::default()
    };
    let mut applied: Vec<Applied> = Vec::new();
    check_components(&value, policy, &mut report, &mut applied)?;
    report
        .violations
        .sort_by(|a, b| (&a.name, &a.version, &a.bom_ref).cmp(&(&b.name, &b.version, &b.bom_ref)));
    report.exceptions_applied = applied;
    Ok(report)
}

fn check_components(
    parent: &Value,
    policy: &Policy,
    report: &mut Report,
    applied: &mut Vec<Applied>,
) -> Result<(), DocumentError> {
    let Some(components) = parent.get("components") else {
        return Ok(());
    };
    let components = components
        .as_array()
        .ok_or_else(|| DocumentError::Malformed("`components` is not an array".to_owned()))?;
    for (index, component) in components.iter().enumerate() {
        validate_component(component, index)?;
        check_component(component, policy, report, applied);
        check_components(component, policy, report, applied)
            .map_err(|error| nested_error(error, index))?;
    }
    Ok(())
}

fn nested_error(error: DocumentError, index: usize) -> DocumentError {
    if let DocumentError::Malformed(detail) = error {
        return DocumentError::Malformed(format!("component {index}: {detail}"));
    }
    error
}

fn check_component(
    component: &Value,
    policy: &Policy,
    report: &mut Report,
    applied: &mut Vec<Applied>,
) {
    if property(component, "githits:record_kind") == Some("manifest") {
        return;
    }
    if property(component, "githits:source_kind") == Some("LOCKED_PACKAGE_SOURCE_KIND_LOCAL") {
        report.local_packages += 1;
        return;
    }
    report.components += 1;
    let Some(reason) = evaluate(component, policy) else {
        return;
    };
    let purl = string(component, "purl");
    if let Some(exception) = policy.exception_for(purl) {
        record_exception(applied, exception, component);
        return;
    }
    report.violations.push(Violation {
        bom_ref: string(component, "bom-ref").unwrap_or_default().to_owned(),
        name: string(component, "name").unwrap_or_default().to_owned(),
        version: string(component, "version").map(str::to_owned),
        purl: purl.map(str::to_owned),
        expression: evidence(component),
        reason,
    });
}

/// Projects whose `githits:resolutions` status is anything but `complete`. A
/// resolutions property that cannot be read is malformed: treating it as
/// absent would let unresolved dependencies pass unseen.
fn unresolved(document: &Value) -> Result<Vec<Unresolved>, DocumentError> {
    let Some(text) = property(document, "githits:resolutions") else {
        return Ok(Vec::new());
    };
    let malformed = || {
        DocumentError::Malformed("`githits:resolutions` is not a list of resolutions".to_owned())
    };
    let entries: Vec<Value> = serde_json::from_str(text).map_err(|_| malformed())?;
    let mut unresolved = Vec::new();
    for entry in &entries {
        let (Some(path), Some(status)) = (string(entry, "path"), string(entry, "status")) else {
            return Err(malformed());
        };
        if status == "complete" {
            continue;
        }
        let mut reasons: Vec<String> = entry
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(|diagnostic| string(diagnostic, "reason").map(str::to_owned))
            .collect();
        reasons.sort();
        reasons.dedup();
        unresolved.push(Unresolved {
            path: path.to_owned(),
            status: status.to_owned(),
            reasons,
        });
    }
    unresolved.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(unresolved)
}

/// Reject evidence that would otherwise be silently skipped.
fn validate_component(component: &Value, index: usize) -> Result<(), DocumentError> {
    if !component.is_object() {
        return Err(DocumentError::Malformed(format!(
            "component {index} is not an object"
        )));
    }
    let Some(licenses) = component.get("licenses") else {
        return Ok(());
    };
    let licenses = licenses.as_array().ok_or_else(|| {
        DocumentError::Malformed(format!("component {index}: `licenses` is not an array"))
    })?;
    if let Some(entry) = licenses.iter().position(|entry| !is_license_entry(entry)) {
        return Err(DocumentError::Malformed(format!(
            "component {index}: license entry {entry} has no `expression`, `license.id`, or `license.name` string"
        )));
    }
    Ok(())
}

fn is_license_entry(entry: &Value) -> bool {
    string(entry, "expression").is_some()
        || entry.get("license").is_some_and(|license| {
            string(license, "id").is_some() || string(license, "name").is_some()
        })
}

/// `None` when the component satisfies the policy, otherwise why not.
fn evaluate(component: &Value, policy: &Policy) -> Option<Reason> {
    let entries: Vec<(&str, bool)> = license_entries(component);
    if entries.is_empty() {
        return Some(Reason::NoLicense);
    }
    for (text, is_name) in entries {
        let Ok(expression) = parse(text) else {
            return Some(parse_failure(is_name));
        };
        if !expression.evaluate(|requirement| policy.allows(requirement)) {
            return Some(Reason::NotAllowed);
        }
    }
    None
}

/// Interpret explicit syntax only, retaining formal GNU postfix-plus notation.
fn parse(text: &str) -> Result<spdx::Expression, spdx::ParseError> {
    spdx::Expression::parse_mode(
        text,
        spdx::ParseMode {
            allow_imprecise_license_names: false,
            allow_slash_as_or_operator: false,
            ..spdx::ParseMode::LAX
        },
    )
}

/// The canonical string of an allow-list entry that is exactly one
/// requirement; `None` for anything else.
fn canonical_requirement(entry: &str) -> Option<String> {
    let expression = parse(entry).ok()?;
    let mut requirements = expression.requirements();
    let first = requirements.next()?;
    if requirements.next().is_some() {
        return None;
    }
    Some(first.req.to_string())
}

const fn parse_failure(is_name: bool) -> Reason {
    if is_name {
        Reason::NonSpdxName
    } else {
        Reason::UnparsableExpression
    }
}

/// `name version`, or just the name without one.
#[must_use]
pub fn package_label(name: &str, version: Option<&str>) -> String {
    version.map_or_else(|| name.to_owned(), |version| format!("{name} {version}"))
}

/// Every license entry as `(text, is_free_text_name)`. An `expression` or a
/// `license.id` is an SPDX string; a `license.name` is free text that may
/// still happen to be a valid expression.
fn license_entries(component: &Value) -> Vec<(&str, bool)> {
    component
        .get("licenses")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| {
            if let Some(expression) = string(entry, "expression") {
                return Some((expression, false));
            }
            let license = entry.get("license")?;
            string(license, "id")
                .map(|id| (id, false))
                .or_else(|| string(license, "name").map(|name| (name, true)))
        })
        .collect()
}

fn evidence(component: &Value) -> Option<String> {
    let entries = license_entries(component);
    if entries.is_empty() {
        return None;
    }
    if entries.len() == 1 {
        return Some(entries[0].0.to_owned());
    }
    Some(
        entries
            .iter()
            .map(|(text, _)| format!("({text})"))
            .collect::<Vec<_>>()
            .join(" AND "),
    )
}

fn record_exception(applied: &mut Vec<Applied>, exception: &Exception, component: &Value) {
    let label = package_label(
        string(component, "name").unwrap_or_default(),
        string(component, "version"),
    );
    if let Some(existing) = applied.iter_mut().find(|a| a.purl == exception.purl) {
        existing.components.push(label);
        return;
    }
    applied.push(Applied {
        purl: exception.purl.clone(),
        reason: exception.reason.clone(),
        components: vec![label],
    });
}

fn string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// A named entry of a CycloneDX `properties` array.
fn property<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    value
        .get("properties")?
        .as_array()?
        .iter()
        .find(|property| string(property, "name") == Some(name))
        .and_then(|property| string(property, "value"))
}

/// A package URL without its `@version`, keeping qualifiers and subpath out
/// of the comparison as well: `pkg:npm/%40scope/name@1.2.3?x=y` becomes
/// `pkg:npm/%40scope/name`.
fn without_version(purl: &str) -> &str {
    let end = purl.find(['?', '#']).unwrap_or(purl.len());
    let base = &purl[..end];
    let name_start = base.rfind('/').map_or(0, |i| i + 1);
    base[name_start..]
        .find('@')
        .map_or(base, |at| &base[..name_start + at])
}

#[cfg(test)]
mod tests;
