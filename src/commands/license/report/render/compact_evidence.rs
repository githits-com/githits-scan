//! Typed schema-2 evidence; no synthetic legacy properties or policy conclusions.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use crate::api::licenses::compact::{self, Diagnostic, Inputs};
use crate::commands::license::display;

use super::{Row, evidence, fields, label, repeats_primary, safe};

pub(super) fn inputs(inputs: &Inputs, out: &mut dyn Write) -> io::Result<()> {
    let paths: BTreeSet<_> = inputs
        .manifest_paths
        .iter()
        .chain(&inputs.lockfile_paths)
        .collect();
    for path in paths {
        writeln!(out, "  input file: {}", safe(path))?;
    }
    Ok(())
}

fn code(out: &mut dyn Write, label: &str, value: Option<&str>, routine: &[&str]) -> io::Result<()> {
    if let Some(value) = value.filter(|v| !routine.contains(v)) {
        writeln!(out, "  {label}: {}", outcome(value))?;
    }
    Ok(())
}

pub(super) fn component(c: &compact::Component, out: &mut dyn Write) -> io::Result<()> {
    for (label, value, routine) in [
        ("metadata", c.metadata_status.as_deref(), &["available"][..]),
        ("metadata reason", c.metadata_reason.as_deref(), &[][..]),
        (
            "package URL omitted",
            c.purl_omission_reason.as_deref(),
            &[][..],
        ),
        (
            "resolution basis",
            c.resolution_basis.as_deref(),
            &["lockfile_record"][..],
        ),
        (
            "resolution limitation",
            c.resolution_limitation.as_deref(),
            &[][..],
        ),
        (
            "component classification basis",
            c.type_basis.as_deref(),
            &[][..],
        ),
        (
            "source kind",
            c.source_kind.as_deref(),
            &[
                "LOCKED_PACKAGE_SOURCE_KIND_REGISTRY",
                "LOCKED_PACKAGE_SOURCE_KIND_LOCAL",
            ][..],
        ),
        (
            "source locator omitted",
            c.source_locator_omission_reason.as_deref(),
            &[][..],
        ),
        (
            "source revision omitted",
            c.source_revision_omission_reason.as_deref(),
            &[][..],
        ),
        (
            "source selector omitted",
            c.source_selector_omission_reason.as_deref(),
            &[][..],
        ),
        (
            "source selector basis",
            c.source_selector_basis.as_deref(),
            &[][..],
        ),
        (
            "source selector kind",
            c.source_selector_kind.as_deref(),
            &[][..],
        ),
    ] {
        code(out, label, value, routine)?;
    }
    fields(
        out,
        "  ",
        None,
        &[
            ("recorded source revision", c.source_revision.as_deref()),
            ("recorded source selector", c.source_selector.as_deref()),
        ],
    )?;
    if let Some(p) = &c.publisher_evidence {
        code(
            out,
            "publisher capture",
            p.capture_status.as_deref(),
            &["present"],
        )?;
        code(
            out,
            "publisher statement coverage",
            p.coverage.as_deref(),
            &["complete"],
        )?;
    }
    let Some(e) = &c.license_evidence else {
        return Ok(());
    };
    independent(c, e, out)
}

fn independent(
    c: &compact::Component,
    e: &compact::Evidence,
    out: &mut dyn Write,
) -> io::Result<()> {
    let source_routine = if c.publisher_evidence.is_some() {
        &["registry_declared"][..]
    } else {
        &[][..]
    };
    for (label, value, routine) in [
        (
            "license evidence source",
            e.source.as_deref(),
            source_routine,
        ),
        ("license evidence scope", e.origin_scope.as_deref(), &[][..]),
        (
            "license applicability",
            e.applicability_reason.as_deref(),
            &["publisher_release_metadata", "uploaded_declaration"][..],
        ),
        (
            "license lookup",
            e.lookup_basis.as_deref(),
            &["registry_name_version"][..],
        ),
        (
            "artifact verification",
            e.artifact_verification.as_deref(),
            &["not_checked"][..],
        ),
        (
            "license interpretation",
            e.status.as_deref(),
            &["expression", "absent"][..],
        ),
        ("license syntax", e.syntax.as_deref(), &["spdx"][..]),
    ] {
        code(out, label, value, routine)?;
    }
    if let Some(raw) = e
        .raw
        .as_deref()
        .filter(|raw| !repeats_primary(&c.licenses, raw))
    {
        display::field(out, "  license statement: ", raw, true)?;
    }
    for method in &e.interpretation_methods {
        code(
            out,
            "license interpretation method",
            Some(method),
            &["spdx_expression"],
        )?;
    }
    for issue in &e.issues {
        writeln!(out, "  license issue: {}", evidence::issue_text(issue))?;
    }
    Ok(())
}

pub(super) fn coverage(view: &compact::View, out: &mut dyn Write) -> io::Result<()> {
    let inventory = &view.inventory;
    code(
        out,
        "inventory construction",
        inventory.resolution_basis.as_deref(),
        &["lockfile_records"],
    )?;
    code(
        out,
        "component classification basis",
        inventory.component_type_basis.as_deref(),
        &[],
    )?;
    let owners: BTreeMap<_, _> = view
        .components
        .iter()
        .filter_map(|c| c.bom_ref.as_deref().map(|reference| (reference, c)))
        .collect();
    for notice in &inventory.notices {
        writeln!(out, "  notice: {}", safe(notice))?;
    }
    for group in &inventory.coverage {
        coverage_group(group, out)?;
    }
    for (owner, coverage) in &inventory.dependency_coverage {
        if coverage.state.as_deref() == Some("complete") && coverage.reasons.is_empty() {
            continue;
        }
        write!(out, "  dependency coverage: ")?;
        coverage_owner(owner, &owners, out)?;
        writeln!(
            out,
            ": {}",
            outcome(coverage.state.as_deref().unwrap_or("unknown"))
        )?;
        for reason in &coverage.reasons {
            code(out, "  reason", Some(reason), &[])?;
        }
    }
    for resolution in &inventory.resolutions {
        resolution_details(resolution, view, out)?;
    }
    for lockfile in &inventory.lockfiles {
        lockfile_details(lockfile, out)?;
    }
    for agreement in &inventory.declaration_agreement {
        agreement_details(agreement, out)?;
    }
    Ok(())
}

fn coverage_group(group: &compact::Coverage, out: &mut dyn Write) -> io::Result<()> {
    let scopes = [
        ("component inventory", group.assemblies.as_ref()),
        ("dependency relationships", group.dependencies.as_ref()),
        ("service inventory", group.services.as_ref()),
    ];
    if scopes.iter().all(|(_, refs)| refs.is_none()) {
        return writeln!(
            out,
            "  inventory coverage: {}; unrecognized scope (retained in JSON)",
            outcome(group.aggregate.as_deref().unwrap_or("unknown"))
        );
    }
    for (scope, refs) in scopes {
        let Some(refs) = refs else { continue };
        if group.aggregate.as_deref() == Some("complete") && !refs.is_empty() {
            continue;
        }
        let suffix = if refs.is_empty() {
            "; no subject references reported"
        } else {
            ""
        };
        writeln!(
            out,
            "  {scope}: {}{suffix}",
            outcome(group.aggregate.as_deref().unwrap_or("unknown"))
        )?;
    }
    Ok(())
}

fn coverage_owner(
    owner: &str,
    owners: &BTreeMap<&str, &compact::Component>,
    out: &mut dyn Write,
) -> io::Result<()> {
    let Some(c) = owners.get(owner) else {
        return write!(out, "unresolved reference {}", safe(owner));
    };
    write!(out, "{}", label(&Row::Compact(c), false, None).text.value)?;
    let paths: BTreeSet<_> = c
        .inputs
        .manifest_paths
        .iter()
        .chain(&c.inputs.lockfile_paths)
        .map(String::as_str)
        .collect();
    super::input_summary(paths, out)
}

fn diagnostics(values: &[Diagnostic], out: &mut dyn Write) -> io::Result<()> {
    for value in values {
        match value {
            Diagnostic::Known { name, reason }
                if name.as_deref().is_some_and(|n| !n.is_empty()) || reason.is_some() =>
            {
                fields(
                    out,
                    "    ",
                    Some("diagnostic"),
                    &[
                        ("name", name.as_deref()),
                        ("reason", reason.as_deref().map(outcome)),
                    ],
                )?;
            }
            _ => writeln!(
                out,
                "    diagnostic: unrecognized evidence (retained in JSON)"
            )?,
        }
    }
    Ok(())
}

fn resolution_details(
    r: &compact::Resolution,
    view: &compact::View,
    out: &mut dyn Write,
) -> io::Result<()> {
    if r.status.as_deref() == Some("complete") && r.diagnostics.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "  resolution: {}: {}",
        safe(r.path.as_deref().unwrap_or("input not reported")),
        outcome(r.status.as_deref().unwrap_or("unknown"))
    )?;
    diagnostics(&r.diagnostics, out)?;
    if r.status.as_deref() == Some("complete") {
        return Ok(());
    }
    let Some(path) = &r.path else { return Ok(()) };
    for declaration in view
        .inventory
        .declarations
        .iter()
        .filter(|d| d.manifest_path.as_ref() == Some(path))
    {
        fields(
            out,
            "    ",
            Some("declaration"),
            &[
                ("name", declaration.name.as_deref()),
                ("requested", declaration.declared_requirement.as_deref()),
                ("scope", declaration.declared_scope.as_deref()),
            ],
        )?;
    }
    Ok(())
}

fn lockfile_details(l: &compact::Lockfile, out: &mut dyn Write) -> io::Result<()> {
    let association = l
        .association_status
        .as_deref()
        .filter(|s| *s != "associated");
    let completeness = l
        .completeness
        .as_deref()
        .filter(|s| *s != "LOCKFILE_COMPLETENESS_PACKAGE_ENTRIES_AND_RECORDED_RELATIONSHIPS");
    if association.is_none()
        && completeness.is_none()
        && l.manifest_lock_consistency.is_none()
        && l.association_diagnostics.is_empty()
        && l.projection_notices.is_empty()
    {
        return Ok(());
    }
    writeln!(
        out,
        "  lockfile: {}",
        safe(l.path.as_deref().unwrap_or("input not reported"))
    )?;
    for path in &l.manifest_paths {
        writeln!(out, "    manifest: {}", safe(path))?;
    }
    if let Some(association) = association {
        writeln!(out, "    association: {}", outcome(association))?;
    }
    code(out, "  recorded inventory", completeness, &[])?;
    code(
        out,
        "  manifest/lockfile consistency",
        l.manifest_lock_consistency.as_deref(),
        &[],
    )?;
    diagnostics(&l.association_diagnostics, out)?;
    for notice in &l.projection_notices {
        writeln!(out, "    notice: {}", safe(notice))?;
    }
    Ok(())
}

fn agreement_details(a: &compact::Agreement, out: &mut dyn Write) -> io::Result<()> {
    if a.status.as_deref() == Some("matched") {
        return Ok(());
    }
    fields(
        out,
        "  ",
        Some("declaration agreement"),
        &[
            ("name", a.name.as_deref()),
            ("lockfile", a.path.as_deref()),
            ("declaration", a.declaration_path.as_deref()),
            ("scope", a.declared_scope.as_deref()),
            ("requested", a.requested_requirement.as_deref()),
            (
                "outcome",
                Some(outcome(a.status.as_deref().unwrap_or("unknown"))),
            ),
            ("requirement", a.requirement_status.as_deref().map(outcome)),
        ],
    )?;
    for scope in &a.recorded_scopes {
        writeln!(out, "    recorded scope: {}", safe(scope))?;
    }
    for (label, versions) in [
        ("matched version", &a.matched_versions),
        ("locked version", &a.locked_versions),
    ] {
        for version in versions {
            writeln!(
                out,
                "    {label}: {}",
                safe(version.as_deref().unwrap_or("not reported"))
            )?;
        }
    }
    Ok(())
}

fn outcome(value: &str) -> &'static str {
    match value {
        "ambiguous" => "ambiguous",
        "absent" => "absent",
        _ => display::evidence_code(value),
    }
}
