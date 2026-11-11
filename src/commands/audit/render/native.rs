//! Compact native input problems, kept separate from vulnerability remedies.
use std::io::{self, Write};

use super::{heading, list, request, safe};
use crate::api::audit::report::{ManifestLockMismatch, NativeConditions};
use crate::commands::audit::view::{MissingRequest, View};
use crate::style::Palette;

pub(super) fn mismatches(view: &View, out: &mut dyn Write, palette: Palette) -> io::Result<()> {
    if view.manifest_lock_mismatches.is_empty() {
        return Ok(());
    }
    heading(
        "Manifest/lock disagreements",
        view.manifest_lock_mismatches.len(),
        out,
        palette,
    )?;
    for item in &view.manifest_lock_mismatches {
        mismatch(item, out)?;
    }
    Ok(())
}

fn mismatch(item: &ManifestLockMismatch, out: &mut dyn Write) -> io::Result<()> {
    writeln!(
        out,
        "  {}; locked {} [{} → {}]",
        request(
            Some(&item.name),
            item.requested_requirement.as_deref(),
            &item.requirement_status
        ),
        if item.locked_versions.is_empty() {
            "versions unavailable".into()
        } else {
            list(&item.locked_versions)
        },
        safe(&item.declaration_path),
        safe(&item.path)
    )?;
    match item.reason.as_str() {
        "locked_version_does_not_satisfy_request" => writeln!(
            out,
            "    locked version does not satisfy the declaration; refresh the lockfile if this declaration is intended"
        ),
        "recorded_git_source_differs" => writeln!(
            out,
            "    the Git source recorded in the lockfile differs from the declaration; reconcile the dependency source and lockfile"
        ),
        "recorded_requirement_differs" => writeln!(
            out,
            "    lock records {}; reconcile the declaration and lockfile",
            list(&item.recorded_requirements)
        ),
        "recorded_dependency_scope_differs" => writeln!(
            out,
            "    declared scope {}; lock records {}; reconcile dependency scopes",
            safe(&item.declared_scope),
            list(&item.recorded_scopes)
        ),
        value => writeln!(
            out,
            "    {}; reconcile the declaration and lockfile",
            safe(value)
        ),
    }
}

pub(super) fn missing_requests(items: &[MissingRequest], out: &mut dyn Write) -> io::Result<()> {
    for item in items {
        let kind = match item.kind.as_deref() {
            Some("PEER") => "missing peer dependency",
            _ => "missing dependency",
        };
        write!(out, "    {kind}: {}", safe(&item.name))?;
        if item.requirement_status.as_deref() == Some("recorded") {
            match item
                .requested_requirement
                .as_deref()
                .filter(|r| !r.is_empty())
            {
                Some(range) => write!(out, " {}", safe(range))?,
                None => write!(out, " (requirement missing)")?,
            }
        } else {
            let status = item.requirement_status.as_deref().unwrap_or("unavailable");
            write!(out, " (requirement {})", super::requirement_status(status))?;
        }
        write!(out, " — requested by {}", safe(&item.requester))?;
        if let Some(kind) = item.kind.as_deref().filter(|kind| *kind != "PEER") {
            write!(out, " (kind: {})", safe(kind))?;
        }
        if let Some(scope) = &item.requester_scope {
            write!(out, " (requester scope: {})", safe(scope))?;
        }
        writeln!(out)?;
        if let Some(conditions) = &item.conditions {
            conditions_line(conditions, out)?;
        }
    }
    Ok(())
}

fn conditions_line(c: &NativeConditions, out: &mut dyn Write) -> io::Result<()> {
    let mut values = Vec::new();
    for (label, value) in [
        ("marker", &c.marker),
        ("Python", &c.requires_python),
        ("group", &c.dependency_group),
    ] {
        if let Some(value) = value {
            values.push(format!("{label}: {}", safe(value)));
        }
    }
    if !c.requested_extras.is_empty() {
        values.push(format!("extras: {}", list(&c.requested_extras)));
    }
    if c.marker_unavailable == Some(true) {
        values.push("marker unavailable".into());
    }
    if c.bundler_source_pinned == Some(true) {
        values.push("source pinned".into());
    }
    if c.bun_bundled == Some(true) {
        values.push("bundled".into());
    }
    if let Some(r) = &c.paket_restriction {
        values.push(format!("{}: {}", safe(&r.syntax), safe(&r.expression)));
    }
    if values.is_empty() {
        return Ok(());
    }
    writeln!(out, "      context: {}", values.join("; "))
}
