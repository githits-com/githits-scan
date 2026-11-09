//! Scoped advisory details and distinct source qualifications.
use super::{Display, View, package, view};
use serde_json::value::RawValue;
use std::io;

pub(super) fn write(v: &View, d: &mut Display<'_>) -> io::Result<()> {
    d.heading(&format!("Advisories: {}", v.advisories.status))?;
    if let Some(reason) = &v.advisories.reason {
        d.line(reason)?;
    }
    let Some(data) = v
        .advisories
        .decode::<view::Advisories>()
        .map_err(io::Error::other)?
    else {
        return d.line("No assessment is inferred from this section status; inspect JSON for additional evidence.");
    };
    d.line("Showing changed-coordinate deltas and the recorded repository union; full source, unit and project scopes remain in JSON.")?;
    for transition in &data.coordinate_transitions {
        let context = v
            .changes
            .iter()
            .find(|c| c.id == transition.change_id)
            .map_or_else(
                || transition.change_id.clone(),
                |c| format!("{} in {}", package(&c.package), c.source_key),
            );
        if transition.deltas.is_empty() {
            d.item(&format!(
                "{context}: no advisory deltas returned; coverage qualifications still apply."
            ))?;
        }
        deltas(&context, transition.deltas.iter(), &data.findings, d)?;
    }
    for exposure in &data.exposures {
        let scope = &exposure.scope;
        let location = scope
            .source_key
            .clone()
            .or_else(|| scope.manifest_path.clone())
            .or_else(|| scope.unit_key.as_ref().map(|v| v.join(" / ")))
            .unwrap_or_default();
        let scope_label = format!("{} {location}", scope.kind.replace('_', " "));
        let label = format!("{} [{}]", scope_label.trim(), scope.qualifier);
        if scope.kind == "repository_union" {
            deltas(
                &label,
                exposure.deltas.iter().filter(|r| r.kind != "non_affecting"),
                &data.findings,
                d,
            )?;
        }
        for (side, coverage) in exposure
            .coverage
            .iter()
            .filter(|(_, c)| c.inventory != "complete" || c.assessment != "complete")
        {
            d.item(&format!(
                "{label}, {side}: inventory {}; assessment {} ({}/{} coordinates checked; {} unqualified occurrences)",
                coverage.inventory, coverage.assessment, coverage.checked, coverage.coordinates,
                number(coverage.unqualified_occurrences)
            ))?;
        }
    }
    if let Some(coverage) = &v.advisories.coverage {
        let c: view::AdvisoryCoverage =
            serde_json::from_str(coverage.get()).map_err(io::Error::other)?;
        d.line(&format!(
            "Coordinate checks: {}; candidates {}; unknown {}; unsupported {}.",
            number(c.checked),
            number(c.coordinates),
            number(c.unknown),
            number(c.unsupported)
        ))?;
    }
    Ok(())
}

fn number(n: Option<u64>) -> String {
    n.map_or_else(|| "not supplied".into(), |n| n.to_string())
}

fn deltas<'a>(
    context: &str,
    rows: impl Iterator<Item = &'a view::Delta>,
    findings: &[view::Finding],
    d: &mut Display<'_>,
) -> io::Result<()> {
    for delta in rows {
        let finding = findings.iter().find(|f| f.id == delta.finding_id);
        let label = finding.map_or_else(
            || format!("unresolved finding {}", delta.finding_id),
            |f| format!("{} ({})", f.osv_id, package(&f.package)),
        );
        d.item(&format!(
            "{context}: {} {label}; {} → {}",
            delta.kind, delta.base.status, delta.head.status
        ))?;
        if let Some(summary) = finding.and_then(|f| f.summary.as_ref()) {
            d.item(&format!("  {summary}"))?;
        }
        for (side, assessment) in [("base", &delta.base), ("head", &delta.head)]
            .into_iter()
            .filter(|(_, a)| !a.reasons.is_empty())
        {
            d.item(&format!("  {side}: {}", assessment.reasons.join(", ")))?;
        }
    }
    Ok(())
}

pub(super) fn gaps(raw: &RawValue, side: &str, d: &mut Display<'_>) -> io::Result<()> {
    let coverage: view::Coverage = serde_json::from_str(raw.get()).map_err(io::Error::other)?;
    if coverage.partial == Some(true) {
        d.line(&format!("{side}: source evidence partial."))?;
    }
    for (kind, rows) in [
        ("source", coverage.sources),
        ("resolution", coverage.resolution),
        ("excluded dependency", coverage.excluded_dependencies),
        ("manifest/lock mismatch", coverage.mismatches),
    ] {
        for row in rows {
            d.item(&format!(
                "{side} {kind}: {} {}; {}",
                row.path.unwrap_or_default(),
                row.name.unwrap_or_default(),
                row.reason.unwrap_or_else(|| row.reasons.join(", "))
            ))?;
        }
    }
    for row in coverage.reachability.iter().filter(|r| !r.complete) {
        d.item(&format!(
            "{side}: project reachability not established for {} via {} ({})",
            row.manifest_path, row.source_key, row.basis
        ))?;
    }
    Ok(())
}
