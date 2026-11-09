//! Checked effects beside changes; supporting request evidence is inspection-only.
use super::{owner, request_requirement, safe};
use crate::api::audit::remediation::reasons::Request;
use crate::commands::audit::view::remediation::{Change, Finding, Record, reasons::Reason};
use std::collections::BTreeSet;
use std::io::{self, Write};

/// Selects concise report explanations or their supporting evidence.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::commands::audit) enum ReasonDetail {
    /// Show checked effects without a request inventory.
    Summary,
    /// Also show request evidence, unavailable and unknown reason states.
    Evidence,
}

/// Write each distinct checked effect at its owning change.
pub(super) fn write(
    change: &Change,
    record: &Record,
    detail: ReasonDetail,
    paths_shown: bool,
    out: &mut dyn Write,
) -> io::Result<()> {
    let mut seen = BTreeSet::new();
    for reason in change.reasons.iter().flatten() {
        let mut text = Vec::new();
        reason_line(reason, change, record, detail, paths_shown, &mut text)?;
        if seen.insert(text.clone()) {
            out.write_all(&text)?;
        }
    }
    Ok(())
}
fn reason_line(
    reason: &Reason,
    change: &Change,
    record: &Record,
    detail: ReasonDetail,
    paths_shown: bool,
    out: &mut dyn Write,
) -> io::Result<()> {
    match reason {
        Reason::Advisory { findings } => {
            if findings.is_empty() || redundant(findings, record, detail) {
                return Ok(());
            }
            let changed = format!(
                "{}:{}@{}",
                change.data.registry, change.data.name, change.data.from_version
            );
            let identities = super::finding_names(findings, &[], &changed);
            writeln!(out, "        why: addresses {identities}")?;
        }
        Reason::Enables {
            dependency,
            path,
            original_requests,
            replacement_requests,
        } => {
            writeln!(
                out,
                "        why: accepts {}, which the current request excludes{}",
                safe(&dependency.to_string()),
                file(path, change, paths_shown)
            )?;
            evidence("original request", original_requests, detail, out)?;
            evidence("replacement request", replacement_requests, detail, out)?;
        }
        Reason::Removes {
            dependency,
            path,
            original_requests,
        } => {
            writeln!(
                out,
                "        why: removes a route to {}{}",
                safe(&dependency.to_string()),
                file(path, change, paths_shown)
            )?;
            evidence("original request", original_requests, detail, out)?;
        }
        Reason::Unavailable if detail == ReasonDetail::Evidence => {
            writeln!(out, "        reason unavailable")?;
        }
        Reason::Unknown { code } if detail == ReasonDetail::Evidence => {
            writeln!(out, "        unrecognized reason: {}", safe(code))?;
        }
        Reason::Unavailable | Reason::Unknown { .. } => {}
    }
    Ok(())
}
fn redundant(findings: &[Finding], record: &Record, detail: ReasonDetail) -> bool {
    detail == ReasonDetail::Summary
        && record.changes.len() == 1
        && findings.iter().collect::<BTreeSet<_>>() == record.addressed_findings.iter().collect()
}
fn file(path: &str, change: &Change, shown: bool) -> String {
    if shown && change.data.paths.len() == 1 && change.data.paths[0] == path {
        String::new()
    } else {
        format!(" [{}]", safe(path))
    }
}
fn evidence(
    label: &str,
    requests: &[Request],
    detail: ReasonDetail,
    out: &mut dyn Write,
) -> io::Result<()> {
    if detail != ReasonDetail::Evidence {
        return Ok(());
    }
    for request in requests {
        writeln!(
            out,
            "          {label}: {} {} [{}]",
            owner(&request.owner.name, request.owner.version.as_deref()),
            request_requirement(
                request.dependency_name.as_deref(),
                request.requested_requirement.as_deref(),
                &request.requirement_status
            ),
            safe(&request.path)
        )?;
    }
    Ok(())
}
