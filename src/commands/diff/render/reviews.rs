//! Direct upgrade attention evidence, without inventing migration advice or URLs.
use super::{Display, View, view};
use std::io;

pub(super) fn write(v: &View, d: &mut Display<'_>) -> io::Result<()> {
    d.heading(&format!(
        "Direct upgrade reviews: {}",
        v.direct_reviews.status
    ))?;
    if let Some(reason) = &v.direct_reviews.reason {
        d.line(reason)?;
    }
    let Some(rows) = v
        .direct_reviews
        .decode::<Vec<view::Review>>()
        .map_err(io::Error::other)?
    else {
        return d.line("Review evidence is not interpreted for this section status.");
    };
    for r in rows {
        d.item(&format!(
            "{}:{} {} → {}: {}{}",
            r.registry,
            r.name,
            r.current_version,
            r.target_version,
            r.status,
            r.reason
                .as_ref()
                .map_or(String::new(), |s| format!(" ({s})"))
        ))?;
        d.item(&format!("  Sources: {}", r.source_keys.join(", ")))?;
        if let Some(data) = r.evidence() {
            detail(&data, d)?;
        } else {
            d.item(
                "  Review detail not interpreted; consult the reported status/reason and JSON.",
            )?;
        }
    }
    if let Some(raw) = &v.direct_reviews.coverage {
        let counts: view::ReviewCoverage =
            serde_json::from_str(raw.get()).map_err(io::Error::other)?;
        d.line(&format!("Review tuples: {} eligible, {} completed, {} returned; {} not assessed, {} unavailable, {} omitted.",
            counts.eligible,counts.completed,counts.returned,counts.not_assessed,counts.unavailable,counts.omitted))?;
    }
    Ok(())
}

fn detail(data: &view::ReviewData, d: &mut Display<'_>) -> io::Result<()> {
    if let Some(security) = &data.security {
        for (side, value) in [("current", &security.current), ("target", &security.target)] {
            let status = security_status(value.as_ref());
            d.item(&format!("  Direct security {side}: {status}"))?;
        }
    } else {
        d.item("  Direct security: unavailable in returned evidence")?;
    }
    for gap in &data.unknown_details {
        d.item(&format!(
            "  {}: {} ({})",
            gap.section, gap.message, gap.code
        ))?;
    }
    let Some(log) = &data.changelog else {
        return d.item("  Changelog: unavailable in returned evidence");
    };
    if let Some(c) = &log.coverage {
        d.item(&format!(
            "  Changelog: {}, {}/{} entries{}",
            c.status,
            c.returned_entries,
            c.total_entries,
            if c.truncated { ", truncated" } else { "" }
        ))?;
    } else {
        d.item("  Changelog coverage: not supplied")?;
    }
    for (label, signals) in [
        ("Breaking signals", &log.breaking_signals),
        ("Migration signals", &log.migration_signals),
    ] {
        if !signals.is_empty() {
            d.item(&format!("  {label}: {}", signals.join(", ")))?;
        }
    }
    let displayed: Vec<_> = log
        .entries
        .iter()
        .enumerate()
        .filter(|(index, entry)| *index < 3 || !entry.signals.is_empty())
        .map(|(_, entry)| entry)
        .collect();
    for entry in &displayed {
        let version = entry.version.as_deref().unwrap_or("unknown release");
        if let Some(headline) = &entry.headline {
            d.item(&format!("  {version}: {headline}"))?;
        }
        if !entry.signals.is_empty() {
            d.item(&format!("  Entry signals: {}", entry.signals.join(", ")))?;
        }
        if let Some(url) = &entry.html_url {
            d.link(&format!("  {version} changelog entry"), url)?;
        }
    }
    if displayed.len() < log.entries.len() {
        d.item(&format!(
            "  {} additional returned changelog entries are available in JSON.",
            log.entries.len() - displayed.len()
        ))?;
    }
    Ok(())
}

fn security_status(value: Option<&view::VersionSecurity>) -> String {
    value.map_or_else(
        || "unavailable".into(),
        |v| {
            format!(
                "{} ({} unknown)",
                v.assessment_status, v.unknown_vulnerability_count
            )
        },
    )
}
