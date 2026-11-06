//! Presentation only; JSON keeps complete facts while tables show changed versions.
use super::Format;
use crate::diff::{Change, Report};
use std::collections::BTreeSet;
use std::io::{self, Write};

pub(super) fn write(report: &Report, format: Format, out: &mut dyn Write) -> io::Result<()> {
    if matches!(format, Format::Json) {
        serde_json::to_writer_pretty(&mut *out, report).map_err(io::Error::other)?;
        return writeln!(out);
    }
    let markdown = matches!(format, Format::Markdown);
    writeln!(
        out,
        "Experimental dependency diff: {} → {}",
        cell(&report.base, markdown),
        cell(&report.head, markdown)
    )?;
    writeln!(out)?;
    if markdown {
        writeln!(
            out,
            "| Package | Scope | Change | Changed versions | Vulns fixed / new / same | Changelog |"
        )?;
        writeln!(out, "| --- | --- | --- | --- | --- | --- |")?;
    } else {
        writeln!(
            out,
            "{:<28} {:<22} {:<14} {:<27} {:<20} Changelog",
            "Package", "Scope", "Change", "Changed versions", "Vulns fixed/new/same"
        )?;
    }
    for change in &report.changes {
        row(change, markdown, out)?;
    }
    if report.changes.is_empty() {
        writeln!(out, "No changes in selected dependency inputs.")?;
    }
    writeln!(out)?;
    for change in &report.changes {
        details(change, markdown, out)?;
    }
    for notice in report.notices.iter().take(10) {
        writeln!(out, "Note: {}", cell(notice, markdown))?;
    }
    if report.notices.len() > 10 {
        writeln!(
            out,
            "{} further notices are available in JSON.",
            report.notices.len() - 10
        )?;
    }
    if report.incomplete {
        writeln!(
            out,
            "Evidence incomplete; this informational command does not enforce a policy."
        )?;
    }
    Ok(())
}

fn row(change: &Change, markdown: bool, out: &mut dyn Write) -> io::Result<()> {
    let scope = match (change.base_scope, change.head_scope) {
        (Some(base), Some(head)) if base != head => format!("{base} → {head}"),
        (_, Some(scope)) | (Some(scope), None) => scope.into(),
        _ => "unknown".into(),
    };
    let delta = &change.vulnerabilities;
    let vulnerabilities = if delta.assessed {
        format!(
            "{}/{}/{}",
            count(delta.fixed.as_ref()),
            count(delta.introduced.as_ref()),
            count(delta.unchanged.as_ref())
        )
    } else {
        "unknown".into()
    };
    let fields = [
        format!(
            "{}:{}",
            change.key.registry.as_deref().unwrap_or("unknown"),
            change.key.name
        ),
        scope,
        change.kind.into(),
        changed_versions(change),
        vulnerabilities,
        changelog_summary(change),
    ]
    .map(|s| cell(&s, markdown));
    if markdown {
        return writeln!(out, "| {} |", fields.join(" | "));
    }
    writeln!(
        out,
        "{:<28} {:<22} {:<14} {:<27} {:<20} {}",
        fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]
    )
}

fn count(set: Option<&BTreeSet<String>>) -> usize {
    set.map_or(0, BTreeSet::len)
}

fn changed_versions(change: &Change) -> String {
    let empty = BTreeSet::new();
    let base = change.base.as_ref().map_or(&empty, |p| &p.versions);
    let head = change.head.as_ref().map_or(&empty, |p| &p.versions);
    if base.is_empty() && head.is_empty() {
        return "unknown".into();
    }
    let removed: Vec<_> = base.difference(head).cloned().collect();
    let added: Vec<_> = head.difference(base).cloned().collect();
    if removed.is_empty() && added.is_empty() {
        return "versions unchanged".into();
    }
    let side = |versions: Vec<String>| {
        if versions.is_empty() {
            "—".into()
        } else {
            versions.join(", ")
        }
    };
    format!("{} → {}", side(removed), side(added))
}

fn changelog_summary(change: &Change) -> String {
    let logs: Vec<_> = change
        .upgrade_reviews
        .iter()
        .filter_map(|r| r.changelog.as_ref())
        .collect();
    if logs.is_empty() {
        return "—".into();
    }
    let returned: usize = logs.iter().map(|c| c.entries.len()).sum();
    let total: u128 = logs.iter().map(|c| u128::from(c.total_entries)).sum();
    format!("{returned}/{total} entries")
}

fn details(change: &Change, markdown: bool, out: &mut dyn Write) -> io::Result<()> {
    let delta = &change.vulnerabilities;
    for (label, values) in [
        ("fixed", &delta.fixed),
        ("introduced", &delta.introduced),
        ("unchanged", &delta.unchanged),
    ] {
        if let Some(values) = values.as_ref().filter(|v| !v.is_empty()) {
            writeln!(
                out,
                "{} {label}: {}",
                cell(&change.key.name, markdown),
                cell(
                    &values.iter().cloned().collect::<Vec<_>>().join(", "),
                    markdown
                )
            )?;
        }
    }
    let link = change
        .upgrade_reviews
        .iter()
        .filter_map(|r| r.changelog.as_ref())
        .flat_map(|c| &c.entries)
        .filter_map(|e| e.html_url.as_deref())
        .find_map(safe_url);
    if let Some(link) = link {
        writeln!(
            out,
            "{} changelog: {}",
            cell(&change.key.name, markdown),
            cell(&link, markdown)
        )?;
    }
    for gap in &change.review_gaps {
        writeln!(
            out,
            "{} note: {}",
            cell(&change.key.name, markdown),
            cell(gap, markdown)
        )?;
    }
    Ok(())
}

fn cell(value: &str, markdown: bool) -> String {
    let safe = super::super::safe(value);
    if !markdown {
        return safe;
    }
    safe.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "&#124;")
        .replace('`', "&#96;")
}
fn safe_url(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none())
    .then(|| url.to_string())
}
