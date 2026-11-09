//! Source-grouped presentation of producer facts, never a second comparison.
use super::Format;
use crate::api::diff::{
    Report,
    view::{self, View},
};
use std::collections::BTreeMap;
use std::io::{self, Write};

mod evidence;
mod reviews;

pub(super) fn write(
    report: &Report,
    format: Format,
    labels: (&str, &str),
    out: &mut dyn Write,
) -> io::Result<()> {
    if matches!(format, Format::Json) {
        return out.write_all(report.bytes());
    }
    let mut display = Display {
        markdown: matches!(format, Format::Markdown),
        out,
    };
    display.line(&format!(
        "Experimental dependency diff: {} → {}",
        labels.0, labels.1
    ))?;
    let Some(view) = report.view() else {
        return display.line(&format!("Report schema {} or kind cannot be rendered by this version; upgrade Scan or use --format json. Evidence is unassessed by this renderer.", report.version()));
    };
    display.line(&format!(
        "Selected inputs only; report: {}. Informational, no policy enforced.",
        view.outcome
    ))?;
    for (key, label) in [
        (
            "changed_source_package_contexts",
            "Changed source/package contexts",
        ),
        ("changed_declarations", "Changed declarations"),
    ] {
        if let Some(count) = view.summary.get(key) {
            display.line(&format!("{label}: {count}"))?;
        }
    }
    changes(view, &mut display)?;
    declarations(view, &mut display)?;
    evidence::write(view, &mut display)?;
    reviews::write(view, &mut display)?;
    for (side, snapshot) in view.snapshots.iter() {
        if side != snapshot.side {
            display.line("Unfamiliar snapshot side; consult JSON evidence.")?;
        }
        evidence::gaps(&snapshot.coverage, side, &mut display)?;
    }
    evidence::gaps(&view.coverage, "Report", &mut display)?;
    for notice in &view.notices {
        display.line(&format!("Note: {notice}"))?;
    }
    if view.outcome != "complete" {
        display.line("Evidence partial or unfamiliar; this report is not a clean assessment.")?;
    }
    Ok(())
}

struct Display<'a> {
    markdown: bool,
    out: &'a mut dyn Write,
}
impl Display<'_> {
    fn line(&mut self, text: &str) -> io::Result<()> {
        writeln!(self.out, "{}", cell(text, self.markdown))
    }
    fn item(&mut self, text: &str) -> io::Result<()> {
        writeln!(self.out, "- {}", cell(text, self.markdown))
    }
    fn heading(&mut self, text: &str) -> io::Result<()> {
        writeln!(self.out)?;
        let prefix = if self.markdown { "### " } else { "" };
        writeln!(self.out, "{prefix}{}", cell(text, self.markdown))?;
        writeln!(self.out)
    }
    fn link(&mut self, label: &str, url: &str) -> io::Result<()> {
        let Some(url) = safe_url(url) else {
            return self.item("Entry link omitted: unsupported or credential-bearing URL.");
        };
        let label = cell(label, self.markdown);
        if self.markdown {
            writeln!(
                self.out,
                "- {label}: <{}>",
                url.replace('<', "%3C").replace('>', "%3E")
            )
        } else {
            writeln!(self.out, "- {label}: {url}")
        }
    }
}

fn package(p: &view::Package) -> String {
    format!(
        "{}:{}",
        p.registry.as_deref().unwrap_or("unknown"),
        p.name.as_deref().unwrap_or("unknown")
    )
}

fn versions(v: &[Option<String>]) -> String {
    if v.is_empty() {
        return "—".into();
    }
    v.iter()
        .map(|s| s.as_deref().unwrap_or("unknown"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn changes(view: &View, d: &mut Display<'_>) -> io::Result<()> {
    let mut sources = BTreeMap::<&str, Vec<&view::Change>>::new();
    for change in &view.changes {
        sources.entry(&change.source_key).or_default().push(change);
    }
    if sources.is_empty() {
        d.line("No reported package version changes in selected inputs.")?;
    }
    for (source, changes) in sources {
        d.heading(&format!("Source: {source}"))?;
        for c in changes {
            change(c, d)?;
        }
    }
    Ok(())
}

fn change(c: &view::Change, d: &mut Display<'_>) -> io::Result<()> {
    let base = c.directness.base.as_str();
    let head = c.directness.head.as_str();
    let scope = match c.kind.as_str() {
        "added" => head.to_owned(),
        "removed" => base.to_owned(),
        _ if base == head => base.to_owned(),
        _ => format!("{base} → {head}"),
    };
    d.item(&format!(
        "{}: {} → {} ({}, {scope}, {})",
        package(&c.package),
        versions(&c.before_versions),
        versions(&c.after_versions),
        c.kind,
        c.ownership
    ))?;
    for retained in &c.retained_elsewhere {
        d.item(&format!(
            "  Retained elsewhere: {} in {}",
            versions(&retained.versions),
            retained.source_key
        ))?;
    }
    Ok(())
}

fn declarations(view: &View, d: &mut Display<'_>) -> io::Result<()> {
    if view.declaration_changes.is_empty() {
        return Ok(());
    }
    d.heading("Direct declarations")?;
    for c in &view.declaration_changes {
        let declaration = view
            .snapshots
            .iter()
            .flat_map(|(_, s)| &s.declarations)
            .find(|decl| {
                Some(&decl.id) == c.after_id.as_ref() || Some(&decl.id) == c.before_id.as_ref()
            });
        let label = declaration.map_or_else(
            || c.id.clone(),
            |decl| format!("{} in {}", decl.declared_name, decl.declaring_manifest),
        );
        d.item(&format!("{label}: {}", c.kind))?;
        for b in &c.binding_transitions {
            binding(b, d)?;
        }
    }
    Ok(())
}

fn binding(b: &view::Binding, d: &mut Display<'_>) -> io::Result<()> {
    let identity = b
        .package
        .as_ref()
        .map_or_else(|| "unknown package".into(), package);
    d.item(&format!(
        "  {}: {identity} {} → {}; binding {} → {}; review {}{}",
        b.source_key,
        b.before_versions
            .first()
            .map_or_else(|| "unmatched".into(), |_| b.before_versions.join(", ")),
        b.after_versions
            .first()
            .map_or_else(|| "unmatched".into(), |_| b.after_versions.join(", ")),
        b.base_status,
        b.head_status,
        b.review_eligibility.status,
        b.review_eligibility
            .reason
            .as_ref()
            .map_or(String::new(), |r| format!(" ({r})"))
    ))?;
    if b.before_versions.is_empty() && !b.recorded_before_versions.is_empty() {
        d.item(&format!(
            "  Recorded base versions: {} (not a qualified direct review target)",
            b.recorded_before_versions.join(", ")
        ))?;
    }
    for (side, target) in [("base", &b.base_target), ("head", &b.head_target)] {
        if let Some(t) = target {
            d.item(&format!(
                "  {side} review target: {}@{}",
                package(&t.package),
                t.version
            ))?;
        } else {
            d.item(&format!("  {side} review target: unavailable"))?;
        }
    }
    Ok(())
}

fn cell(value: &str, markdown: bool) -> String {
    let safe = super::super::safe(value);
    if !markdown {
        return safe;
    }
    let mut escaped = String::new();
    for character in safe.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '|' => escaped.push_str("&#124;"),
            '`' => escaped.push_str("&#96;"),
            '[' => escaped.push_str("&#91;"),
            ']' => escaped.push_str("&#93;"),
            '(' => escaped.push_str("&#40;"),
            ')' => escaped.push_str("&#41;"),
            '!' => escaped.push_str("&#33;"),
            '*' => escaped.push_str("&#42;"),
            '_' => escaped.push_str("&#95;"),
            // GitHub applies mention/issue filters after decoding entities.
            '@' => escaped.push_str("@&#8203;"),
            '\\' => escaped.push_str("&#92;"),
            '#' => escaped.push_str("#&#8203;"),
            ':' => escaped.push_str("&#58;"),
            '+' => escaped.push_str("&#43;"),
            '-' => escaped.push_str("&#45;"),
            '.' => escaped.push_str("&#46;"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn safe_url(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none())
    .then(|| url.to_string())
}
