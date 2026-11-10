//! Source-grouped presentation of producer facts, never a second comparison.
use super::Format;
use crate::api::diff::{
    Report,
    view::{self, View},
};
use std::collections::BTreeMap;
use std::io::{self, Write};

mod evidence;
mod explanations;
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
        in_list: false,
    };
    display.line(&format!("Dependency changes: {} → {}", labels.0, labels.1))?;
    let Some(view) = report.view() else {
        return display.line("Scan cannot explain this report because its format is newer than this version supports. Update Scan to read it; the original report is available as JSON.");
    };
    display.line("This compares the supplied dependency files, not an observed installation.")?;
    match view.outcome.as_str() {
        "complete" => {},
        "partial" => display.line("Some checks could not be completed. Review the limitations below before accepting these changes.")?,
        _ => display.line("The service did not confirm a complete comparison. Scan cannot explain its completion result; review the original JSON before relying on it.")?,
    }
    let explanations = explanations::new(view);
    changes(view, &explanations, &mut display)?;
    declarations(view, &explanations, &mut display)?;
    evidence::write(view, &mut display)?;
    reviews::write(view, &explanations, &mut display)?;
    for (side, snapshot) in view.snapshots.iter() {
        if side != snapshot.side {
            display.line("The service returned inconsistent revision labels, so file limitations may be incomplete.")?;
        }
        evidence::gaps(&snapshot.coverage, side, &explanations, &mut display)?;
    }
    evidence::gaps(&view.coverage, "Report", &explanations, &mut display)?;
    let mut notices = std::collections::BTreeSet::new();
    for notice in &view.notices {
        if notice != "Recorded input comparison, not an observed installation or solver ancestry."
            && notice
                != "Both sides use current shared advisory evidence; this is not historical advisory knowledge."
            && notices.insert(notice)
        {
            display.line(notice)?;
        }
    }
    Ok(())
}

struct Display<'a> {
    markdown: bool,
    out: &'a mut dyn Write,
    in_list: bool,
}
impl Display<'_> {
    fn line(&mut self, text: &str) -> io::Result<()> {
        if self.in_list {
            writeln!(self.out)?;
        }
        self.in_list = false;
        writeln!(self.out, "{}", cell(text, self.markdown))
    }
    fn item(&mut self, text: &str) -> io::Result<()> {
        self.in_list = true;
        let (prefix, text) = item_parts(text);
        writeln!(self.out, "{prefix}{}", cell(text, self.markdown))
    }
    fn heading(&mut self, text: &str) -> io::Result<()> {
        self.in_list = false;
        writeln!(self.out)?;
        let prefix = if self.markdown { "### " } else { "" };
        writeln!(self.out, "{prefix}{}", cell(text, self.markdown))?;
        writeln!(self.out)
    }
    fn link(&mut self, label: &str, url: &str) -> io::Result<()> {
        let Some(url) = safe_url(url) else {
            return self.item("  This release-note link was omitted because its address is unsafe or unsupported.");
        };
        self.in_list = true;
        let (prefix, label) = item_parts(label);
        let label = cell(label, self.markdown);
        if self.markdown {
            writeln!(
                self.out,
                "{prefix}{label}: <{}>",
                url.replace('<', "%3C").replace('>', "%3E")
            )
        } else {
            writeln!(self.out, "{prefix}{label}: {url}")
        }
    }
}

fn item_parts(text: &str) -> (&str, &str) {
    text.strip_prefix("  ")
        .map_or(("- ", text), |text| ("  - ", text))
}

fn package(p: &view::Package) -> String {
    p.name
        .clone()
        .unwrap_or_else(|| "package whose name was not supplied".into())
}

fn versions(v: &[Option<String>]) -> String {
    if v.is_empty() {
        return "no package version listed".into();
    }
    v.iter()
        .map(|s| s.as_deref().unwrap_or("version not supplied"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn changes(
    v: &View,
    explanations: &explanations::Evidence<'_>,
    d: &mut Display<'_>,
) -> io::Result<()> {
    let mut sources = BTreeMap::<&str, Vec<&view::Change>>::new();
    for change in &v.changes {
        sources.entry(&change.source_key).or_default().push(change);
    }
    if sources.is_empty() {
        d.line("No package version changes were reported in the supplied files.")?;
    }
    for (source, changes) in sources {
        d.heading(&format!("File: {source}"))?;
        if changes.iter().any(|c| c.ownership == "auxiliary") {
            d.line("This is a secondary lockfile; the workspace uses another lockfile to choose package versions.")?;
        }
        if changes
            .iter()
            .any(|c| !matches!(c.ownership.as_str(), "recorded" | "effective" | "auxiliary"))
        {
            d.line("The service could not establish whether this file controls the workspace's package versions.")?;
        }
        for c in &changes {
            change(c, d)?;
        }
        explanations::changes(explanations, &changes, d)?;
    }
    Ok(())
}

fn change(c: &view::Change, d: &mut Display<'_>) -> io::Result<()> {
    let transition = match c.kind.as_str() {
        "added" => format!("added {}", versions(&c.after_versions)),
        "removed" => format!("removed {}", versions(&c.before_versions)),
        _ => format!(
            "{} → {}",
            versions(&c.before_versions),
            versions(&c.after_versions)
        ),
    };
    let base = usage(&c.directness.base);
    let head = usage(&c.directness.head);
    let role = match c.kind.as_str() {
        "added" => head.map(str::to_owned),
        "removed" => base.map(str::to_owned),
        _ if base == head => base.map(str::to_owned),
        _ => match (base, head) {
            (Some(b), Some(h)) => Some(format!("{b} → {h}")),
            (Some(b), None) => Some(format!("{b} before this change")),
            (None, Some(h)) => Some(format!("{h} after this change")),
            (None, None) => None,
        },
    }
    .map_or(String::new(), |r| format!(" ({r})"));
    d.item(&format!("{}: {transition}{role}", package(&c.package)))?;
    for retained in &c.retained_elsewhere {
        d.item(&format!(
            "  {} also appears in {}.",
            versions(&retained.versions),
            retained.source_key
        ))?;
    }
    Ok(())
}

fn section_message(section: &crate::api::diff::Section, checks: &str) -> String {
    if section.status == "not_requested" {
        return format!("{checks} were not requested for this comparison.");
    }
    let reason = match section.reason.as_deref() {
        Some("provider_unavailable") => "the service's information provider was unavailable",
        Some("deadline") => "the comparison's time limit was reached",
        _ => "the service returned no supported results or explanation this version can display",
    };
    format!(
        "{checks} could not be returned because {reason}. Review the relevant package information manually before accepting these changes."
    )
}

fn revision(side: &str) -> &str {
    match side {
        "base" => "earlier",
        "head" => "later",
        _ => "compared",
    }
}

fn revision_context(side: &str) -> &'static str {
    match side {
        "base" => "in the earlier revision",
        "head" => "in the later revision",
        _ => "in this comparison",
    }
}

fn usage(status: &str) -> Option<&'static str> {
    match status {
        "direct" => Some("direct dependency"),
        "transitive" => Some("through another package"),
        _ => None,
    }
}

fn declarations(
    v: &View,
    explanations: &explanations::Evidence<'_>,
    d: &mut Display<'_>,
) -> io::Result<()> {
    if v.declaration_changes.is_empty() {
        return Ok(());
    }
    d.heading("Dependency declarations")?;
    for c in &v.declaration_changes {
        let label = explanations::declaration_label(explanations, c);
        let text = match c.kind.as_str() {
            "ambiguous" => "Scan could not compare a dependency declaration because the service could not distinguish matching declarations. Review the dependency declarations in your project files.".into(),
            "added" => format!("Added {label}"),
            "removed" => format!("Removed {label}"),
            _ => format!("Changed {label}"),
        };
        d.item(&text)?;
        for b in &c.binding_transitions {
            binding(c, b, d)?;
            explanations::binding(explanations, c, b, d)?;
        }
    }
    Ok(())
}

fn binding(c: &view::DeclarationChange, b: &view::Binding, d: &mut Display<'_>) -> io::Result<()> {
    let identity = b
        .package
        .as_ref()
        .map_or_else(|| "package name not supplied".into(), package);
    let before = if c.kind == "added" {
        "not declared".into()
    } else if b.before_versions.is_empty() {
        "no matching version".into()
    } else {
        b.before_versions.join(", ")
    };
    let after = if c.kind == "removed" {
        "no longer declared".into()
    } else if b.after_versions.is_empty() {
        "no matching version".into()
    } else {
        b.after_versions.join(", ")
    };
    d.item(&format!(
        "  {identity} in {}: {before} → {after}",
        b.source_key
    ))?;
    if c.kind != "added" && b.before_versions.is_empty() && !b.recorded_before_versions.is_empty() {
        d.item(&format!("  The earlier file lists {}, but these versions could not be matched to the dependency declaration.", b.recorded_before_versions.join(", ")))?;
    }
    for (side, id, absent) in [
        ("earlier", &c.before_id, c.kind == "added"),
        ("later", &c.after_id, c.kind == "removed"),
    ] {
        if !absent && id.is_none() {
            d.item(&format!("  The service did not identify a unique dependency declaration in the {side} revision. Review the matching declarations manually."))?;
        }
    }
    if b.review_eligibility.status != "eligible" {
        d.item(&format!(
            "  No upgrade review: {}",
            eligibility(b.review_eligibility.reason.as_deref())
        ))?;
    }
    Ok(())
}

fn eligibility(reason: Option<&str>) -> &'static str {
    match reason {
        Some("base_declaration_mismatch") => {
            "the earlier package details do not match the dependency declaration."
        }
        Some("became_direct") => {
            "the package was already present, but is now declared directly; there is no earlier direct dependency to compare."
        }
        Some("direct_addition") => {
            "this dependency was added, so there is no earlier declared version to compare."
        }
        Some("direct_removal") => {
            "this dependency was removed, so there is no later declared version to review."
        }
        Some("base_binding_unavailable") => {
            "the earlier dependency declaration could not be matched to a package entry."
        }
        Some("head_binding_unavailable") => {
            "the later dependency declaration could not be matched to a package entry."
        }
        Some("binding_not_matched") => {
            "the earlier or later dependency declaration could not be matched conclusively to a package entry."
        }
        Some("target_occurrence_not_qualified") => {
            "the service could not identify comparable package versions for this dependency."
        }
        Some("target_identity_changed") => {
            "the declaration now refers to a different package, rather than a new version of the same package."
        }
        Some("version_unchanged") => "the package version did not change.",
        _ => {
            "the service did not identify matching earlier and later versions that it could review, and supplied no more specific explanation Scan can display."
        }
    }
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
            '~' => escaped.push_str("&#126;"),
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
