//! Compact package/license rows with optional supporting evidence.

use std::collections::BTreeSet;
use std::io::{self, Write};

use super::super::display::{self, Text};
use super::super::occurrences::{Format, Occurrences};
use crate::api::licenses::compact;
use crate::api::licenses::{Choice, Component, Publisher, Reference, Source, View};

use crate::commands::plural;
use crate::style::Palette;

mod compact_evidence;
mod evidence;

pub(super) fn write(
    view: &View,
    bytes: &[u8],
    details: bool,
    out: &mut dyn Write,
    palette: Palette,
) -> io::Result<()> {
    let mut rows: Vec<_> = match view {
        View::Legacy(view) => view.components.iter().map(Row::Legacy).collect(),
        View::Compact(view) => view.components.iter().map(Row::Compact).collect(),
    };
    rows.sort_by(|a, b| {
        (a.subject().name, a.subject().version, a.subject().purl).cmp(&(
            b.subject().name,
            b.subject().version,
            b.subject().purl,
        ))
    });
    let repeated = rows
        .windows(2)
        .any(|pair| same_coordinate(&pair[0], &pair[1]));
    let occurrences = if repeated {
        let format = match view {
            View::Legacy(_) => Format::LegacyReport,
            View::Compact(_) => Format::CompactReport,
        };
        Occurrences::new(
            bytes,
            format,
            rows.chunk_by(same_coordinate)
                .filter(|group| group.len() > 1)
                .flatten()
                .map(Row::reference),
        )
    } else {
        Occurrences::default()
    };
    let width = rows
        .iter()
        .map(|c| {
            let context = occurrences.label(c.reference(), !details);
            label(c, false, context).text.value.chars().count()
        })
        .max()
        .unwrap_or(0)
        .clamp(7, display::PACKAGE_PADDING);
    if details {
        let basis = view.completeness().unwrap_or("not reported");
        writeln!(
            out,
            "{}",
            palette.bold(&format!(
                "{} (inventory: {}); informational, not a policy check",
                plural(rows.len(), "reported occurrence"),
                display::completeness(basis)
            ))
        )?;
    } else {
        writeln!(
            out,
            "{}",
            palette.bold(&format!("{:<width$}  License", "Package"))
        )?;
    }
    let mut shortened = false;
    for group in rows.chunk_by(same_coordinate) {
        shortened |= write_group(group, &occurrences, details, width, out)?;
    }

    if details {
        writeln!(out, "\nCoverage and limitations")?;
        match view {
            View::Legacy(view) => evidence::coverage(view, out)?,
            View::Compact(view) => compact_evidence::coverage(view, out)?,
        }
        writeln!(
            out,
            "Inventory completeness is not license coverage; use --json for complete evidence."
        )?;
    } else if shortened {
        writeln!(out, "Abbreviated evidence; use --json for full values.")?;
    }
    Ok(())
}

fn write_group(
    group: &[Row<'_>],
    occurrences: &Occurrences,
    details: bool,
    width: usize,
    out: &mut dyn Write,
) -> io::Result<bool> {
    let mut shortened = false;
    let base = group[0].subject().purl.map(display::purl_base);
    let distinguish = group
        .iter()
        .any(|c| c.subject().purl.map(display::purl_base) != base);
    let remaining = group
        .iter()
        .filter(|row| !occurrences.skip(row.reference()))
        .count();
    for component in group {
        if !details && occurrences.skip(component.reference()) {
            continue;
        }
        let context = occurrences.label(component.reference(), !details);
        shortened |= write_row(component, distinguish, details, width, context, out)?;
        shortened |= occurrences.continuation(component.reference(), !details, "  ", out)?;
        if !details && remaining > 1 {
            component.inputs(out)?;
        }
    }
    Ok(shortened)
}

fn write_row(
    component: &Row<'_>,
    distinguish: bool,
    details: bool,
    width: usize,
    context: Option<&str>,
    out: &mut dyn Write,
) -> io::Result<bool> {
    if details {
        writeln!(out)?;
    }
    let id = label(component, distinguish, context);
    let subject = component.subject();
    let licenses = choices(subject.licenses);
    if details {
        writeln!(out, "{}  {}", id.text.value, licenses.value)?;
    } else {
        writeln!(out, "{:<width$}  {}", id.text.value, licenses.value)?;
    }
    display::continuation(out, &id)?;
    if details {
        component_details(component, out)?;
    }
    Ok(id.text.shortened
        || licenses.shortened
        || id
            .continuation
            .as_ref()
            .is_some_and(|(_, value)| value.shortened))
}

#[derive(Clone, Copy)]
enum Row<'a> {
    Legacy(&'a Component),
    Compact(&'a compact::Component),
}

struct Subject<'a> {
    name: &'a str,
    version: Option<&'a str>,
    purl: Option<&'a str>,
    kind: &'a str,
    scope: Option<&'a str>,
    record_kind: Option<&'a str>,
    licenses: &'a [Choice],
    observed_licenses: &'a [Choice],
    publisher_evidence: Option<&'a Publisher>,
    source_evidence: Option<&'a Source>,
    external_references: &'a [Reference],
}

fn same_coordinate(a: &Row<'_>, b: &Row<'_>) -> bool {
    a.subject().name == b.subject().name && a.subject().version == b.subject().version
}

impl Row<'_> {
    fn reference(&self) -> &str {
        match self {
            Self::Legacy(c) => c.bom_ref.as_deref().unwrap_or_default(),
            Self::Compact(c) => c.bom_ref.as_deref().unwrap_or_default(),
        }
    }

    fn subject(&self) -> Subject<'_> {
        macro_rules! subject {
            ($c:expr) => {
                Subject {
                    name: &$c.name,
                    version: $c.version.as_deref(),
                    purl: $c.purl.as_deref(),
                    kind: &$c.kind,
                    scope: $c.scope.as_deref(),
                    record_kind: $c.record_kind.as_deref(),
                    licenses: &$c.licenses,
                    observed_licenses: &$c.observed_licenses,
                    publisher_evidence: $c.publisher_evidence.as_ref(),
                    source_evidence: $c.source_evidence.as_ref(),
                    external_references: &$c.external_references,
                }
            };
        }
        match self {
            Self::Legacy(c) => subject!(c),
            Self::Compact(c) => subject!(c),
        }
    }

    fn inputs(&self, out: &mut dyn Write) -> io::Result<()> {
        match self {
            Self::Legacy(c) => evidence::inputs(&c.properties, out),
            Self::Compact(c) => compact_evidence::inputs(&c.inputs, out),
        }
    }

    fn local(&self) -> bool {
        match self {
            Self::Legacy(c) => c.properties.iter().any(|p| {
                p.name == "githits:source_kind"
                    && p.value.as_deref() == Some("LOCKED_PACKAGE_SOURCE_KIND_LOCAL")
            }),
            Self::Compact(c) => {
                c.source_kind.as_deref() == Some("LOCKED_PACKAGE_SOURCE_KIND_LOCAL")
            }
        }
    }
}

fn label(component: &Row<'_>, distinguish: bool, context: Option<&str>) -> display::Identity {
    let c = component.subject();
    let marker = if c.record_kind == Some("manifest") {
        "[project]"
    } else if component.local() {
        "[local]"
    } else {
        ""
    };
    display::identity(c.name, c.version, c.purl, marker, distinguish, context)
}

fn identity(component: &Component, out: &mut dyn Write) -> io::Result<()> {
    write!(
        out,
        "{}",
        label(&Row::Legacy(component), false, None).text.value
    )
}

fn safe(value: &str) -> String {
    Text::new(value, display::DETAIL).value
}

fn component_details(row: &Row<'_>, out: &mut dyn Write) -> io::Result<()> {
    row.inputs(out)?;
    let component = row.subject();
    fields(
        out,
        "  ",
        None,
        &[
            (
                "kind",
                component
                    .record_kind
                    .filter(|kind| !matches!(*kind, "locked_package" | "resolved_package")),
            ),
            (
                "type",
                (component.kind != "library").then_some(component.kind),
            ),
            ("scope", component.scope),
        ],
    )?;
    choice_details("reported license", component.licenses, out)?;
    if !component.observed_licenses.is_empty() {
        writeln!(
            out,
            "  observed licenses: {}",
            choices(component.observed_licenses).value
        )?;
        choice_details("observed license", component.observed_licenses, out)?;
    }
    evidence::publisher(&component, out)?;
    if let Row::Compact(c) = row {
        compact_evidence::component(c, out)?;
    }
    evidence::source(component.source_evidence, out)?;
    let mut seen = BTreeSet::new();
    for reference in component.external_references {
        let label = match reference.kind.as_deref() {
            Some("vcs") => "repository",
            Some("license") => "license",
            Some("distribution") => "distribution",
            _ => continue,
        };
        if let Some(url) = &reference.url
            && seen.insert((label, url))
        {
            writeln!(out, "  {label}: {}", safe(url))?;
        }
    }
    Ok(())
}

fn repeats_primary(choices: &[Choice], text: &str) -> bool {
    choices.iter().any(|choice| {
        choice.expression.as_deref() == Some(text)
            || choice.license.as_ref().is_some_and(|license| {
                license.id.as_deref() == Some(text) || license.name.as_deref() == Some(text)
            })
    })
}

// Preview source choices independently; no relationship is inferred between them.
fn choice_text(choice: &Choice, limit: usize) -> Text {
    if let Some(expression) = &choice.expression {
        return Text::new(expression, limit);
    }
    let Some(license) = &choice.license else {
        return Text::new("unrecognized choice (retained in JSON)", limit);
    };
    match (&license.id, &license.name) {
        (Some(id), Some(name)) => Text::prose_parts([id.as_str(), " (", name.as_str(), ")"], limit),
        (Some(value), None) => Text::new(value, limit),
        (None, Some(value)) => Text::prose(value, limit),
        (None, None) => Text::new("unrecognized choice (retained in JSON)", limit),
    }
}

fn choices(choices: &[Choice]) -> Text {
    if choices.is_empty() {
        return Text::new("not reported", display::LICENSE);
    }
    let mut value = String::new();
    let mut shortened = false;
    for choice in choices {
        if !value.is_empty() {
            value.push_str("; ");
        }
        let text = choice_text(choice, display::LICENSE);
        if text.value.contains(';') || text.value.starts_with('"') {
            value.push('"');
            value.push_str(&text.value.replace('"', "\\\""));
            value.push('"');
        } else {
            value.push_str(&text.value);
        }
        shortened |= text.shortened;
        if shortened || value.chars().count() > display::LICENSE {
            shortened = true;
            break;
        }
    }
    let mut text = Text::displayed(&value, display::LICENSE);
    text.shortened |= shortened;
    text
}

fn choice_details(label: &str, choices: &[Choice], out: &mut dyn Write) -> io::Result<()> {
    let summarized = self::choices(choices).shortened;
    for choice in choices {
        let license = choice.license.as_ref();
        let license_acknowledgement = license
            .and_then(|license| license.acknowledgement.as_deref())
            .filter(|value| *value != "declared");
        let acknowledgement = choice
            .acknowledgement
            .as_deref()
            .filter(|value| *value != "declared");
        if acknowledgement.is_none()
            && license_acknowledgement.is_none()
            && !summarized
            && !(choice.expression.is_some() && license.is_some())
        {
            continue;
        }
        let primary = choice_text(choice, display::DETAIL);
        write_parts(out, "  ", &[format!("{label}: {}", primary.value)], "")?;
        fields(
            out,
            "    ",
            None,
            &[
                (
                    "id",
                    license
                        .filter(|_| choice.expression.is_some())
                        .and_then(|license| license.id.as_deref()),
                ),
                (
                    "name",
                    license
                        .filter(|_| choice.expression.is_some())
                        .and_then(|license| license.name.as_deref()),
                ),
                ("acknowledgement", acknowledgement),
                ("license acknowledgement", license_acknowledgement),
            ],
        )?;
    }
    Ok(())
}

// Pack bounded fields without splitting an atomic URL/path token.
fn fields(
    out: &mut dyn Write,
    indent: &str,
    heading: Option<&str>,
    fields: &[(&str, Option<&str>)],
) -> io::Result<()> {
    let parts: Vec<_> = fields
        .iter()
        .filter_map(|(label, value)| {
            value
                .filter(|v| !v.trim().is_empty())
                .map(|value| format!("{label}: {}", safe(value)))
        })
        .collect();
    if parts.is_empty() && heading.is_none() {
        return Ok(());
    }
    let prefix = heading.map_or_else(
        || indent.to_owned(),
        |heading| format!("{indent}{heading}:"),
    );
    write_parts(out, &prefix, &parts, "")
}

fn write_parts<S: AsRef<str>>(
    out: &mut dyn Write,
    prefix: &str,
    parts: impl IntoIterator<Item = S>,
    suffix: &str,
) -> io::Result<()> {
    write!(out, "{prefix}")?;
    let mut width = prefix.chars().count();
    for (index, part) in parts.into_iter().enumerate() {
        let part = part.as_ref();
        let mut separator = separator(prefix, index);
        if index > 0 && width + part.chars().count() + separator.len() > 100 {
            write!(out, "\n    ")?;
            width = 4;
            separator = "";
        }
        write!(out, "{separator}{part}")?;
        width += separator.len() + part.chars().count();
    }
    writeln!(out, "{suffix}")
}

fn separator(prefix: &str, index: usize) -> &'static str {
    if index > 0 {
        return "; ";
    }
    if prefix.ends_with(':') { " " } else { "" }
}

// Both wire adapters supply paths; only this layer packs the bounded preview.
fn input_summary<'a>(
    paths: impl IntoIterator<Item = &'a str>,
    out: &mut dyn Write,
) -> io::Result<()> {
    let mut paths = paths.into_iter().peekable();
    if paths.peek().is_none() {
        return Ok(());
    }
    let parts = std::iter::once(" (inputs: ")
        .chain(
            paths
                .enumerate()
                .flat_map(|(index, path)| [if index == 0 { "" } else { ", " }, path]),
        )
        .chain([")"]);
    write!(out, "{}", Text::parts(parts, display::DETAIL).value)
}
