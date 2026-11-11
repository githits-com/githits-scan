//! Native wording without exposing protocol codes or choosing source authority.
use std::collections::BTreeSet;
use std::io::{self, Write};

use crate::api::audit::lifecycle::{Event, Lifecycle, Observation};
use crate::style::Palette;

use super::{file_list, heading, safe};

pub(in crate::commands::audit) fn write(
    data: &Lifecycle,
    details: bool,
    out: &mut dyn Write,
    palette: Palette,
) -> io::Result<()> {
    let count = data.findings.len() + data.retained_warnings.len();
    if count != 0 {
        heading("Package warnings", count, out, palette)?;
    }
    for event in &data.findings {
        event_line(event, details, out)?;
    }
    for warning in &data.retained_warnings {
        let qualification = if warning.classification == "legacy_unclassified" {
            "native classification was not retained"
        } else {
            "the warning classification is unfamiliar"
        };
        writeln!(
            out,
            "  {} — registry warning ({qualification}): {}",
            safe(&warning.coordinate.to_string()),
            supplied_reason(Some(&warning.reason))
        )?;
        if details {
            file_list(
                "Affected files",
                &warning.paths.iter().cloned().collect(),
                "    ",
                out,
            )?;
        }
    }
    if data.content_safety.filtered {
        writeln!(
            out,
            "  The service filtered some publisher text in the lifecycle evidence."
        )?;
    }
    Ok(())
}

fn event_line(event: &Event, details: bool, out: &mut dyn Write) -> io::Result<()> {
    let mut package = format!("{}:{}", event.registry, event.name);
    if let Some(version) = &event.version {
        package.push('@');
        package.push_str(version);
    }
    write!(
        out,
        "  {} — {} ({})",
        safe(&package),
        kind(&event.kind),
        scope(&event.scope)
    )?;
    if !details {
        let reasons: BTreeSet<_> = event
            .observations
            .iter()
            .map(|o| supplied_reason(o.reason.as_deref()))
            .collect();
        let reason = if reasons.is_empty() {
            supplied_reason(None)
        } else {
            reasons.into_iter().collect::<Vec<_>>().join("; ")
        };
        return writeln!(out, ": {reason}");
    }
    writeln!(out)?;
    for observation in &event.observations {
        observation_details(&event.source, observation, out)?;
    }
    Ok(())
}

fn observation_details(source: &str, o: &Observation, out: &mut dyn Write) -> io::Result<()> {
    write!(out, "    Source: {}", safe(source))?;
    if let Some(version) = &o.source_version {
        write!(out, "; source version {}", safe(version))?;
    }
    if let Some(time) = &o.observed_at {
        write!(out, "; metadata observed {}", safe(time))?;
    }
    writeln!(out)?;
    writeln!(out, "    Reason: {}", supplied_reason(o.reason.as_deref()))?;
    if let Some(replacement) = &o.replacement {
        writeln!(
            out,
            "    Publisher replacement advice: {} (not a verified upgrade)",
            safe(replacement)
        )?;
    }
    for reference in &o.affected {
        writeln!(
            out,
            "    Affected dependency: {}",
            safe(&reference.coordinate.to_string())
        )?;
        file_list(
            "Files",
            &reference.paths.iter().cloned().collect(),
            "      ",
            out,
        )?;
    }
    Ok(())
}

fn supplied_reason(reason: Option<&str>) -> String {
    reason
        .filter(|s| !s.trim().is_empty())
        .map_or_else(|| "The source supplied no reason.".into(), safe)
}

fn kind(value: &str) -> &'static str {
    match value {
        "deprecated" => "deprecated",
        "retired" => "retired",
        "abandoned" => "abandoned",
        "discontinued" => "discontinued",
        "yanked" => "yanked",
        "partially_yanked" => "partly yanked",
        "retracted" => "retracted",
        "unlisted" => "unlisted",
        _ => "lifecycle warning of an unfamiliar type",
    }
}

fn scope(value: &str) -> &'static str {
    match value {
        "package" => "package-wide",
        "release" => "release",
        "files" => "affected files only",
        _ => "scope not recognized",
    }
}
