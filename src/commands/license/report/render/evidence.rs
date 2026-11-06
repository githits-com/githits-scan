//! Source attribution and coverage presentation; original JSON stays authoritative.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::{self, Write};

use serde::Deserialize;

use super::{safe, write_parts};
use crate::api::licenses::{
    Component, Interpretation, Issue, LegacyView, Observation, Property, Source,
};
use crate::commands::license::{display, occurrences::input_paths};

use super::{Subject, fields, identity, repeats_primary};

pub(super) fn inputs(properties: &[Property], out: &mut dyn Write) -> io::Result<()> {
    let (paths, unrecognized) = input_paths(properties);
    for path in paths {
        writeln!(out, "  input file: {}", safe(&path))?;
    }
    if unrecognized {
        writeln!(
            out,
            "  input attribution: unrecognized evidence (retained in JSON)"
        )?;
    }
    Ok(())
}

pub(super) fn publisher(component: &Subject<'_>, out: &mut dyn Write) -> io::Result<()> {
    let Some(value) = &component.publisher_evidence else {
        return Ok(());
    };
    let status = value
        .status
        .as_deref()
        .filter(|status| !matches!(*status, "expression" | "absent"));
    let reason = value
        .reason
        .as_deref()
        .filter(|reason| *reason != "publisher_release_metadata");
    if status.is_some() || reason.is_some() {
        fields(
            out,
            "  ",
            Some("publisher"),
            &[
                ("status", status.map(display::evidence_code)),
                ("reason", reason.map(display::evidence_code)),
            ],
        )?;
    }
    for entry in &value.observations {
        publisher_observation(component, entry, out)?;
    }
    Ok(())
}

fn routine_observation(component: &Subject<'_>, entry: &Observation) -> bool {
    let Some(statement) = &entry.statement else {
        return false;
    };
    let interpretation_ok = entry.interpretation.as_ref().is_none_or(|value| {
        value
            .status
            .as_deref()
            .is_none_or(|status| matches!(status, "expression" | "absent"))
            && value.issues.as_ref().is_none_or(Vec::is_empty)
    });
    entry.relationship.as_deref() == Some("controlling")
        && statement.scope.as_deref() == Some("release")
        && statement.field.as_deref() == Some("license")
        && statement
            .version
            .as_deref()
            .is_none_or(|version| Some(version) == component.version)
        && statement
            .statements
            .iter()
            .all(|text| repeats_primary(component.licenses, text))
        && interpretation_ok
}

fn publisher_observation(
    component: &Subject<'_>,
    entry: &Observation,
    out: &mut dyn Write,
) -> io::Result<()> {
    if routine_observation(component, entry) {
        return Ok(());
    }
    let statement = entry.statement.as_ref();
    let has_interpretation = entry.interpretation.as_ref().is_some_and(|value| {
        value
            .status
            .as_deref()
            .is_some_and(|status| !matches!(status, "expression" | "absent"))
            || value
                .issues
                .as_ref()
                .is_some_and(|issues| !issues.is_empty())
    });
    if statement.is_none() && entry.relationship.is_none() && !has_interpretation {
        return Ok(());
    }
    let (label, mut metadata) = observation_metadata(entry);
    if let Some(version) = statement.and_then(|value| value.version.as_deref()) {
        metadata.push(format!("version: {}", safe(version)));
    }
    if let Some(field) = statement
        .and_then(|value| value.field.as_deref())
        .filter(|field| *field != "license")
    {
        metadata.push(format!("field: {}", safe(field)));
    }
    let texts = statement.map_or(&[][..], |value| value.statements.as_slice());
    let different = texts
        .iter()
        .any(|text| !repeats_primary(component.licenses, text));
    let suffix = if !texts.is_empty() && !different {
        "): matches reported license text"
    } else {
        ")"
    };
    write_parts(out, &format!("  {label} ("), &metadata, suffix)?;
    if different {
        for text in texts {
            display::field(out, "    statement: ", text, true)?;
        }
    }
    if let Some(value) = &entry.interpretation {
        interpretation(value, out)?;
    }
    Ok(())
}

fn observation_metadata(entry: &Observation) -> (&'static str, Vec<String>) {
    let relationship = entry.relationship.as_deref();
    let label = if relationship == Some("context") {
        "publisher context"
    } else {
        "publisher statement"
    };
    let mut metadata = Vec::new();
    if !matches!(relationship, Some("controlling" | "context")) {
        metadata.push(format!(
            "relationship: {}",
            safe(relationship.unwrap_or("not reported"))
        ));
    }
    metadata.push(format!(
        "scope: {}",
        safe(
            entry
                .statement
                .as_ref()
                .and_then(|value| value.scope.as_deref())
                .unwrap_or("not reported")
        )
    ));
    (label, metadata)
}

fn interpretation(value: &Interpretation, out: &mut dyn Write) -> io::Result<()> {
    fields(
        out,
        "    ",
        None,
        &[(
            "interpretation",
            value
                .status
                .as_deref()
                .filter(|status| !matches!(*status, "expression" | "absent"))
                .map(display::evidence_code),
        )],
    )?;
    for issue in value.issues.iter().flatten() {
        writeln!(out, "    issue: {}", issue_text(issue))?;
    }
    Ok(())
}

pub(super) fn issue_text(issue: &Issue) -> String {
    match issue {
        Issue::Code {
            code,
            offset,
            identifier,
        } => {
            let mut text = display::evidence_code(code).to_owned();
            if let Some(identifier) = identifier {
                let _ = write!(text, " ({})", safe(identifier));
            }
            if let Some(offset) = offset {
                let _ = write!(text, " at position {offset}");
            }
            text
        }
        Issue::Other(_opaque) => "unrecognized issue (retained in JSON)".into(),
    }
}

pub(super) fn source(value: Option<&Source>, out: &mut dyn Write) -> io::Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let latest = value
        .last_attempt_status
        .as_deref()
        .filter(|status| Some(*status) != value.status.as_deref());
    let metadata = [
        (
            "status",
            value.status.as_deref().map(display::evidence_code),
        ),
        ("module", value.module.as_deref()),
        ("version", value.version.as_deref()),
        ("URL", value.url.as_deref()),
        ("latest check", latest.map(display::evidence_code)),
    ];
    if metadata.iter().all(|(_, value)| value.is_none()) && value.files.is_empty() {
        return Ok(());
    }
    fields(out, "  ", Some("source observations"), &metadata)?;
    for file in &value.files {
        let parts = std::iter::once(safe(&file.path)).chain(
            file.detected_licenses
                .iter()
                .map(|value| format!("detected: {}", safe(value))),
        );
        write_parts(out, "    observed file:", parts, "")?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct Resolution {
    path: Option<String>,
    status: Option<String>,
}

#[derive(Deserialize)]
struct Coverage {
    state: Option<String>,
    #[serde(default)]
    reasons: Vec<String>,
}

pub(super) fn coverage(view: &LegacyView, out: &mut dyn Write) -> io::Result<()> {
    let inventory = &view.inventory;
    let owners: BTreeMap<_, _> = view
        .components
        .iter()
        .filter_map(|component| {
            component
                .bom_ref
                .as_deref()
                .map(|reference| (reference, component))
        })
        .collect();
    for composition in &inventory.compositions {
        match (
            composition.aggregate.as_deref(),
            composition.assemblies.is_some() || composition.dependencies.is_some(),
        ) {
            (Some("complete"), true) => continue,
            (Some("complete"), false) => {
                writeln!(
                    out,
                    "  inventory coverage: unrecognized scope (retained in JSON)"
                )?;
                continue;
            }
            _ => (),
        }
        let aggregate = safe(
            composition
                .aggregate
                .as_deref()
                .unwrap_or("unrecognized (retained in JSON)"),
        );
        for (label, _) in [
            ("component inventory", composition.assemblies.is_some()),
            (
                "dependency relationships",
                composition.dependencies.is_some(),
            ),
            (
                "inventory coverage",
                composition.assemblies.is_none() && composition.dependencies.is_none(),
            ),
        ]
        .into_iter()
        .filter(|(_, present)| *present)
        {
            writeln!(out, "  {label}: {aggregate}")?;
        }
    }
    for property in &inventory.properties {
        let Some(value) = property.value.as_deref() else {
            continue;
        };
        match property.name.as_ref() {
            "githits:notice" => writeln!(out, "  notice: {}", safe(value))?,
            "githits:resolutions" => resolutions(value, out)?,
            "githits:dependency_coverage" => dependency_coverage(value, &owners, out)?,
            _ => (),
        }
    }
    Ok(())
}

fn resolutions(value: &str, out: &mut dyn Write) -> io::Result<()> {
    let Ok(values) = serde_json::from_str::<Vec<Resolution>>(value) else {
        return writeln!(
            out,
            "  resolution evidence: unrecognized (retained in JSON)"
        );
    };
    for resolution in values {
        writeln!(
            out,
            "  resolution: {}: {}",
            safe(resolution.path.as_deref().unwrap_or("input not reported")),
            display::evidence_code(
                resolution
                    .status
                    .as_deref()
                    .unwrap_or("unrecognized (retained in JSON)")
            )
        )?;
    }
    Ok(())
}

fn dependency_coverage(
    value: &str,
    owners: &BTreeMap<&str, &Component>,
    out: &mut dyn Write,
) -> io::Result<()> {
    let Ok(values) = serde_json::from_str::<BTreeMap<String, Coverage>>(value) else {
        return writeln!(
            out,
            "  dependency coverage: unrecognized (retained in JSON)"
        );
    };
    for (owner, coverage) in values
        .iter()
        .filter(|(_, c)| c.state.as_deref() != Some("complete"))
    {
        write!(out, "  dependency coverage: ")?;
        coverage_owner(owner, owners, out)?;
        write!(
            out,
            ": {}",
            display::evidence_code(
                coverage
                    .state
                    .as_deref()
                    .unwrap_or("unrecognized (retained in JSON)")
            )
        )?;
        writeln!(out)?;
        let reasons = BTreeSet::from_iter(
            coverage
                .reasons
                .iter()
                .map(|reason| display::evidence_code(reason)),
        );
        for reason in reasons {
            writeln!(out, "    reason: {reason}")?;
        }
    }
    Ok(())
}

fn coverage_owner(
    owner: &str,
    owners: &BTreeMap<&str, &Component>,
    out: &mut dyn Write,
) -> io::Result<()> {
    let Some(component) = owners.get(owner) else {
        return write!(out, "unresolved reference {}", safe(owner));
    };
    identity(component, out)?;
    let (paths, _) = input_paths(&component.properties);
    super::input_summary(paths.iter().map(String::as_str), out)
}
