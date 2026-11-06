//! Compact human presentation of the same results emitted as JSON.
use std::collections::BTreeSet;
use std::io::{self, Write};

use super::view::{Duplicate, DuplicateVersion, Finding, Issue, Origin, View};
use crate::style::Palette;

mod native;
pub(super) mod remediation;

pub(super) use crate::commands::safe;

pub(super) fn requirement_status(value: &str) -> String {
    match value {
        "not_recorded" => "not recorded".into(),
        "provider_requirement" => "bound to a provider package".into(),
        _ => safe(value),
    }
}

fn list<'a>(values: impl IntoIterator<Item = &'a String>) -> String {
    values
        .into_iter()
        .map(|s| safe(s))
        .collect::<Vec<_>>()
        .join(", ")
}
fn paths(files: &BTreeSet<String>) -> String {
    if files.is_empty() {
        return String::new();
    }
    format!(" [{}]", list(files))
}
pub(super) fn file_list(
    label: &str,
    files: &BTreeSet<String>,
    indent: &str,
    out: &mut dyn Write,
) -> io::Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    let inline = format!("{indent}{label}: {}", list(files));
    if inline.chars().count() <= 100 {
        return writeln!(out, "{inline}");
    }
    writeln!(out, "{indent}{label} ({}):", files.len())?;
    for file in files {
        writeln!(out, "{indent}  {}", safe(file))?;
    }
    Ok(())
}

fn heading(name: &str, count: usize, out: &mut dyn Write, palette: Palette) -> io::Result<()> {
    writeln!(out, "\n{} ({count})", palette.bold(name))
}
pub(super) fn write(
    view: &View,
    details: bool,
    out: &mut dyn Write,
    palette: Palette,
) -> io::Result<()> {
    if let Some(analysis) = &view.analysis {
        writeln!(out, "Saved analysis from {}", safe(&analysis.generated_at))?;
    }
    let headline = if !view.vulnerabilities.is_empty()
        || !view.deprecated.is_empty()
        || !view.outdated.is_empty()
        || !view.duplicates.is_empty()
        || !view.manifest_lock_mismatches.is_empty()
    {
        "Audit findings"
    } else if view.incomplete {
        "Audit results"
    } else {
        "No audit findings in checked dependencies"
    };
    writeln!(out, "{}", palette.bold(headline))?;
    if let Some(s) = &view.summary {
        writeln!(
            out,
            "{} {}; {} {}, {} deprecated, {} outdated, {} duplicate {}{}",
            s.dependencies,
            noun(s.dependencies, "dependency", "dependencies"),
            s.vulnerabilities,
            noun(s.vulnerabilities, "vulnerability", "vulnerabilities"),
            s.deprecated,
            s.outdated,
            s.duplicates,
            noun(s.duplicates, "package", "packages"),
            s.manifest_lock_mismatches
                .map_or_else(String::new, |count| format!(
                    "; {count} manifest/lock {}",
                    if count == 1 {
                        "disagreement"
                    } else {
                        "disagreements"
                    }
                ))
        )?;
    }
    file_list("Manifests", &view.manifests, "", out)?;
    file_list(
        "Resolved from manifest constraints",
        &view.resolved_from_manifests,
        "",
        out,
    )?;
    vulnerability_section(view, out, palette)?;
    remediation::write(view, out, palette)?;
    native::mismatches(view, out, palette)?;
    maintenance(view, details, out, palette)?;
    for (excluded, title) in [(false, "Incomplete checks"), (true, "Packages not checked")] {
        let issues: Vec<_> = view
            .issues
            .iter()
            .filter(|i| package_exclusion(i) == excluded)
            .collect();
        if issues.is_empty() {
            continue;
        }
        writeln!(out, "\n{}", palette.bold(title))?;
        for i in &issues {
            issue(i, out)?;
        }
        if issues.iter().any(|i| !i.required_files.is_empty()) {
            writeln!(
                out,
                "  action: check githits-scan detect and exclusions; add supported files to [lockfiles].manifests in githits-scan.toml"
            )?;
        }
    }
    for note in &view.limitations {
        writeln!(out, "\n{}", safe(note))?;
    }
    Ok(())
}
fn maintenance(
    view: &View,
    details: bool,
    out: &mut dyn Write,
    palette: Palette,
) -> io::Result<()> {
    if !details {
        if !view.deprecated.is_empty() || !view.outdated.is_empty() || !view.duplicates.is_empty() {
            writeln!(
                out,
                "\nUse --details to list deprecated, outdated and duplicate packages."
            )?;
        }
        return Ok(());
    }
    for (name, findings) in [
        ("Deprecated releases", &view.deprecated),
        ("Outdated versions", &view.outdated),
    ] {
        finding_section(name, findings, out, palette)?;
    }
    if !view.duplicates.is_empty() {
        heading("Duplicate versions", view.duplicates.len(), out, palette)?;
        for d in &view.duplicates {
            duplicate(d, out)?;
        }
    }
    Ok(())
}

const fn noun(count: u64, one: &'static str, many: &'static str) -> &'static str {
    if count == 1 { one } else { many }
}

fn vulnerability_section(view: &View, out: &mut dyn Write, palette: Palette) -> io::Result<()> {
    let uncovered: Vec<_> = view
        .vulnerabilities
        .iter()
        .enumerate()
        .filter(|(index, _)| !view.remediation.covers_finding(*index))
        .map(|(_, finding)| finding)
        .collect();
    if uncovered.is_empty() {
        return Ok(());
    }
    heading("Vulnerabilities", uncovered.len(), out, palette)?;
    for item in uncovered {
        finding(item, out)?;
    }
    Ok(())
}

fn finding_section(
    name: &str,
    findings: &[Finding],
    out: &mut dyn Write,
    palette: Palette,
) -> io::Result<()> {
    if findings.is_empty() {
        return Ok(());
    }
    heading(name, findings.len(), out, palette)?;
    for f in findings {
        finding(f, out)?;
    }
    Ok(())
}
fn finding(f: &Finding, out: &mut dyn Write) -> io::Result<()> {
    write!(out, "  {}", safe(&f.package))?;
    if let Some(latest) = &f.latest {
        write!(out, " -> {}", safe(latest))?;
    }
    if let Some(id) = &f.advisory {
        write!(out, " — {}", safe(id))?;
    }
    if let Some(severity) = f.human_severity() {
        write!(out, " ({})", safe(&severity))?;
    }
    if let Some(change) = &f.change {
        write!(out, " ({})", safe(change))?;
    }
    if f.malicious {
        write!(out, " MALICIOUS")?;
    }
    if let Some(reason) = &f.reason {
        write!(out, " — {}", safe(reason))?;
    }
    writeln!(out, "{}", paths(&f.files))?;
    if let Some(title) = f.title.as_ref().filter(|s| !s.is_empty()) {
        writeln!(out, "    {}", safe(title))?;
    }
    for (label, values) in [
        ("aliases", &f.aliases),
        ("advisory-reported fix versions", &f.proposed_fixes),
        ("verified advisory fixes", &f.verified_advisory_fixes),
    ] {
        if !values.is_empty() {
            writeln!(out, "    {label}: {}", list(values))?;
        }
    }
    Ok(())
}

fn shared_file(d: &Duplicate) -> Option<&str> {
    let file = d.versions.first()?.files.first()?.as_str();
    (d.versions.iter().all(|v| {
        v.files.len() == 1 && v.files.contains(file) && v.origins.iter().all(|o| o.file == file)
    }) && d.unattributed_requirements.iter().all(|u| u.file == file))
    .then_some(file)
}

fn duplicate(d: &Duplicate, out: &mut dyn Write) -> io::Result<()> {
    let shared = shared_file(d);
    write!(out, "  {}", safe(&d.package))?;
    if let Some(file) = shared {
        write!(out, " [{}]", safe(file))?;
    }
    writeln!(out)?;
    for v in &d.versions {
        duplicate_version(v, out, shared.is_none())?;
    }
    if !d.unattributed_requirements.is_empty() {
        writeln!(out, "    Declarations without a recorded dependency link")?;
    }
    for u in &d.unattributed_requirements {
        write!(
            out,
            "      {}",
            request(
                Some(&u.requester),
                u.requested_requirement.as_deref(),
                &u.requirement_status
            )
        )?;
        match u.target_status.as_str() {
            "untargeted" => (),
            "absent" => write!(out, "; dependency absent from recorded graph")?,
            value => write!(out, "; unrecognized link status: {}", safe(value))?,
        }
        if shared.is_none() {
            write!(out, " [{}]", safe(&u.file))?;
        }
        writeln!(out)?;
    }
    Ok(())
}

fn duplicate_version(
    v: &DuplicateVersion,
    out: &mut dyn Write,
    show_files: bool,
) -> io::Result<()> {
    let files = if show_files {
        paths(&v.files)
    } else {
        String::new()
    };
    writeln!(out, "    {}{files}", safe(&v.version))?;
    for o in &v.origins {
        write!(out, "      {}", origin_request(o))?;
        if v.files.len() != 1 || !v.files.contains(&o.file) {
            write!(out, " [{}]", safe(&o.file))?;
        }
        writeln!(out)?;
    }
    Ok(())
}

fn origin_request(origin: &Origin) -> String {
    if origin.status != "parent_release_compatible" {
        return request(
            origin.requester.as_deref(),
            origin.requested_requirement.as_deref(),
            &origin.status,
        );
    }
    let requester = safe(origin.requester.as_deref().unwrap_or("unknown requester"));
    origin.requested_requirement.as_deref().map_or_else(
        || format!("possible requester: {requester} — requirement unavailable"),
        |requirement| {
            format!(
                "possible requester: {requester} (requires {})",
                safe(requirement)
            )
        },
    )
}

fn request(requester: Option<&str>, requirement: Option<&str>, status: &str) -> String {
    let label = match status {
        "recorded" => "requirement missing",
        "parent_release_declared" => "published requirement unavailable",
        "requirement_not_recorded" | "not_recorded" => "requirement not recorded",
        "requirement_withheld" | "withheld" => "requirement withheld",
        "requirement_ambiguous" => "requirement ambiguous",
        "provider_requirement" => "requirement bound to a provider package",
        "parent_not_recorded" => "requesting dependency not recorded",
        value => value,
    };
    let Some(requirement) = requirement else {
        return requester.map_or_else(|| safe(label), |r| format!("{} — {}", safe(r), safe(label)));
    };
    let mut text = format!(
        "{} requests {}",
        safe(requester.unwrap_or("unknown requester")),
        safe(requirement)
    );
    if !matches!(status, "recorded" | "parent_release_declared") {
        text.push_str(" (");
        text.push_str(&safe(label));
        text.push(')');
    }
    text
}

pub(super) fn issue(i: &Issue, out: &mut dyn Write) -> io::Result<()> {
    if package_exclusion(i) {
        return writeln!(
            out,
            "  {} — {}{}",
            list(&i.packages),
            safe(&i.reason),
            paths(&i.files)
        );
    }
    let reason = if i.reason.is_empty() {
        String::new()
    } else {
        format!(": {}", safe(&i.reason))
    };
    let status = if i.status == "not_collected" {
        "not collected"
    } else {
        &i.status
    };
    writeln!(
        out,
        "  {} {}{reason}{}",
        safe(&i.check),
        safe(status),
        paths(&i.files)
    )?;
    native::missing_requests(&i.missing_requests, out)?;
    if !i.required_files.is_empty() {
        file_list("required files", &i.required_files, "    ", out)?;
    }
    if let Some(count) = i.package_count {
        writeln!(out, "    {count} packages ({})", list(&i.registries))?;
    }
    if !i.packages.is_empty() {
        writeln!(out, "    {}", list(&i.packages))?;
    }
    if !i.advisories.is_empty() {
        writeln!(out, "    advisories: {}", list(&i.advisories))?;
    }
    Ok(())
}

fn package_exclusion(issue: &Issue) -> bool {
    issue.check == "package checks" && issue.status == "excluded"
}
