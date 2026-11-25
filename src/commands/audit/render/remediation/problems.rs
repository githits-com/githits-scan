//! Borrowed human problem context and stable grouping of independent alternatives.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use super::super::{file_list, list, paths, safe};
use crate::commands::audit::{
    presentation::{
        Plan,
        context::{Context, facts},
        remediation::Qualification,
    },
    view::remediation::{Finding, Record, Remediation},
};
use crate::style::Palette;

type Groups<'a> = BTreeMap<&'a str, Group<'a>>;
type Problems<'a> = BTreeMap<&'a str, BTreeSet<&'a Finding>>;

#[derive(Default)]
struct Group<'a> {
    suggested: bool,
    alternatives: Vec<Alternative<'a>>,
}

struct Alternative<'a> {
    record: &'a Record,
    qualification: Qualification,
}

impl Alternative<'_> {
    fn plan(&self, status: &str, context: &Context<'_>) -> Plan {
        Plan::with_qualification(
            self.record,
            status,
            context,
            super::ReasonDetail::Summary,
            self.qualification,
        )
    }
}

pub(super) fn write(
    data: &Remediation,
    details: bool,
    out: &mut dyn Write,
    palette: Palette,
) -> io::Result<()> {
    let (mut groups, mut order) = groups(data);
    let mut problems = problems(data);
    if !details {
        order.sort_by_key(|subject| !groups.get(subject).is_some_and(|group| group.suggested));
    }
    let mut previous = None;
    for subject in order {
        let Some(mut group) = groups.remove(subject) else {
            continue;
        };
        let displayed = take_context(subject, &group.alternatives, &groups, &mut problems);
        let context = Context::new(displayed.iter().copied());
        if details {
            write_problem(subject, &displayed, out)?;
            detailed_alternatives(&group.alternatives, &data.status, &context, out)?;
            continue;
        }
        if previous != Some(group.suggested) {
            let heading = compact_heading(group.suggested);
            writeln!(out, "\n{}", palette.bold(heading))?;
            previous = Some(group.suggested);
        }
        group
            .alternatives
            .sort_by_key(|a| !a.qualification.suggested());
        compact_group(subject, &group, &data.status, &context, &displayed, out)?;
    }
    Ok(())
}

const fn compact_heading(suggested: bool) -> &'static str {
    if suggested {
        "Suggested updates"
    } else {
        "Needs a decision"
    }
}

fn groups(data: &Remediation) -> (Groups<'_>, Vec<&str>) {
    let mut groups = Groups::new();
    let mut order = Vec::new();
    for record in &data.recommendations {
        let group = groups.entry(&record.subject).or_insert_with(|| {
            order.push(record.subject.as_str());
            Group::default()
        });
        let qualification = Qualification::new(record, &data.status);
        group.suggested |= qualification.suggested();
        group.alternatives.push(Alternative {
            record,
            qualification,
        });
    }
    (groups, order)
}

fn problems(data: &Remediation) -> Problems<'_> {
    let mut problems = Problems::new();
    for finding in data.recommendations.iter().flat_map(facts) {
        problems
            .entry(&finding.package)
            .or_default()
            .insert(finding);
    }
    problems
}

fn take_context<'a>(
    subject: &str,
    alternatives: &[Alternative<'a>],
    remaining: &Groups<'_>,
    problems: &mut Problems<'a>,
) -> Vec<&'a Finding> {
    let mut displayed: Vec<_> = problems.remove(subject).into_iter().flatten().collect();
    let related: BTreeSet<_> = alternatives
        .iter()
        .flat_map(|a| facts(a.record))
        .map(|f| f.package.as_str())
        .collect();
    // A component with its own group gets its full problem there. Otherwise,
    // give the context to the first displayed group that refers to it.
    for package in related {
        if !remaining.contains_key(package) {
            displayed.extend(problems.remove(package).into_iter().flatten());
        }
    }
    displayed
}

fn detailed_alternatives(
    alternatives: &[Alternative<'_>],
    status: &str,
    context: &Context<'_>,
    out: &mut dyn Write,
) -> io::Result<()> {
    for (index, alternative) in alternatives.iter().enumerate() {
        if alternatives.len() > 1 {
            writeln!(out, "\n    Alternative {}", index + 1)?;
        }
        super::detailed_plan(&alternative.plan(status, context), out)?;
    }
    Ok(())
}

fn compact_group(
    subject: &str,
    group: &Group<'_>,
    status: &str,
    context: &Context<'_>,
    findings: &[&Finding],
    out: &mut dyn Write,
) -> io::Result<()> {
    writeln!(out, "  {}", safe(subject))?;
    let mut search_limit = None;
    for a in &group.alternatives {
        super::lines(
            &a.plan(status, context).terminal(a.record, a.qualification),
            "    ",
            out,
        )?;
        if search_limit.is_none() {
            search_limit = Plan::terminal_search_limit(a.record, a.qualification);
        }
    }
    if let Some(limit) = search_limit {
        super::line(&limit, "    ", out)?;
    }
    compact_advisories(subject, findings, out)
}

fn compact_advisories(subject: &str, findings: &[&Finding], out: &mut dyn Write) -> io::Result<()> {
    let mut evidence: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for finding in findings {
        evidence
            .entry((&finding.package, &finding.files))
            .or_default()
            .push(*finding);
    }
    for ((package, files), advisories) in evidence {
        let package = if package == subject {
            String::new()
        } else {
            format!(" {}", safe(package))
        };
        let source = paths(files);
        let advisories = advisories
            .iter()
            .map(|finding| compact_advisory(finding))
            .collect::<Vec<_>>()
            .join(", ");
        super::line(
            &format!("Advisories{package}{source}: {advisories}"),
            "    ",
            out,
        )?;
    }
    Ok(())
}

fn compact_advisory(finding: &Finding) -> String {
    let advisory = safe(&finding.advisory);
    let mut label = match &finding.severity {
        Some(severity) => format!("{advisory} ({})", safe(severity)),
        None => advisory,
    };
    if finding.malicious {
        label.push_str(" MALICIOUS");
    }
    label
}

fn write_problem(subject: &str, findings: &[&Finding], out: &mut dyn Write) -> io::Result<()> {
    let mut groups: BTreeMap<&str, BTreeSet<&Finding>> = BTreeMap::new();
    for finding in findings {
        groups.entry(&finding.package).or_default().insert(finding);
    }
    if let Some(findings) = groups.remove(subject) {
        component(subject, &findings, out)?;
    } else {
        writeln!(out, "  {}", safe(subject))?;
    }
    for (package, findings) in groups {
        component(package, &findings, out)?;
    }
    Ok(())
}

fn component(package: &str, findings: &BTreeSet<&Finding>, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "  {} — vulnerable", safe(package))?;
    let mut files = BTreeSet::new();
    for finding in findings {
        advisory_line(finding, out)?;
        files.extend(finding.files.iter().cloned());
    }
    file_list("Found in", &files, "    ", out)
}

fn advisory_line(finding: &Finding, out: &mut dyn Write) -> io::Result<()> {
    write!(out, "    {}", safe(&finding.advisory))?;
    for alias in &finding.aliases {
        write!(out, " / {}", safe(alias))?;
    }
    if let Some(severity) = &finding.severity {
        write!(out, " ({})", safe(severity))?;
    }
    if finding.malicious {
        write!(out, " MALICIOUS")?;
    }
    if let Some(title) = &finding.title {
        write!(out, ": {}", safe(title))?;
    }
    writeln!(out)?;
    for (label, values) in [
        ("advisory-reported fix versions", &finding.proposed_fixes),
        ("verified advisory fixes", &finding.verified_advisory_fixes),
    ] {
        if !values.is_empty() {
            writeln!(out, "      {label}: {}", list(values))?;
        }
    }
    Ok(())
}
