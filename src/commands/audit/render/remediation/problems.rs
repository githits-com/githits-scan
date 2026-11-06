//! Borrowed human problem context and stable grouping of independent alternatives.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use super::super::{file_list, list, safe};
use crate::commands::audit::view::{
    self,
    remediation::{Finding, Record, Remediation},
};

type Identity<'a> = (&'a str, Option<&'a str>, &'a BTreeSet<String>);
type Groups<'a> = BTreeMap<&'a str, Vec<&'a Record>>;
type Problems<'a> = BTreeMap<&'a str, BTreeSet<&'a Finding>>;

/// Finding identities actually displayed before guidance, not an inferred fix scope.
pub(in crate::commands::audit) struct Context<'a> {
    findings: BTreeSet<Identity<'a>>,
}

impl<'a> Context<'a> {
    /// The selected explanation can be narrower than a joint recommendation.
    pub(in crate::commands::audit) fn selected(findings: &[&'a view::Finding]) -> Self {
        Self {
            findings: findings
                .iter()
                .map(|f| (f.package.as_str(), f.advisory.as_deref(), &f.files))
                .collect(),
        }
    }

    /// A record's own problem context includes every explicitly referenced finding.
    pub(super) fn record(record: &'a Record) -> Self {
        Self::new(facts(record))
    }

    fn new(findings: impl Iterator<Item = &'a Finding>) -> Self {
        Self {
            findings: findings.map(identity).collect(),
        }
    }

    /// Full source paths are compared independently of advisory identity.
    pub(super) fn files(&self) -> BTreeSet<String> {
        self.findings
            .iter()
            .flat_map(|(_, _, files)| files.iter().cloned())
            .collect()
    }

    /// Equal packages alone never establish equal displayed advisory coverage.
    pub(super) fn matches(&self, findings: &[Finding]) -> bool {
        self.findings == findings.iter().map(identity).collect()
    }
}

fn identity(finding: &Finding) -> Identity<'_> {
    (
        &finding.package,
        Some(finding.advisory.as_str()),
        &finding.files,
    )
}

fn facts(record: &Record) -> impl Iterator<Item = &Finding> {
    record
        .findings
        .iter()
        .chain(&record.addressed_findings)
        .chain(&record.remaining_findings)
}

pub(super) fn write(
    data: &Remediation,
    planning_known: bool,
    out: &mut dyn Write,
) -> io::Result<()> {
    let mut groups = groups(data);
    let mut problems = problems(data);
    // Removing a group on first appearance preserves producer order within each subject.
    for record in &data.recommendations {
        let Some(records) = groups.remove(record.subject.as_str()) else {
            continue;
        };
        let displayed = take_context(&record.subject, &records, &groups, &mut problems);
        write_problem(&record.subject, &displayed, out)?;
        let context = Context::new(displayed.into_iter());
        alternatives(&records, planning_known, &context, out)?;
    }
    Ok(())
}

fn groups(data: &Remediation) -> Groups<'_> {
    let mut groups: Groups<'_> = BTreeMap::new();
    for record in &data.recommendations {
        groups.entry(&record.subject).or_default().push(record);
    }
    groups
}

fn problems(data: &Remediation) -> Problems<'_> {
    let mut problems: Problems<'_> = BTreeMap::new();
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
    records: &[&'a Record],
    remaining: &Groups<'_>,
    problems: &mut Problems<'a>,
) -> Vec<&'a Finding> {
    let mut displayed: Vec<_> = problems.remove(subject).into_iter().flatten().collect();
    let related: BTreeSet<_> = records
        .iter()
        .flat_map(|r| facts(r))
        .map(|f| f.package.as_str())
        .collect();
    // A related component with its own group gets its full problem there. Otherwise
    // show it before the first joint alternative that refers to it, exactly once.
    for package in related {
        if remaining.contains_key(package) {
            continue;
        }
        displayed.extend(problems.remove(package).into_iter().flatten());
    }
    displayed
}

fn alternatives(
    records: &[&Record],
    planning_known: bool,
    context: &Context<'_>,
    out: &mut dyn Write,
) -> io::Result<()> {
    for (index, record) in records.iter().enumerate() {
        if records.len() > 1 {
            writeln!(out, "\n    Alternative {}", index + 1)?;
        }
        super::guidance(record, planning_known, context, out)?;
    }
    Ok(())
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
