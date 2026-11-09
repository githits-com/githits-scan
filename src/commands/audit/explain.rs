//! Focused explanation of one component using the existing mitigation guidance.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use serde::Serialize;

use super::render::{self, safe};
use super::view::{self, View, remediation::State};
use crate::audit::{
    explain::{Explanation, Source},
    saved::Provenance,
};

mod requests;

#[derive(Serialize)]
struct Document<'a, 'b> {
    schema_version: u8,
    kind: &'static str,
    analysis: &'a Provenance,
    problems: Vec<&'a view::Finding>,
    sources: &'a [Source<'b>],
    #[serde(skip_serializing_if = "State::omitted")]
    remediation: &'a State,
    issues: &'a std::collections::BTreeSet<&'static str>,
    audit_incomplete: bool,
    audit_issues: &'a [view::Issue],
}

pub(super) fn write(
    view: &View,
    provenance: &Provenance,
    selected: &Explanation<'_>,
    json: bool,
    out: &mut dyn Write,
) -> io::Result<()> {
    let problems: Vec<_> = selected
        .finding_indices
        .iter()
        .filter_map(|&i| view.vulnerabilities.get(i))
        .collect();
    if json {
        serde_json::to_writer_pretty(
            &mut *out,
            &Document {
                schema_version: 1,
                kind: "audit_explanation",
                analysis: provenance,
                problems,
                sources: &selected.sources,
                remediation: &view.remediation,
                issues: &selected.issues,
                audit_incomplete: view.incomplete,
                audit_issues: &view.issues,
            },
        )
        .map_err(io::Error::other)?;
        writeln!(out)?;
        return out.flush();
    }
    writeln!(
        out,
        "Saved analysis from {}",
        safe(&provenance.generated_at)
    )?;
    if let Some(first) = problems.first() {
        writeln!(out, "{} — vulnerable", safe(&first.package))?;
    }
    problem_details(&problems, out)?;
    let sources: Vec<_> = selected
        .sources
        .iter()
        .map(requests::Requests::new)
        .collect();
    for source in &sources {
        // Source groups use the same finding paths already shown by problem_details.
        source.introduction(sources.len() > 1, out)?;
    }
    write_issues(&selected.issues, "\n", out)?;
    guidance(view, &problems, selected, out)?;
    for source in &sources {
        source.further(out)?;
    }
    if !view.issues.is_empty() {
        writeln!(
            out,
            "\nAudit evidence gaps: {} reported. Replay without --explain for details.",
            crate::commands::plural(view.issues.len(), "issue")
        )?;
    }
    out.flush()
}

fn problem_details(problems: &[&view::Finding], out: &mut dyn Write) -> io::Result<()> {
    for f in problems {
        write!(
            out,
            "  {}",
            safe(f.advisory.as_deref().unwrap_or("advisory not recorded"))
        )?;
        for alias in &f.aliases {
            write!(out, " / {}", safe(alias))?;
        }
        if let Some(ignore) = &f.ignore {
            write!(out, " IGNORED — {}", safe(&ignore.reason))?;
        }
        if let Some(severity) = f.human_severity() {
            write!(out, " ({})", safe(&severity))?;
        }
        if f.malicious {
            write!(out, " MALICIOUS")?;
        }
        if let Some(title) = &f.title {
            write!(out, ": {}", safe(title))?;
        }
        writeln!(out)?;
    }
    let files = problems
        .iter()
        .flat_map(|f| f.files.iter().cloned())
        .collect();
    render::file_list("Found in", &files, "  ", out)
}

fn guidance(
    view: &View,
    problems: &[&view::Finding],
    selected: &Explanation<'_>,
    out: &mut dyn Write,
) -> io::Result<()> {
    writeln!(out, "\nFix guidance:")?;
    let State::Present(data) = &view.remediation else {
        return writeln!(
            out,
            "\nMitigation guidance is unavailable or unverified in this saved report."
        );
    };
    if data.recommendations.is_empty() {
        writeln!(
            out,
            "\nNo recommendation retained for this component; this does not establish that no fix exists."
        )?;
    }
    let names: ScopeNames<'_> = selected
        .sources
        .iter()
        .flat_map(|s| {
            s.nodes
                .iter()
                .map(|n| ((s.id.as_str(), n.id.as_str()), (n.package.as_str(), s.file)))
        })
        .collect();
    let context = render::remediation::ProblemContext::selected(problems);
    for (i, record) in data.recommendations.iter().enumerate() {
        if data.recommendations.len() > 1 {
            writeln!(out, "\nAlternative {}", i + 1)?;
        }
        render::remediation::guidance(
            record,
            matches!(data.status.as_str(), "completed" | "limited"),
            &context,
            render::remediation::ReasonDetail::Evidence,
            out,
        )?;
        occurrence_scope(record, &names, out)?;
    }
    if data.limits.omitted_recommendations != 0 || !data.limits.reasons.is_empty() {
        writeln!(out, "\nFix search limits for the whole audit:")?;
    }
    render::remediation::shared_limits(data, out)
}

type ScopeNames<'a> = BTreeMap<(&'a str, &'a str), (&'a str, &'a str)>;

fn occurrence_scope(
    record: &view::remediation::Record,
    names: &ScopeNames<'_>,
    out: &mut dyn Write,
) -> io::Result<()> {
    let Some(scope) = &record.occurrence_scope else {
        return Ok(());
    };
    let remaining = scope
        .remaining
        .as_ref()
        .is_some_and(|r| !r.nodes.is_empty() || r.not_in_selected_trace != 0);
    if record.outcome != "partial"
        && scope.subject.nodes.len() <= 1
        && scope.subject.not_in_selected_trace == 0
        && !remaining
    {
        return Ok(());
    }
    let subject = format!("Subject copies of {}", safe(&record.subject));
    ref_set(&subject, &scope.subject, names, out)?;
    for (change, refs) in record.changes.iter().zip(&scope.changes) {
        let label = format!(
            "Copies for {}:{}",
            safe(&change.data.registry),
            safe(&change.data.name)
        );
        if let Some(refs) = refs {
            ref_set(&label, refs, names, out)?;
        } else {
            writeln!(out, "    {label}: detail not supplied")?;
        }
    }
    if let Some(refs) = &scope.remaining {
        ref_set("Remaining copies", refs, names, out)
    } else {
        writeln!(out, "    Remaining copy references were not supplied.")
    }
}

fn ref_set(
    label: &str,
    refs: &crate::audit::explain::RefSet,
    names: &ScopeNames<'_>,
    out: &mut dyn Write,
) -> io::Result<()> {
    writeln!(out, "    {label}:")?;
    for r in &refs.nodes {
        if let Some((package, file)) = names.get(&(r.source.as_str(), r.node.as_str())) {
            writeln!(out, "      {} [{}; {}]", safe(package), safe(file), r.node)?;
        }
    }
    if refs.not_in_selected_trace != 0 {
        writeln!(
            out,
            "      Copy references not represented in the selected trace: {}",
            refs.not_in_selected_trace
        )?;
    } else if refs.nodes.is_empty() {
        writeln!(out, "      no copy references reported")?;
    }
    Ok(())
}

fn write_issues(issues: &BTreeSet<&str>, prefix: &str, out: &mut dyn Write) -> io::Result<()> {
    let messages: BTreeSet<_> = issues.iter().map(|issue| issue_text(issue)).collect();
    for message in messages {
        writeln!(out, "{prefix}{message}")?;
    }
    Ok(())
}

fn issue_text(issue: &str) -> &'static str {
    match issue {
        "remediation_unavailable" => "Dependency trace was not supplied in this analysis.",
        "trace_not_retained" => "Dependency trace was not retained in this analysis.",
        "trace_status_unavailable" => "Dependency trace status is not supported.",
        "no_recorded_occurrence" => "No matching recorded occurrence is available for this file.",
        "relation_refs_unverified" | "relation_source_unverified" => {
            "Some recorded requests have unverified references; affected routes are not shown."
        }
        "recommendation_occurrence_refs_unverified" => {
            "Recommendation occurrence references are unverified."
        }
        "recommendation_copy_detail_unavailable" => {
            "Copy-specific recommendation detail is unavailable."
        }
        "dependency_coverage_incomplete" => "Recorded dependency evidence is incomplete.",
        "dependency_coverage_unknown" => "Completeness of recorded dependency evidence is unknown.",
        "additional_dependency_observations" => {
            "Additional recorded observations are listed after the fixes; they do not establish dependency ancestry."
        }
        _ => "Dependency detail is unverified.",
    }
}

/// Rank exact name/substring matches before spelling distance; suggestions never
/// change the selector. Only coordinates from vulnerable saved findings qualify.
pub(super) fn candidates(view: &View, selector: &str) -> String {
    let query = package_name(selector).to_lowercase();
    let packages: BTreeSet<_> = view
        .vulnerabilities
        .iter()
        .map(|f| f.package.as_str())
        .collect();
    if packages.is_empty() {
        return "\n  this saved report contains no vulnerable components".into();
    }
    let mut ranked: Vec<_> = packages
        .into_iter()
        .map(|package| {
            let name = package_name(package).to_lowercase();
            let rank = if name == query {
                0
            } else if name.contains(&query) {
                1
            } else {
                2
            };
            ((rank, spelling_distance(&query, &name)), package)
        })
        .collect();
    ranked.sort_unstable();
    let mut text = "\n  closest candidates in this saved report:".to_owned();
    for (_, package) in ranked.into_iter().take(5) {
        text.push_str("\n    ");
        let preview: String = package.chars().take(240).collect();
        text.push_str(&safe(&preview));
        if package.chars().nth(240).is_some() {
            text.push_str("... (see saved report for full coordinate)");
        }
    }
    text
}

fn package_name(coordinate: &str) -> &str {
    let name = coordinate
        .split_once(':')
        .map_or(coordinate, |(_, name)| name);
    name.rsplit_once('@')
        .filter(|(name, _)| !name.is_empty())
        .map_or(name, |(name, _)| name)
}

// Bound ranking work for arbitrary CLI input and unusually long package names.
fn spelling_distance(left: &str, right: &str) -> usize {
    let right: Vec<_> = right.chars().take(128).collect();
    let mut row: Vec<_> = (0..=right.len()).collect();
    for (i, a) in left.chars().take(128).enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, b) in right.iter().enumerate() {
            let above = row[j + 1];
            row[j + 1] = (above + 1)
                .min(row[j] + 1)
                .min(diagonal + usize::from(a != *b));
            diagonal = above;
        }
    }
    row[right.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(packages: &[&str], query: &str) -> String {
        let report = crate::api::audit::Report::from_bytes(include_bytes!(
            "../../../tests/fixtures/audit/v2-findings.json"
        ))
        .expect("report");
        let (mut view, _) =
            super::super::project(&report, Vec::new(), &crate::config::Audit::default());
        view.vulnerabilities = packages
            .iter()
            .map(|package| view::Finding {
                package: (*package).into(),
                ..view::Finding::default()
            })
            .collect();
        candidates(&view, query)
    }

    #[test]
    fn suggestions_rank_names_and_typos_deduplicate_and_cap_candidates() {
        let packages = [
            "npm:@babel/core@1",
            "npm:zulu@1",
            "npm:demo@2",
            "npm:demo@1",
            "npm:demo@1",
            "npm:alpha@1",
            "npm:bravo@1",
            "npm:charlie@1",
            "npm:delta@1",
        ];
        for query in ["demo", "npm:demo@99", "dmeo"] {
            let text = result(&packages, query);
            let lines: Vec<_> = text.lines().skip(2).collect();
            assert_eq!(lines.len(), 5, "{text}");
            assert_eq!(lines[0], "    npm:demo@1", "{query}: {text}");
            assert_eq!(text.matches("npm:demo@1").count(), 1);
        }
        for query in ["@babel/core", "npm:@babel/core", "npm:@babel/core@99"] {
            let text = result(&packages, query);
            assert_eq!(text.lines().nth(2), Some("    npm:@babel/core@1"), "{text}");
        }
    }

    #[test]
    fn suggestions_escape_untrusted_coordinates_and_bound_long_values() {
        let package = format!("npm:evil\nline\u{1b}[31m{}@1", "a".repeat(1000));
        let text = result(&[&package], "evil");
        assert_eq!(text.lines().count(), 3, "{text}");
        assert!(text.contains("evil\\nline\\u{1b}[31m"), "{text}");
        assert!(text.contains("see saved report for full coordinate"));
        assert!(text.len() < 400);
        assert!(result(&[], "demo").contains("no vulnerable components"));
    }
}
