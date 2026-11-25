//! Select the material evidence for the default audit report.
use super::{
    AdvisoryIdentities, Finding, Plan, Qualification, Record, Remediation, added_branches,
    advisory_identities, capitalize, check_line, compact_limitation, limitations, location, owner,
    qualified_advisory, safe, search_only_limit, sentence, target_checks,
};
use crate::commands::audit::presentation::{added, search};
use crate::commands::audit::view::remediation::reasons::Reason;
use std::collections::BTreeSet;

/// Report-wide limits that qualify the completeness of the displayed guidance.
pub(in crate::commands::audit) fn report_limit(data: &Remediation) -> Option<String> {
    let mut seen = BTreeSet::new();
    let reasons = &data.limits.reasons;
    let omitted = data.limits.omitted_recommendations != 0
        || reasons.iter().any(|reason| reason == "output_limit");
    let mut lines: Vec<_> = reasons
        .iter()
        .filter(|reason| reason.as_str() != "output_limit" && !search_only_limit(reason))
        .map(|reason| sentence(capitalize(super::explanation(reason))))
        .filter(|message| seen.insert(message.clone()))
        .collect();
    if omitted {
        lines.push(
            "Some fix guidance was omitted because the report reached its size limit.".into(),
        );
    }
    if lines.is_empty() {
        return None;
    }
    if data.status == "limited" {
        lines.insert(0, "Fix guidance is incomplete.".into());
    }
    Some(lines.join(" "))
}

impl Plan {
    /// Show the action and return any additional search limits for its group.
    pub(in crate::commands::audit) fn terminal(
        &self,
        record: &Record,
        qualification: Qualification,
        report_limits: &[String],
    ) -> (Vec<String>, Vec<String>) {
        let show_search_limit = (!qualification.suggested()
            || !record.remaining_findings.is_empty())
            && record.checks.parent_search == "limited"
            && !record.changes.is_empty();
        let unbound = record
            .limitations
            .iter()
            .any(|reason| reason == "unbound_request");
        let combine_metadata = show_search_limit
            && unbound
            && record
                .limitations
                .iter()
                .any(|reason| reason == "parent_evidence_incomplete");
        let declaration = (unbound || record.changes.is_empty())
            .then(|| search::unbound_request(record, combine_metadata))
            .flatten();
        let search_limits = if show_search_limit {
            terminal_search_limits(record, combine_metadata && declaration.is_some())
        } else {
            Vec::new()
        };

        let mut lines = self.terminal_action(record, qualification);
        lines.extend(self.terminal_impact(record));
        for constraint in &self.constraints {
            lines.push(sentence(capitalize(constraint.summary.clone())));
            lines.extend(constraint.details.iter().cloned());
        }
        lines.extend(self.terminal_checks(record, report_limits, unbound, declaration));
        (lines, search_limits)
    }

    fn terminal_impact(&self, r: &Record) -> Vec<String> {
        let scoped = r
            .addressed_findings
            .iter()
            .chain(&r.remaining_findings)
            .map(|finding| &finding.files)
            .collect::<BTreeSet<_>>();
        if r.remaining_findings.is_empty() || scoped.len() <= 1 {
            return self
                .impact
                .iter()
                .cloned()
                .map(capitalize)
                .map(sentence)
                .collect();
        }
        let addressed = advisory_identities(&r.addressed_findings);
        let remaining = advisory_identities(&r.remaining_findings);
        [
            ("Would address", &r.addressed_findings, &remaining),
            ("Still unresolved", &r.remaining_findings, &addressed),
        ]
        .into_iter()
        .flat_map(|(label, findings, other)| {
            findings
                .iter()
                .map(move |f| scoped_finding(label, f, other))
        })
        .collect()
    }

    fn terminal_action(&self, r: &Record, qualification: Qualification) -> Vec<String> {
        let mut lines: Vec<_> = self.outcome.iter().cloned().collect();
        if self.changes.is_empty() {
            return lines;
        }
        let label = if qualification.suggested() {
            "Upgrade"
        } else {
            "Candidate"
        };
        let partial = if r.outcome == "partial" {
            " (partial)"
        } else {
            ""
        };
        let location = location(&self.files);
        let joint = self.changes.len() > 1;
        if joint {
            lines.push(format!("{label} together{partial}{location}:"));
        }
        let (prefix, suffix, evidence_indent) = if joint {
            ("  ".into(), "", "    ")
        } else {
            (format!("{label}{partial}: "), location.as_str(), "")
        };
        let show_method = r.checks.requirements == "matched" && self.constraints.is_empty();
        for (change, supplied) in self.changes.iter().zip(&r.changes) {
            lines.push(format!("{prefix}{}{suffix}", change.compact));
            let evidence = change
                .application_issue
                .iter()
                .filter(|_| show_method)
                .cloned()
                .map(sentence)
                .chain(
                    change
                        .reasons
                        .iter()
                        .map(|reason| sentence(capitalize(reason.summary.clone()))),
                )
                .chain(
                    added_branches(supplied)
                        .iter()
                        .flat_map(added::problem_lines),
                );
            lines.extend(evidence.map(|line| format!("{evidence_indent}{line}")));
        }
        if !qualification.suggested() || !self.constraints.is_empty() {
            return lines;
        }
        match (&r.requester, self.files.is_empty()) {
            (Some(request), _) => lines.push(format!(
                "One recorded requester is {} ({}) [{}].",
                owner(&request.owner_name, request.owner_version.as_deref()),
                safe(&request.requirement),
                safe(&request.path),
            )),
            (None, true) => {
                lines.extend(self.context.first().cloned().map(capitalize).map(sentence));
            }
            (None, false) => {}
        }
        lines
    }

    fn terminal_checks(
        &self,
        r: &Record,
        report_limits: &[String],
        unbound: bool,
        declaration: Option<String>,
    ) -> Vec<String> {
        let explains_unbound = declaration.is_some();
        let mut lines: Vec<_> = target_checks(r)
            .filter(|(label, value)| {
                !(*label == "requirements"
                    && unbound
                    && matches!(
                        *value,
                        "not_checked" | "unchecked" | "not_assessed" | "unknown"
                    ))
            })
            .map(|(label, value)| sentence(check_line(label, value, true)))
            .collect();
        lines.extend(declaration);
        lines.extend(super::other_checks(r, false, false));
        let route_removal = has_route_removal(r);
        for limit in limitations(r, &self.constraints).filter(|(code, _)| {
            !(report_limits.iter().any(|reason| reason == code)
                || search_only_limit(code)
                || matches!(*code, "no_checked_parent_upgrade" | "no_checked_leaf")
                || (explains_unbound && *code == "unbound_request")
                || (route_removal && *code == "represented_routes_cut"))
        }) {
            lines.push(sentence(compact_limitation(limit)));
        }
        if r.changes.is_empty() && !unbound && !explains_unbound {
            lines.extend(search::compact_obstacle(r, &self.search_explanations));
        }
        lines
    }
}

fn terminal_search_limits(r: &Record, metadata_explained: bool) -> Vec<String> {
    let mut limits: Vec<_> = r
        .limitations
        .iter()
        .filter(|reason| {
            search_only_limit(reason)
                && !(metadata_explained && *reason == "parent_evidence_incomplete")
        })
        .map(|reason| sentence(compact_limitation((reason, super::explanation(reason)))))
        .collect();
    if limits.is_empty() && !metadata_explained {
        limits.push("The service could not finish checking updates to requesting packages.".into());
    }
    limits
}

fn scoped_finding(label: &str, f: &Finding, other: &AdvisoryIdentities<'_>) -> String {
    format!(
        "{label}: {} — {}{}.",
        safe(&f.package),
        qualified_advisory(f, other),
        location(&f.files)
    )
}

fn has_route_removal(r: &Record) -> bool {
    r.changes
        .iter()
        .flat_map(|c| c.reasons.iter().flatten())
        .any(|reason| matches!(reason, Reason::Removes { .. }))
}
