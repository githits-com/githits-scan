//! Exact displayed advisory context for semantic compression.
use crate::commands::audit::view::{
    self,
    remediation::{Finding, Record},
};
use std::collections::BTreeSet;

type Identity<'a> = (&'a str, Option<&'a str>, &'a BTreeSet<String>);

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
    pub(in crate::commands::audit) fn record(record: &'a Record) -> Self {
        Self::new(facts(record))
    }

    /// Build context from findings actually displayed by native grouping.
    pub(in crate::commands::audit) fn new(findings: impl Iterator<Item = &'a Finding>) -> Self {
        Self {
            findings: findings.map(identity).collect(),
        }
    }

    /// Full source paths are compared independently of advisory identity.
    pub(in crate::commands::audit) fn files(&self) -> BTreeSet<String> {
        self.findings
            .iter()
            .flat_map(|(_, _, files)| files.iter().cloned())
            .collect()
    }

    /// Equal packages alone never establish equal displayed advisory coverage.
    pub(in crate::commands::audit) fn matches(&self, findings: &[Finding]) -> bool {
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

/// All findings explicitly referenced by a recommendation.
pub(in crate::commands::audit) fn facts(record: &Record) -> impl Iterator<Item = &Finding> {
    record
        .findings
        .iter()
        .chain(&record.addressed_findings)
        .chain(&record.remaining_findings)
}
