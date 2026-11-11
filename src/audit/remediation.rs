//! Only consumed reference bounds and scoped-negative prerequisites are checked here.
use crate::api::audit::{remediation::Reason, report::Data};

pub(crate) const UNVERIFIED: &str =
    "mitigation recommendation references or search domain are unverified";

pub(super) fn verified(report: &Data) -> bool {
    let Some(remediation) = &report.remediation else {
        return true;
    };
    remediation.recommendations.iter().all(|r| {
        r.finding_refs
            .iter()
            .chain(&r.addressed_finding_refs)
            .chain(&r.remaining_finding_refs)
            .all(|&index| index < report.findings.vulnerabilities.len())
            && r.changes
                .iter()
                .flat_map(|c| c.reasons.iter().flatten())
                .flat_map(|reason| match reason {
                    Reason::Advisory(data) => data.finding_refs.as_slice(),
                    _ => &[],
                })
                .all(|&index| index < report.findings.vulnerabilities.len())
            && (r.outcome != "no_upgrade_path" || r.search_domain.is_some())
    })
}
