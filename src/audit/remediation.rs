//! Only consumed reference bounds and scoped-negative prerequisites are checked here.
use crate::api::audit::v2::V2;

pub(crate) const UNVERIFIED: &str =
    "mitigation recommendation references or search domain are unverified";

pub(super) fn verified(report: &V2) -> bool {
    let Some(remediation) = &report.remediation else {
        return true;
    };
    remediation.recommendations.iter().all(|r| {
        r.finding_refs
            .iter()
            .chain(&r.addressed_finding_refs)
            .chain(&r.remaining_finding_refs)
            .all(|&index| index < report.findings.vulnerabilities.len())
            && (r.outcome != "no_upgrade_path" || r.search_domain.is_some())
    })
}
