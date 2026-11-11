//! Pure interpretation of native audit evidence, never an advisory or upgrade solver.
use crate::api::audit::wire::MetadataCoverage;
use std::collections::BTreeSet;

mod assessment;
pub(crate) mod explain;
mod lifecycle;
pub(crate) mod remediation;
pub(crate) mod saved;
#[cfg(test)]
mod test_support;
pub(crate) use assessment::assess;

pub(crate) struct Summary {
    pub dependencies: u64,
    pub vulnerabilities: u64,
    pub lifecycle: u64,
    pub retained_lifecycle_warnings: u64,
    pub outdated: u64,
    pub duplicates: u64,
}

/// Only exact producer advisory IDs select ignores; aliases stay evidence.
pub(crate) fn ignored<'a>(
    policy: &'a crate::config::Audit,
    id: &str,
) -> Option<&'a crate::config::AdvisoryIgnore> {
    policy.ignore.iter().find(|ignore| ignore.id == id)
}

pub(crate) struct Assessment {
    pub summary: Summary,
    pub unverified: BTreeSet<&'static str>,
    pub attention: bool,
    pub incomplete: bool,
}

/// Whether outdated metadata remains unchecked.
pub(crate) const fn metadata_gap(c: &MetadataCoverage) -> bool {
    c.checked_count != c.candidates_count
        || c.unknown_count != 0
        || c.not_collected_count != 0
        || !c.not_collected_registries.is_empty()
}

fn metadata_total(c: &MetadataCoverage) -> Option<u64> {
    c.checked_count
        .checked_add(c.unknown_count)
        .and_then(|n| n.checked_add(c.not_collected_count))
}

#[cfg(test)]
mod tests;
