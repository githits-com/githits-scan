//! Producer-owned causes joined through exact same-snapshot references.
use super::super::coverage;
use super::{Display, view};
use std::collections::{BTreeMap, BTreeSet};
use std::io;

pub(super) struct Evidence<'a> {
    base: Side<'a>,
    head: Side<'a>,
    declarations: BTreeMap<&'a str, &'a view::DeclarationChange>,
}

struct Side<'a> {
    occurrences: BTreeMap<&'a str, &'a view::Occurrence>,
    proofs: BTreeMap<&'a str, &'a view::RootProof>,
    bindings: BTreeMap<(&'a str, &'a str), Vec<&'a view::SnapshotBinding>>,
    declarations: BTreeMap<&'a str, &'a view::Declaration>,
}

pub(super) fn new(v: &view::View) -> Evidence<'_> {
    Evidence {
        base: side(&v.snapshots.base),
        head: side(&v.snapshots.head),
        declarations: v
            .declaration_changes
            .iter()
            .map(|c| (c.id.as_str(), c))
            .collect(),
    }
}

pub(super) fn changes(
    evidence: &Evidence<'_>,
    rows: &[&view::Change],
    d: &mut Display<'_>,
) -> io::Result<()> {
    let mut groups: Vec<(String, String, Vec<String>)> = Vec::new();
    for c in rows {
        group_change(evidence, c, &mut groups);
    }
    let mut headings = BTreeMap::<_, Vec<_>>::new();
    for (revision, reason, names) in groups {
        headings.entry((revision, names)).or_default().push(reason);
    }
    for ((revision, names), reasons) in headings {
        let verb = if names.len() == 1 { "is" } else { "are" };
        d.item(&format!("Scan could not tell whether {} {verb} used directly or through another package {revision}.",names.join(", ")))?;
        for reason in reasons {
            d.item(&format!("  {reason}"))?;
        }
    }
    Ok(())
}

fn group_change(
    evidence: &Evidence<'_>,
    c: &view::Change,
    groups: &mut Vec<(String, String, Vec<String>)>,
) {
    for (revision, reasons) in change_reasons(evidence, c) {
        for reason in reasons {
            group(groups, &revision, reason, super::package(&c.package));
        }
    }
}

fn group(
    groups: &mut Vec<(String, String, Vec<String>)>,
    revision: &str,
    reason: String,
    name: String,
) {
    if let Some((_, _, names)) = groups
        .iter_mut()
        .find(|(r, text, _)| r == revision && text == &reason)
    {
        if !names.contains(&name) {
            names.push(name);
        }
    } else {
        groups.push((revision.into(), reason, vec![name]));
    }
}

fn change_reasons(e: &Evidence<'_>, c: &view::Change) -> Vec<(String, Vec<String>)> {
    let before = if c.kind == "added" {
        Vec::new()
    } else {
        usage_reasons(&e.base, &c.before_ids, &c.directness.base)
    };
    let after = if c.kind == "removed" {
        Vec::new()
    } else {
        usage_reasons(&e.head, &c.after_ids, &c.directness.head)
    };
    let shared = before
        .iter()
        .filter(|r| after.contains(r))
        .cloned()
        .collect();
    let earlier = before
        .iter()
        .filter(|r| !after.contains(r))
        .cloned()
        .collect();
    let later = after
        .iter()
        .filter(|r| !before.contains(r))
        .cloned()
        .collect();
    [
        ("in either revision", shared),
        ("in the earlier revision", earlier),
        ("in the later revision", later),
    ]
    .into_iter()
    .filter(|(_, r): &(_, Vec<String>)| !r.is_empty())
    .map(|(r, v)| (r.into(), v))
    .collect()
}

fn usage_reasons(side: &Side<'_>, ids: &[String], status: &str) -> Vec<String> {
    if matches!(status, "direct" | "transitive") {
        return Vec::new();
    }
    if status != "unknown" {
        return vec!["The service returned a dependency classification that this version of Scan cannot explain. Review the dependency declarations and lockfile entries manually.".into()];
    }
    let mut reasons = change_side(side, ids);
    reasons.sort();
    reasons.dedup();
    reasons
}

pub(super) fn declaration_label(evidence: &Evidence<'_>, c: &view::DeclarationChange) -> String {
    let head = c
        .after_id
        .as_deref()
        .and_then(|id| evidence.head.declarations.get(id));
    let base = c
        .before_id
        .as_deref()
        .and_then(|id| evidence.base.declarations.get(id));
    head.or(base).map_or_else(
        || "a dependency whose name and declaring file were not supplied".into(),
        |decl| format!("{} in {}", decl.declared_name, decl.declaring_manifest),
    )
}

pub(super) fn binding(
    evidence: &Evidence<'_>,
    c: &view::DeclarationChange,
    binding: &view::Binding,
    d: &mut Display<'_>,
) -> io::Result<()> {
    for (label, side, id, status, absent) in [
        (
            "base",
            &evidence.base,
            c.before_id.as_deref(),
            binding.base_status.as_str(),
            c.kind == "added",
        ),
        (
            "head",
            &evidence.head,
            c.after_id.as_deref(),
            binding.head_status.as_str(),
            c.kind == "removed",
        ),
    ] {
        let rows = id.and_then(|id| side.bindings.get(&(id, binding.source_key.as_str())));
        let mut causes = Vec::new();
        for row in rows.into_iter().flatten() {
            collect(&mut causes, &row.reasons);
        }
        let expected = status == "source_unavailable"
            && !causes.is_empty()
            && causes.iter().all(|c| coverage::cause_is_git(c));
        if !absent
            && !expected
            && !matches!(status, "matched" | "absent")
            && !causes.iter().any(|cause| cause.code == status)
        {
            d.item(&format!(
                "  In the {} revision, {} Review the declaration and {}.",
                super::revision(label),
                binding_reason(status),
                binding.source_key
            ))?;
        }
        write_causes(
            &format!("In the {} revision", super::revision(label)),
            &causes,
            d,
        )?;
    }
    Ok(())
}

pub(super) fn review_context(
    evidence: &Evidence<'_>,
    review: &view::Review,
    d: &mut Display<'_>,
) -> io::Result<()> {
    let mut labels = BTreeSet::new();
    let mut missing = false;
    for id in &review.declaration_change_ids {
        if let Some(change) = evidence.declarations.get(id.as_str()) {
            labels.insert(declaration_label(evidence, change));
        } else {
            missing = true;
        }
    }
    for label in labels {
        d.item(&format!("  Declared as {label}."))?;
    }
    if missing {
        d.item(
            "  The service did not identify which dependency declaration requested this review.",
        )?;
    }
    Ok(())
}

pub(super) fn coverage(
    evidence: &Evidence<'_>,
    label: &str,
    proof_id: Option<&str>,
    d: &mut Display<'_>,
) -> io::Result<()> {
    let side = match label {
        "base" => &evidence.base,
        "head" => &evidence.head,
        _ => return Ok(()),
    };
    let proof = proof_id.and_then(|id| side.proofs.get(id));
    let mut causes = Vec::new();
    if let Some(proof) = proof {
        collect(&mut causes, &proof.reasons);
    }
    if causes.is_empty() {
        return d.item(&format!(
            "  In the {} revision, the service did not explain why it could not connect the dependency declarations to their package entries.", super::revision(label)
        ));
    }
    write_causes(
        &format!("In the {} revision", super::revision(label)),
        &causes,
        d,
    )
}

fn side(v: &view::Snapshot) -> Side<'_> {
    let mut bindings = BTreeMap::<_, Vec<_>>::new();
    for row in &v.bindings {
        bindings
            .entry((row.declaration_id.as_str(), row.source_key.as_str()))
            .or_default()
            .push(row);
    }
    Side {
        occurrences: v.occurrences.iter().map(|o| (o.id.as_str(), o)).collect(),
        proofs: v
            .reachability
            .iter()
            .filter_map(|p| p.id.as_deref().map(|id| (id, p)))
            .collect(),
        bindings,
        declarations: v.declarations.iter().map(|d| (d.id.as_str(), d)).collect(),
    }
}

fn change_side(side: &Side<'_>, ids: &[String]) -> Vec<String> {
    let mut causes = Vec::new();
    let mut proof_ids = BTreeSet::new();
    let mut unknown = false;
    let mut unexplained = false;
    let mut unresolved = false;
    for id in ids {
        let Some(row) = side.occurrences.get(id.as_str()) else {
            unexplained = true;
            continue;
        };
        if row.directness != "unknown" {
            continue;
        }
        unknown = true;
        let has_proof_cause = row.directness_proof_ids.iter().any(|id| {
            side.proofs
                .get(id.as_str())
                .is_some_and(|p| !p.reasons.is_empty())
        });
        unexplained |= row.directness_reasons.is_empty() && !has_proof_cause;
        collect(&mut causes, &row.directness_reasons);
        proof_ids.extend(row.directness_proof_ids.iter().map(String::as_str));
    }
    for id in proof_ids {
        if let Some(proof) = side.proofs.get(id) {
            collect(&mut causes, &proof.reasons);
        } else {
            unresolved = true;
        }
    }
    let mut text: Vec<_> = causes.into_iter().map(cause_text).collect();
    if !unknown || unexplained {
        text.push("The service did not return its explanation. Review the dependency declarations and corresponding lockfile entries manually.".into());
    }
    if unresolved {
        text.push("Part of the service's explanation was missing from this report. Review the dependency declarations and corresponding lockfile entries manually.".into());
    }
    text
}

fn collect<'a>(causes: &mut Vec<&'a view::Cause>, rows: &'a [view::Cause]) {
    for cause in rows {
        if !causes.contains(&cause) {
            causes.push(cause);
        }
    }
}

fn write_causes(label: &str, causes: &[&view::Cause], d: &mut Display<'_>) -> io::Result<()> {
    for cause in causes {
        d.item(&format!("  {label}: {}", cause_text(cause)))?;
    }
    Ok(())
}

fn cause_text(c: &view::Cause) -> String {
    let declarations = c
        .manifest_path
        .as_deref()
        .unwrap_or("the supplied dependency declarations");
    let name = c.dependency_name.as_deref().unwrap_or("a dependency");
    let source = &c.source_key;
    if let Some(note) = crate::coverage::note(&c.code) {
        return format!("{note} This concerns {name} in {source}.");
    }
    match c.code.as_str() {
        "root_dependency_coverage_incomplete" => incomplete_dependencies(c, declarations),
        "authored_request_not_linked" => format!(
            "Scan could not match {name} in {declarations} to its package version in {source}."
        ),
        "selected_binding_target_missing" => format!(
            "The package version requested by {name} in {declarations} was not available in the comparison of {source}."
        ),
        "native_root_not_linked" => format!(
            "Scan could not connect the dependency declarations in {declarations} to package entries in {source}."
        ),
        "declaration_binding_missing" => format!(
            "The service did not return a package match for {name} in {declarations} when comparing {source}."
        ),
        "root_association_missing" => format!(
            "The service could not identify the file declaring the project's dependencies for {source}. Check which dependency files were included in the comparison."
        ),
        "root_reachability_missing" => format!(
            "The comparison could not show how {name} is used from {declarations} in {source}. This does not establish that the package is unused."
        ),
        "version_mismatch"
        | "scope_mismatch"
        | "ambiguous"
        | "not_recorded"
        | "unsupported_requirement"
        | "unresolved_activation" => format!(
            "For {name} in {declarations}, {} Check the corresponding entries in {source}.",
            binding_reason(&c.code)
        ),
        _ if c.message.trim().is_empty() => format!(
            "The service did not supply a readable explanation for {name} in {declarations} when comparing {source}. Review those files manually."
        ),
        _ => format!(
            "{} This concerns {name} in {declarations} and {source}.",
            c.message
        ),
    }
}

fn incomplete_dependencies(c: &view::Cause, manifest: &str) -> String {
    let notes: BTreeSet<_> = c
        .coverage_reasons
        .iter()
        .filter_map(|r| crate::coverage::note(r))
        .collect();
    if coverage::cause_is_git(c) {
        return format!(
            "{} ({manifest}; {})",
            notes.into_iter().collect::<Vec<_>>().join(" "),
            c.source_key
        );
    }
    let has_unmatched = c
        .coverage_reasons
        .iter()
        .any(|r| r == "untargeted_requirement");
    let mut text = if has_unmatched {
        format!(
            "Not every dependency declared in {manifest} could be matched to an entry in {}.",
            c.source_key
        )
    } else {
        format!(
            "The dependency information linking {manifest} to {} is incomplete.",
            c.source_key
        )
    };
    let mut details: Vec<_> = c
        .coverage_reasons
        .iter()
        .filter_map(|r| native_reason(r))
        .collect();
    details.sort_unstable();
    details.dedup();
    if !details.is_empty() {
        text.push_str(" This is because ");
        text.push_str(&details.join("; "));
        text.push('.');
    }
    for note in notes {
        text.push(' ');
        text.push_str(note);
    }
    if c.coverage_reasons.is_empty()
        || c.coverage_reasons.iter().any(|r| {
            r != "untargeted_requirement"
                && !crate::coverage::expected_git(r)
                && native_reason(r).is_none()
        })
    {
        text.push_str(
            " The service did not supply a further reason this version of Scan can explain.",
        );
    }
    if let Some(name) = &c.dependency_name {
        text.push_str(" The problem concerns ");
        text.push_str(name);
        text.push('.');
    }
    format!("{text} Review those files to confirm how the package is used.")
}

fn native_reason(reason: &str) -> Option<&'static str> {
    match reason {
        "dependency_list_unavailable" | "replacement_dependency_list_unknown" => {
            Some("a package's dependency list was unavailable")
        }
        "not_expanded" | "reduced_capture" => {
            Some("some package dependencies were not included in the available information")
        }
        "unresolved_dependency" | "unrepresented_endpoint" => {
            Some("a dependency could not be matched to a package entry")
        }
        "unsupported_dependency" => Some("a dependency could not be interpreted"),
        "unmet_dependency" => Some("a dependency requirement was not met"),
        "unknown_relationship" => {
            Some("the service could not determine which package uses a dependency")
        }
        "inventory_only" => Some(
            "the files list packages without enough information about which package uses which",
        ),
        _ => None,
    }
}

pub(super) fn binding_reason(reason: &str) -> &'static str {
    match reason {
        "version_mismatch" => {
            "the listed package versions do not satisfy the declared requirement."
        }
        "scope_mismatch" => "the declared and listed dependency categories disagree.",
        "ambiguous" => "the dependency declaration matches more than one possible package entry.",
        "not_recorded" => "no package entry was found for the dependency declaration.",
        "unsupported_requirement" => {
            "the declared requirement could not be checked against package versions."
        }
        "unresolved_activation" => {
            "the service could not determine whether the dependency declaration applies."
        }
        _ => {
            "the service did not explain why it could not match the dependency declaration to a package version."
        }
    }
}
