//! Producer-owned causes joined through exact same-snapshot references.
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

pub(super) fn change(
    evidence: &Evidence<'_>,
    c: &view::Change,
    d: &mut Display<'_>,
) -> io::Result<()> {
    for (label, side, ids, status) in [
        (
            "base",
            &evidence.base,
            &c.before_ids,
            c.directness.base.as_str(),
        ),
        (
            "head",
            &evidence.head,
            &c.after_ids,
            c.directness.head.as_str(),
        ),
    ] {
        if (c.kind == "added" && label == "base") || (c.kind == "removed" && label == "head") {
            continue;
        }
        if status == "unknown" {
            change_side(side, label, ids, d)?;
        }
    }
    Ok(())
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
        || "no unique declaration".into(),
        |decl| format!("{} in {}", decl.declared_name, decl.declaring_manifest),
    )
}

pub(super) fn binding(
    evidence: &Evidence<'_>,
    c: &view::DeclarationChange,
    binding: &view::Binding,
    d: &mut Display<'_>,
) -> io::Result<()> {
    for (label, side, id) in [
        ("base", &evidence.base, c.before_id.as_deref()),
        ("head", &evidence.head, c.after_id.as_deref()),
    ] {
        let rows = id.and_then(|id| side.bindings.get(&(id, binding.source_key.as_str())));
        let mut causes = Vec::new();
        for row in rows.into_iter().flatten() {
            collect(&mut causes, &row.reasons);
        }
        write_causes(&format!("{label} binding cause"), &causes, d)?;
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
        d.item(&format!("  Declared by: {label}"))?;
    }
    if missing {
        d.item("  Authored declaration context is unavailable in this report.")?;
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
            "  {label} reachability: producer explanation unavailable for this qualification."
        ));
    }
    write_causes(&format!("{label} reachability"), &causes, d)
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

fn change_side(
    side: &Side<'_>,
    label: &str,
    ids: &[String],
    d: &mut Display<'_>,
) -> io::Result<()> {
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
    write_causes(&format!("{label} dependency type"), &causes, d)?;
    if !unknown || unexplained {
        d.item(&format!(
            "  {label} dependency type unknown; no producer explanation is associated."
        ))?;
    }
    if unresolved {
        d.item(&format!(
            "  {label} dependency type: referenced explanation unavailable in this snapshot."
        ))?;
    }
    Ok(())
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
        let mut context = vec![format!("source {}", cause.source_key)];
        if let Some(path) = &cause.manifest_path {
            context.push(format!("manifest {path}"));
        }
        if let Some(name) = &cause.dependency_name {
            let kind = cause
                .declaration_id
                .as_ref()
                .map_or("dependency", |_| "declaration");
            context.push(format!("{kind} {name}"));
        }
        if let Some(state) = &cause.coverage_state {
            context.push(format!("coverage {state}"));
        }
        if !cause.coverage_reasons.is_empty() {
            context.push(format!(
                "coverage reasons: {}",
                cause.coverage_reasons.join(", ")
            ));
        }
        d.item(&format!(
            "  {label}: {} ({}); {}",
            cause.message,
            cause.code,
            context.join("; ")
        ))?;
    }
    Ok(())
}
