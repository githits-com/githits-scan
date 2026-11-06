//! Selection of recorded source-local evidence, never a dependency solver.
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Serialize;

use crate::api::audit::{Body, Report, remediation::Trace, trace};

mod current;
pub(crate) use current::{RecordedRequest, recorded_requests};

pub(crate) struct Explanation<'a> {
    pub finding_indices: BTreeSet<usize>,
    pub recommendation_indices: BTreeSet<usize>,
    pub recommendation_scopes: BTreeMap<usize, OccurrenceScope>,
    pub sources: Vec<Source<'a>>,
    pub issues: BTreeSet<&'static str>,
}

#[derive(Serialize)]
pub(crate) struct Source<'a> {
    pub id: String,
    #[serde(skip)]
    labels: BTreeMap<usize, String>,
    pub file: &'a str,
    pub nodes: Vec<Node<'a>>,
    pub relations: Vec<Edge<'a>>,
    pub observations: Vec<Edge<'a>>,
    pub has_cycle: bool,
    pub issues: BTreeSet<&'static str>,
}

#[derive(Serialize)]
pub(crate) struct Node<'a> {
    /// Exact coordinate/path seed identity, never inferred from the display label.
    #[serde(skip)]
    pub selected_component: bool,
    /// Recorded occurrence name used for exact request-owner comparison.
    #[serde(skip)]
    pub recorded_name: &'a str,
    /// Recorded occurrence version; absence remains distinct from any version.
    #[serde(skip)]
    pub recorded_version: Option<&'a str>,
    pub id: String,
    pub package: String,
    pub project_root: bool,
    pub ancestry: bool,
    pub dependency_coverage: Option<&'a trace::Coverage>,
}

#[derive(Serialize)]
pub(crate) struct Edge<'a> {
    pub from: Option<String>,
    pub to: Option<String>,
    pub kind: &'a str,
    pub basis: &'a str,
    pub disposition: &'a str,
    pub requests: &'a [trace::Request],
}

pub(crate) fn select<'a>(report: &'a Report, package: &str) -> Option<Explanation<'a>> {
    let Body::V2(body) = &report.body else {
        return None;
    };
    let indices: BTreeSet<_> = body
        .findings
        .vulnerabilities
        .iter()
        .enumerate()
        .filter(|(_, f)| f.coordinate.to_string() == package)
        .map(|(i, _)| i)
        .collect();
    let first = *indices.first()?;
    let finding = &body.findings.vulnerabilities[first];
    let mut result = Explanation {
        finding_indices: indices,
        recommendation_indices: BTreeSet::new(),
        recommendation_scopes: BTreeMap::new(),
        sources: Vec::new(),
        issues: BTreeSet::new(),
    };
    let Some(remediation) = &body.remediation else {
        result.issues.insert("remediation_unavailable");
        return Some(result);
    };
    result.recommendation_indices = remediation
        .recommendations
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            r.finding_refs
                .iter()
                .chain(&r.addressed_finding_refs)
                .chain(&r.remaining_finding_refs)
                .any(|i| result.finding_indices.contains(i))
        })
        .map(|(i, _)| i)
        .collect();
    if remediation.trace.status != "retained" {
        result
            .issues
            .insert(if remediation.trace.status == "not_retained" {
                "trace_not_retained"
            } else {
                "trace_status_unavailable"
            });
        return Some(result);
    }
    let paths: BTreeSet<_> = result
        .finding_indices
        .iter()
        .flat_map(|&i| {
            body.findings.vulnerabilities[i]
                .paths
                .iter()
                .map(String::as_str)
        })
        .collect();
    for (i, input) in group_sources(&remediation.trace, paths)
        .into_iter()
        .enumerate()
    {
        let seeds: Vec<_> = input
            .nodes
            .iter()
            .copied()
            .filter(|&i| {
                remediation.trace.occurrences[i].coordinate.as_ref() == Some(&finding.coordinate)
            })
            .collect();
        result.sources.push(source(
            &remediation.trace,
            &input,
            seeds,
            format!("s{}", i + 1),
        ));
    }
    populate_scopes(&mut result, remediation);
    Some(result)
}

fn populate_scopes(
    result: &mut Explanation<'_>,
    remediation: &crate::api::audit::remediation::Remediation,
) {
    let labels: BTreeMap<_, _> = result
        .sources
        .iter()
        .flat_map(|source| {
            source.labels.iter().map(|(&i, node)| {
                (
                    i,
                    NodeRef {
                        source: source.id.clone(),
                        node: node.clone(),
                    },
                )
            })
        })
        .collect();
    for (i, r) in remediation.recommendations.iter().enumerate() {
        if !result.recommendation_indices.contains(&i) {
            continue;
        }
        if r.detail_status != "retained" {
            result
                .issues
                .insert("recommendation_copy_detail_unavailable");
            continue;
        }
        if !valid_occurrences(r, remediation.trace.occurrences.len()) {
            result
                .issues
                .insert("recommendation_occurrence_refs_unverified");
        }
        result.recommendation_scopes.insert(
            i,
            OccurrenceScope {
                subject: resolve_refs(&r.occurrence_refs, &labels),
                changes: r
                    .changes
                    .iter()
                    .map(|c| {
                        c.occurrence_refs
                            .as_ref()
                            .map(|refs| resolve_refs(refs, &labels))
                    })
                    .collect(),
                remaining: r
                    .remaining_occurrence_refs
                    .as_ref()
                    .map(|refs| resolve_refs(refs, &labels)),
            },
        );
    }
}

#[derive(Serialize)]
pub(crate) struct OccurrenceScope {
    pub subject: RefSet,
    /// Positions correspond to the unchanged ordered action set.
    pub changes: Vec<Option<RefSet>>,
    /// Null means not supplied, distinct from an explicitly empty set.
    pub remaining: Option<RefSet>,
}

#[derive(Serialize)]
pub(crate) struct RefSet {
    pub nodes: Vec<NodeRef>,
    pub not_in_selected_trace: usize,
}

#[derive(Clone, Serialize)]
pub(crate) struct NodeRef {
    pub source: String,
    pub node: String,
}

fn resolve_refs(refs: &[usize], labels: &BTreeMap<usize, NodeRef>) -> RefSet {
    let unique: BTreeSet<_> = refs.iter().copied().collect();
    let nodes: Vec<_> = unique
        .iter()
        .filter_map(|i| labels.get(i).cloned())
        .collect();
    RefSet {
        not_in_selected_trace: unique.len() - nodes.len(),
        nodes,
    }
}

fn valid_occurrences(r: &crate::api::audit::remediation::Recommendation, count: usize) -> bool {
    r.occurrence_refs
        .iter()
        .chain(r.remaining_occurrence_refs.iter().flatten())
        .chain(
            r.changes
                .iter()
                .flat_map(|c| c.occurrence_refs.iter().flatten()),
        )
        .all(|&i| i < count)
}

struct SourceInput<'a> {
    file: &'a str,
    nodes: Vec<usize>,
    relations: Vec<usize>,
}

fn group_sources<'a>(trace: &'a Trace, paths: BTreeSet<&'a str>) -> Vec<SourceInput<'a>> {
    let mut groups: BTreeMap<_, _> = paths
        .into_iter()
        .map(|file| {
            (
                file,
                SourceInput {
                    file,
                    nodes: Vec::new(),
                    relations: Vec::new(),
                },
            )
        })
        .collect();
    for (i, n) in trace.occurrences.iter().enumerate() {
        if let Some(g) = groups.get_mut(n.path.as_str()) {
            g.nodes.push(i);
        }
    }
    for (i, r) in trace.relations.iter().enumerate() {
        group_relation(&mut groups, trace, r, i);
    }
    groups.into_values().collect()
}

fn group_relation<'a>(
    groups: &mut BTreeMap<&'a str, SourceInput<'a>>,
    trace: &'a Trace,
    relation: &'a trace::Relation,
    index: usize,
) {
    // Validate claimed sources even when that claim disagrees with a known endpoint.
    let paths: BTreeSet<_> = std::iter::once(relation.path.as_str())
        .chain(
            [relation.from_ref, relation.to_ref]
                .into_iter()
                .flatten()
                .filter_map(|i| trace.occurrences.get(i))
                .map(|n| n.path.as_str()),
        )
        .collect();
    for path in paths {
        if let Some(group) = groups.get_mut(path) {
            group.relations.push(index);
        }
    }
}

fn source<'a>(
    trace: &'a Trace,
    input: &SourceInput<'a>,
    seeds: Vec<usize>,
    id: String,
) -> Source<'a> {
    let mut result = Source {
        id,
        labels: BTreeMap::new(),
        file: input.file,
        nodes: Vec::new(),
        relations: Vec::new(),
        observations: Vec::new(),
        has_cycle: false,
        issues: BTreeSet::new(),
    };
    if seeds.is_empty() {
        result.issues.insert("no_recorded_occurrence");
    }
    let (incoming, valid) = index_relations(trace, &input.relations, &mut result.issues);
    let component_nodes = seeds.iter().copied().collect();
    let selected = ancestors(&incoming, seeds);
    let mut visible = selected.clone();
    for &index in &valid {
        let r = &trace.relations[index];
        if r.to_ref.is_some_and(|i| selected.contains(&i))
            || (r.kind == "feature_activation" && r.from_ref.is_some_and(|i| selected.contains(&i)))
        {
            visible.extend([r.from_ref, r.to_ref].into_iter().flatten());
        }
    }
    let labels: BTreeMap<_, _> = visible
        .iter()
        .enumerate()
        .map(|(i, &index)| (index, format!("n{}", i + 1)))
        .collect();
    result.nodes = nodes(
        trace,
        &labels,
        &selected,
        &component_nodes,
        &mut result.issues,
    );
    let positive = populate_edges(&mut result, trace, &valid, &selected, &labels);
    result.has_cycle = has_cycle(&selected, &positive);
    result.labels = labels;
    result
}

type Incoming = BTreeMap<usize, Vec<usize>>;
fn index_relations(
    trace: &Trace,
    candidates: &[usize],
    issues: &mut BTreeSet<&'static str>,
) -> (Incoming, Vec<usize>) {
    let mut incoming: Incoming = BTreeMap::new();
    let mut valid = Vec::new();
    for &index in candidates {
        let relation = &trace.relations[index];
        if let Some(issue) = relation_issue(trace, relation) {
            issues.insert(issue);
            continue;
        }
        valid.push(index);
        if relation.disposition == "standard_dependency"
            && let (Some(from), Some(to)) = (relation.from_ref, relation.to_ref)
        {
            incoming.entry(to).or_default().push(from);
        }
    }
    (incoming, valid)
}

fn ancestors(incoming: &Incoming, seeds: Vec<usize>) -> BTreeSet<usize> {
    let mut selected = BTreeSet::new();
    let mut queue: VecDeque<_> = seeds.into();
    while let Some(index) = queue.pop_front() {
        if !selected.insert(index) {
            continue;
        }
        queue.extend(incoming.get(&index).into_iter().flatten().copied());
    }
    selected
}

fn nodes<'a>(
    trace: &'a Trace,
    labels: &BTreeMap<usize, String>,
    selected: &BTreeSet<usize>,
    component_nodes: &BTreeSet<usize>,
    issues: &mut BTreeSet<&'static str>,
) -> Vec<Node<'a>> {
    labels
        .iter()
        .map(|(&index, label)| {
            let node = &trace.occurrences[index];
            if let Some(issue) = coverage_issue(node, selected.contains(&index)) {
                issues.insert(issue);
            }
            Node {
                selected_component: component_nodes.contains(&index),
                recorded_name: &node.name,
                recorded_version: node.version.as_deref(),
                id: label.clone(),
                package: node.coordinate.as_ref().map_or_else(
                    || {
                        node.version
                            .as_ref()
                            .map_or_else(|| node.name.clone(), |v| format!("{}@{v}", node.name))
                    },
                    ToString::to_string,
                ),
                project_root: node.project_root,
                ancestry: selected.contains(&index),
                dependency_coverage: node.dependency_coverage.as_ref(),
            }
        })
        .collect()
}

fn coverage_issue(node: &trace::Occurrence, selected: bool) -> Option<&'static str> {
    if node.project_root || !selected {
        return None;
    }
    match node.dependency_coverage.as_ref().map(|c| c.state.as_str()) {
        Some("complete") => None,
        Some("incomplete") => Some("dependency_coverage_incomplete"),
        _ => Some("dependency_coverage_unknown"),
    }
}

fn populate_edges<'a>(
    result: &mut Source<'a>,
    trace: &'a Trace,
    valid: &[usize],
    selected: &BTreeSet<usize>,
    labels: &BTreeMap<usize, String>,
) -> Vec<(usize, usize)> {
    let mut positive = Vec::new();
    for &index in valid {
        let r = &trace.relations[index];
        let to_selected = r.to_ref.is_some_and(|i| selected.contains(&i));
        let from_selected = r.from_ref.is_some_and(|i| selected.contains(&i));
        if !(to_selected || r.kind == "feature_activation" && from_selected) {
            continue;
        }
        let edge = Edge {
            from: r.from_ref.and_then(|i| labels.get(&i).cloned()),
            to: r.to_ref.and_then(|i| labels.get(&i).cloned()),
            kind: &r.kind,
            basis: &r.basis,
            disposition: &r.disposition,
            requests: &r.requests,
        };
        if let (Some(from), Some(to)) = (r.from_ref, r.to_ref)
            && r.disposition == "standard_dependency"
            && from_selected
            && to_selected
        {
            positive.push((from, to));
            result.relations.push(edge);
        } else {
            result.observations.push(edge);
            result.issues.insert("additional_dependency_observations");
        }
    }
    positive
}

fn relation_issue(trace: &Trace, r: &trace::Relation) -> Option<&'static str> {
    for index in [r.from_ref, r.to_ref].into_iter().flatten() {
        let Some(node) = trace.occurrences.get(index) else {
            return Some("relation_refs_unverified");
        };
        if node.path != r.path {
            return Some("relation_source_unverified");
        }
    }
    None
}

fn has_cycle(nodes: &BTreeSet<usize>, edges: &[(usize, usize)]) -> bool {
    let mut indegrees: BTreeMap<_, usize> = nodes.iter().map(|&i| (i, 0)).collect();
    let mut outgoing: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for &(from, to) in edges {
        *indegrees.entry(to).or_default() += 1;
        outgoing.entry(from).or_default().push(to);
    }
    let mut queue: VecDeque<_> = indegrees
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(&i, _)| i)
        .collect();
    let mut removed = 0;
    while let Some(index) = queue.pop_front() {
        removed += 1;
        release_edges(index, &outgoing, &mut indegrees, &mut queue);
    }
    removed < nodes.len()
}

fn release_edges(
    index: usize,
    outgoing: &BTreeMap<usize, Vec<usize>>,
    indegrees: &mut BTreeMap<usize, usize>,
    queue: &mut VecDeque<usize>,
) {
    for &to in outgoing.get(&index).into_iter().flatten() {
        let Some(degree) = indegrees.get_mut(&to) else {
            continue;
        };
        *degree -= 1;
        if *degree == 0 {
            queue.push_back(to);
        }
    }
}

#[cfg(test)]
mod tests;
