//! Human grouping of recorded requests; graph selection stays in the audit layer.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Write};

use crate::api::audit::{remediation::Owner, trace::Request};
use crate::audit::explain::{Edge, Node, Source};
use crate::commands::audit::render::{self, safe};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Requirement<'a> {
    value: Option<&'a str>,
    status: &'a str,
    basis: &'a str,
    path: &'a str,
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Key<'a> {
    target: Option<&'a str>,
    request: Option<Requirement<'a>>,
}
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Context<'a> {
    role: Option<&'a str>,
    request_kind: Option<&'a str>,
    relation_kind: &'a str,
    relation_basis: &'a str,
}
struct Parent<'a> {
    from: Option<&'a str>,
    owner: Option<&'a Owner>,
}
struct Parents<'a> {
    items: Vec<Parent<'a>>,
    first: (usize, usize),
}
struct Row<'a> {
    key: Key<'a>,
    parents: Parents<'a>,
    qualifiers: Vec<(&'static str, &'a str)>,
}
struct Label<'a> {
    node: &'a Node<'a>,
    text: String,
}
type Groups<'a> = BTreeMap<Key<'a>, BTreeMap<Context<'a>, Parents<'a>>>;

// Soft budget in escaped Unicode scalars; complete requester items may exceed it.
const REQUEST_LINE_CHARS: usize = 100;

/// Prepared source-local labels and groups shared by the two human sections.
pub(super) struct Requests<'a> {
    source: &'a Source<'a>,
    labels: BTreeMap<&'a str, Label<'a>>,
    rows: Vec<Row<'a>>,
    selected_copies: usize,
}

impl<'a> Requests<'a> {
    /// Group requests without changing occurrence identity or request multiplicity.
    pub(super) fn new(source: &'a Source<'a>) -> Self {
        let mut counts = BTreeMap::new();
        for node in &source.nodes {
            *counts.entry(node.package.as_str()).or_insert(0) += 1;
        }
        let labels = source
            .nodes
            .iter()
            .map(|node| {
                let text = node_label(node, counts[node.package.as_str()] > 1);
                (node.id.as_str(), Label { node, text })
            })
            .collect();
        Self {
            source,
            labels,
            rows: rows(source),
            selected_copies: source
                .nodes
                .iter()
                .filter(|node| node.selected_component)
                .count(),
        }
    }

    /// Write immediate requesters and evidence gaps before fix guidance.
    pub(super) fn introduction(&self, show_source: bool, out: &mut dyn Write) -> io::Result<()> {
        if show_source {
            writeln!(out, "\nRequested by — {}:", safe(self.source.file))?;
        } else {
            writeln!(out, "\nRequested by:")?;
        }
        let requested: BTreeSet<_> = self.rows.iter().filter_map(|row| row.key.target).collect();
        self.ancestry(true, out)?;
        for node in self
            .source
            .nodes
            .iter()
            .filter(|node| node.selected_component && !requested.contains(node.id.as_str()))
        {
            isolated(node, self.selected_copies > 1, out)?;
        }
        super::write_issues(&self.source.issues, "  ", out)?;
        if self.source.has_cycle {
            writeln!(
                out,
                "  Recorded dependency cycle; each request is shown once."
            )?;
        }
        Ok(())
    }

    /// Write remaining ancestry and separate non-ancestry observations.
    pub(super) fn further(&self, out: &mut dyn Write) -> io::Result<()> {
        let mut rows = self.rows.iter().filter(|row| !self.direct(row)).peekable();
        if rows.peek().is_some() {
            writeln!(
                out,
                "\nFurther recorded requests — {}:",
                safe(self.source.file)
            )?;
        }
        self.ancestry(false, out)?;
        if !self.source.observations.is_empty() {
            writeln!(
                out,
                "\nOther recorded observations — {} (do not establish ancestry):",
                safe(self.source.file)
            )?;
        }
        for edge in &self.source.observations {
            self.observation(edge, out)?;
        }
        Ok(())
    }

    fn ancestry(&self, immediate: bool, out: &mut dyn Write) -> io::Result<()> {
        let headings = !immediate || self.selected_copies > 1;
        let indent = if headings { "    " } else { "  " };
        let mut previous = None;
        for row in self.rows.iter().filter(|row| self.direct(row) == immediate) {
            self.target_heading(
                row.key.target,
                immediate,
                headings && previous != row.key.target,
                out,
            )?;
            self.row(row, indent, out)?;
            previous = row.key.target;
        }
        Ok(())
    }

    fn target_heading(
        &self,
        target: Option<&str>,
        immediate: bool,
        show: bool,
        out: &mut dyn Write,
    ) -> io::Result<()> {
        if !show {
            return Ok(());
        }
        if immediate && let Some(id) = target {
            return writeln!(out, "  Copy {id}:");
        }
        writeln!(
            out,
            "  {}:",
            self.label(target, "target occurrence not recorded")
        )
    }

    fn direct(&self, row: &Row<'_>) -> bool {
        row.key
            .target
            .and_then(|id| self.labels.get(id))
            .is_some_and(|label| label.node.selected_component)
    }

    fn label(&self, id: Option<&str>, missing: &'static str) -> &str {
        id.and_then(|id| self.labels.get(id))
            .map_or(missing, |label| label.text.as_str())
    }

    fn parent(&self, parent: &Parent<'_>) -> String {
        let text = self
            .label(parent.from, "requester occurrence not recorded")
            .to_owned();
        let Some(owner) = parent.owner else {
            return text;
        };
        let same = parent
            .from
            .and_then(|id| self.labels.get(id))
            .is_some_and(|label| {
                owner.name == label.node.recorded_name
                    && owner.version.as_deref() == label.node.recorded_version
            });
        if same {
            return text;
        }
        let owner = owner.version.as_ref().map_or_else(
            || format!("{} (version not recorded)", safe(&owner.name)),
            |v| format!("{}@{}", safe(&owner.name), safe(v)),
        );
        format!("{text} (request owner: {owner})")
    }

    fn row(&self, row: &Row<'_>, indent: &str, out: &mut dyn Write) -> io::Result<()> {
        let qualifiers = row
            .qualifiers
            .iter()
            .map(|(label, value)| format!("{label}: {}", evidence_value(value)))
            .collect::<Vec<_>>()
            .join("; ");
        let detail = range(row.key.request, self.source.file);
        let detail = if qualifiers.is_empty() {
            detail
        } else {
            format!("{detail} ({qualifiers})")
        };
        let prefix = format!("{indent}{detail}: ");
        requester_list(
            prefix,
            indent,
            &row.parents.items,
            |parent| self.parent(parent),
            out,
        )
    }

    fn observation(&self, edge: &Edge<'_>, out: &mut dyn Write) -> io::Result<()> {
        writeln!(
            out,
            "  {} ({}; relation basis: {})",
            safe(edge.kind),
            safe(edge.disposition),
            evidence_value(edge.basis)
        )?;
        let target = self.label(edge.to.as_deref(), "target occurrence not recorded");
        if edge.requests.is_empty() {
            return writeln!(
                out,
                "    {} -> {target}: requirement not recorded",
                self.label(edge.from.as_deref(), "requester occurrence not recorded")
            );
        }
        for request in edge.requests {
            let parent = self.parent(&Parent {
                from: edge.from.as_deref(),
                owner: Some(&request.owner),
            });
            writeln!(
                out,
                "    {parent} -> {target}: {}; owner role: {}; request kind: {}",
                detail(Some(requirement(request)), self.source.file),
                evidence_value(&request.owner_role),
                evidence_value(&request.kind)
            )?;
        }
        Ok(())
    }
}

fn isolated(node: &Node<'_>, named: bool, out: &mut dyn Write) -> io::Result<()> {
    write!(out, "  ")?;
    if named {
        write!(out, "Copy {}: ", node.id)?;
    }
    writeln!(out, "No immediate request in recorded ancestry.")
}

fn requirement(request: &Request) -> Requirement<'_> {
    Requirement {
        value: request.requested_requirement.as_deref(),
        status: &request.requirement_status,
        basis: &request.basis,
        path: &request.path,
    }
}

fn add<'a>(
    groups: &mut Groups<'a>,
    edge: &'a Edge<'a>,
    request: Option<&'a Request>,
    first: (usize, usize),
) {
    let key = Key {
        target: edge.to.as_deref(),
        request: request.map(requirement),
    };
    let context = Context {
        role: request.map(|r| r.owner_role.as_str()),
        request_kind: request.map(|r| r.kind.as_str()),
        relation_kind: edge.kind,
        relation_basis: edge.basis,
    };
    let parents = groups
        .entry(key)
        .or_default()
        .entry(context)
        .or_insert_with(|| Parents {
            items: Vec::new(),
            first,
        });
    parents.items.push(Parent {
        from: edge.from.as_deref(),
        owner: request.map(|r| &r.owner),
    });
}

fn rows<'a>(source: &'a Source<'a>) -> Vec<Row<'a>> {
    let mut groups = Groups::new();
    let mut first_target = BTreeMap::new();
    for (i, edge) in source.relations.iter().enumerate() {
        first_target.entry(edge.to.as_deref()).or_insert(i);
        if edge.requests.is_empty() {
            add(&mut groups, edge, None, (i, 0));
        }
        for (j, request) in edge.requests.iter().enumerate() {
            add(&mut groups, edge, Some(request), (i, j));
        }
    }
    let mut rows = Vec::new();
    for (key, variants) in groups {
        let role = varies(variants.keys().map(|c| c.role));
        let request_kind = varies(variants.keys().map(|c| c.request_kind));
        let relation_kind = varies(variants.keys().map(|c| c.relation_kind));
        let relation_basis = varies(variants.keys().map(|c| c.relation_basis));
        for (context, parents) in variants {
            let qualifiers = qualifiers(
                &context,
                [role, request_kind, relation_kind, relation_basis],
            );
            rows.push(Row {
                key,
                parents,
                qualifiers,
            });
        }
    }
    let distances = distances(source);
    rows.sort_by_key(|row| {
        (
            row.key.target.and_then(|id| distances.get(id)).copied(),
            first_target.get(&row.key.target).copied(),
            row.parents.first,
        )
    });
    rows
}

fn node_label(node: &Node<'_>, repeated: bool) -> String {
    if repeated {
        format!("{} [{}]", safe(&node.package), node.id)
    } else {
        safe(&node.package)
    }
}

fn qualifiers<'a>(context: &Context<'a>, varying: [bool; 4]) -> Vec<(&'static str, &'a str)> {
    [
        ("owner role", context.role),
        ("request kind", context.request_kind),
        ("relation kind", Some(context.relation_kind)),
        ("relation basis", Some(context.relation_basis)),
    ]
    .into_iter()
    .zip(varying)
    .filter_map(|((label, value), show)| {
        show.then_some(value).flatten().map(|value| (label, value))
    })
    .collect()
}

fn varies<T: PartialEq>(mut values: impl Iterator<Item = T>) -> bool {
    values
        .next()
        .is_some_and(|first| values.any(|value| value != first))
}

fn distances<'a>(source: &'a Source<'a>) -> BTreeMap<&'a str, usize> {
    let mut incoming: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in &source.relations {
        if let (Some(from), Some(to)) = (edge.from.as_deref(), edge.to.as_deref()) {
            incoming.entry(to).or_default().push(from);
        }
    }
    let mut result = BTreeMap::new();
    let mut queue = VecDeque::new();
    for node in source.nodes.iter().filter(|node| node.selected_component) {
        result.insert(node.id.as_str(), 0);
        queue.push_back((node.id.as_str(), 0));
    }
    while let Some((target, distance)) = queue.pop_front() {
        visit(target, distance + 1, &incoming, &mut result, &mut queue);
    }
    result
}

fn visit<'a>(
    target: &str,
    distance: usize,
    incoming: &BTreeMap<&str, Vec<&'a str>>,
    distances: &mut BTreeMap<&'a str, usize>,
    queue: &mut VecDeque<(&'a str, usize)>,
) {
    use std::collections::btree_map::Entry;
    for &parent in incoming.get(target).into_iter().flatten() {
        if let Entry::Vacant(entry) = distances.entry(parent) {
            entry.insert(distance);
            queue.push_back((parent, distance));
        }
    }
}

fn range(request: Option<Requirement<'_>>, source: &str) -> String {
    match request {
        Some(Requirement {
            value: Some(value),
            status: "recorded",
            basis: "lockfile",
            path,
        }) if path == source => safe(value),
        _ => detail(request, source),
    }
}

fn detail(request: Option<Requirement<'_>>, source: &str) -> String {
    let Some(request) = request else {
        return "requirement not recorded".into();
    };
    let requirement = if request.status == "recorded" {
        request
            .value
            .map_or_else(|| "requirement not recorded".into(), safe)
    } else {
        format!("requirement {}", render::requirement_status(request.status))
    };
    let basis = match request.basis {
        "manifest" => "project declaration".into(),
        "lockfile" => "locked requirement".into(),
        "resolver" => "resolved request".into(),
        "exact_parent" => "parent release declaration".into(),
        value => format!("unrecognized request basis: {}", safe(value)),
    };
    if request.path == source {
        format!("{requirement} ({basis})")
    } else {
        format!("{requirement} ({basis}; {})", safe(request.path))
    }
}

fn evidence_value(value: &str) -> String {
    match value {
        "project" => "project".into(),
        "unknown" => "unknown".into(),
        "dependency" => "dependency".into(),
        "lockfile" => "lockfile".into(),
        "manifest_lock_agreement" => "manifest/lock agreement".into(),
        "recorded_context_union" => "combined recorded contexts".into(),
        "third_party" => "third party".into(),
        "RUNTIME" => "runtime".into(),
        "PEER" => "peer".into(),
        "OPTIONAL_PEER" => "optional peer".into(),
        "OPTIONAL" => "optional".into(),
        "UNCLASSIFIED" => "unclassified".into(),
        "DEVELOPMENT" => "development".into(),
        "DEPENDENCY_GROUP" => "dependency group".into(),
        value => format!("unrecognized ({})", safe(value)),
    }
}

fn requester_list(
    prefix: String,
    indent: &str,
    parents: &[Parent<'_>],
    format: impl Fn(&Parent<'_>) -> String,
    out: &mut dyn Write,
) -> io::Result<()> {
    let mut line = prefix;
    for (i, parent) in parents.iter().enumerate() {
        let comma = if i + 1 < parents.len() { "," } else { "" };
        let item = format!("{}{comma}", format(parent));
        let separator = if line.ends_with(' ') { "" } else { " " };
        if line.chars().count() + separator.len() + item.chars().count() > REQUEST_LINE_CHARS {
            writeln!(out, "{}", line.trim_end())?;
            line = format!("{indent}  ");
        } else {
            line.push_str(separator);
        }
        line.push_str(&item);
    }
    writeln!(out, "{line}")
}
