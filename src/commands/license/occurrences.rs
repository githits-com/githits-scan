//! Human grouping uses full evidence equality, never package URL equality.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::io::{self, Write};
use std::rc::Rc;

use serde::Deserialize;
use serde_json::{Value, value::RawValue};

use crate::api::licenses::Property;

use super::display;

#[derive(Clone, Copy)]
pub(super) enum Format {
    Sbom,
    LegacyReport,
    CompactReport,
}

impl Format {
    const fn reference(self) -> &'static str {
        match self {
            Self::Sbom => "bom-ref",
            Self::LegacyReport | Self::CompactReport => "bom_ref",
        }
    }
}

#[derive(Default)]
pub(super) struct Occurrences {
    entries: BTreeMap<String, Option<Occurrence>>,
}

struct Occurrence {
    label: String,
    merge: Option<MergeKey>,
    paths: BTreeSet<String>,
    // One class label may list thousands of categories; share its text rather
    // than storing that whole list once per occurrence.
    combined: Option<(Rc<str>, bool)>,
}

// Display all readable conditions, but only single-condition leaves may merge.
struct MergeKey {
    evidence: String,
    group: String,
    marker: String,
}

#[derive(Deserialize)]
struct Inventory<'a> {
    #[serde(default, borrow)]
    components: Vec<&'a RawValue>,
}

#[derive(Deserialize)]
struct Component<'a> {
    #[serde(rename = "bom-ref", borrow)]
    sbom_ref: Option<&'a RawValue>,
    #[serde(borrow)]
    bom_ref: Option<&'a RawValue>,
    #[serde(borrow)]
    context: Option<&'a RawValue>,
    #[serde(borrow)]
    properties: Option<&'a RawValue>,
    #[serde(borrow)]
    components: Option<&'a RawValue>,
}

impl Occurrences {
    pub(super) fn new<'a>(
        bytes: &[u8],
        format: Format,
        references: impl Iterator<Item = &'a str>,
    ) -> Self {
        // Typed report decoding intentionally ignores unfamiliar additions that
        // RawValue/Value may reject (invalid UTF-8 or surrogate escapes). Display
        // grouping must never reject a report already accepted by its owner.
        let references: BTreeSet<_> = references.collect();
        let mut index = Self::read(bytes, format, &references).unwrap_or_default();
        combine(&mut index.entries);
        index
    }

    fn read(bytes: &[u8], format: Format, references: &BTreeSet<&str>) -> serde_json::Result<Self> {
        let inventory: Inventory<'_> = serde_json::from_slice(bytes)?;
        let mut index = Self::default();
        collect(
            &mut index,
            &inventory.components,
            format,
            &mut Vec::new(),
            references,
        )?;
        Ok(index)
    }

    fn insert(
        &mut self,
        raw: &RawValue,
        component: &Component<'_>,
        format: Format,
        owner: &[usize],
        references: &BTreeSet<&str>,
    ) -> serde_json::Result<()> {
        let reference = match format {
            Format::Sbom => component.sbom_ref,
            Format::LegacyReport | Format::CompactReport => component.bom_ref,
        }
        .and_then(|r| serde_json::from_str::<String>(r.get()).ok());
        let Some(reference) = reference.filter(|r| !r.is_empty()) else {
            return Ok(());
        };
        if !references.contains(reference.as_str()) {
            return Ok(());
        }
        let occurrence = occurrence(raw, component, format, owner)?;
        match self.entries.entry(reference) {
            Entry::Vacant(entry) => {
                entry.insert(occurrence);
            }
            // A reference must identify exactly one input occurrence.
            Entry::Occupied(mut entry) => {
                entry.insert(None);
            }
        }
        Ok(())
    }

    fn get(&self, reference: &str) -> Option<&Occurrence> {
        self.entries.get(reference).and_then(Option::as_ref)
    }

    pub(super) fn label(&self, reference: &str, compact: bool) -> Option<&str> {
        let o = self.get(reference)?;
        if !compact {
            return Some(&o.label);
        }
        Some(
            o.combined
                .as_ref()
                .map_or(o.label.as_str(), |(label, _)| label),
        )
    }

    pub(super) fn combined(&self, reference: &str) -> bool {
        self.get(reference).is_some_and(|o| o.combined.is_some())
    }

    pub(super) fn skip(&self, reference: &str) -> bool {
        self.get(reference)
            .is_some_and(|o| o.combined.as_ref().is_some_and(|(_, first)| !first))
    }

    pub(super) fn continuation(
        &self,
        reference: &str,
        compact: bool,
        indent: &str,
        out: &mut dyn Write,
    ) -> io::Result<bool> {
        let Some(label) = self.label(reference, compact) else {
            return Ok(false);
        };
        if display::Text::parts([" [", label, "]"], display::GROUP).shortened {
            display::field(out, &format!("{indent}group context: "), label, false)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn inputs(
        &self,
        reference: &str,
        indent: &str,
        out: &mut dyn Write,
    ) -> io::Result<bool> {
        let Some(o) = self.get(reference) else {
            return Ok(false);
        };
        let mut shortened = false;
        for path in &o.paths {
            shortened |= display::field(out, &format!("{indent}input file: "), path, false)?;
        }
        Ok(shortened)
    }
}

fn collect(
    index: &mut Occurrences,
    components: &[&RawValue],
    format: Format,
    owner: &mut Vec<usize>,
    references: &BTreeSet<&str>,
) -> serde_json::Result<()> {
    for (position, raw) in components.iter().enumerate() {
        let component: Component<'_> = serde_json::from_str(raw.get())?;
        index.insert(raw, &component, format, owner, references)?;
        if matches!(format, Format::Sbom) && component.components.is_some() {
            let nested: Inventory<'_> = serde_json::from_str(raw.get())?;
            owner.push(position);
            collect(index, &nested.components, format, owner, references)?;
            owner.pop();
        }
    }
    Ok(())
}

fn combine(entries: &mut BTreeMap<String, Option<Occurrence>>) {
    let mut classes: BTreeMap<&str, Vec<(&str, &MergeKey)>> = BTreeMap::new();
    for (reference, occurrence) in &*entries {
        let Some(o) = occurrence else {
            continue;
        };
        let Some(key) = o.merge.as_ref() else {
            continue;
        };
        classes
            .entry(&key.evidence)
            .or_default()
            .push((reference, key));
    }
    let combinations: Vec<_> = classes
        .values()
        .filter_map(|members| combination(members))
        .collect();
    for (references, label) in combinations {
        set_combination(entries, &references, &Rc::from(label));
    }
}

fn set_combination(
    entries: &mut BTreeMap<String, Option<Occurrence>>,
    references: &[String],
    label: &Rc<str>,
) {
    for (position, reference) in references.iter().enumerate() {
        let Some(Some(o)) = entries.get_mut(reference) else {
            continue;
        };
        o.combined = Some((Rc::clone(label), position == 0));
    }
}

fn combination(members: &[(&str, &MergeKey)]) -> Option<(Vec<String>, String)> {
    let groups: BTreeSet<_> = members.iter().map(|(_, o)| o.group.as_str()).collect();
    if members.len() < 2 || groups.len() != members.len() {
        return None;
    }
    let names = groups
        .into_iter()
        .map(group_label)
        .collect::<Vec<_>>()
        .join(", ");
    let label = context_label(&names, &members[0].1.marker);
    Some((
        members.iter().map(|(r, _)| (*r).to_owned()).collect(),
        label,
    ))
}

fn occurrence(
    raw: &RawValue,
    c: &Component<'_>,
    format: Format,
    owner: &[usize],
) -> serde_json::Result<Option<Occurrence>> {
    let properties: Vec<Property> = c
        .properties
        .and_then(|raw| serde_json::from_str(raw.get()).ok())
        .unwrap_or_default();
    let context = match format {
        Format::CompactReport => c.context.map(RawValue::get).map(str::to_owned),
        Format::Sbom | Format::LegacyReport => properties
            .iter()
            .find(|p| p.name == "githits:context")
            .and_then(|p| p.value.clone()),
    };
    let Some(mut context) = context.and_then(|s| serde_json::from_str::<Value>(&s).ok()) else {
        return Ok(None);
    };
    let Some(conditions) = context
        .get_mut("group_conditions")
        .and_then(Value::as_array_mut)
    else {
        return Ok(None);
    };
    let Some(groups) = conditions.iter().map(condition).collect::<Option<Vec<_>>>() else {
        return Ok(None);
    };
    let Some((group, marker)) = groups.first() else {
        return Ok(None);
    };
    let label = groups
        .iter()
        .map(|(group, marker)| context_label(&group_label(group), marker))
        .collect::<Vec<_>>()
        .join(", ");
    // Never materialize a whole document tree. Only single-condition leaf
    // candidates need a key; enclosing assemblies remain distinct owners.
    let merge = if groups.len() == 1 && c.components.is_none() {
        conditions[0]["group"] = Value::Null;
        let mut value: Value = serde_json::from_str(raw.get())?;
        normalize(&mut value, format, context)?;
        Some(MergeKey {
            evidence: serde_json::to_string(&(owner, value))?,
            group: group.clone(),
            marker: marker.clone(),
        })
    } else {
        None
    };
    Ok(Some(Occurrence {
        label,
        merge,
        paths: input_paths(&properties).0,
        combined: None,
    }))
}

fn condition(value: &Value) -> Option<(String, String)> {
    let group = value
        .get("group")?
        .as_str()
        .filter(|group| !group.is_empty())?;
    let marker = value.get("marker")?.as_str()?;
    Some((group.to_owned(), marker.to_owned()))
}

fn normalize(value: &mut Value, format: Format, context: Value) -> serde_json::Result<()> {
    if let Some(object) = value.as_object_mut() {
        object.remove(format.reference());
    }
    if matches!(format, Format::CompactReport) {
        value["context"] = context;
        return Ok(());
    }
    let encoded = serde_json::to_string(&context)?;
    if let Some(properties) = value.get_mut("properties").and_then(Value::as_array_mut) {
        // Match the same first context property used to obtain the group. Any
        // additional properties remain evidence in the equivalence comparison.
        if let Some(property) = properties
            .iter_mut()
            .find(|p| p.get("name").and_then(Value::as_str) == Some("githits:context"))
        {
            property["value"] = encoded.into();
        }
        for property in properties
            .iter_mut()
            .filter(|p| p.get("name").and_then(Value::as_str) == Some("githits:package_id"))
        {
            property["value"] = Value::Null;
        }
    }
    Ok(())
}

fn group_label(group: &str) -> String {
    if group
        .chars()
        .all(|ch| ch.is_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        group.to_owned()
    } else {
        format!("\"{}\"", group.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn context_label(group: &str, marker: &str) -> String {
    if marker.is_empty() {
        group.to_owned()
    } else {
        format!("{group}; {marker}")
    }
}

pub(super) fn input_paths(properties: &[Property]) -> (BTreeSet<String>, bool) {
    let mut paths = BTreeSet::new();
    let mut unrecognized = false;
    for property in properties {
        let values = match property.name.as_ref() {
            "githits:manifest_path" | "githits:lockfile_path" => {
                property.value.as_deref().map(|path| vec![path.to_owned()])
            }
            "githits:manifest_paths" | "githits:lockfile_paths" => property
                .value
                .as_deref()
                .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok()),
            _ => continue,
        };
        match values {
            Some(values) => paths.extend(values),
            None => unrecognized = true,
        }
    }
    (paths, unrecognized)
}
