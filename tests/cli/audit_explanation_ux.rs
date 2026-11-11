//! Compact human inspection keeps the complete recorded graph and JSON contract.
use super::*;
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn fixture() -> Value {
    serde_json::from_slice(include_bytes!("../fixtures/audit/analysis.json")).expect("archive")
}
fn trace(input: &mut Value) -> &mut Value {
    &mut input["producer_report"]["remediation"]["trace"]
}
fn no_actions(input: &mut Value) {
    input["producer_report"]["remediation"]["recommendations"] = json!([]);
}
fn run_saved(input: &Value, flags: &[&str]) -> Output {
    let root = repo();
    let file = root.path().join("analysis.json");
    fs::write(&file, serde_json::to_vec(input).expect("JSON")).expect("archive file");
    githits_scan()
        .args(["audit", "--from-analysis"])
        .arg(file)
        .args(flags)
        .current_dir(root.path())
        .env_remove("GITHITS_API_TOKEN")
        .env("GITHITS_API_URL", "not-an-origin")
        .output()
        .expect("offline command")
}
fn explain(input: &Value) -> String {
    let output = run_saved(input, &["--explain", "npm:demo@1.0.0", "--no-color"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(output.stderr.is_empty(), "{}", stderr(&output));
    stdout(&output)
}
fn document(input: &Value) -> Value {
    let output = run_saved(input, &["--explain", "npm:demo@1.0.0", "--json"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    serde_json::from_slice(&output.stdout).expect("explanation JSON")
}
fn push_node(input: &mut Value, node: Value) -> usize {
    let nodes = trace(input)["occurrences"].as_array_mut().expect("nodes");
    let i = nodes.len();
    nodes.push(node);
    i
}
fn relation(input: &mut Value, from: usize, to: usize, requirement: &str) -> Value {
    let t = trace(input);
    let mut edge = t["relations"][1].clone();
    edge["from_ref"] = from.into();
    edge["to_ref"] = to.into();
    edge["requests"][0]["owner"] =
        json!({"name":t["occurrences"][from]["name"],"version":t["occurrences"][from]["version"]});
    edge["requests"][0]["requested_requirement"] = requirement.into();
    edge
}
fn push_edge(input: &mut Value, edge: Value) {
    trace(input)["relations"]
        .as_array_mut()
        .expect("edges")
        .push(edge);
}
fn recount(input: &mut Value) {
    let coordinates: BTreeSet<_> = trace(input)["occurrences"]
        .as_array()
        .expect("nodes")
        .iter()
        .filter(|node| !node["coordinate"].is_null())
        .map(|node| node["coordinate"].to_string())
        .collect();
    let count = coordinates.len();
    input["producer_report"]["summary"]["dependencies"] = count.into();
    for check in ["vulnerabilities", "deprecation", "outdated"] {
        input["producer_report"]["coverage"][check]["candidates_count"] = count.into();
        input["producer_report"]["coverage"][check]["checked_count"] = count.into();
    }
}

#[test]
fn audit_explain_ux_names_single_source_once_and_labels_multiple_sources() {
    let single = explain(&fixture());
    let intro = single.split_once("Fix guidance:").expect("guidance").0;
    assert_eq!(intro.matches("package-lock.json").count(), 1, "{single}");
    assert!(intro.contains("Found in: package-lock.json\n"), "{single}");
    assert!(intro.contains("\nRequested by:\n"), "{single}");
    let mut input = fixture();
    no_actions(&mut input);
    let mut copy = trace(&mut input)["occurrences"][0].clone();
    copy["path"] = "nested/package-lock.json".into();
    let target = push_node(&mut input, copy);
    let mut parent = trace(&mut input)["occurrences"][1].clone();
    parent["path"] = "nested/package-lock.json".into();
    let requester = push_node(&mut input, parent);
    let mut edge = relation(&mut input, requester, target, "^1.0.0");
    edge["path"] = "nested/package-lock.json".into();
    edge["requests"][0]["path"] = "nested/package-lock.json".into();
    push_edge(&mut input, edge);
    input["producer_report"]["findings"]["vulnerabilities"][0]["paths"] =
        json!(["package-lock.json", "nested/package-lock.json"]);
    let text = explain(&input);
    let intro = text.split_once("Fix guidance:").expect("guidance").0;
    for source in ["package-lock.json", "nested/package-lock.json"] {
        assert!(
            intro.contains(&format!("Requested by — {source}:")),
            "{text}"
        );
    }
}

#[test]
fn audit_explain_ux_prints_dependency_once_with_range_rows() {
    let mut input = fixture();
    no_actions(&mut input);
    let mut other = trace(&mut input)["occurrences"][1].clone();
    other["name"] = "other".into();
    other["coordinate"]["name"] = "other".into();
    let index = push_node(&mut input, other);
    let edge = relation(&mut input, index, 0, "<1.1.0");
    push_edge(&mut input, edge);
    let edge = relation(&mut input, 1, 0, "^1.0.0");
    push_edge(&mut input, edge);
    let mut root_request = trace(&mut input)["relations"][0].clone();
    root_request["requests"][0]["requested_requirement"] = "~2.0.0".into();
    push_edge(&mut input, root_request);
    recount(&mut input);
    let text = explain(&input);
    let (intro, after) = text.split_once("Fix guidance:").expect("guidance");
    assert_eq!(intro.matches("npm:demo@1.0.0").count(), 1, "{text}");
    assert!(
        intro.contains("  <1.1.0: npm:parent@2.0.0, npm:other@2.0.0\n"),
        "{text}"
    );
    assert!(intro.contains("  ^1.0.0: npm:parent@2.0.0\n"), "{text}");
    assert_eq!(after.matches("  npm:parent@2.0.0:").count(), 1, "{text}");
    for range in ["^2.0.0", "~2.0.0"] {
        assert!(
            after.contains(&format!(
                "    {range} (project declaration; package.json): application"
            )),
            "{text}"
        );
    }
}

#[test]
fn audit_explain_ux_action_order_and_whole_audit_gap_summary() {
    let mut input = fixture();
    input["producer_report"]["unknowns"]["sources"] = json!([
        {"path":"elsewhere-one.lock","reasons":["unexpanded_dependencies"]},
        {"path":"elsewhere-two.lock","reasons":["unexpanded_dependencies"]}
    ]);
    input["producer_report"]["summary"]["incomplete_sources"] = 2.into();
    let text = explain(&input);
    let problem = text.find("npm:demo@1.0.0 — vulnerable").expect("problem");
    let immediate = text.find("Requested by:").expect("intro");
    let fix = text.find("Fix guidance:").expect("guidance");
    let further = text
        .find("Further recorded requests — package-lock.json:")
        .expect("rest");
    assert!(
        problem < immediate && immediate < fix && fix < further,
        "{text}"
    );
    for value in [
        "Upgrade npm:demo 1.0.0 -> 1.1.1",
        "Upgrade npm:parent 2.0.0 -> 2.1.0",
        "target is deprecated",
    ] {
        assert!(text.contains(value), "{text}");
    }
    let json = document(&input);
    assert_eq!(json["audit_issues"].as_array().expect("issues").len(), 2);
    assert!(
        text.contains("Audit evidence gaps: 2 issues reported."),
        "{text}"
    );
    assert!(text.contains("Replay without --explain"), "{text}");
    assert!(
        !text.contains("elsewhere-one.lock") && !text.contains("elsewhere-two.lock"),
        "{text}"
    );
    assert!(
        !text.contains("unrelated") && !text.contains("not attributed"),
        "{text}"
    );
    let full = run_saved(&input, &["--no-color"]);
    assert_eq!(full.status.code(), Some(1));
    assert!(stdout(&full).contains("elsewhere-one.lock"));
    assert!(stdout(&full).contains("elsewhere-two.lock"));
}

#[test]
fn audit_explain_ux_grouping_preserves_requester_copies_and_multiplicity() {
    let mut input = fixture();
    no_actions(&mut input);
    let copy = trace(&mut input)["occurrences"][1].clone();
    let index = push_node(&mut input, copy);
    let root_edge = relation(&mut input, 2, index, "^2.0.0");
    push_edge(&mut input, root_edge);
    let duplicate = trace(&mut input)["relations"][1].clone();
    push_edge(&mut input, duplicate);
    let other = relation(&mut input, index, 0, "<1.1.0");
    push_edge(&mut input, other);
    let json = document(&input);
    let parents: Vec<_> = json["sources"][0]["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .filter(|n| n["package"] == "npm:parent@2.0.0")
        .map(|n| format!("npm:parent@2.0.0 [{}]", n["id"].as_str().expect("id")))
        .collect();
    assert_eq!(parents.len(), 2);
    let text = explain(&input);
    let intro = text.split_once("Fix guidance:").expect("fix heading").0;
    assert_eq!(intro.matches("  <1.1.0").count(), 1, "{text}");
    assert_eq!(intro.matches(&parents[0]).count(), 2, "{text}");
    assert_eq!(intro.matches(&parents[1]).count(), 1, "{text}");
    assert!(text.contains("Further recorded requests"), "{text}");
}

#[test]
fn audit_explain_ux_names_isolated_copies_beside_copies_with_requesters() {
    let mut input = fixture();
    no_actions(&mut input);
    let copy = trace(&mut input)["occurrences"][0].clone();
    push_node(&mut input, copy);
    let json = document(&input);
    let copies: Vec<_> = json["sources"][0]["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .filter(|node| node["package"] == "npm:demo@1.0.0")
        .map(|node| format!("Copy {}", node["id"].as_str().expect("id")))
        .collect();
    assert_eq!(copies.len(), 2);
    let text = explain(&input);
    let intro = text.split_once("Fix guidance:").expect("guidance").0;
    assert!(
        intro.contains(&format!("{}:\n    <1.1.0:", copies[0])),
        "{text}"
    );
    assert!(
        intro.contains(&format!(
            "{}: No immediate request in recorded ancestry.",
            copies[1]
        )),
        "{text}"
    );
}

#[test]
fn audit_explain_ux_evidence_variants_and_independent_owners_remain_visible() {
    for (pointer, value, expected, rows) in [
        (
            "/requests/0/owner_role",
            json!("project"),
            "owner role: project",
            2,
        ),
        ("/requests/0/kind", json!("PEER"), "request kind: peer", 2),
        ("/kind", json!("RUNTIME"), "relation kind: runtime", 2),
        (
            "/basis",
            json!("manifest_lock_agreement"),
            "relation basis: manifest/lock agreement",
            2,
        ),
        (
            "/requests/0/path",
            json!("different/package.json"),
            "different/package.json",
            2,
        ),
        (
            "/requests/0/basis",
            json!("future_basis"),
            "unrecognized request basis: future_basis",
            2,
        ),
        (
            "/requests/0/kind",
            json!("peer"),
            "request kind: unrecognized (peer)",
            2,
        ),
        (
            "/requests/0/owner/name",
            json!("declared-owner\n\u{1b}"),
            "request owner: declared-owner\\n\\u{1b}@2.0.0",
            1,
        ),
        (
            "/requests/0/owner/version",
            Value::Null,
            "request owner: parent (version not recorded)",
            1,
        ),
    ] {
        let mut input = fixture();
        no_actions(&mut input);
        let mut extra = trace(&mut input)["relations"][1].clone();
        *extra.pointer_mut(pointer).expect("field") = value;
        push_edge(&mut input, extra);
        let text = explain(&input);
        let intro = text.split_once("Fix guidance:").expect("fix heading").0;
        assert_eq!(intro.matches("  <1.1.0").count(), rows, "{pointer}: {text}");
        assert!(intro.contains(expected), "{pointer}: {text}");
        let context = matches!(
            pointer,
            "/requests/0/owner_role" | "/requests/0/kind" | "/kind" | "/basis"
        );
        assert!(
            !context || intro.contains(&format!("  <1.1.0 ({expected}): npm:parent@2.0.0\n")),
            "{pointer}: {text}"
        );
        assert!(!text.contains('\u{1b}'), "{text}");
    }
}

#[test]
fn audit_explain_ux_component_identity_does_not_come_from_a_formatted_label() {
    let mut input = fixture();
    no_actions(&mut input);
    let real_copy = trace(&mut input)["occurrences"][0].clone();
    let copy = push_node(&mut input, real_copy);
    let edge = relation(&mut input, 1, copy, "<1.1.0");
    push_edge(&mut input, edge);
    let mut lookalike = trace(&mut input)["occurrences"][2].clone();
    lookalike["name"] = "npm:demo@1.0.0".into();
    let fake = push_node(&mut input, lookalike);
    let edge = relation(&mut input, fake, 0, "<1.1.0");
    push_edge(&mut input, edge);
    let edge = relation(&mut input, 2, fake, "*");
    push_edge(&mut input, edge);
    let json = document(&input);
    let text = explain(&input);
    let intro = text.split_once("Fix guidance:").expect("fix heading").0;
    let rest = text
        .split("Further recorded requests")
        .nth(1)
        .expect("rest");
    for node in json["sources"][0]["nodes"].as_array().expect("nodes") {
        for hidden in ["selected_component", "recorded_name", "recorded_version"] {
            assert!(node.get(hidden).is_none(), "{json}");
        }
        if node["package"] != "npm:demo@1.0.0" {
            continue;
        }
        let target = format!("npm:demo@1.0.0 [{}]:", node["id"].as_str().expect("id"));
        if node["project_root"] == true {
            assert!(!intro.contains(&target) && rest.contains(&target), "{text}");
        } else {
            let copy = format!("Copy {}:", node["id"].as_str().expect("id"));
            assert!(intro.contains(&copy), "{text}");
        }
    }
}

#[test]
fn audit_explain_ux_cycles_observations_and_empty_requests_remain_explicit() {
    let mut input = fixture();
    no_actions(&mut input);
    let back = relation(&mut input, 0, 1, "^2.0.0");
    push_edge(&mut input, back);
    let mut empty = relation(&mut input, 1, 0, "<1.1.0");
    empty["requests"] = json!([]);
    push_edge(&mut input, empty);
    let mut indirect = relation(&mut input, 1, 0, "<1.1.0");
    indirect["from_ref"] = Value::Null;
    indirect["kind"] = "unexported_endpoint".into();
    indirect["disposition"] = "indirect_seed".into();
    push_edge(&mut input, indirect);
    let text = explain(&input);
    assert_eq!(text, explain(&input), "deterministic cyclic output");
    let fix = text.find("Fix guidance:").expect("fix");
    assert!(
        text.find("Recorded dependency cycle").expect("cycle") < fix,
        "{text}"
    );
    assert!(
        text.find("Additional recorded observations").expect("note") < fix,
        "{text}"
    );
    assert!(
        text.find("Other recorded observations")
            .expect("observations")
            > fix,
        "{text}"
    );
    assert!(
        text.contains("requester occurrence not recorded (request owner:"),
        "{text}"
    );
    assert!(
        text.contains("  requirement not recorded: npm:parent@2.0.0"),
        "{text}"
    );
    assert!(text.contains("indirect_seed"), "{text}");
    let self_edge = relation(&mut input, 0, 0, "^1.0.0");
    trace(&mut input)["relations"] = json!([self_edge]);
    let self_cycle = explain(&input);
    assert!(self_cycle.contains("Recorded dependency cycle"));
    assert!(!self_cycle.contains("Further recorded requests"));
}

#[test]
fn audit_explain_ux_missing_and_unavailable_requesters_precede_inline_guidance() {
    for state in ["isolated", "observations_only", "missing", "not_retained"] {
        let mut input = fixture();
        let expected = match state {
            "isolated" => {
                trace(&mut input)["relations"] = json!([]);
                "No immediate request in recorded ancestry."
            }
            "observations_only" => {
                let mut observation = trace(&mut input)["relations"][1].clone();
                observation["from_ref"] = Value::Null;
                observation["disposition"] = "indirect_seed".into();
                trace(&mut input)["relations"] = json!([observation]);
                "No immediate request in recorded ancestry."
            }
            "missing" => {
                trace(&mut input)["occurrences"][0]["coordinate"] = Value::Null;
                "No matching recorded occurrence"
            }
            _ => {
                trace(&mut input)["status"] = "not_retained".into();
                "Dependency trace was not retained"
            }
        };
        let text = explain(&input);
        assert!(
            text.find(expected).expect("missing detail") < text.find("Fix guidance:").expect("fix"),
            "{text}"
        );
        assert!(text.contains("Upgrade npm:demo 1.0.0 -> 1.1.1"), "{text}");
        assert!(!text.contains("Further recorded requests"), "{text}");
        if state == "observations_only" {
            assert!(
                text.find("Other recorded observations")
                    .expect("observation")
                    > text.find("Fix guidance:").expect("guidance"),
                "{text}"
            );
        }
    }
}

#[test]
fn audit_explain_ux_wraps_requester_items_without_cutting_or_losing_them() {
    let mut input = fixture();
    no_actions(&mut input);
    let mut expected = Vec::new();
    for i in 0..20 {
        let name = format!("pârênt-{i:02}-{}", "親".repeat(25));
        let mut node = trace(&mut input)["occurrences"][1].clone();
        node["name"] = name.clone().into();
        node["coordinate"]["name"] = name.clone().into();
        let index = push_node(&mut input, node);
        let edge = relation(&mut input, index, 0, "<1.1.0");
        push_edge(&mut input, edge);
        expected.push(format!("npm:{name}@2.0.0"));
    }
    recount(&mut input);
    let text = explain(&input);
    let intro = text.split_once("Fix guidance:").expect("fix heading").0;
    for item in &expected {
        assert_eq!(intro.matches(item).count(), 1, "{text}");
    }
    let requests = intro.split_once("Requested by").expect("requests").1;
    assert!(
        requests.lines().any(|line| line.starts_with("    ")),
        "{text}"
    );
    assert!(
        requests
            .lines()
            .any(|line| line.matches("npm:pârênt-").count() == 2),
        "Unicode items fit together by scalar count, not byte count: {text}"
    );
    for line in requests.lines().filter(|line| line.starts_with("  ")) {
        assert!(line.chars().count() <= 100, "{line}");
    }
    let parsed = document(&input);
    assert_eq!(
        parsed["sources"][0]["relations"]
            .as_array()
            .expect("relationships")
            .len(),
        22
    );
}

#[test]
fn audit_explain_ux_further_requests_follow_distance_then_first_relation() {
    let mut input = fixture();
    no_actions(&mut input);
    let mut grandparents = Vec::new();
    for name in ["grand-a", "grand-b"] {
        let mut node = trace(&mut input)["occurrences"][1].clone();
        node["name"] = name.into();
        node["coordinate"]["name"] = name.into();
        grandparents.push(push_node(&mut input, node));
    }
    let distant_b_first = relation(&mut input, 2, grandparents[1], "^2.0.0");
    let distant_a_second = relation(&mut input, 2, grandparents[0], "^2.0.0");
    let nearer_a = relation(&mut input, grandparents[0], 1, "^2.0.0");
    let nearer_b = relation(&mut input, grandparents[1], 1, "^2.0.0");
    let immediate = trace(&mut input)["relations"][1].clone();
    trace(&mut input)["relations"] = json!([
        distant_b_first,
        distant_a_second,
        nearer_a,
        nearer_b,
        immediate
    ]);
    recount(&mut input);
    let text = explain(&input);
    let further = text
        .split_once("Further recorded requests —")
        .expect("further")
        .1;
    let parent = further.find("npm:parent@2.0.0:").expect("nearer");
    let grand_b = further
        .find("npm:grand-b@2.0.0:")
        .expect("first farther target");
    let grand_a = further
        .find("npm:grand-a@2.0.0:")
        .expect("second farther target");
    assert!(parent < grand_b && grand_b < grand_a, "{text}");
}
