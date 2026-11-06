use super::*;
use crate::test_support::diff as fixture;

fn inventory(head: bool) -> Inventory {
    Inventory::decode(&Document {
        bytes: serde_json::to_vec(&fixture::inventory(head)).expect("JSON"),
    })
    .expect("inventory")
}

fn audit(head: bool, inventory: &Inventory) -> Audit {
    let report = AuditReport::from_bytes(&serde_json::to_vec(&fixture::audit(head)).expect("JSON"))
        .expect("audit");
    Audit::project(&report, inventory).expect("projection")
}

#[test]
fn diff_fixture_classifies_all_changes_and_audit_deltas_without_reviewing_transitives() {
    let (base, head) = (inventory(false), inventory(true));
    let changes = compare(&base, &head, (&audit(false, &base), &audit(true, &head)));
    assert_eq!(
        changes
            .iter()
            .map(|c| (c.key.name.as_str(), c.kind))
            .collect::<Vec<_>>(),
        [
            ("added", "added"),
            ("leaf", "downgraded"),
            ("minimist", "upgraded"),
            ("removed", "removed")
        ]
    );
    let mut changes = changes;
    let leaf = &mut changes[1];
    assert_eq!(leaf.head.as_ref().expect("head").scope(), "transitive");
    assert!(leaf.vulnerabilities.assessed);
    assert_eq!(
        leaf.vulnerabilities.introduced,
        Some(Set::from(["GHSA-introduced".into()]))
    );
    assert_eq!(
        leaf.vulnerabilities.unchanged,
        Some(Set::from(["GHSA-unchanged".into()]))
    );
    assert_eq!(transitions(leaf).len(), 0);
    assert_eq!(transitions(&mut changes[2])[0].target_version, "1.2.8");
    assert_eq!(
        changes[2].vulnerabilities.fixed,
        Some(Set::from(["GHSA-fixed".into()]))
    );
    assert_eq!(transitions(&mut changes[0]).len(), 0);
    assert_eq!(changes[0].review_gaps.len(), 1);
}

#[test]
fn diff_source_local_pairing_keeps_upgrade_when_another_manifest_retains_old_version() {
    let mut base = inventory(false);
    let mut head = inventory(true);
    let key = Key {
        registry: Some("npm".into()),
        name: "minimist".into(),
    };
    for inv in [&mut base, &mut head] {
        let p = inv.packages.get_mut(&key).expect("package");
        p.versions.insert("1.2.5".into());
        p.direct
            .insert("other/package.json".into(), Set::from(["1.2.5".into()]));
    }
    let mut changes = compare(&base, &head, (&Audit::empty(), &Audit::empty()));
    let change = changes
        .iter_mut()
        .find(|c| c.key == key)
        .expect("minimist change");
    let requests = transitions(change);
    assert_eq!(requests.len(), 1);
    assert_eq!(
        (
            &requests[0].current_version[..],
            &requests[0].target_version[..]
        ),
        ("1.2.5", "1.2.8")
    );
}

#[test]
fn diff_direct_promotion_without_version_change_is_visible_and_has_no_fake_baseline() {
    let base = inventory(false);
    let mut head = inventory(false);
    let key = Key {
        registry: Some("npm".into()),
        name: "leaf".into(),
    };
    head.packages
        .get_mut(&key)
        .expect("leaf")
        .direct
        .insert("package.json".into(), Set::from(["2.0.0".into()]));
    let mut changes = compare(&base, &head, (&Audit::empty(), &Audit::empty()));
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].kind, "scope_changed");
    assert_eq!(transitions(&mut changes[0]).len(), 0);
    assert!(changes[0].review_gaps[0].contains("no unique previous"));
}

#[test]
fn diff_empty_matched_versions_and_aliases_never_invent_direct_versions() {
    for alias in [false, true] {
        let mut doc = fixture::inventory(false);
        let property = doc["properties"]
            .as_array_mut()
            .expect("props")
            .iter_mut()
            .find(|p| p["name"] == "githits:declaration_agreement")
            .expect("agreement");
        let mut agreements: Value =
            serde_json::from_str(property["value"].as_str().expect("JSON")).expect("agreements");
        if alias {
            agreements[0]["name"] = "manifest-alias".into();
        } else {
            agreements[0]["matched_versions"] = serde_json::json!([]);
        }
        property["value"] = serde_json::to_string(&agreements).expect("JSON").into();
        let inventory = Inventory::decode(&Document {
            bytes: serde_json::to_vec(&doc).expect("JSON"),
        })
        .expect("inventory");
        assert_ne!(inventory.notices.len(), 0);
        assert!(inventory.packages.values().any(|p| p.scope_unknown));
    }
}

#[test]
fn diff_missing_audit_does_not_claim_fixes_or_introductions() {
    let (base, head) = (inventory(false), inventory(true));
    let changes = compare(&base, &head, (&audit(false, &base), &Audit::default()));
    let minimist = changes
        .iter()
        .find(|c| c.key.name == "minimist")
        .expect("change");
    assert!(!minimist.vulnerabilities.assessed);
    assert_eq!(minimist.vulnerabilities.fixed, None);
    assert_eq!(minimist.vulnerabilities.introduced, None);
    assert!(
        minimist
            .vulnerabilities
            .base_observed
            .contains("GHSA-fixed")
    );
}

#[test]
fn diff_direct_downgrade_and_transitive_upgrade_are_classified() {
    let (base, head) = (inventory(true), inventory(false));
    let mut changes = compare(&base, &head, (&Audit::empty(), &Audit::empty()));
    let direct = changes
        .iter_mut()
        .find(|c| c.key.name == "minimist")
        .expect("direct");
    assert_eq!(direct.kind, "downgraded");
    assert_eq!(transitions(direct)[0].target_version, "1.2.5");
    let transitive = changes
        .iter_mut()
        .find(|c| c.key.name == "leaf")
        .expect("transitive");
    assert_eq!(transitive.kind, "upgraded");
    assert_eq!(transitions(transitive).len(), 0);
}

#[test]
fn diff_unfamiliar_version_order_is_changed_not_lexically_guessed() {
    assert_eq!(numeric_version("1.2.3-beta.1"), None);
    assert_eq!(numeric_version("1.02.3"), None);
    assert_eq!(numeric_version("2026.11"), None);
    assert_eq!(numeric_version("1.10.0"), Some([1, 10, 0]));
}

#[test]
fn diff_missing_direct_agreement_is_unknown_without_false_direct_removal() {
    let base = inventory(false);
    let mut doc = fixture::inventory(false);
    let property = doc["properties"]
        .as_array_mut()
        .expect("properties")
        .iter_mut()
        .find(|p| p["name"] == "githits:declaration_agreement")
        .expect("agreement");
    let mut agreements: Vec<Value> =
        serde_json::from_str(property["value"].as_str().expect("JSON")).expect("agreements");
    agreements.retain(|a| a["name"] != "minimist");
    property["value"] = serde_json::to_string(&agreements).expect("JSON").into();
    let head = Inventory::decode(&Document {
        bytes: serde_json::to_vec(&doc).expect("JSON"),
    })
    .expect("inventory");
    let p = &head.packages[&Key {
        registry: Some("npm".into()),
        name: "minimist".into(),
    }];
    assert_eq!(p.scope(), "unknown");
    assert!(p.direct_unknown.contains("package.json"));
    assert_eq!(
        compare(&base, &head, (&Audit::empty(), &Audit::empty())).len(),
        0
    );
    assert!(
        head.notices
            .iter()
            .any(|n| n.contains("direct agreement unavailable"))
    );
}

#[test]
fn diff_unchanged_direct_version_does_not_label_new_transitive_version_direct() {
    let base = inventory(false);
    let mut head = inventory(false);
    let key = Key {
        registry: Some("npm".into()),
        name: "minimist".into(),
    };
    head.packages
        .get_mut(&key)
        .expect("package")
        .versions
        .insert("2.0.0".into());
    let mut changes = compare(&base, &head, (&Audit::empty(), &Audit::empty()));
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].base_scope, None);
    assert_eq!(changes[0].head_scope, Some("transitive"));
    assert_eq!(transitions(&mut changes[0]).len(), 0);
}

#[test]
fn diff_orphan_unknown_audit_coordinate_invalidates_per_row_assessment_with_reason() {
    let inventory = inventory(false);
    let mut value = fixture::audit(false);
    value["unknowns"]["vulnerabilities"] = serde_json::json!([{"coordinate":{"registry":"npm","name":"orphan-alias","version":"1.0.0"},"paths":["package-lock.json"],"check":"vulnerabilities","status":"unknown","reasons":["metadata_unavailable"],"advisory_ids":[]}]);
    value["coverage"]["vulnerabilities"]["checked_count"] = 3.into();
    value["coverage"]["vulnerabilities"]["unknown_count"] = 1.into();
    value["summary"]["incomplete_checks"] = 1.into();
    let report =
        AuditReport::from_bytes(&serde_json::to_vec(&value).expect("JSON")).expect("report");
    assert_eq!(
        crate::audit::assess(&report)
            .expect("assessment")
            .unverified
            .len(),
        0
    );
    let audit = Audit::project(&report, &inventory).expect("projection");
    assert!(!audit.available);
    assert!(
        audit
            .notices
            .iter()
            .any(|n| n.contains("absent from inventory") && n.contains("orphan-alias"))
    );
    assert!(!audit.checked(&Key {
        registry: Some("npm".into()),
        name: "minimist".into()
    }));
}

#[test]
fn diff_audit_inventory_count_mismatch_has_an_explicit_reason() {
    let mut inventory = inventory(false);
    inventory.packages.remove(&Key {
        registry: Some("npm".into()),
        name: "parent".into(),
    });
    let audit = audit(false, &inventory);
    assert!(!audit.available);
    assert!(
        audit
            .notices
            .iter()
            .any(|n| n.contains("coordinate count 4 does not match inventory 3"))
    );
}

#[test]
fn diff_source_resolution_gap_does_not_erase_checked_coordinate_assessments() {
    let base = inventory(false);
    let mut value = fixture::audit(false);
    value["unknowns"]["sources"] = serde_json::json!([{"path":"package.json","reasons":["not_expanded","incomplete_native_declarations"]}]);
    value["unknowns"]["resolution"] = serde_json::json!([{"path":"package.json","name":null,"reason":"incomplete_native_declarations"}]);
    value["summary"]["incomplete_sources"] = 1.into();
    let report =
        AuditReport::from_bytes(&serde_json::to_vec(&value).expect("JSON")).expect("report");
    let assessment = crate::audit::assess(&report).expect("assessment");
    assert_eq!(assessment.unverified.len(), 0);
    assert!(assessment.incomplete);
    let audit = Audit::project(&report, &base).expect("projection");
    assert!(audit.incomplete);
    assert!(audit.checked(&Key {
        registry: Some("npm".into()),
        name: "minimist".into()
    }));
    assert!(
        audit
            .notices
            .iter()
            .any(|n| n.contains("incomplete or excluded evidence"))
    );
    let head = inventory(true);
    let head_audit = self::audit(true, &head);
    let changes = compare(&base, &head, (&audit, &head_audit));
    let minimist = changes
        .iter()
        .find(|c| c.key.name == "minimist")
        .expect("change");
    assert_eq!(
        minimist.vulnerabilities.fixed,
        Some(Set::from(["GHSA-fixed".into()]))
    );
}
