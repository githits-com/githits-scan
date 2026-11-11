//! Compact maintenance visibility in the real audit binary.
use super::*;
use crate::support::audit::findings;

#[test]
fn audit_details_expands_maintenance_without_hiding_security_or_gaps() {
    let report = findings();

    let compact_root = repo();
    let compact_server = server(&serde_json::to_vec(&report).expect("report"));
    let compact = run(
        compact_root.path(),
        Some(&compact_server.origin()),
        &["--quiet", "--no-color"],
    );
    assert_eq!(compact.status.code(), Some(1), "{}", stderr(&compact));
    assert!(stderr(&compact).is_empty(), "{:?}", stderr(&compact));
    assert_eq!(compact_server.requests().len(), 3);
    let compact_text = stdout(&compact);
    for text in [
        "GHSA-demo",
        "Incomplete checks",
        "Packages not checked",
        "1 package warning, 1 outdated version, 1 duplicate package",
        "--details",
    ] {
        assert!(compact_text.contains(text), "{text}: {compact_text}");
    }
    for heading in ["Outdated versions", "Duplicate versions"] {
        assert!(!compact_text.contains(heading), "{heading}: {compact_text}");
    }

    let detailed_root = repo();
    let detailed_server = server(&serde_json::to_vec(&report).expect("report"));
    let detailed = run(
        detailed_root.path(),
        Some(&detailed_server.origin()),
        &["--quiet", "--no-color", "--details"],
    );
    assert_eq!(detailed.status.code(), Some(1), "{}", stderr(&detailed));
    assert!(stderr(&detailed).is_empty(), "{:?}", stderr(&detailed));
    assert_eq!(detailed_server.requests().len(), 3);
    let detailed_text = stdout(&detailed);
    for text in [
        "Package warnings",
        "Outdated versions",
        "Duplicate versions",
        "use the maintained package",
        "tool@3.0.0",
        "web/package-lock.json",
    ] {
        assert!(detailed_text.contains(text), "{text}: {detailed_text}");
    }
    assert!(!detailed_text.contains("--details"), "{detailed_text}");
}
