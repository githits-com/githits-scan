use super::*;
use crate::api::upgrade::{Package, Review};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

struct Reviews {
    batches: RefCell<Vec<usize>>,
    limited: bool,
}
impl UpgradeApi for Reviews {
    fn review(&self, packages: &[Package]) -> Result<Vec<Review>, api::ApiError> {
        self.batches.borrow_mut().push(packages.len());
        if self.limited {
            return Err(api::ApiError::Unexpected {
                status: 429,
                request_id: None,
            });
        }
        Ok(packages
            .iter()
            .map(|p| {
                serde_json::from_value(crate::test_support::diff::review(
                    &p.name,
                    &p.current_version,
                    &p.target_version,
                ))
                .expect("review")
            })
            .collect())
    }
}

fn changes() -> Vec<diff::Change> {
    let inventory = |version: &str| diff::Inventory {
        packages: (0..31)
            .map(|i| {
                (
                    diff::Key {
                        registry: Some("npm".into()),
                        name: format!("package-{i}"),
                    },
                    diff::Package {
                        versions: BTreeSet::from([version.into()]),
                        direct: BTreeMap::from([(
                            "package.json".into(),
                            BTreeSet::from([version.into()]),
                        )]),
                        ..diff::Package::default()
                    },
                )
            })
            .collect(),
        notices: Vec::new(),
    };
    diff::compare(
        &inventory("1.0.0"),
        &inventory("2.0.0"),
        (&diff::Audit::empty(), &diff::Audit::empty()),
    )
}

#[test]
fn diff_reviews_thirty_plus_one_direct_transitions_in_bounded_batches() {
    let api = Reviews {
        batches: RefCell::new(Vec::new()),
        limited: false,
    };
    let mut changes = changes();
    enrich(&mut changes, &api);
    assert_eq!(*api.batches.borrow(), [30, 1]);
    assert!(changes.iter().all(|c| c.upgrade_reviews.len() == 1));
}

#[test]
fn diff_stops_upgrade_batches_after_rate_limit_and_retains_all_scan_rows() {
    let api = Reviews {
        batches: RefCell::new(Vec::new()),
        limited: true,
    };
    let mut changes = changes();
    enrich(&mut changes, &api);
    assert_eq!(*api.batches.borrow(), [30]);
    assert_eq!(changes.len(), 31);
    assert!(
        changes
            .iter()
            .all(|c| c.review_gaps.len() == 1 && c.upgrade_reviews.is_empty())
    );
}

#[test]
fn diff_markdown_escapes_names_keeps_rows_together_and_omits_unsafe_links() {
    let mut changes = changes();
    changes.truncate(2);
    changes[0].key.name = "evil|<script>\nname".into();
    changes[0]
        .base
        .as_mut()
        .expect("base")
        .versions
        .insert("9.9.9".into());
    changes[0]
        .head
        .as_mut()
        .expect("head")
        .versions
        .insert("9.9.9".into());
    let mut review: Review =
        serde_json::from_value(crate::test_support::diff::review("x", "1.0.0", "2.0.0"))
            .expect("review");
    review.changelog.as_mut().expect("changelog").entries[0].html_url =
        Some("javascript:alert(1)".into());
    changes[0].upgrade_reviews.push(review);
    let report = diff::Report {
        schema_version: 1,
        comparison_scope: "repository",
        base: "base".into(),
        head: "head".into(),
        analysis_performed: true,
        incomplete: false,
        notices: vec![],
        changes,
    };
    let mut bytes = Vec::new();
    render::write(&report, Format::Markdown, &mut bytes).expect("render");
    let text = String::from_utf8(bytes).expect("UTF-8");
    assert!(text.contains("evil&#124;&lt;script&gt;&#92;nname"));
    assert!(!text.contains("javascript:"));
    assert!(!text.contains("9.9.9"));
    assert!(
        serde_json::to_string(&report)
            .expect("JSON")
            .contains("9.9.9")
    );
    assert_eq!(text.lines().filter(|line| line.starts_with('|')).count(), 4);
}

#[test]
fn diff_terminal_changelog_url_keeps_query_parameters_unchanged() {
    let mut changes = changes();
    changes.truncate(1);
    let mut review: Review =
        serde_json::from_value(crate::test_support::diff::review("x", "1.0.0", "2.0.0"))
            .expect("review");
    let link = "https://example.invalid/changelog?a=1&b=2";
    review.changelog.as_mut().expect("changelog").entries[0].html_url = Some(link.into());
    changes[0].upgrade_reviews.push(review);
    let report = diff::Report {
        schema_version: 1,
        comparison_scope: "repository",
        base: "base".into(),
        head: "head".into(),
        analysis_performed: true,
        incomplete: false,
        notices: vec![],
        changes,
    };
    let mut bytes = Vec::new();
    render::write(&report, Format::Human, &mut bytes).expect("render");
    let text = String::from_utf8(bytes).expect("UTF-8");
    assert!(text.contains(link));
    assert!(!text.contains("&amp;"));
}

#[test]
fn diff_markdown_package_text_cannot_create_links_images_or_mentions() {
    let mut changes = changes();
    changes.truncate(1);
    changes[0].key.name =
        "[click](https://evil.invalid) ![](https://evil.invalid/pixel) @someone *bold* _italic_"
            .into();
    let report = diff::Report {
        schema_version: 1,
        comparison_scope: "repository",
        base: "base".into(),
        head: "head".into(),
        analysis_performed: true,
        incomplete: false,
        notices: vec![],
        changes,
    };
    let mut bytes = Vec::new();
    render::write(&report, Format::Markdown, &mut bytes).expect("render");
    let text = String::from_utf8(bytes).expect("UTF-8");
    for markup in ["[click]", "![](", "@someone", "*bold*", "_italic_"] {
        assert!(!text.contains(markup), "unescaped {markup}");
    }
    assert!(text.contains("&#91;click&#93;"));
    assert!(text.contains("&#64;someone"));
}

#[test]
fn diff_empty_markdown_message_is_separate_from_the_table() {
    let report = diff::Report {
        schema_version: 1,
        comparison_scope: "repository",
        base: "base".into(),
        head: "head".into(),
        analysis_performed: false,
        incomplete: false,
        notices: vec![],
        changes: vec![],
    };
    let mut bytes = Vec::new();
    render::write(&report, Format::Markdown, &mut bytes).expect("render");
    let text = String::from_utf8(bytes).expect("UTF-8");
    assert!(text.contains("| --- | --- | --- | --- | --- | --- |\n\nNo changes"));
}
