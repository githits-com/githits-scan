//! Shared human wording for service evidence diagnostics.

/// Known evidence reasons shared by audit and license presentation. Unknown
/// values remain a caller decision: audit retains them, license points to JSON.
pub(super) fn reason(value: &str) -> Option<&'static str> {
    Some(match value {
        "invalid_version" => "package version could not be evaluated",
        "invalid_range" => "advisory range could not be evaluated",
        "metadata_unavailable" => "package metadata missing",
        "comparison_unknown" => "version comparison could not be determined",
        "skipped_requirement" => "dependency requirement skipped",
        "not_expanded" => "transitive dependencies were not included",
        "untargeted_requirement" => "dependency requirement without a recorded link",
        "inventory_only" => "dependency relationships not recorded",
        "unknown_relationship" => "dependency relationships could not be determined",
        "non_registry_source" => "non-registry dependency",
        "missing_coordinate" => "package registry or version not identified",
        "required_input_not_supplied" => "required project files were not uploaded",
        "incomplete_native_declarations" => "dependency declarations are incomplete",
        "incomplete_dependency_list" => "dependency list is incomplete",
        "unresolved_manifest_activation" => "dependency activation could not be determined",
        "missing_requirement" => "dependency requirement could not be determined",
        "unsupported_dependency" => "dependency not supported by this check",
        "unsupported_dependency_facets" => "dependency attributes not supported by this check",
        "unsupported_ecosystem" => "ecosystem not supported by this check",
        "unmet_dependency" | "unresolved_dependency" => "unresolved dependency",
        "unsupported_registry_context" => "package registry configuration not supported",
        "manifest_lock_target_ambiguous" => "manifest requirement matches multiple locked packages",
        "manifest_lock_target_not_recorded" => {
            "manifest requirement has no recorded locked package"
        }
        "incomplete_dependency_groups" => "dependency groups are incomplete",
        "unsupported_manifest_lock_requirement" => {
            "manifest requirement cannot be compared with the lockfile"
        }
        "missing_ranges" => "advisory affected-version ranges unavailable",
        "dependency_list_unavailable" => "dependency list unavailable",
        _ => return None,
    })
}
