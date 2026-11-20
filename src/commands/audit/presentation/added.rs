//! Plain-language evidence for added branches, shared by changes and search.
use super::{
    list, remediation::request_requirement, requirement_status, safe, search::known_cause,
};
use crate::api::audit::remediation::added::{Branch, CheckedCoordinate, Issue};

pub(super) fn lines(branch: &Branch) -> impl Iterator<Item = String> + '_ {
    let registry_basis = branch.selection_basis == "registry_resolution";
    let package = format!("{}:{}", safe(&branch.registry), safe(&branch.name));
    let request = request_requirement(
        Some(&branch.authored_name),
        branch.requested_requirement.as_deref(),
        &branch.requirement_status,
    );
    let selected = branch.selected_version.as_ref().map_or_else(
        || format!("No version was selected for {package}."),
        |version| format!("The selected version is {package}@{}.", safe(version)),
    );
    let basis = if registry_basis {
        "This is a registry-resolved branch. The project installer may select different copies or apply different policy."
    } else {
        "Scan cannot explain how this branch was selected. See JSON for the reported basis."
    };
    [
        format!("This release {request} as a new dependency. {selected}"),
        basis.into(),
    ]
    .into_iter()
    .chain(non_affecting(&branch.coordinates))
    .chain(
        branch
            .coordinates
            .iter()
            .filter(|checked| checked.advisory_status != "non_affecting")
            .map(advisory_check),
    )
    .chain(
        branch
            .issues
            .iter()
            .filter(move |issue| !reported_by_advisory_check(issue, &branch.coordinates))
            .flat_map(move |issue| issue_lines(issue, branch)),
    )
}

fn non_affecting(coordinates: &[CheckedCoordinate]) -> Option<String> {
    let checked = coordinates
        .iter()
        .filter(|checked| checked.advisory_status == "non_affecting")
        .map(|checked| safe(&checked.coordinate.to_string()))
        .collect::<Vec<_>>();
    (!checked.is_empty())
        .then(|| format!("No affecting advisories found for {}.", checked.join(", ")))
}

fn advisory_check(checked: &CheckedCoordinate) -> String {
    let coordinate = safe(&checked.coordinate.to_string());
    let result = match checked.advisory_status.as_str() {
        "affected" if !checked.advisory_ids.is_empty() => {
            format!(
                "found applicable advisories ({})",
                list(&checked.advisory_ids)
            )
        }
        "affected" => "found an affecting advisory. The service supplied no advisory ID".into(),
        "unknown" => "could not determine which advisories apply".into(),
        "unsupported" => "could not run because advisory checks do not cover this registry".into(),
        _ => "returned a result Scan cannot interpret. See JSON for the reported result".into(),
    };
    format!("Advisory check for {coordinate} {result}.")
}

fn reported_by_advisory_check(issue: &Issue, coordinates: &[CheckedCoordinate]) -> bool {
    let status = match issue.reason.as_str() {
        "added_coordinate_affected" => "affected",
        "advisory_registry_not_covered" => "unsupported",
        _ => return false,
    };
    issue.coordinate.as_ref().is_some_and(|coordinate| {
        coordinates
            .iter()
            .any(|checked| &checked.coordinate == coordinate && checked.advisory_status == status)
    })
}

fn issue_lines(issue: &Issue, branch: &Branch) -> Vec<String> {
    let operation = match issue.operation.as_str() {
        "catalog" => "Registry version catalog lookup",
        "selection" => "Registry version selection",
        "release" => "Release metadata lookup",
        "closure" => "Dependency branch check",
        "advisories" => "Advisory check",
        _ => "Check the service did not identify in terms Scan recognizes",
    };
    let input = issue_input(issue, branch);
    let cause = cause(issue);
    let summary = issue.http_status.map_or_else(
        || format!("{operation} for {input} — {cause}."),
        |status| format!("{operation} for {input} — {cause} (HTTP {status})."),
    );
    let mut lines = vec![summary];
    version_conflict(issue, &mut lines);
    activation_input(issue, &mut lines);
    lines
}

fn issue_input(issue: &Issue, branch: &Branch) -> String {
    let declaring_release = issue.owner.as_ref().and_then(Option::as_deref);
    let input = match (&issue.coordinate, declaring_release, &issue.name) {
        (Some(coordinate), _, _) => safe(&coordinate.to_string()),
        (None, Some(owner), Some(name)) => format!("{} requesting {}", safe(owner), safe(name)),
        (None, Some(owner), None) => safe(owner),
        (None, None, Some(name)) => {
            let registry = issue.registry.as_deref().unwrap_or(&branch.registry);
            format!("{}:{}", safe(registry), safe(name))
        }
        (None, None, None) => branch_input(branch, &issue.operation),
    };
    let requirement = issue
        .requested_requirement
        .as_ref()
        .and_then(Option::as_deref);
    match (requirement, issue.requirement_status.as_deref()) {
        (Some(text), None | Some("recorded")) => format!("{input} {}", safe(text)),
        (Some(text), Some(status)) => {
            format!(
                "{input} {} (requirement {})",
                safe(text),
                requirement_status(status)
            )
        }
        (None, Some(status)) => format!("{input} (requirement {})", requirement_status(status)),
        (None, None) => input,
    }
}

fn branch_input(branch: &Branch, operation: &str) -> String {
    let package = format!("{}:{}", safe(&branch.registry), safe(&branch.name));
    if matches!(operation, "release" | "advisories")
        && let Some(version) = &branch.selected_version
    {
        return format!("{package}@{}", safe(version));
    }
    package
}

fn version_conflict(issue: &Issue, lines: &mut Vec<String>) {
    for (label, versions) in [
        ("The registry branch selected", &issue.selected_versions),
        (
            "The project assignment retained",
            &issue.represented_versions,
        ),
    ] {
        if let Some(versions) = versions.as_ref().filter(|v| !v.is_empty()) {
            lines.push(format!("{label} {}.", list(versions)));
        }
    }
    if let Some(requirements) = issue.requirements.as_ref().filter(|r| !r.is_empty()) {
        let requirements = requirements
            .iter()
            .map(|r| r.as_deref().map_or_else(|| "text unavailable".into(), safe))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("The conflicting requirements were {requirements}."));
    }
}

fn activation_input(issue: &Issue, lines: &mut Vec<String>) {
    if let Some(group) = &issue.feature {
        lines.push(format!(
            "The declaration uses Cargo feature group {}.",
            safe(group)
        ));
    }
    if let Some(features) = &issue.requested_features {
        lines.push(if features.is_empty() {
            "The declaration requested no explicit Cargo features.".into()
        } else {
            format!(
                "The declaration requested Cargo features {}.",
                list(features)
            )
        });
    }
    if let Some(defaults) = issue.default_features {
        let setting = if defaults { "enabled" } else { "disabled" };
        lines.push(format!("The declaration {setting} Cargo default features."));
    }
    if let Some(marker) = &issue.marker {
        lines.push(format!("The declared Python marker is {}.", safe(marker)));
    }
    if let Some(extras) = issue.requested_extras.as_ref().filter(|e| !e.is_empty()) {
        lines.push(format!(
            "The declaration requested Python extras {}.",
            list(extras)
        ));
    }
}

fn cause(issue: &Issue) -> &'static str {
    match issue.reason.as_str() {
        "package_not_found" => "the registry did not find the package",
        "not_found" => "the registry did not find the requested metadata",
        "security_removed" | "registry_removed" => {
            "the registry withdrew the requested package or release"
        }
        "catalog_observation_missing" | "catalog_not_held" => "no version catalog was available",
        "registry_http_error" => "the registry returned an HTTP error",
        "registry_returned_unclassified_error" => "the registry returned an unclassified error",
        "transport_error" => "the registry connection failed",
        "timeout" | "page_timeout" | "cumulative_timeout" => "the registry lookup timed out",
        "rate_limited" => "the registry rate limit was reached",
        "rate_limit_rejected" => "the registry lookup was rejected because of a rate limit",
        "rate_limit_timeout" => "the registry lookup timed out while waiting for the rate limit",
        "invalid_response" => "the registry response could not be used",
        "no_matching_version" => "no published version matched the requirement",
        "invalid_constraint" => "the registry could not interpret the requirement",
        "unknown_dist_tag" => "the registry did not have the requested distribution tag",
        "no_versions_found" => "the registry supplied no versions",
        "no_supported_versions" => "the registry supplied no supported versions",
        "selected_release_not_found" | "version_not_found" => {
            "the requested release could not be found"
        }
        "selected_release_row_missing" => "no metadata was returned for the selected release",
        "single_version_requirements_conflict"
            if issue
                .represented_versions
                .as_ref()
                .is_some_and(|v| !v.is_empty()) =>
        {
            "none of the versions retained for the project satisfied all of the requirements"
        }
        "single_version_requirements_conflict" => {
            "none of the registry-selected versions satisfied all of the requirements"
        }
        "added_coordinate_affected" => "an advisory affects this version",
        "advisory_registry_not_covered" => "advisory checks do not cover this registry",
        "added_requirement_limit" => "the limit for selecting added dependencies was reached",
        "closure_deadline" => "the transitive request was pending when the time limit was reached",
        "closure_request_limit" => {
            "the transitive request was pending when the request limit was reached"
        }
        "added_dependency_deadline_before_start" => {
            "the time limit was reached before the check started"
        }
        "added_dependency_operation_timed_out" => "the check timed out",
        "added_dependency_operation_exited" => "the check stopped without returning a result",
        "go_project_module_selection_required" => {
            "selection requires the project's Go module graph"
        }
        "pub_workspace_selection_required" => "selection requires the project's Pub workspace",
        "maven_project_mediation_required" => {
            "selection requires Maven's project-level version rules"
        }
        "no_registry_consumer_projection" => {
            "the service could not determine dependencies for this registry"
        }
        "cargo_feature_graph_missing" => "the Cargo feature graph was unavailable",
        "cargo_feature_graph_lookup_failed" => "the Cargo feature graph lookup failed",
        "cargo_feature_graph_lookup_deadline" => {
            "the Cargo feature graph was not retrieved before the time limit"
        }
        "cargo_feature_name_filtered" => {
            "the manifest capture omitted a requested Cargo feature name"
        }
        "cargo_transitive_features_not_applied" => {
            "the transitive Cargo feature settings were not applied to this branch"
        }
        "cargo_feature_request_unrecorded" => {
            "the lockfile did not record which Cargo features the incoming request enables"
        }
        "python_transitive_extras_not_applied" => {
            "the transitive Python extras were not applied to this branch"
        }
        "python_extra_name_filtered" => {
            "the manifest capture omitted a requested Python extra name"
        }
        "python_extra_request_unrecorded" => {
            "the lockfile did not record which Python extras the incoming request enables"
        }
        reason => known_cause(reason)
            .unwrap_or("Scan cannot explain the supplied reason. See JSON for the original value"),
    }
}

#[cfg(test)]
mod tests;
