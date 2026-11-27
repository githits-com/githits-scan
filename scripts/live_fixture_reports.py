"""Reviewable evidence from Scan's public JSON outputs."""

import json
import re


class BadReport(ValueError):
    """Scan did not produce a usable document."""

    exit_code = 3


class Regression(ValueError):
    """The report lost required evidence."""

    exit_code = 1


def expect(condition, message):
    if not condition:
        raise Regression(message)


def typed(value, key, kind, default=None):
    field = value.get(key, default)
    if type(field) is not kind:
        raise BadReport(f"Expected {key} as {kind.__name__} in the report")
    return field


def rows(value, key, optional=False):
    items = typed(value, key, list, [] if optional else None)
    if any(not isinstance(row, dict) for row in items):
        raise BadReport(f"Expected objects in {key}")
    return items


def strings(value, key, optional=False):
    items = typed(value, key, list, [] if optional else None)
    if any(not isinstance(item, str) for item in items):
        raise BadReport(f"Expected text in {key}")
    return sorted(items)


def count(value, key):
    result = typed(value, key, int)
    if result < 0:
        raise BadReport(f"Expected a nonnegative count for {key}")
    return result


def fields(value, *keys):
    return {key: value[key] for key in keys if key in value}


def sorted_rows(items):
    return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=True))


def version(value):
    if isinstance(value, str) and re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", value, re.ASCII):
        return tuple(int(part) for part in value.split("."))
    return None


def fixture_strings(value):
    return isinstance(value, list) and bool(value) and all(isinstance(item, str) and item for item in value)


def validate_expectations(checks):
    for name, expected in checks.items():
        if not isinstance(expected, dict):
            raise ValueError(f"{name} expectations must be an object")
        if name in ("sbom", "license_report"):
            witnesses = expected.get("witnesses")
            if (
                not isinstance(expected.get("completeness"), str)
                or not isinstance(witnesses, list)
                or not witnesses
                or any(
                    not isinstance(witness, dict)
                    or not isinstance(witness.get("name"), str)
                    or not fixture_strings(witness.get("paths"))
                    or any(not isinstance(witness[key], str) for key in ("version", "expression") if key in witness)
                    or (name == "sbom" and "expression" in witness)
                    or ("versioned" in witness and witness["versioned"] is not True)
                    for witness in witnesses
                )
            ):
                raise ValueError(f"{name} needs completeness and named, attributed witnesses")
        elif name == "license_policy":
            if any(not isinstance(expected.get(key), str) for key in ("name", "version")):
                raise ValueError("license policy needs a named, versioned denial witness")
        else:
            if not fixture_strings(expected.get("manifests")):
                raise ValueError("audit needs expected manifest paths")
            if "remediation" in expected:
                fixed = expected["remediation"]
                if (
                    not isinstance(fixed, dict)
                    or any(not isinstance(fixed.get(key), str)
                           for key in ("registry", "name", "installed", "path", "minimum", "exclusive_maximum",
                                       "native_resolution"))
                    or version(fixed["minimum"]) is None
                    or version(fixed["exclusive_maximum"]) is None
                    or version(fixed["minimum"]) >= version(fixed["exclusive_maximum"])
                    or not fixture_strings(fixed.get("advisories"))
                ):
                    raise ValueError("audit remediation needs a subject, affected path, stable range and advisories")


def result(stable, observations=None):
    return {"stable": stable, "observations": observations}


def assertions(witnesses, components):
    for witness in witnesses:
        def matches(component):
            return (
                component["name"] == witness["name"]
                and ("version" not in witness or component.get("version") == witness["version"])
                and (not witness.get("versioned") or bool(component.get("version")))
                and set(witness["paths"]) <= set(component["paths"])
                and (
                    "expression" not in witness
                    or any(choice.get("expression") == witness["expression"]
                           for choice in component["licenses"])
                )
            )

        if not any(matches(component) for component in components):
            label = witness["name"] + (" " + witness["version"] if "version" in witness else "")
            raise Regression(f"Missing expected evidence for {label} in {', '.join(witness['paths'])}")


def cdx_properties(value):
    return {
        typed(row, "name", str): typed(row, "value", str)
        for row in rows(value, "properties", optional=True)
    }


def cdx_json(properties, name, kind, default):
    if name not in properties:
        return default
    try:
        value = json.loads(properties[name])
    except ValueError as error:
        raise BadReport(f"Invalid JSON in {name}") from error
    if not isinstance(value, kind):
        raise BadReport(f"Invalid value in {name}")
    return value


def cdx_component(component):
    typed(component, "name", str)
    props = cdx_properties(component)
    identity = fields(component, "name", "version", "purl", "type", "scope")
    paths = []
    for role in ("manifest", "lockfile"):
        key = f"githits:{role}_path"
        paths += strings({"paths": cdx_json(props, key + "s", list, [])}, "paths")
        if key in props:
            paths.append(props[key])
    identity["paths"] = sorted(set(paths))
    for key in ("record_kind", "source_kind", "source_revision"):
        if f"githits:{key}" in props:
            identity[key] = props[f"githits:{key}"]
    if "githits:context" in props:
        identity["context"] = occurrence_context(cdx_json(props, "githits:context", dict, {}))
    return identity


def occurrence_context(context):
    result = dict(context)
    if isinstance(result.get("group_conditions"), list):
        result["group_conditions"] = sorted_rows(result["group_conditions"])
    return result


def component_tree(components, references, entries, relationships, parent=None):
    for component in components:
        identity = cdx_component(component)
        entries.append(identity)
        if "bom-ref" in component:
            ref = typed(component, "bom-ref", str)
            if ref in references and references[ref] != identity:
                raise BadReport("A CycloneDX reference names different occurrences")
            references[ref] = identity
        if parent is not None:
            relationships.append({"contains": [parent, identity]})
        component_tree(rows(component, "components", optional=True),
                       references, entries, relationships, identity)


def sbom(document, _code, expected):
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.7":
        raise BadReport("Expected CycloneDX 1.7")
    props = cdx_properties(document)
    completeness = props.get("githits:completeness")
    expect(completeness == expected["completeness"],
           f"Expected {expected['completeness']} inventory, got {completeness}")
    locked = completeness == "recorded_lockfile_inventory"

    entries, relationships, references = [], [], {}
    component_tree(rows(document, "components"), references, entries, relationships)
    assertions(expected["witnesses"], entries)

    metadata = typed(document, "metadata", dict, {})
    if "component" in metadata:
        component_tree([typed(metadata, "component", dict)], references, [], relationships)
    for dependency in rows(document, "dependencies", optional=True):
        ref = typed(dependency, "ref", str)
        for key in ("dependsOn", "provides"):
            if key in dependency:
                for target in strings(dependency, key):
                    try:
                        relationships.append({key: [references[ref], references[target]]})
                    except KeyError as error:
                        raise BadReport("CycloneDX relationship points to an absent reference") from error

    stable = {"completeness": completeness}
    for name in ("lockfiles", "resolutions"):
        items = cdx_json(props, f"githits:{name}", list, None)
        if items is not None:
            stable[name] = resolution_rows({name: items}, name)
    inventory = {"components": sorted_rows(entries), "relationships": sorted_rows(relationships)}
    if locked:
        stable.update(inventory)
        return result(stable)
    stable["occurrences"] = sorted_rows(
        occurrence_subject(identity, identity.get("record_kind") == "manifest")
        for identity in entries
    )
    return result(stable, inventory)


def resolution_rows(document, key):
    projected = []
    for row in rows(document, key, optional=True):
        facts = fields(row, "path", "status", "format", "native_format_version", "completeness",
                       "association_status", "manifest_lock_consistency")
        if "manifest_paths" in row:
            facts["manifest_paths"] = strings(row, "manifest_paths")
        for name in ("diagnostics", "association_diagnostics"):
            if name in row:
                facts[name] = sorted_rows(fields(item, "name", "reason") for item in rows(row, name))
        projected.append(facts)
    return sorted_rows(projected)


def license_choices(component, key):
    return sorted_rows(
        fields(choice, "expression", "license", "acknowledgement")
        for choice in rows(component, key)
    )


def license_component(component):
    typed(component, "name", str)
    identity = fields(component, "name", "version", "type", "purl", "scope", "record_kind",
                      "source_kind", "source_revision", "metadata_status", "metadata_reason",
                      "resolution_basis", "resolution_limitation")
    inputs = typed(component, "inputs", dict)
    for key in ("manifest_paths", "lockfile_paths"):
        identity[key] = strings(inputs, key)
    identity["paths"] = sorted(set(identity["manifest_paths"] + identity["lockfile_paths"]))
    for key in ("licenses", "observed_licenses"):
        identity[key] = license_choices(component, key)
    if "context" in component:
        context = component["context"]
        identity["context"] = occurrence_context(context) if isinstance(context, dict) else context
    if "license_evidence" in component:
        evidence = component["license_evidence"]
        identity["license_evidence"] = evidence if evidence is None else fields(
            typed(component, "license_evidence", dict), "source", "lookup_basis",
            "applicability_reason", "status", "artifact_verification", "origin_scope",
        )
    return identity


def occurrence_subject(identity, pinned):
    subject = fields(identity, "name", "paths", "type", "record_kind", "scope", "context", "source_kind")
    if pinned:
        subject.update(fields(identity, "version", "purl", "source_revision"))
    return subject


def coverage_subjects(components, identities):
    subjects = {}
    for component, identity in zip(components, identities):
        if component.get("bom_ref") is None:
            continue
        reference = typed(component, "bom_ref", str)
        pinned = bool(identity["lockfile_paths"]) or identity.get("record_kind") == "manifest"
        subject = occurrence_subject(identity, pinned)
        if reference in subjects and subjects[reference] != subject:
            raise BadReport("A license report reference names different occurrences")
        subjects[reference] = subject
    return subjects


def license_coverage(inventory, subjects):
    def subject_for(reference):
        if reference not in subjects:
            raise BadReport("License coverage points to an absent occurrence")
        return subjects[reference]

    coverage = sorted_rows({
        **fields(row, "aggregate"),
        **{
            key: sorted_rows(subject_for(ref) for ref in strings(row, key))
            for key in ("assemblies", "dependencies", "services") if key in row
        },
    } for row in rows(inventory, "coverage"))
    scoped = typed(inventory, "dependency_coverage", dict, {})
    dependency_coverage = sorted_rows({
        "subject": subject_for(ref),
        **fields(typed(scoped, ref, dict), "state"),
        "reasons": strings(scoped[ref], "reasons", optional=True),
    } for ref in scoped)
    return coverage, dependency_coverage


def license_report(document, _code, expected):
    if document.get("schema_version") != 2:
        raise BadReport("Expected license report schema 2")
    inventory = typed(document, "inventory", dict)
    completeness = inventory.get("completeness")
    expect(completeness == expected["completeness"],
           f"Expected {expected['completeness']} license inventory, got {completeness}")
    components = rows(document, "components")
    identities = [license_component(component) for component in components]
    assertions(expected["witnesses"], identities)
    coverage, dependency_coverage = license_coverage(inventory, coverage_subjects(components, identities))

    stable = {
        "completeness": completeness,
        "resolutions": resolution_rows(inventory, "resolutions"),
        "lockfiles": resolution_rows(inventory, "lockfiles"),
        "declarations": sorted_rows(fields(row, "manifest_path", "name", "declared_requirement", "declared_scope")
                                    for row in rows(inventory, "declarations", optional=True)),
        "components": sorted_rows(identity for identity in identities
                                  if identity["lockfile_paths"] or identity.get("record_kind") == "manifest"),
        "coverage": coverage,
        "dependency_coverage": dependency_coverage,
    }
    observations = {
        "resolved": sorted_rows(identity for identity in identities
                                if not identity["lockfile_paths"] and identity.get("record_kind") != "manifest"),
        "links": sorted_rows(
            {"name": identity["name"], **fields(link, "type", "url")}
            for row, identity in zip(components, identities)
            for link in rows(row, "external_references")
        ),
    }
    return result(stable, observations)


def audit_findings(document, field):
    return sorted_rows(
        {**fields(row, "package", "advisory", "severity", "latest", "ignored", "malicious"),
         "files": strings(row, "files")}
        for row in rows(document, field, optional=True)
    )


def check_remediation(document, findings, code, expected):
    package = f"{expected['registry']}:{expected['name']}@{expected['installed']}"
    path = expected["path"]
    advisories = set(expected["advisories"])

    def ids(records):
        return {
            row.get("advisory") for row in records
            if row.get("package") == package and path in strings(row, "files") and not row.get("ignored")
        }

    expect(code == 1 and advisories <= ids(findings),
           f"Expected advisory findings at exit 1 for {package} in {path}")
    remediation = typed(document, "remediation", dict, {})
    expect(remediation.get("status") == "completed", f"Remediation did not complete for {package}")
    lower = version(expected["minimum"])
    upper = version(expected["exclusive_maximum"])
    for record in rows(remediation, "recommendations"):
        if record.get("subject") != package or record.get("outcome") != "proposed":
            continue
        if not advisories <= ids(rows(record, "addressed_findings")):
            continue
        checks = typed(record, "checks", dict)
        if any(checks.get(key) != value for key, value in {
            "release_availability": "observed", "advisories": "non_affecting", "requirements": "matched",
            "native_resolution": expected["native_resolution"],
        }.items()):
            continue
        for change in rows(record, "changes"):
            target = version(change.get("target_version"))
            if (
                change.get("registry") == expected["registry"]
                and change.get("name") == expected["name"]
                and change.get("from_version") == expected["installed"]
                and change.get("strategy") == "upgrade"
                and path in strings(change, "paths", optional=True)
                and target is not None
                and lower <= target < upper
            ):
                return
    raise Regression(f"No qualified upgrade for {package} in {path} addresses {', '.join(sorted(advisories))}")


def audit(document, code, expected):
    if document.get("schema_version") != 2:
        raise BadReport("Expected audit report schema 2")
    expect(strings(document, "manifests", optional=True) == sorted(expected["manifests"]),
           "Audit manifest attribution changed")
    summary = typed(document, "summary", dict)
    dependencies = count(summary, "dependencies")
    expect(dependencies > 0, "Audit did not account for any dependencies")
    issues = rows(document, "issues", optional=True)
    expect(all(issue.get("check") != "report" for issue in issues),
           "Audit could not verify service report accounting")
    findings = audit_findings(document, "vulnerabilities")
    outdated = audit_findings(document, "outdated")
    duplicates = rows(document, "duplicates", optional=True)
    mismatches = rows(document, "manifest_lock_mismatches", optional=True)
    lifecycle = typed(document, "lifecycle", dict)
    native_findings = rows(lifecycle, "findings")
    warnings = rows(lifecycle, "retained_warnings")
    coverage = typed(lifecycle, "coverage", dict)
    incomplete = typed(document, "incomplete", bool)
    actionable = typed(document, "actionable_incomplete", bool)
    has_findings = (
        any(not row.get("ignored") for row in findings) or outdated or native_findings or warnings
        or duplicates or mismatches
    )
    expect(code == int(bool(has_findings or actionable)), "Audit exit disagrees with the report")
    if "remediation" in expected:
        check_remediation(document, findings, code, expected["remediation"])

    stable = {
        "incomplete": incomplete,
        "actionable_incomplete": actionable,
        "coverage": {
            key: {
                "unknown": count(typed(coverage, key, dict), "unknown_count") > 0,
                "not_collected": strings(coverage[key], "not_collected_registries"),
                "not_applicable": strings(coverage[key], "not_applicable_registries"),
            }
            for key in ("deprecation", "withdrawal", "registry_archival", "repository_archival")
        },
        "gaps": sorted_rows({
            **fields(issue, "check", "status", "actionable"),
            "files": strings(issue, "files", optional=True),
            "required_files": strings(issue, "required_files", optional=True),
        } for issue in issues),
        "native_gaps": sorted_rows({
            **fields(row, "check", "status", "reason"),
            "paths": strings(row, "paths"),
        } for row in rows(lifecycle, "unknowns")),
    }
    observations = {
        "exit": code,
        "dependencies": dependencies,
        "vulnerabilities": findings,
        "outdated": outdated,
        "duplicates": sorted_rows(duplicates),
        "manifest_lock_mismatches": sorted_rows(mismatches),
        "lifecycle": sorted_rows(
            {**fields(row, "registry", "name", "version", "category", "kind", "scope", "source"),
             "observations": sorted_rows(fields(observation, "reason", "replacement", "source_version", "affected")
                                         for observation in rows(row, "observations"))}
            for row in native_findings
        ),
        "retained_warnings": sorted_rows(warnings),
        "recommendations": sorted_rows({
            **fields(row, "subject", "outcome", "checks"),
            "changes": sorted_rows(
                {**fields(change, "registry", "name", "from_version", "target_version", "strategy"),
                 "paths": strings(change, "paths", optional=True)}
                for change in rows(row, "changes")
            ),
            "addressed_findings": audit_findings(row, "addressed_findings"),
            "remaining_findings": audit_findings(row, "remaining_findings"),
        } for row in rows(typed(document, "remediation", dict, {}), "recommendations", optional=True)),
    }
    if expected.get("locked"):
        stable["dependencies"] = observations.pop("dependencies")
    return result(stable, observations)


def license_policy(document, code, expected):
    if document.get("schema_version") != 1:
        raise BadReport("Expected license policy report schema 1")
    violations = rows(document, "violations")
    expect(code == 1 and any(
        row.get("name") == expected["name"] and row.get("version") == expected["version"]
        and row.get("reason") == "not_allowed" and bool(row.get("expression"))
        for row in violations
    ), f"Deny-all policy did not report a license violation for {expected['name']} {expected['version']}")
    return result(None, sorted_rows(fields(row, "name", "version", "purl", "reason", "expression")
                                    for row in violations))


def project(command, document, code, expected):
    return {
        "sbom": sbom,
        "audit": audit,
        "license_report": license_report,
        "license_policy": license_policy,
    }[command](document, code, expected)
