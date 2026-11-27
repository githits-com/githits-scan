"""Network-free tests of contributor fixture verification."""

import argparse
from contextlib import redirect_stdout
from copy import deepcopy
from hashlib import sha256
from http.client import IncompleteRead
from io import BytesIO, StringIO
import json
from pathlib import Path
from subprocess import CompletedProcess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

import live_fixture_reports as reports
import live_fixtures as runner


COVERAGE = {
    key: {
        "unknown_count": 0,
        "not_collected_registries": [],
        "not_applicable_registries": [],
    }
    for key in ("deprecation", "withdrawal", "registry_archival", "repository_archival")
}


def audit_document(manifest="Cargo.toml", dependencies=2):
    return {
        "schema_version": 2,
        "summary": {"dependencies": dependencies},
        "manifests": [manifest],
        "incomplete": False,
        "actionable_incomplete": False,
        "lifecycle": {"findings": [], "retained_warnings": [], "coverage": COVERAGE, "unknowns": []},
    }


def observed_remediation(target):
    expected = next(fixture for fixture in runner.select_fixtures(runner.FIXTURES / "fixtures.json", None)
                    if fixture["id"] == "npm-minimist-remediation")["checks"]["audit"]
    subject = "npm:minimist@0.0.8"
    affected = [{"package": subject, "advisory": item, "files": ["package-lock.json"]}
                for item in expected["remediation"]["advisories"]]
    document = audit_document("package.json", 1)
    document["vulnerabilities"] = affected
    document["remediation"] = {
        "status": "completed",
        "recommendations": [{
            "subject": subject,
            "outcome": "proposed",
            "checks": {
                "release_availability": "observed",
                "advisories": "non_affecting",
                "requirements": "matched",
                "native_resolution": "not_checked",
            },
            "changes": [{
                "registry": "npm",
                "name": "minimist",
                "from_version": "0.0.8",
                "target_version": target,
                "strategy": "upgrade",
                "paths": ["package-lock.json"],
            }],
            "addressed_findings": affected,
        }],
    }
    return document, expected


class ProjectionTests(unittest.TestCase):
    def test_qualified_target_drift_passes_and_prints_changed_versions(self):
        snapshots = []
        for target in ("0.2.4", "0.2.5"):
            document, expected = observed_remediation(target)
            snapshots.append({"audit": reports.audit(document, 1, expected)})
        with redirect_stdout(StringIO()) as output:
            stable_changed = runner.compare("npm-minimist-remediation", *snapshots, False)
        self.assertFalse(stable_changed)
        self.assertRegex(output.getvalue(), r'(?m)^- +"target_version": "0\.2\.4"')
        self.assertRegex(output.getvalue(), r'(?m)^\+ +"target_version": "0\.2\.5"')

    def test_minimist_requires_the_same_affected_copy_and_qualified_alternative(self):
        document, expected = observed_remediation("0.2.5")
        proposal = document["remediation"]["recommendations"][0]
        for mutation in ("unpatched", "prerelease", "range", "wrong_lock", "advisories", "requirements", "native"):
            with self.subTest(mutation):
                alternative = deepcopy(proposal)
                change = alternative["changes"][0]
                if mutation in ("unpatched", "prerelease", "range"):
                    change["target_version"] = {"unpatched": "0.2.3", "prerelease": "0.2.5-rc.1",
                                                "range": "0.3.0"}[mutation]
                elif mutation == "wrong_lock":
                    change["paths"] = ["other/package-lock.json"]
                elif mutation == "advisories":
                    alternative["addressed_findings"].pop()
                elif mutation == "requirements":
                    alternative["checks"]["requirements"] = "blocked"
                else:
                    alternative["checks"]["native_resolution"] = "failed"
                document["remediation"]["recommendations"] = [alternative]
                with self.assertRaisesRegex(reports.Regression, "No qualified upgrade"):
                    reports.audit(document, 1, expected)
                document["remediation"]["recommendations"].append(proposal)
                reports.audit(document, 1, expected)

    def test_new_native_coverage_gap_is_stable_drift(self):
        complete = audit_document()
        partial = deepcopy(complete)
        partial["lifecycle"]["coverage"]["deprecation"]["unknown_count"] = 1
        partial["incomplete"] = True
        partial["actionable_incomplete"] = True
        expected = {"manifests": ["Cargo.toml"]}
        old = {"audit": reports.audit(complete, 0, expected)}
        new = {"audit": reports.audit(partial, 1, expected)}
        with redirect_stdout(StringIO()) as output:
            changed = runner.compare("fd", old, new, False)
        self.assertTrue(changed)
        self.assertIn("fd audit stable changed", output.getvalue())

    def test_lock_only_audit_and_explicit_unassessed_gap(self):
        document = audit_document(dependencies=2)
        del document["manifests"]
        reports.validate_expectations({"audit": {"manifests": []}})
        self.assertEqual(reports.audit(document, 0, {"manifests": []})["observations"]["dependencies"], 2)

        gap = {"check": "dependency information", "status": "incomplete", "files": ["Gopkg.lock"]}
        expected = {"manifests": [], "unassessed_gap": gap}
        reports.validate_expectations({"audit": expected})
        document["summary"]["dependencies"] = 0
        document["incomplete"] = True
        document["actionable_incomplete"] = True
        document["issues"] = [{**gap, "actionable": True}]
        self.assertEqual(reports.audit(document, 1, expected)["stable"]["gaps"][0]["files"], ["Gopkg.lock"])
        document["issues"][0]["files"] = ["other/Gopkg.lock"]
        with self.assertRaisesRegex(reports.Regression, "unassessed audit"):
            reports.audit(document, 1, expected)
        document["issues"] = []
        with self.assertRaisesRegex(reports.Regression, "unassessed audit"):
            reports.audit(document, 1, expected)
        with self.assertRaisesRegex(reports.Regression, "any dependencies"):
            reports.audit(document, 1, {"manifests": []})

    def test_audit_duplicate_and_manifest_mismatch_drift_are_visible_at_the_same_exit(self):
        document = audit_document()
        document["outdated"] = [{"package": "cargo:example@1.0.0", "files": ["Cargo.lock"]}]
        expected = {"manifests": ["Cargo.toml"]}
        first = reports.audit(document, 1, expected)
        document["duplicates"] = [{
            "package": "cargo:example",
            "versions": [{"version": "1.0.0", "origins": [{"file": "a.lock"}, {"file": "b.lock"}]},
                         {"version": "2.0.0", "files": ["a.lock", "b.lock"]}],
        }]
        document["manifest_lock_mismatches"] = [{
            "name": "example", "path": "Cargo.lock", "locked_versions": ["1.0.0", "2.0.0"],
        }]
        second = reports.audit(document, 1, expected)
        self.assertEqual(first["stable"], second["stable"])
        duplicate = second["observations"]["duplicates"][0]
        self.assertEqual(duplicate["package"], document["duplicates"][0]["package"])
        self.assertCountEqual(duplicate["versions"], document["duplicates"][0]["versions"])
        self.assertEqual(second["observations"]["manifest_lock_mismatches"], document["manifest_lock_mismatches"])
        versions = document["duplicates"][0]["versions"]
        versions[0]["origins"].reverse()
        versions[1]["files"].reverse()
        versions.reverse()
        document["manifest_lock_mismatches"][0]["locked_versions"].reverse()
        self.assertEqual(second, reports.audit(document, 1, expected))

    def test_manifest_resolved_sbom_gates_occurrence_loss_but_allows_version_changes(self):
        completeness = "resolved_manifest_inventory"
        document = {
            "bomFormat": "CycloneDX", "specVersion": "1.7",
            "properties": [{"name": "githits:completeness", "value": completeness}],
            "components": [
                {"name": name, "version": "v1.0.0", "type": "library", "bom-ref": name,
                 "properties": [{"name": "githits:manifest_path", "value": "go.mod"}]}
                for name in ("pflag", "secondary")
            ],
        }
        expected = {"completeness": completeness, "witnesses": [{"name": "pflag", "paths": ["go.mod"]}]}
        before = reports.sbom(document, 0, expected)
        document["components"][1]["version"] = "v1.1.0"
        after = reports.sbom(document, 0, expected)
        self.assertEqual(before["stable"], after["stable"])
        self.assertNotEqual(before["observations"], after["observations"])
        document["components"].pop()
        missing = reports.sbom(document, 0, expected)
        self.assertNotEqual(after["stable"]["occurrences"], missing["stable"]["occurrences"])

    def test_manifest_declaration_witness_requires_its_owning_path(self):
        declaration = {
            "name": "github.com/spf13/pflag",
            "manifest_path": "go.mod",
            "declared_requirement": "v1.0.9",
        }
        expected = {"declarations": [declaration]}
        projected = reports.dependency_declarations({"declarations": [declaration]}, expected)
        self.assertEqual(projected, [declaration])
        other = {**declaration, "manifest_path": "other/go.mod"}
        with self.assertRaisesRegex(reports.Regression, "declaration.*in go.mod"):
            reports.dependency_declarations({"declarations": [other]}, expected)

    def test_mixed_sbom_gates_locked_versions_and_relationships(self):
        completeness = "mixed_dependency_inventory"
        document = {
            "bomFormat": "CycloneDX", "specVersion": "1.7",
            "properties": [
                {"name": "githits:completeness", "value": completeness},
                {"name": "githits:lockfiles", "value": '[{"path":"Cargo.lock"}]'},
            ],
            "components": [
                {"name": name, "version": "1.0.0", "type": "library", "bom-ref": name,
                 "properties": [{"name": f"githits:{role}_path", "value": path}]}
                for name, role, path in (("locked", "lockfile", "Cargo.lock"), ("resolved", "manifest", "go.mod"))
            ],
            "dependencies": [{"ref": "locked", "dependsOn": ["resolved"]}],
        }
        expected = {"completeness": completeness, "witnesses": [{"name": "resolved", "paths": ["go.mod"]}]}
        before = reports.sbom(document, 0, expected)
        document["components"][1]["version"] = "1.1.0"
        changed_resolved = reports.sbom(document, 0, expected)
        self.assertEqual(before["stable"], changed_resolved["stable"])
        self.assertNotEqual(before["observations"], changed_resolved["observations"])
        document["components"][0]["version"] = "1.1.0"
        changed_locked = reports.sbom(document, 0, expected)
        self.assertNotEqual(before["stable"]["occurrences"], changed_locked["stable"]["occurrences"])
        document["dependencies"].clear()
        changed_edge = reports.sbom(document, 0, expected)
        self.assertNotEqual(changed_locked["stable"]["locked_relationships"], changed_edge["stable"]["locked_relationships"])

    def test_sbom_preserves_repeated_occurrences_and_resolves_ephemeral_references(self):
        def component(ref):
            return {"name": "example", "version": "1.0.0", "type": "library", "bom-ref": ref,
                    "properties": [{"name": "githits:lockfile_path", "value": "Cargo.lock"}]}

        expected = {"completeness": "recorded_lockfile_inventory", "witnesses": [
            {"name": "example", "version": "1.0.0", "paths": ["Cargo.lock"]}
        ]}
        document = {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": [],
                    "properties": [{"name": "githits:completeness", "value": expected["completeness"]}]}
        with self.assertRaisesRegex(reports.Regression, "Missing expected evidence"):
            reports.sbom(document, 0, expected)
        document["components"] = [component("a"), component("b")]
        document["dependencies"] = [{"ref": "b", "dependsOn": ["a"]}]
        first = reports.sbom(document, 0, expected)
        document["components"] = [component("beta"), component("alpha")]
        document["dependencies"] = [{"ref": "beta", "dependsOn": ["alpha"]}]
        second = reports.sbom(document, 0, expected)
        self.assertEqual(first, second)
        self.assertEqual(len(first["stable"]["components"]), 2)
        self.assertEqual(len(first["stable"]["relationships"]), 1)

        for node, group in zip(document["components"], ["default", "develop"]):
            node["properties"].append({
                "name": "githits:context",
                "value": json.dumps({"group_conditions": [{"group": group, "marker": ""}]}),
            })
        document["components"].append({"name": "parent", "type": "library", "bom-ref": "parent"})
        document["dependencies"] = [{"ref": "parent", "dependsOn": ["beta"]}]
        default = reports.sbom(document, 0, expected)
        document["dependencies"][0]["dependsOn"] = ["alpha"]
        develop = reports.sbom(document, 0, expected)
        self.assertEqual(default["stable"]["components"], develop["stable"]["components"])
        self.assertNotEqual(default["stable"]["relationships"], develop["stable"]["relationships"])

    def test_license_report_requires_declared_evidence_and_retains_observations(self):
        document = json.loads((runner.ROOT / "tests/fixtures/licenses/report-v2.json").read_bytes())
        expected = {"completeness": "mixed_dependency_inventory", "witnesses": [
            {"name": "license-example", "version": "1.0.0", "paths": ["app/package.json"],
             "expression": "GPL-2.0+"}
        ]}
        projected = reports.license_report(document, 0, expected)
        go = next(item for item in projected["observations"]["resolved"]
                  if item["purl"] == "pkg:golang/example.com/source@v1.0.0")
        self.assertEqual(go["licenses"], [])
        detected = [entry["license"]["name"] for entry in go["observed_licenses"]]
        self.assertEqual(detected, ["Apache-2.0", "MIT"])
        document["components"][0]["licenses"] = []
        with self.assertRaisesRegex(reports.Regression, "Missing expected evidence"):
            reports.license_report(document, 0, expected)

    def test_license_coverage_keeps_subjects_and_rejects_unresolved_references(self):
        document = json.loads((runner.ROOT / "tests/fixtures/licenses/report-v2.json").read_bytes())
        expected = {"completeness": "mixed_dependency_inventory", "witnesses": [
            {"name": "license-example", "paths": ["app/package.json"]}
        ]}
        before = reports.license_report(document, 0, expected)
        go = next(row for row in document["components"] if row["bom_ref"] == "go")
        go["version"] = "v1.0.1"
        go["purl"] = "pkg:golang/example.com/source@v1.0.1"
        after = reports.license_report(document, 0, expected)
        self.assertEqual(before["stable"], after["stable"])
        self.assertNotEqual(before["observations"], after["observations"])
        dependencies = document["inventory"]["coverage"][1]["dependencies"]
        dependencies.remove("go")
        after = reports.license_report(document, 0, expected)
        self.assertNotEqual(before["stable"]["coverage"], after["stable"]["coverage"])
        document["inventory"]["dependency_coverage"]["absent"] = {"state": "unknown"}
        with self.assertRaisesRegex(reports.BadReport, "absent occurrence"):
            reports.license_report(document, 0, expected)
        del document["inventory"]["dependency_coverage"]["absent"]
        dependencies.append("absent")
        with self.assertRaisesRegex(reports.BadReport, "absent occurrence"):
            reports.license_report(document, 0, expected)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inventory = self.root / "fixtures.json"
        source = self.root / "local"
        source.mkdir()
        contents = b"test package"
        (source / "Cargo.toml").write_bytes(contents)
        self.fixtures = [
            {"id": key, "ecosystem": "rust", "local": "local",
             "files": {"Cargo.toml": sha256(contents).hexdigest()}, "upload_paths": ["Cargo.toml"],
             "checks": {"audit": {"manifests": ["Cargo.toml"], "locked": True}}}
            for key in ("first", "second")
        ]
        self.write_inventory()
        self.environment = {runner.TOKEN_ENV: "sentinel-not-a-real-credential"}
        self.results = {}

    def write_inventory(self):
        self.inventory.write_text(json.dumps(self.fixtures), encoding="utf-8")

    def fake_scan(self, arguments, root, environment, context):
        self.assertNotIn(self.environment[runner.TOKEN_ENV], arguments)
        self.assertIn("--quiet", arguments)
        if "detect" in arguments:
            self.assertNotIn(runner.TOKEN_ENV, environment)
            data = {"schema_version": 2, "upload_paths": self.results.get("paths", ["Cargo.toml"])}
        else:
            self.assertEqual(environment[runner.TOKEN_ENV], self.environment[runner.TOKEN_ENV])
            data = self.results.get(root.name, audit_document())
        return CompletedProcess(arguments, 0, json.dumps(data).encode(), b"")

    def run_fixture(self, command, selection=None, **kwargs):
        options = argparse.Namespace(command=command, fixture=selection, binary=Path(sys.executable))
        with redirect_stdout(StringIO()) as output, patch.object(runner, "process", side_effect=self.fake_scan) as child:
            result = runner.execute(options, self.root, self.root, self.environment, **kwargs)
        return result, output.getvalue(), child.call_args_list

    def test_single_and_all_refresh_and_check_use_only_selected_files(self):
        code, output, calls = self.run_fixture("refresh")
        paths = self.root / "baselines"
        first = paths / "first.json"
        second = paths / "second.json"
        originals = [file.read_bytes() for file in (first, second)]
        self.assertEqual(code, 0)
        self.assertIn("2 checks, 2 planned API jobs", output)
        self.assertEqual([call.args[0][1] for call in calls], ["detect", "detect", "audit", "audit"])
        code, _, calls = self.run_fixture("check")
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 4)
        self.assertEqual([file.read_bytes() for file in (first, second)], originals)
        self.results["first"] = audit_document(dependencies=3)
        self.results["second"] = audit_document(dependencies=4)
        code, output, calls = self.run_fixture("check", "first")
        self.assertEqual(code, 1)
        self.assertIn("first audit stable changed", output)
        self.assertRegex(output, r'(?m)^\+ +"dependencies": 3,')
        self.assertEqual([call.args[0][1] for call in calls], ["detect", "audit"])
        self.assertEqual(first.read_bytes(), originals[0])
        self.run_fixture("refresh", "first")
        self.assertNotEqual(first.read_bytes(), originals[0])
        self.assertEqual(second.read_bytes(), originals[1])
        self.run_fixture("refresh")
        self.assertNotEqual(second.read_bytes(), originals[1])

    def test_list_reports_job_count_offline(self):
        code, output, calls = self.run_fixture("list")
        self.assertEqual(code, 0)
        self.assertEqual(calls, [])
        self.assertIn("2 fixtures, 2 planned API jobs.", output)

    def test_failed_selected_command_preserves_every_baseline(self):
        self.run_fixture("refresh")
        paths = sorted((self.root / "baselines").glob("*.json"))
        original = [file.read_bytes() for file in paths]
        self.results["first"] = audit_document(dependencies=3)
        self.results["second"] = audit_document(dependencies=0)
        with self.assertRaisesRegex(reports.Regression, "did not account"):
            self.run_fixture("refresh")
        self.assertEqual([file.read_bytes() for file in paths], original)

    def test_preflight_finishes_before_credentials_or_any_paid_work(self):
        with patch.object(runner, "acquire_token") as auth:
            self.fixtures[1]["files"]["Cargo.toml"] = "0" * 64
            self.write_inventory()
            with self.assertRaisesRegex(runner.ExecutionError, "SHA-256 mismatch"):
                self.run_fixture("refresh")
            auth.assert_not_called()
            self.fixtures[1]["files"] = self.fixtures[0]["files"]
            self.write_inventory()
            self.results["paths"] = ["different.toml"]
            with self.assertRaisesRegex(reports.Regression, "selected"):
                self.run_fixture("refresh")
            auth.assert_not_called()

    def test_each_online_command_obtains_a_current_credential_after_preflight(self):
        with patch.object(runner, "acquire_token", wraps=runner.acquire_token) as auth:
            _, _, calls = self.run_fixture("refresh")
        self.assertEqual(auth.call_count, 2)
        self.assertEqual([call.args[0][1] for call in calls], ["detect", "detect", "audit", "audit"])

    def test_invalid_selection_inventory_and_baseline_fail_closed(self):
        with self.assertRaisesRegex(runner.UsageError, "Unknown fixture"):
            self.run_fixture("refresh", "typo")
        with self.assertRaisesRegex(runner.UsageError, "Cannot read fixture data"):
            self.run_fixture("check")
        self.fixtures[1]["files"] = {"../Cargo.toml": "0" * 64}
        self.write_inventory()
        with self.assertRaisesRegex(runner.UsageError, "relative paths"):
            self.run_fixture("refresh")
        self.fixtures = []
        self.write_inventory()
        with self.assertRaisesRegex(runner.UsageError, "empty"):
            self.run_fixture("list")

    def test_license_expression_is_rejected_as_an_sbom_expectation(self):
        fixture = self.fixtures[0]
        fixture["checks"] = {
            "sbom": {"completeness": "recorded_lockfile_inventory", "witnesses": [
                {"name": "example", "paths": ["Cargo.toml"], "expression": "MIT"}
            ]}
        }
        with self.assertRaises(runner.UsageError) as failure:
            runner.validate_fixture(fixture)
        self.assertEqual(failure.exception.exit_code, 2)

    def test_remote_fetch_uses_pinned_files_rejects_redirect_and_checks_bytes(self):
        fixture = self.fixtures[0]
        fixture["project"] = {"repository": "owner/repo", "release": "v1", "commit": "a" * 40}
        del fixture["local"]
        runner.validate_fixture(fixture)
        opener = Mock()
        with patch.object(runner.urllib.request, "build_opener", return_value=opener) as build_opener:
            opener.open.return_value = BytesIO(b"test package")
            staged = self.root / "staged"
            runner.stage_inputs(fixture, staged, self.root)
            opener.open.assert_called_once_with(
                "https://raw.githubusercontent.com/owner/repo/" + "a" * 40 + "/Cargo.toml", timeout=30)
            self.assertIsInstance(build_opener.call_args.args[0], runner.NoRedirect)
            self.assertIsNone(build_opener.call_args.args[0].redirect_request(None, None, 302, "", {}, ""))
            self.assertEqual((staged / "Cargo.toml").read_bytes(), b"test package")
            opener.open.side_effect = HTTPError("", 302, "redirect", {}, None)
            with self.assertRaisesRegex(runner.ExecutionError, "HTTP 302"):
                runner.stage_inputs(fixture, self.root / "redirected", self.root)
            opener.open.side_effect = IncompleteRead(b"partial package data")
            with self.assertRaisesRegex(runner.ExecutionError, "IncompleteRead") as failure:
                runner.stage_inputs(fixture, self.root / "truncated", self.root)
            self.assertEqual(failure.exception.exit_code, 3)
            self.assertNotIn("partial package data", str(failure.exception))

    def test_remote_subdirectory_is_verified_and_preserves_the_project_root(self):
        fixture = self.fixtures[0]
        fixture["project"] = {"repository": "owner/repo", "commit": "a" * 40, "subdirectory": "test projects/example"}
        del fixture["local"]
        runner.validate_fixture(fixture)
        opener = Mock()
        opener.open.return_value = BytesIO(b"test package")
        with patch.object(runner.urllib.request, "build_opener", return_value=opener):
            staged = self.root / "staged"
            runner.stage_inputs(fixture, staged, self.root)
            opener.open.assert_called_once_with(
                "https://raw.githubusercontent.com/owner/repo/" + "a" * 40
                + "/test%20projects/example/Cargo.toml", timeout=30
            )
            self.assertEqual((staged / "Cargo.toml").read_bytes(), b"test package")
        for path in ("../escape", "/root", "a//b", "a\\b"):
            with self.subTest(path=path), self.assertRaises(runner.UsageError):
                fixture["project"]["subdirectory"] = path
                runner.validate_fixture(fixture)

    def test_echoed_token_is_withheld_before_report_or_baseline(self):
        original = self.fake_scan

        def leaking_scan(arguments, root, environment, context):
            result = original(arguments, root, environment, context)
            if context == "second audit":
                result.stderr = environment[runner.TOKEN_ENV].encode()
            return result

        self.fake_scan = leaking_scan
        with self.assertRaisesRegex(runner.ExecutionError, "Output withheld") as failure:
            self.run_fixture("refresh")
        self.assertNotIn(self.environment[runner.TOKEN_ENV], str(failure.exception))
        self.assertFalse((self.root / "baselines").exists())

    def test_missing_credential_fails_closed_in_ci_and_bad_reports_fail(self):
        with self.assertRaisesRegex(runner.ExecutionError, "secret"):
            runner.acquire_token({"CI": "true"}, self.root)
        with self.assertRaisesRegex(runner.ExecutionError, "empty"):
            runner.acquire_token({runner.TOKEN_ENV: ""}, self.root)
        with patch.object(runner, "process") as child:
            with self.assertRaisesRegex(runner.ExecutionError, "matching"):
                runner.acquire_token({"GITHITS_API_URL": "https://example.com"}, self.root)
            child.assert_not_called()
        for code, output in [(3, b"{}"), (0, b"malformed"), (0, b"[]")]:
            with self.subTest(code=code, output=output):
                with patch.object(runner, "process", return_value=CompletedProcess([], code, output, b"")):
                    with self.assertRaises(runner.ExecutionError):
                        runner.scan_json(Path(sys.executable), [], self.root, {}, "fixture audit", (0, 1))


if __name__ == "__main__":
    unittest.main()
