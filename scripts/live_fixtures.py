"""Run reviewed fixtures through the real Scan binary. Importing this module is offline."""

import argparse
import difflib
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

import live_fixture_reports as reports


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/live"
PRODUCTION = "https://api.githits.dev"
TOKEN_ENV = "GITHITS_API_TOKEN"
MAX_INPUT_BYTES = 5_242_880
COMMANDS = {
    "sbom": ("sbom", "generate"),
    "audit": ("audit",),
    "license_report": ("license", "report"),
    "license_policy": ("license", "check"),
}
ONLINE = ("sbom", "audit", "license_report")


class UsageError(ValueError):
    """Invalid invocation or fixture data."""

    exit_code = 2


class ExecutionError(RuntimeError):
    """An input could not be staged or a command could not produce a report."""

    exit_code = 3


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_object(path):
    try:
        return json.loads(path.read_bytes())
    except (OSError, ValueError) as error:
        raise UsageError(f"Cannot read fixture data at {path.name}") from error


def relative_path(path):
    # Keep the spelling identical on POSIX and Windows and in upload filenames.
    if (
        not isinstance(path, str)
        or any(part in ("", ".", "..") for part in path.split("/"))
        or any(ch in path for ch in "\\:")
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in path)
    ):
        raise UsageError("Fixture paths must be exact, portable relative paths")
    return path


def local_path(root, path):
    for part in relative_path(path).split("/"):
        root = root / part
        if root.is_symlink():
            raise ExecutionError(f"Fixture input traverses a symbolic link at {path}")
    return root


def validate_fixture(fixture):
    if not isinstance(fixture, dict):
        raise UsageError("Fixture entries must be objects")
    fixture_id = fixture.get("id")
    if not isinstance(fixture_id, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", fixture_id):
        raise UsageError("Expected a lowercase fixture ID")
    context = f"{fixture_id}: invalid fixture definition"
    project = fixture.get("project")
    local = fixture.get("local")
    if project is not None and local is None:
        if (
            not isinstance(project, dict)
            or not re.fullmatch(r"[\w.-]+/[\w.-]+", project.get("repository", ""), re.ASCII)
            or any(part in (".", "..") for part in project["repository"].split("/"))
            or not re.fullmatch(r"[0-9a-f]{40}", project.get("commit", ""))
            or ("release" in project and (not isinstance(project["release"], str) or not project["release"]))
        ):
            raise UsageError(f"{context}. Expected a GitHub repository and full commit")
        if "subdirectory" in project:
            relative_path(project["subdirectory"])
    elif local is not None and project is None:
        relative_path(local)
    else:
        raise UsageError(f"{context}. Choose exactly one input source")
    files = fixture.get("files")
    if not isinstance(files, dict) or not files:
        raise UsageError(f"{context}. Expected pinned files")
    for path, digest in files.items():
        relative_path(path)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise UsageError(f"{context}. Expected SHA-256 for {path}")
    paths = fixture.get("upload_paths")
    if not isinstance(paths, list) or not paths or any(not isinstance(path, str) for path in paths):
        raise UsageError(f"{context}. Expected upload paths")
    for path in paths:
        relative_path(path)
    # A generated evidence file can be selected by Scan without a pinned input.
    if len(set(paths)) != len(paths):
        raise UsageError(f"{context}. Upload paths must be unique")
    checks = fixture.get("checks")
    if (
        not isinstance(checks, dict)
        or not checks
        or not checks.keys() <= COMMANDS.keys()
        or ("license_policy" in checks and "sbom" not in checks)
        or not isinstance(fixture.get("ecosystem"), str)
    ):
        raise UsageError(f"{context}. Expected known checks and an ecosystem")
    try:
        reports.validate_expectations(checks)
    except ValueError as error:
        raise UsageError(f"{context}. {error}") from error
    return fixture_id


def select_fixtures(inventory, selection):
    entries = read_object(inventory)
    if not isinstance(entries, list) or not entries:
        raise UsageError("Fixture inventory is empty or is not a list")
    fixtures = {}
    for fixture in entries:
        try:
            fixture_id = validate_fixture(fixture)
        except TypeError as error:
            raise UsageError("Fixture repository or commit must be text") from error
        if fixture_id in fixtures:
            raise UsageError(f"Duplicate fixture ID {fixture_id}")
        fixtures[fixture_id] = fixture
    if selection is None:
        return list(fixtures.values())
    if selection not in fixtures:
        raise UsageError(f"Unknown fixture {selection!r}. Run list to see fixture IDs")
    return [fixtures[selection]]


def stage_inputs(fixture, root, workspace):
    root.mkdir()
    project = fixture.get("project")
    if project is None:
        source = local_path(workspace, fixture["local"])
    else:
        url = f"https://raw.githubusercontent.com/{project['repository']}/{project['commit']}/"
        if "subdirectory" in project:
            url += urllib.parse.quote(project["subdirectory"], safe="/") + "/"
        opener = urllib.request.build_opener(NoRedirect())
    for path, digest in fixture["files"].items():
        try:
            if project is None:
                origin = path
                source_file = local_path(source, path)
                if not source_file.is_file():
                    raise ExecutionError(f"Expected a regular fixture file at {path}")
                with source_file.open("rb") as stream:
                    contents = stream.read(MAX_INPUT_BYTES + 1)
            else:
                origin = url + urllib.parse.quote(path, safe="/")
                with opener.open(origin, timeout=30) as stream:
                    contents = stream.read(MAX_INPUT_BYTES + 1)
            if len(contents) > MAX_INPUT_BYTES or hashlib.sha256(contents).hexdigest() != digest:
                raise ExecutionError(f"Size or SHA-256 mismatch for {origin}")
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(contents)
        except urllib.error.HTTPError as error:
            raise ExecutionError(f"Cannot fetch pinned input {origin} (HTTP {error.code})") from error
        except (OSError, http.client.HTTPException) as error:
            raise ExecutionError(f"Cannot stage pinned input {origin} ({type(error).__name__})") from error


def without_token(environment):
    return {key: value for key, value in environment.items() if key != TOKEN_ENV}


def process(arguments, root, environment, context, timeout=None):
    try:
        return subprocess.run(
            arguments, cwd=root, env=environment, capture_output=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ExecutionError(f"{context} failed ({type(error).__name__})") from error


def acquire_token(environment, workspace):
    supplied = environment.get(TOKEN_ENV)
    if supplied is None:
        if environment.get("GITHITS_API_URL", PRODUCTION) != PRODUCTION:
            raise ExecutionError(f"Supply a matching {TOKEN_ENV} for a custom API origin")
        if environment.get("CI") == "true":
            raise ExecutionError(f"Configure the {TOKEN_ENV} secret for the live job")
        acquired = process(
            ["npx", "-y", "githits@latest", "auth", "token"],
            workspace,
            {**without_token(environment), "GITHITS_ENV": "prod"},
            "GitHits CLI authentication",
            timeout=90,
        )
        if acquired.returncode or not acquired.stdout.strip().isascii():
            raise ExecutionError("Could not acquire a production token from the signed-in GitHits CLI")
        supplied = acquired.stdout.decode("ascii")
    token = supplied.strip()
    if not token or not token.isascii() or any(not 33 <= ord(ch) <= 126 for ch in token):
        raise ExecutionError(f"{TOKEN_ENV} is empty or invalid")
    return token


def scan_binary(supplied, workspace, environment):
    if supplied is not None:
        return supplied.resolve()
    completed = process(
        ["cargo", "build", "--locked", "-p", "githits-scan", "--bin", "githits-scan",
         "--message-format=json"],
        workspace,
        without_token(environment),
        "Locked Scan build",
    )
    if completed.returncode:
        raise ExecutionError("Locked Scan build failed. Run cargo build --locked -p githits-scan for details")
    try:
        for line in completed.stdout.splitlines():
            message = json.loads(line)
            if (
                message.get("reason") == "compiler-artifact"
                and message["target"]["name"] == "githits-scan"
                and "bin" in message["target"]["kind"]
                and message.get("executable")
            ):
                return Path(message["executable"]).resolve()
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        raise ExecutionError("Could not read the Scan build result from Cargo") from error
    raise ExecutionError("Cargo did not report an executable for githits-scan")


def scan_json(binary, arguments, root, environment, context, allowed_exits, token=None):
    child_env = without_token(environment)
    if token is not None:
        child_env[TOKEN_ENV] = token
    result = process([binary, *arguments, "--quiet", "--no-color"], root, child_env, context)
    if token is not None:
        for candidate in {token.encode(), json.dumps(token)[1:-1].encode()}:
            if candidate in result.stdout or candidate in result.stderr:
                raise ExecutionError(f"{context} returned credential material. Output withheld")
    if result.returncode not in allowed_exits:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        suffix = f"\n{detail}" if detail else ""
        raise ExecutionError(f"{context} failed with Scan exit {result.returncode}{suffix}")
    try:
        document = json.loads(result.stdout)
    except ValueError as error:
        raise ExecutionError(f"{context} did not return JSON") from error
    if not isinstance(document, dict):
        raise ExecutionError(f"{context} did not return a JSON object")
    return result.returncode, document, result.stdout


def detect(binary, fixture, root, environment):
    context = f"{fixture['id']} detect"
    code, document, _ = scan_json(binary, ["detect", "--json", str(root)], root, environment,
                                  context, (0, 1))
    if document.get("schema_version") != 2:
        raise reports.BadReport(f"{context}: expected report schema 2")
    if code == 1 or document.get("upload_error") is not None:
        raise reports.Regression(f"{context}: Scan could not select the expected fixture inputs")
    upload_paths = reports.strings(document, "upload_paths")
    if sorted(upload_paths) != sorted(fixture["upload_paths"]):
        raise reports.Regression(
            f"{fixture['id']} selected {sorted(upload_paths)}, expected {sorted(fixture['upload_paths'])}"
        )


def observe_fixture(binary, fixture, root, environment, workspace):
    checks = fixture["checks"]
    snapshot = {}
    sbom = None
    for name, command in COMMANDS.items():
        if name not in checks:
            continue
        context = f"{fixture['id']} {' '.join(command)}"
        if name == "license_policy":
            config = root.parent / "deny-all.toml"
            config.write_text("version = 1\n[licenses]\nallow = []\n", encoding="utf-8")
            document_path = root.parent / "generated.cdx.json"
            document_path.write_bytes(sbom)
            arguments = [*command, "--sbom", str(document_path), "--config", str(config), "--json"]
        elif name == "sbom":
            arguments = [*command, str(root), "--format", "cyclonedx"]
        else:
            arguments = [*command, str(root), "--json"]
        code, document, raw = scan_json(
            binary, arguments, root, environment, context,
            (0, 1) if name in ("audit", "license_policy") else (0,),
            acquire_token(environment, workspace) if name in ONLINE else None,
        )
        try:
            snapshot[name] = reports.project(name, document, code, checks[name])
        except (reports.BadReport, reports.Regression) as error:
            raise type(error)(f"{context}: {error}") from error
        if name == "sbom" and "license_policy" in checks:
            sbom = raw
    return snapshot


def baseline_at(path, checks, creating):
    if creating and not path.exists():
        return {}
    baseline = read_object(path)
    if (
        not isinstance(baseline, dict)
        or not baseline
        or not baseline.keys() <= COMMANDS.keys()
        or (not creating and baseline.keys() != checks.keys())
        or any(not isinstance(facts, dict) or facts.keys() != {"stable", "observations"}
               for facts in baseline.values())
    ):
        raise UsageError(f"Invalid baseline at {path.name}. Run refresh to record changed checks")
    return baseline


def json_lines(value):
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def compare(fixture_id, before, after, creating):
    different = False
    for name in sorted(after.keys() | before.keys()):
        for kind in ("stable", "observations"):
            old = before.get(name, {}).get(kind)
            new = after.get(name, {}).get(kind)
            if old == new:
                continue
            if kind == "stable":
                different = True
            label = f"{fixture_id} {name} {kind}"
            print(f"{label} changed")
            if old is None and creating:
                continue
            print("".join(difflib.unified_diff(
                json_lines(old).splitlines(keepends=True),
                json_lines(new).splitlines(keepends=True),
                f"{label} baseline", f"{label} current",
            )), end="")
    return different


def write_baseline(path, contents):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                     dir=path.parent, delete=False) as staged:
        staged_path = Path(staged.name)
        try:
            staged.write(contents)
            staged.close()
            staged_path.replace(path)
        finally:
            staged_path.unlink(missing_ok=True)


def execute(options, workspace=ROOT, fixtures_path=FIXTURES, environment=None):
    if environment is None:
        environment = os.environ
    selected = select_fixtures(fixtures_path / "fixtures.json", getattr(options, "fixture", None))
    jobs = sum(len(fixture["checks"].keys() & set(ONLINE)) for fixture in selected)
    if options.command == "list":
        for fixture in selected:
            print(f"{fixture['id']}  {', '.join(fixture['checks'])}")
        print(f"{len(selected)} fixtures, {jobs} planned API jobs.")
        return 0

    creating = options.command == "refresh"
    baseline_dir = fixtures_path / "baselines"
    baselines = {
        fixture["id"]: baseline_at(baseline_dir / f"{fixture['id']}.json", fixture["checks"], creating)
        for fixture in selected
    }
    check_count = sum(len(fixture["checks"]) for fixture in selected)
    print(f"{options.command}: {', '.join(baselines)}. {check_count} checks, {jobs} planned API jobs.",
          flush=True)
    binary = scan_binary(options.binary, workspace, environment)
    snapshots = {}
    with tempfile.TemporaryDirectory(prefix="scan-live-fixtures-") as temp:
        for fixture in selected:
            root = Path(temp) / fixture["id"]
            stage_inputs(fixture, root, workspace)
            detect(binary, fixture, root, environment)
        for fixture in selected:
            fixture_id = fixture["id"]
            print(f"Running {fixture_id}", flush=True)
            snapshots[fixture_id] = observe_fixture(
                binary, fixture, Path(temp) / fixture_id, environment, workspace
            )

    changed = False
    for fixture_id, snapshot in snapshots.items():
        changed |= compare(fixture_id, baselines[fixture_id], snapshot, creating)
    if creating:
        baseline_dir.mkdir(parents=True, exist_ok=True)
        for fixture_id, snapshot in snapshots.items():
            write_baseline(baseline_dir / f"{fixture_id}.json", json_lines(snapshot))
        print(f"Refreshed {len(snapshots)} baselines. Review their git diff before committing.")
        return 0
    if changed:
        print("Stable evidence changed. Review the differences before refreshing a baseline.")
        return 1
    print(f"Checked {len(snapshots)} fixtures.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="Show fixture IDs and checks without contacting the API")
    for command, help_text in (
        ("check", "Verify fixtures against their baselines"),
        ("refresh", "Verify authored expectations and update selected baselines"),
    ):
        subparser = commands.add_parser(command, help=help_text)
        subparser.add_argument("--fixture", metavar="ID", help="Run one fixture. Default is all.")
        subparser.add_argument("--binary", type=Path, metavar="PATH", help="Use an existing Scan binary")
    try:
        return execute(parser.parse_args(argv))
    except (UsageError, ExecutionError, reports.BadReport, reports.Regression) as error:
        print(error, file=sys.stderr)
        return error.exit_code
    except OSError as error:
        print(f"Fixture runner could not access a file ({type(error).__name__})", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
