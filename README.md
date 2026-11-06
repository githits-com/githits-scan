<h1 align="center">githits-scan</h1>

<p align="center">
  Generate an SBOM, report licenses, audit dependencies, and enforce a license
  policy from your repository's lockfiles, using the GitHits public API.
</p>

<p align="center">
  <a href="https://github.com/githits-com/githits-scan/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/githits-com/githits-scan/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/githits-com/githits-scan/blob/main/LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <a href="https://docs.githits.com/api/overview"><img alt="GitHits API" src="https://img.shields.io/badge/GitHits-public%20API-5C4EE5"></a>
</p>

<p align="center">
  <a href="https://githits.com">Website</a> ·
  <a href="https://docs.githits.com/api/overview">API documentation</a> ·
  <a href="https://github.com/githits-com/githits-scan/issues">Issues</a>
</p>

`githits-scan` discovers package files in a repository and uses the
[GitHits public API](https://docs.githits.com/api/overview) to:

- generate a CycloneDX 1.7, SPDX 2.3 tag-value, or text SBOM;
- audit vulnerabilities, deprecated releases, outdated and duplicate versions,
  and manifest/lockfile disagreements;
- report license evidence or check it against an explicit license policy.

The service parses and resolves dependencies. The Rust client selects files,
checks upload limits, and writes reports. Local discovery and saved-report replay
work without a token or network access.

> [!WARNING]
> **Alpha.** Commands and JSON can change before 1.0. Scan uses the experimental
> lockfile-jobs API, and the [v1 API contract](https://docs.githits.com/api/versioning)
> is not finalized. Pin a released version in CI and review its migration notes.

## Quick start

1. Install from [crates.io](https://crates.io/crates/githits-scan) with Rust 1.99 or newer:

   ```bash
   cargo install githits-scan --locked
   ```

   For pinned installations and prebuilt binaries, see [Installation](#installation).

2. Sign in or create an account at [app.githits.com](https://app.githits.com),
   then create an API token in [Settings → Tokens](https://app.githits.com/settings/tokens).
   See the official [API authentication instructions](https://docs.githits.com/api/authentication).
   In **Bash**, read the token without putting it in shell history:

   ```bash
   printf 'GitHits API token: '
   read -r -s GITHITS_API_TOKEN
   printf '\n'
   export GITHITS_API_TOKEN
   ```

   Keep shell tracing (`set -x`) off. In CI, inject the variable from a secret
   store. Scan reads tokens only from `GITHITS_API_TOKEN`.

3. Run these commands in the repository you want to scan:

   ```bash
   githits-scan detect                         # local inventory, no token needed
   githits-scan sbom generate -o bom.cdx.json  # upload selected package files
   githits-scan audit                          # findings or incomplete checks exit 1
   githits-scan license report                 # informational, no policy needed
   ```

## Privacy and uploaded data

Upload commands send the **full contents** of selected lockfiles and manifests,
with their paths relative to the scan root. Package files can contain private
package names, registry URLs, and other sensitive values; Scan does not redact
file contents. Review the selection and the files before uploading.

Requests carry `Authorization: Bearer …`, `User-Agent: githits-scan/<version>`,
`X-GitHits-Client-Name: githits-scan`, and
`X-GitHits-Client-Version: <version>`. Scan has no telemetry or analytics reporting.
Its HTTP requests submit jobs, receive progress, and retrieve results from the
configured API origin. It does not upload source files outside the package-file
catalog, Git history, or the Scan configuration file.

`detect` lists candidates and configured selections and reads selected
package-file contents locally to preview the upload. It uses the same preparation
path as upload commands, including eligible Cargo/npm workspace member expansion.

`detect`, `audit --from-analysis`, `license report --from-report`, and
`license check --sbom` do not contact the API. Saved reports contain dependency
evidence and paths; review them before sharing.

For how GitHits processes submitted data, read the
[Privacy Policy](https://githits.com/privacy) and
[Terms of Service](https://githits.com/legal/terms-of-service/).

## Supported package files

Recognition is by exact filename and case. Renaming an unsupported file does not
make its format supported. Owning manifests are included when present.

| Ecosystem | Lockfiles | Owning manifest / manifest-only input |
| --- | --- | --- |
| Rust | `Cargo.lock` | `Cargo.toml` |
| JavaScript (npm, pnpm, Yarn, Bun) | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, text `bun.lock` | `package.json` |
| Python (uv, Poetry, PDM) | `uv.lock`, `poetry.lock`, `pdm.lock` | `pyproject.toml` |
| Python (Pipenv) | `Pipfile.lock` | No paired manifest |
| Swift | `Package.resolved` | `Package.swift` |
| Gradle | `gradle.lockfile`, `buildscript-gradle.lockfile`, `settings-gradle.lockfile`, `gradle/dependency-locks/*.lockfile` | `build.gradle` or `build.gradle.kts` only as manifest-only or explicitly configured evidence |
| .NET / NuGet | `packages.lock.json` | The only `.csproj` in its directory; several make the lockfile ambiguous |
| Dart / Flutter | `pubspec.lock` | `pubspec.yaml` |
| PHP / Composer | `composer.lock` | `composer.json` |
| Elixir / Mix | `mix.lock` | `mix.exs` |
| Ruby / Bundler | `Gemfile.lock`, `gems.locked` | `Gemfile` pairs only with `Gemfile.lock` |
| Erlang / Rebar3 | `rebar.lock` | `rebar.config` |
| C/C++ / Conan | `conan.lock` | No paired manifest |
| Go dep (legacy) | `Gopkg.lock` | No paired manifest |
| Go modules | None | `go.mod` |
| C/C++ / vcpkg | None | `vcpkg.json` |
| Zig | None | `build.zig.zon` |

Manifest-only projects are included by default. The service resolves declared
constraints, so the result can differ from an installed or previously locked
build. Resolution and audit coverage vary by ecosystem; incomplete evidence
remains visible. `--lockfiles-only` skips unconfigured manifest-only projects,
while retaining owning companions and eligible Cargo/npm workspace members.
See the [catalog](docs/implementation/package-file-catalog.md) and
[selection rules](docs/implementation/discovery.md).

| Unsupported input | Alternative / limitation |
| --- | --- |
| Python `requirements.txt`, `constraints.txt`, `setup.py`, `setup.cfg` | Use a supported lockfile or `pyproject.toml` |
| Deno `deno.lock` | No native Deno input support |
| Maven `pom.xml` | No native Maven input support |
| Binary Bun `bun.lockb` | Use text `bun.lock` |
| Go `go.sum`, `go.work` | Scan selects `go.mod`; these files are not uploaded |
| CocoaPods `Podfile.lock`, Nix `flake.lock`, NuGet `packages.config` / `project.assets.json` | Not cataloged |

Notices identify `requirements.txt`, `deno.lock`, and `pom.xml`. Other omitted
formats are listed in the [catalog](docs/implementation/package-file-catalog.md#deliberate-omissions).

Discovery honors Git ignore rules and skips hidden entries, symbolic links, and
installed-dependency directories such as `node_modules` and `vendor`. Fixture
directories are excluded by default. Ordinary test, eval, and `truth` directories
remain eligible; review the inventory for your repository. See
[discovery](docs/implementation/discovery.md) for exclusions and explicit selection.

Directory patterns ending in `/**`, such as `--exclude 'locked/**'`, prune
matching subtrees before reading their contents. Configuration inclusions preserve
needed ancestors; CLI exclusions always win. Unreadable non-excluded directories
stop the scan with exit 3 and permissions/repository-relative `--exclude` guidance,
so incomplete discovery cannot look like a complete audit.

## Commands

Run `githits-scan <command> --help` for the current flags. Commands accept
`-o/--output FILE` (`-` means stdout), `-q/--quiet`, and `--no-color`.
Quiet suppresses routine progress and success messages; reports, findings,
warnings, and errors remain. Diagnostics go to stderr; reports go to stdout or
the output file. Existing output files are overwritten.

### Discovery and SBOMs

```bash
githits-scan detect
githits-scan detect --json -o inventory.json
githits-scan sbom generate -o bom.cdx.json             # CycloneDX 1.7 JSON
githits-scan sbom generate --format spdx -o bom.spdx   # SPDX 2.3 tag-value
githits-scan sbom generate --format text              # text on stdout
```

`detect` reads selected package files locally through the same bounded preparation
as upload commands, including declared Cargo/npm workspace members. It separates
selected files from unselected candidates and counts discovered exclusions
separately. Pruned subtrees have unknown file counts and are shown as patterns.
Test-looking suggestions show at most ten paths; JSON retains the complete list.
No token or network is needed. No selected evidence exits 1.

`detect --json` uses schema 2; `upload_paths` is the exact locally prepared
selection. When preparation is blocked, the inventory remains available with
null `upload_paths` and `upload_error`, followed by the normal usage (2) or I/O (3)
exit. See [JSON contracts](docs/implementation/json-output.md).
SBOM generation submits one job and writes the complete returned document.

### Dependency audits

```bash
githits-scan audit
githits-scan audit --json -o audit.json
githits-scan audit --save-analysis analysis.json
githits-scan audit --from-analysis analysis.json     # offline replay
```

Any audit finding or incomplete check exits 1. A clean audit covers only the
selected evidence, not proof of an installed build's safety. JSON and saved
analyses retain findings independently of human presentation. Scan proposes
changes when the service supplies them; it does not edit dependencies.
See [audit design](docs/implementation/audit.md) for evidence and replay semantics.

### License reports and policy checks

```bash
githits-scan license report
githits-scan license report --json -o licenses.json
githits-scan license report --from-report licenses.json  # offline replay
```

License reporting needs no policy. Exit 0 means a report was produced, even with
unknown or incomplete evidence. JSON is the compact experimental service report
(schema 2); offline replay accepts saved schemas 1 and 2 and preserves exact JSON
bytes. Reported licenses, publisher context, source
observations, and coverage gaps remain distinct.

To enforce a policy, first run `githits-scan detect --save`, then enable or edit
`[licenses]` in the generated `githits-scan.toml`:

```toml
[licenses]
allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-3-Clause", "ISC"]
```

```bash
githits-scan license check
githits-scan license check --sbom bom.cdx.json         # offline, still needs policy
githits-scan license check --sbom bom.cdx.json --json  # policy verdict
```

Use explicit SPDX identifiers and `AND`/`OR`/`WITH` expressions. Missing or
unrecognized licenses, policy violations, and unresolved projects are findings.
Project-root and local-source markers exclude their own nodes, not their children;
a local path alone does not prove first-party ownership. See
[license policy](docs/implementation/license-check.md) for scope and exceptions.

Checks warn on stderr when no components were evaluated or dependency resolution
is incomplete. Offline SBOMs without `githits:completeness` also warn that inventory
completeness is unknown. Warnings remain visible with `--quiet` and `--json`;
they leave the verdict and exit code unchanged.

| Document | Produced by | Replay / use |
| --- | --- | --- |
| Experimental license evidence JSON | `license report --json` | `license report --from-report FILE` |
| CycloneDX JSON SBOM | `sbom generate` | `license check --sbom FILE` |
| Policy verdict JSON | `license check --json` | Automation; not a replay input |
| Saved audit analysis | `audit --save-analysis FILE` | `audit --from-analysis FILE` |
| Compact audit JSON | `audit --json` | Automation; not a saved analysis |

## Configuration

Without configuration, upload commands select discovered lockfiles and
manifest-only projects. Record a reviewed inventory with:

```bash
githits-scan detect --save
git add githits-scan.toml
```

Example configuration (replace the paths with your own):

```toml
version = 1

[lockfiles]
include = ["Cargo.lock", "web/package-lock.json"]
exclude = ["examples/**"]
manifests = ["services/legacy/package.json"]
```

With a configuration, new or missing projects are **drift**: commands exit 1,
and upload commands stop before any request. `--no-check` permits scanning the
configured selection despite drift. It does not disable license policy or audit
findings. Run `detect --save` after reviewing inventory changes; it preserves
license policy, comments, and existing excludes.

`--config FILE` selects a configuration; its paths stay relative to the scan root.
`detect --config FILE --save` creates a missing file from the same commented
template as plain `detect --save`, including excludes and a license-policy example.
Existing files retain comments and policy. Unknown keys, invalid versions, and
other missing explicit configurations are errors.

`--exclude GLOB` omits matching package files, including owning and workspace
manifests. With `detect --save`, the pattern is persisted; existing configured
inclusion overrides remain unless the CLI excludes them. See
[configuration](docs/implementation/configuration.md) for the schema and precedence.

## Use in CI

| Exit | Meaning | Action |
| --- | --- | --- |
| 0 | Success; checks have no findings; license reports are informational | Continue |
| 1 | Findings, incomplete audit, inventory drift, violations, unresolved license projects, or nothing selected | Review the repository or selection |
| 2 | Invalid invocation/configuration/input, upload limits, missing/rejected token, or account access | Correct the diagnostic's cause |
| 3 | Network, I/O, rate limit, service, or protocol failure | Investigate; respect `Retry-After` before a deliberate retry |

This complete GitHub Actions workflow runs on pushes and manual dispatch. It
requires a reviewed `githits-scan.toml` with a `[licenses]` policy and a repository
secret named `GITHITS_API_TOKEN`. It installs version `0.3.0` from crates.io.
Save as `.github/workflows/dependencies.yml`:

```yaml
name: Dependency checks
on: [push, workflow_dispatch]
permissions:
  contents: read
jobs:
  sbom:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@683b588c487a69d01f6c6ddf40f036ff682cc2c8 # master
        with:
          toolchain: 1.99.1
      - name: Install githits-scan
        run: cargo install githits-scan --locked --version 0.3.0
      - name: Generate the SBOM (fails on inventory drift)
        env:
          GITHITS_API_TOKEN: ${{ secrets.GITHITS_API_TOKEN }}
        run: githits-scan sbom generate --output bom.cdx.json
      - name: Enforce the license policy on the same document
        run: githits-scan license check --sbom bom.cdx.json
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: sbom
          path: bom.cdx.json
          if-no-files-found: error
```

Keep secrets out of untrusted fork jobs. Do not use `pull_request_target` to run
untrusted code with a token. A scan is remote work; do not automatically resubmit
failed jobs in a retry loop.

## Installation

**Cargo (crates.io):** Rust 1.99 or newer is required:

```bash
cargo install githits-scan --locked
```

For a pinned installation, including CI, specify the release version:

```bash
cargo install githits-scan --locked --version 0.3.0
```

**Prebuilt binaries:** the [release workflow](docs/implementation/release-process.md)
builds archives for Linux x86_64/ARM64, macOS Intel/Apple Silicon, and Windows
x86_64, with `SHA256SUMS`. Download the archive for your platform and the checksum
file from the same [GitHub release](https://github.com/githits-com/githits-scan/releases).
Verify it before extracting. In a directory containing those two downloads:

```bash
sha256sum --check --ignore-missing SHA256SUMS  # Linux
shasum -a 256 --check --ignore-missing SHA256SUMS  # macOS
```

Verify that your downloaded archive is marked `OK`. On Windows, use `Get-FileHash -Algorithm
SHA256` on the downloaded ZIP and compare it with the matching `SHA256SUMS` entry.
Extract the verified archive and put the executable in a directory on `PATH`.
Build baselines are Ubuntu 24.04, macOS 15, and Windows Server 2025; older systems
are not tested.

**From a checkout:** Rust 1.99 or newer is required. In the repository checkout:

```bash
cargo install --path . --locked
```

### Uninstall

For a Cargo installation:

```bash
cargo uninstall githits-scan
```

For an extracted binary, remove the executable you put on `PATH`. Scan has no
daemon or installed background service. Uninstalling does not remove generated
reports or repository configuration. Remove those separately if desired, unset
`GITHITS_API_TOKEN` in your shell/CI configuration, and revoke an unused token in
[GitHits token settings](https://app.githits.com/settings/tokens).

## Authentication and environment

| Variable | Purpose | Default |
| --- | --- | --- |
| `GITHITS_API_TOKEN` | Bearer token; required by upload commands | None |
| `GITHITS_API_URL` | API origin override (HTTPS; HTTP only for loopback) | `https://api.githits.dev` |
| `NO_COLOR` | Disable color when nonempty; also `--no-color` | Color only on a terminal |

Scan never invokes credential commands. If you use the GitHits CLI, see its
[authentication guide](https://docs.githits.com/api/authentication) for login.
A Bash helper can capture its signed-in production token, fail closed, and pass
it only to the Scan child without printing or saving it:

```bash
scan_with_cli_token() (
  set +x
  unset GITHITS_API_TOKEN
  scan_token="$(GITHITS_ENV=prod npx -y githits@latest auth token)" || return
  [ -n "$scan_token" ] || return 1
  GITHITS_API_TOKEN="$scan_token" GITHITS_API_URL=https://api.githits.dev githits-scan "$@"
)
scan_with_cli_token audit
```

The CLI login environment must match Scan's origin. `GITHITS_ENV` selects the
CLI login namespace; it does not change Scan's origin. The helper above explicitly
uses production. Keep token acquisition output out of logs, files, and arguments.
See [SECURITY.md](SECURITY.md) for credential and transport safeguards.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Missing or rejected token (exit 2) | Set `GITHITS_API_TOKEN` in the process running Scan. Create or replace it in [token settings](https://app.githits.com/settings/tokens). Verify that token and API origin match; never paste the token into an issue. |
| Access denied / terms required (exit 2) | Sign in at [app.githits.com](https://app.githits.com) and follow the diagnostic's account, feature-access, or terms action. Retrying cannot grant access. |
| Upload too large (exit 2) | Limits: 256 files, 5,242,880 bytes per file, 8,000,000 bytes including multipart framing. Scan a smaller root or explicitly exclude unrelated projects; workspace member manifests count too. See [selection rules](docs/implementation/discovery.md). |
| Unsupported file or `UNUSABLE_MANIFEST` (exit 2 for rejected input) | Check the catalog, actual format, and diagnostic's file paths. Scan does not convert formats. A selected unusable file rejects the whole upload; exclude only evidence you intend to omit. |
| Inventory drift / nothing selected (exit 1) | Review `detect`, configuration, ignore rules, and the scan root. Save a changed inventory only after reviewing it. |
| Proxy, TLS, timeout, or connection failure (exit 3) | Check connectivity to the configured origin and your proxy settings. Proxies must permit authenticated HTTPS and streaming progress responses. Redirects are refused. Do not disable TLS checks. |
| Rate limit or service failure (exit 3) | Keep the request ID and follow `Retry-After` when supplied. Re-running submits a new job; submission/result requests are not retried automatically. |
| Permission denied / unreadable file or output (usually exit 3) | Ensure the scan root and selected files are readable and the output directory is writable. A missing input/configuration instead exits 2. Fix access or selection rather than running Scan as administrator. |

Connections have a 15-second establishment timeout. Submission/result headers
and individual body reads have a 210-second allowance; event reads use 60 seconds. An established progress
stream may reconnect, without resubmitting the job.

For bug reports, include `githits-scan --version`, OS, the command, exit code,
and redacted stderr. Inventory and reports can reveal private paths and package
names; review them before attaching. Report security concerns privately via
[SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
[Implementation docs](docs/implementation/README.md) describe client contracts
and design.

## License

Apache-2.0. See [LICENSE](LICENSE).
