# Command Model

## Purpose

This document records the contract every command shares: the audiences it serves, the command surface, the configuration file, exit codes, and output conventions. Per-command details live in `discovery.md`, `sbom-generate.md`, `configuration.md`, `license-check.md`, `license-report.md`, `audit.md`, and `dependency-diff.md`; this page is what ties them together and what a new command must fit.

## Two Audiences, One Model

- **Individual developers** exploring a repository run `detect`, `sbom generate`, `license report` or `audit` with no configuration and get a readable answer.
- **Pipelines** guarding an organization run the same command against a reviewed configuration and get a deterministic pass/fail plus structured JSON.

`detect`, `sbom generate`, `license report` and `audit` work without configuration and become strict when `githits-scan.toml` exists. `license check` requires a configuration file with a `[licenses]` policy. Nothing is uploaded or accepted silently: manifest-only resolution, selected audit manifests, blocked scans, and license exceptions are explicit and visible in output. Audit describes selected scope rather than listing every deliberately omitted file.

## Commands

| Command | Purpose | Network |
| --- | --- | --- |
| `githits-scan detect [PATH]` | List every lockfile and its owning manifest, nested and uncombined manifests, ambiguous lockfiles, manifest-only projects, and, with a configuration, each entry's status | No |
| `githits-scan sbom generate [PATH]` | Upload the inventory and write the SBOM document | One submission, events and result reads |
| `githits-scan license report [PATH]` | Package/license rows, with `--details` for observations, attribution and coverage; `--from-report FILE` replays saved JSON | One submission, events and licenses-view read; none for saved replay |
| `githits-scan license check [PATH]` | Generate (or read with `--sbom`) a CycloneDX document and evaluate the component inventory and nested assemblies against explicit policy; root/local markers exclude their own nodes | One submission plus reads, or none with `--sbom` |
| `githits-scan audit [PATH]` | Audit vulnerabilities, native lifecycle warnings, outdated and duplicate versions, preserving genuine evidence gaps | One submission, events and result reads |
| `githits-scan audit --from-analysis FILE [--explain PACKAGE]` | Re-display a saved audit or inspect recorded requests for an exact vulnerable coordinate | None; no token or repository/config reads |
| `githits-scan diff [PATH] --base REF [--head REF]` | Experimental repository dependency/advisory comparison; `--format human|json|markdown` | One paired diff submission, events and result reads, including identical/empty inputs |

The experimental `diff` command ignores configuration, requires a Git root and
uses explicit exclusions/manifest flags. It returns 0 for a completed informational
report, including unavailable sections or unfamiliar evidence, with independent
producer statuses and coverage. Required core and output failures retain the usual 2/3
classification. It is not a policy check. Diff also accepts `--output-json PATH` and
`--output-markdown PATH` together or separately instead of `--format`/`--output`.
Named outputs emit only requested documents; at most one may be `-` for stdout.
Both consume the same report, with JSON written first. Conflicting destinations
fail before submission where locally detectable; write failures exit 3 and leave
previously completed output intact. See [dependency diff](dependency-diff.md#output-destinations).

### Shared arguments

| Argument | Meaning |
| --- | --- |
| `PATH` | Scan root; defaults to `.`; must be a directory. Every reported path is relative to it with forward slashes |
| `--config <FILE>` | Configuration file; defaults to `<PATH>/githits-scan.toml`. An explicitly selected file must exist unless `detect --save` creates it; implicit default discovery is optional except for `license check`, which requires a policy. Paths inside the file are relative to `PATH` regardless of where the file lives |
| `--no-check` | Report inventory drift without failing on drift itself. Empty selection still exits 1. Never the default |
| `--json` | JSON on stdout or `--output` instead of the human report (`detect`, `license report`, `license check`, `audit`); audit emits focused findings and incomplete checks |
| `-q`, `--quiet` | Suppress routine progress and success messages (all commands); reports/documents, errors, actionable warnings and blocked-scan diagnostics are preserved |
| `--no-color` | Disable color; `NO_COLOR` is honored too. Color never carries meaning |
| `--lockfiles-only` | Leave manifest-only projects out of the inventory (`detect`) and the upload (`sbom generate`, `license report`, `license check`, `audit`, `diff`); by default they are part of both and resolved from their declared constraints |
| `--exclude <GLOB>` | Omit matching package files, including owning/workspace manifests; patterns ending in `/**` prune subtrees (repeatable; same glob rules as `lockfiles.exclude`). `detect --save` merges the patterns into the configuration. Conflicts with `license check --sbom` |

All commands accept `-o/--output FILE` (`-` means stdout). `license check --details` adds component references, package URLs and bounded
recorded Git-source previews; JSON retains full selector values. Detect quiet suppresses save notes, preserving the inventory.

Per-command arguments: `license report --details`, `license report --from-report FILE` and `-o/--output FILE` (human or exact public JSON with `--json`); `detect --save`; `sbom generate --format <cyclonedx|spdx|text>` and `-o, --output <FILE>`; `license check --sbom <FILE>`; `audit -o/--output <FILE>` (human by default, compact result JSON with `--json`);
`audit --details` (expand maintenance lists in ordinary human reports, including saved replay);
`audit --save-analysis FILE`; `audit --from-analysis FILE [--explain PACKAGE]`.
`--save-analysis` conflicts with `--output`; saved replay accepts `--output`, including explanations.
Offline mode rejects scan-selection arguments and requires no token.

## Configuration File

`githits-scan.toml` at the scan root, one file so a pipeline reviews one thing. Unknown keys and unsupported versions are errors (exit 2) so a typo cannot silently widen policy. `detect --save` creates and maintains the inventory lists; `exclude` and `[licenses]` are written by hand and survive a save byte for byte. The schema and evaluation rules are in `configuration.md`.

Strictness:

| State | `detect` | `sbom generate` / `license report` / `license check` / `audit` |
| --- | --- | --- |
| No configuration | Report everything; exit 1 only if the inventory is empty | Upload everything detected, including manifest-only projects unless `--lockfiles-only` |
| Configuration, inventory matches | Report with statuses; exit 0 | Upload `include` plus `manifests` |
| Configuration, unlisted or missing entry | Exit 1 naming each drifted path | Exit 1 before any request, same message |
| Configuration with `--no-check` | Report drift; exit 0 if evidence remains selected, otherwise 1 | Upload `include` plus `manifests`, ignore drift |

## Exit Codes

Pipelines need to tell "the repository failed policy" from "the tool or service failed" so they can block a merge in one case and retry a job in the other.

| Code | Meaning | Examples |
| --- | --- | --- |
| 0 | Success; for checks, no unignored findings or blocking gaps | SBOM written; inventory matches; no license violations |
| 1 | Findings | Empty inventory; inventory drift; license violations; audit findings other than explicitly ignored advisories; unassessed evidence |
| 2 | Usage or configuration error | Unknown flag (clap); invalid configuration or unknown key; missing token or insecure origin; upload limits exceeded; non-UTF-8 upload content or paths; missing or invalid `[licenses]` policy; a missing selected input or non-CycloneDX `--sbom`; caller-action HTTP 4xx failures (except 408/429) |
| 3 | Execution error | Unreadable tree; network failure; rate limits, service/API protocol failures; output/config file cannot be written (including a missing parent directory) |

Authentication failures name the rejected token without displaying it; access-denied problems preserve account/terms actions. HTTP 405 remains a caller/configuration error (2), with an API-origin/proxy hint.
Transport/read timeouts retain execution exit 3 and name `GITHITS_API_URL`, network
connectivity and proxy settings without displaying environment values. HTTP 408/429 and 5xx remain execution errors. A remote body that breaches the advertised client response cap is a service/protocol execution error (3); this differs from a typed output-size rejection requiring narrower input (2). An `ANALYSIS_FAILED` problem uses its terminal failure code: unsupported output format, no package evidence and oversized output require caller action (2); other or absent failure codes mean execution failure (3).

The constants live in `src/cli.rs`; command handlers return an `Outcome` or a typed `Error` with an `ErrorKind`, and only `src/cli.rs` maps those to numbers.

## Output Conventions

- Documents and reports (all commands) go to stdout or `--output`; every diagnostic goes to stderr; the two are never mixed.
- Human reports lead with the outcome in one line, then command-specific tables or grouped sections. They include actionable findings, file locations and relevant omissions or incomplete checks.
- Tool-owned JSON reports (`detect`, `license check`, `audit`) carry `schema_version` (detect/audit: 2; license check: 1) and are emitted on success or findings (exit 0 or 1); detect also preserves the inventory on upload-preparation failure (exit 2/3), with null `upload_paths` and `upload_error`. Errors go to stderr as text. Fields are `snake_case`. Additive changes keep the version; removals or renames bump it and get a `changes/` fragment with `major` impact after 1.0.
- `license report --json` emits the exact public experimental license report (online schema 2; saved schemas 1 and 2), preserving full evidence and unknown additive fields. Its version belongs to the API, not a Scan wrapper. Saved replay is token-free and rejects scan-selection flags. Partial or unknown evidence still exits 0; this is informational, not policy enforcement.
- Audit JSON contains actionable findings, unique source-file paths, selected manifests, recorded duplicate origins, meaningful incomplete checks and optional mitigation proposals with blockers, independent checks and omission limits. Internal API IDs, input/graph inventories and parser/search counters are not output. Only producer audit schema 3 is accepted. Any other version fails with exit 3 and no report or automatic resubmission; Scan's JSON version is independent of the producer's version. Structural errors produce no report. See `audit.md`.
- Audit lists the manifest files selected for upload. When the report supplies manifest-resolution evidence, that is named separately; absent evidence is never inferred. Deliberately omitted files are not dumped. SBOM generation retains its upload summary unless `--quiet` is used.

See [JSON output contracts](json-output.md) for command-specific fields.

## Ownership Summary

| Concept | Owner |
| --- | --- |
| File names and ecosystems | `catalog` |
| Walking, pairing lockfiles with manifests, nested and manifest-only detection, file reads | `discover` |
| Configuration schema, inventory statuses, drift computation, saving | `config`; drift is computed once and consumed by every command |
| API limits, request, problem parsing | `api` |
| Licenses wire decoding and exact JSON retention | `api::licenses` |
| Informational license presentation | `commands::license::report` |
| Audit wire decoding and producer version | `api::audit` |
| Compact audit result projection and human/JSON presentation | `commands::audit` |
| Audit evidence projections, accounting, duplicate groups, explicit advisory-ignore enforcement and consumed recommendation references | `audit`, pure; no advisory/upgrade assessment |
| Token and origin | `env` |
| SPDX expression evaluation and policy decisions | `license`, pure over a parsed document |
| Human rendering, JSON rendering, outcome and error kinds | `commands`; one module per command |
| Exit-code mapping | `cli` |

## Deliberate Non-Goals

- SARIF output and GitHub Actions annotations: follow-ups once JSON is stable.
- Version-pinned registry license exceptions: PURLs remain package-wide. Named
  Git-source exceptions can pin an exact recorded revision.
- A cache of the generated SBOM for `license check`: `--sbom FILE` covers reuse.
- Splitting an oversized repository into several uploads: `PATH` scopes a scan.
