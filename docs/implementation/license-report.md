# `license report`

`githits-scan license report [PATH]` produces an informational dependency-license
inventory. It uses the same discovery, configuration, exclusions, drift gate and
bounded upload as `sbom generate`. Configuration is optional; `[licenses]` is not
required. The service owns resolution, license identification and applicability
of evidence. Shared preparation includes admitted Cargo and supported npm/Bun member manifests
under the [workspace selection rules](discovery.md#javascript-workspace-member-evidence).
Scan owns selection and presentation; `license check` continues to
evaluate a separate CycloneDX document against an explicit policy.

## API and ownership

`api::LicensesApi` is the injectable command boundary. The HTTP implementation
submits one `/v1/experimental/lockfile-jobs?kind=sbom&format=cyclonedx` job, follows
its existing events, and downloads `/v1/experimental/license-reports/{id}` after success.
The ID and all supplied job links are validated before use. The ordinary SBOM
result is not downloaded. There is no second analysis, result retry, synchronous
fallback or status polling. The synchronous public `POST /v1/experimental/license-reports`
is available to other clients but is not used by Scan.

`api::licenses` validates version-1 and version-2 envelopes and typed display
fields, retaining the original bytes for JSON. Additive fields and unfamiliar vocabulary remain
accepted. `commands::license::report` renders without policy evaluation or a
second interpretation layer. It does not combine choices, rewrite inventory, infer artifact verification,
or promote repository context to release evidence. Compact human rows may summarize
equivalent group occurrences under the presentation rules below.
The shared command-layer escaping helper keeps untrusted control characters out
of terminal text. Evidence URLs and paths are displayed, never fetched or opened.

Both remote and saved reports are capped at the API's 16,777,216-byte response
limit. Construction decodes one narrow owned view and retains it alongside the
original bytes; rendering cannot introduce a second decode failure. Unknown fields
are skipped by the typed view and remain intact in the original bytes. When
coordinates repeat, human rendering borrows raw component fragments and builds
one selected leaf candidate tree at a time, retaining canonical comparison keys
only for repeated coordinates. Combined occurrences share one group label, so
label storage grows with the supplied group text rather than its square. It does
not construct a whole-document JSON tree. If this optional pass cannot decode
ignored additive data that the typed view accepted, it retains the ordinary
per-occurrence rendering; presentation never introduces a new decode failure.
An envelope version probe chooses a narrow version-specific decoder; future
versions produce the upgrade diagnostic, while malformed known versions are
invalid. JSON output does not rebuild the document or create a
Scan-specific wrapper. This is the experimental API report, not a settled stable
JSON contract. Online reports use compact schema 2; saved schema 1 remains
accepted without rewriting. Schema 2 uses typed input paths and purpose-specific coverage,
resolution, declaration and lockfile summaries. It omits generic adjacency,
digests and duplicate property bookkeeping.

## Command and output

```sh
githits-scan license report
githits-scan license report --details
githits-scan license report services --json -o licenses.json
githits-scan license report --from-report licenses.json
```

Online options are `--config`, `--no-check`, `--lockfiles-only`, repeated `--exclude`,
`--details`, `--json`, `-o/--output` (`-` for stdout), `-q/--quiet` and `--no-color`.
`--from-report FILE` replays a saved version-1 or version-2 public license report without a
token, network access, repository discovery or configuration reads. It rejects
`-`, explicit PATH and scan-selection flags; replay writes to stdout or `--output`.
It accepts `--details`, `--json`, `--quiet` and `--no-color`. `--sbom` belongs to `license check`.

Default human output contains aligned `Package` and `License` columns with package,
optional version and reported-license rows. Human rows
are stable-sorted by name, version and supplied PURL; equal identities keep their
original relative order. JSON bytes and producer order remain unchanged.
Project/local subjects are labelled. Repeated coordinates follow the group
presentation rules below; singleton rows remain unchanged.
Supplied PURL qualifiers/subpaths distinguish variants; differing PURL bases under
the same name/version get a source-PURL line. These values are displayed as
supplied, without inference, decoding or coordinate normalization. A missing
version is omitted; an empty inventory prints only the header. Missing choices
are `not reported`; unknown choice objects are `unrecognized choice (retained in
JSON)`. Observations and contextual statements never substitute for reported
licenses.

### Repeated group occurrences

The shared `commands::license::occurrences` helper owns human grouping for both
report and check. Within repeated name/version coordinates, supplied
`context.group_conditions` (schema 2) or JSON-valued `githits:context` (schema 1
and CycloneDX) provides native group names and markers. `dev_only` never supplies
a group name. A default/develop pair can read as one row:

```text
Package                             License
requests 2.32.0 [default, develop]  MIT
```

Only leaf occurrences with exactly one explicit group/marker condition, unique
nonempty occurrence references, and distinct group names may combine. All
component evidence must match except the occurrence reference, the value of the
lock-local `githits:package_id`, and the group name. Unknown additive fields,
license choices/applicability, source/input provenance, versions, PURL
qualifiers, scope and markers remain in the comparison. Enclosing assemblies
stay distinct. Equal PURLs or equal shortened display strings are insufficient;
repeated same-group records remain separate. Multiple readable group/marker
conditions remain visible on their own row, without making that row eligible
for combination. Report context is optional: absent
or unreadable context leaves ordinary per-occurrence rows.

A shared nonempty marker appears once after the group list. Non-equivalent rows
retain their own groups/markers and input attribution. An entirely combined
report pair omits the redundant input lines. Group previews reserve at most 48
of the identity's 160 rendered scalars; shortened context adds a 240-scalar
continuation and the JSON hint. Group names containing separators are quoted.
`--details` retains individual report occurrences and their own groups, inputs
and evidence. Counts and JSON always describe the original occurrences.

Within a choice, the summary prefers the expression, then the license ID with
its name in parentheses if supplied, then a name alone. Separate choices use
semicolons; text containing a semicolon or starting with a double quote is quoted
with embedded quotes escaped. Original expressions remain unchanged in meaning;
no AND/OR relationship is inferred.

Human previews use rendered Unicode-scalar budgets: 160 for compact identity,
with up to 64 reserved for qualifiers; 80 for reported-license summaries; 240 for
detailed fields and PURL continuations. Package padding stops at 48; longer rows
use a two-space separator. Short ASCII rows align; no Unicode cell-width promise
is made. Every abbreviation is marked and full evidence remains in JSON. Long
free-text names collapse whitespace; prose wraps between words, while ordinary
URLs/paths remain atomic up to the detailed budget. Escaping happens before budget
calculation, without escaping a whole oversized string just to retain a prefix.

`--details` focuses on investigation: input files, exceptional subject kind/scope,
useful repository/license/distribution links, distinct publisher statements,
applicability and interpretation issues, source-file observations and coverage
gaps. Ordinary success metadata, opaque occurrence IDs, repeated package URLs,
raw reference comments and registry-index/homepage links are omitted. Identical
external-reference label/URL pairs are shown once per subject; different labels,
URLs and source-owner attribution remain. Routine interpretation status `absent`
and empty routine release observations are omitted; issues and unfamiliar states
remain visible.

When every statement in a publisher observation exactly matches reported choice
text, the repeated text is compressed. If any statement differs, the complete
statement list is shown so a mixed observation is never misrepresented.
Contextual or unfamiliar applicability and different supplied
versions remain explicit; this is text compression, not license equivalence or
an agreement/compliance decision. Normal controlling release metadata may be
omitted only when its text is repeated and no interpretation issue remains.
Known status, reason and issue codes use plain-language descriptions and labelled source positions. Newly recognized codes and supplied issue identifiers can improve older reports’ human details too; their original JSON is unchanged. Unfamiliar codes are labelled unrecognized evidence retained in JSON; JSON preserves original codes and offsets. Empty fields are omitted and child evidence is indented under its owner.
Reported licenses and source detections stay separate. Source module/version,
file detections, direct observation URL and latest check state remain under the
source owner, without provider/method bookkeeping or inferred versions.

Schema-2 details also show supplied inventory/classification bases, metadata and identity gaps, publisher capture
or statement-coverage limitations, independent license issues and recorded source
selectors/revisions. Routine success metadata is omitted; recorded values never
imply artifact inspection. Resolutions with gaps retain their explicit input path
and declarations from that input, labelled as requests rather than resolved packages.
Lockfile association/consistency limitations and declaration-agreement mismatches
retain their owner paths and requested/locked values. Missing version values do not
mean no lock evidence. Unknown open diagnostics remain accepted and are labelled
unrecognized evidence retained in JSON.

Coverage appears once after rows. Composition gaps identify component inventory
or dependency relationships; schema 2 also distinguishes service inventory.
Complete groups are omitted only when they supply nonempty subject references.
An explicitly empty group says no subject references were reported; missing scope
is labelled unrecognized. Neither is evidence that licenses were checked. Per-subject
coverage gaps identify the package and input paths when the reference resolves,
with unresolved references labelled explicitly. Inventory completeness is not
license coverage. The full experimental report remains available in JSON.

`--json` emits the exact accepted public report bytes, including its own
`schema_version`, full inventory and unfamiliar additive evidence. Saved-report
JSON replay is lossless. It differs from the policy result of `license check
--json`. Unsupported report versions fail before output.

Progress, upload/inventory summaries and saved-file diagnostics go to stderr.
JSON suppresses progress; quiet suppresses routine diagnostics. Nonquiet compact
human output gives one stderr pointer to `--details` for evidence/coverage and
`--json` for the complete report. Details do not affect JSON bytes. The incomplete
resolution warning for `partial_manifest_inventory` remains in JSON, quiet and
offline modes. The CLI escapes error messages and causes line by line, including third-party
ignore-file diagnostics, without flattening their intended layout or doubling
Windows backslashes. Standard Rust debug escaping also renders combining marks
and other non-printing Unicode scalars as explicit escapes in diagnostic paths.
Drift, ambiguity, skipped-manifest and upload filename fields escape line breaks.
A path supplied by the caller or embedded in a discovery failure may still span
lines when it contains a literal newline; other controls remain escaped and
exit codes are unchanged.
Human output files are plain text, buffered and explicitly flushed;
flush errors are execution failures. API/parse failures preserve an
existing destination; output I/O failures can leave a partial write.

Saved replay supports `-o/--output FILE` with the same human/JSON representation
as stdout. Repeated coordinates that remain separate include input files in
compact output; entirely combined pairs omit those redundant lines. Details
retain each occurrence's input files. Known inventory completeness values are
rendered as prose; incomplete dependency resolution emits one stderr warning,
without a repeated completeness success note. Raw evidence codes remain intact
in JSON.

## Exit contract and verification

| Exit | Meaning |
| --- | --- |
| 0 | A valid report was rendered/saved, including partial or unknown evidence; no policy verdict |
| 1 | Existing inventory drift or empty-selection gate stopped before submission |
| 2 | Arguments/configuration/token/access/origin error, caller-action API failure, or missing/invalid/unsupported saved report |
| 3 | Transport/service/rate-limit/protocol/unsupported remote version, other saved-file read failures or output I/O error |

`tests/api_licenses.rs` pins the single-job licenses-view flow, reconnect behavior,
canonical-link checks, problem codes, request IDs and download failure handling.
`tests/cli/license_report*.rs` pins binary streams, saved replay, file preservation,
flag conflicts, occurrence/evidence separation and terminal escaping. The ignored
`license_report_uses_deployed_api_and_saved_report_offline` test uses the fixed
minimist fixture for one live analysis and token-free compact/details/JSON saved
replay, preserving exact bytes. The production compact endpoint must be available
before releasing this client; the existing release live check qualifies that path. The test accepts a
nonempty `GITHITS_API_TOKEN`, including the release job's repository secret,
without requiring a CLI login or environment selector. An explicitly provided
empty or invalid-encoding token fails closed.

When that variable is absent, the explicitly invoked local test harness privately
acquires the signed-in CLI token with matching `GITHITS_ENV` and `GITHITS_API_URL`
([development authentication](../../CONTRIBUTING.md#development)), and passes it
only to the Scan child. Scan itself never acquires credentials. The nonignored
`license_report_live_harness_accepts_release_environment_without_cli_login` case
runs this exact ignored case in a child test process against a loopback API with a
provided fixture token and no login selector. It covers the release credential
contract without production access or secrets.

Run that single live check after signing into the CLI:

```sh
env -u GITHITS_API_TOKEN GITHITS_ENV=prod \
  cargo nextest run --locked --all-features --run-ignored ignored-only \
  -E 'test(=license_report_uses_deployed_api_and_saved_report_offline)'
```

The harness acquires a token only for the production origin; any other origin
needs `GITHITS_API_TOKEN` provided for it. It fails closed on mismatched
environment/origin, acquisition failure or an empty token. Credential-command output is captured privately and never logged.

## Narrow file-output measurements

The ignored `license_and_audit_file_output_benchmark` case exercises command
handlers through fixture APIs, without network or credentials. It requires
`--release`, measures the 10,000-occurrence report file and 100 audit-file runs,
and checks output identity across samples. Run only this case:

```sh
cargo nextest run --release --locked --all-features --test file_output_bench \
  --run-ignored ignored-only -E 'test(=license_and_audit_file_output_benchmark)' \
  --success-output immediate
```

Measurements and candidate comparisons belong on the PR.

Known service resolution reasons share one command-layer wording table with audit.
License policy/report JSON retains raw codes; human policy output deduplicates
translated reason labels.
