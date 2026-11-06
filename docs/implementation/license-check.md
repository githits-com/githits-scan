# `license check`

`githits-scan license check` applies the explicit `[licenses]` policy in
`githits-scan.toml` to a CycloneDX JSON component inventory. Policy construction
and evaluation belong to `src/license.rs`; the command chooses the document and
renders the result.

## Inputs and scope

Generate a document through the same upload selection as `sbom generate`, or
read one with `--sbom FILE` without a token or network. Configuration is required;
missing files and missing `[licenses]` tables produce distinct exit-2 setup
instructions. `--sbom` conflicts with generation-selection flags.
Offline document readability and byte limits are checked before policy setup; policy evaluation follows policy validation. Policy errors stop before submitting an analysis. Generated mode still constructs its authenticated client
before loading policy.

The check evaluates every type in `components` and nested component assemblies,
including files. It does not interpret metadata/tool/formulation objects as
additional dependency inventory. Service properties are optional: foreign and
older CycloneDX JSON documents with a usable shape are supported. This is a
policy evaluator, not a full CycloneDX schema validator.

Offline input without a string-valued `githits:completeness` property emits a
warning that inventory completeness is unknown. This does not establish the
document's provenance or reject foreign documents. The marker alone does not
prove that an inventory is complete or authentic.

Nodes marked `githits:record_kind=manifest` are excluded project roots. Nodes
marked `githits:source_kind=LOCKED_PACKAGE_SOURCE_KIND_LOCAL` are excluded local
sources and counted separately. A local source may be a workspace member or a
path dependency; location does not prove authorship. Excluding a parent never
excludes its descendants automatically.

Normal Cargo workspace members can be project roots after the service joins
native manifest and lock identities. The live
`generates_recorded_npm_and_cargo_workspace_inventory` test qualifies that joined
representation, retained local lock facts, an unjoined out-of-tree path dependency
and offline policy exclusion alongside an evaluated registry package. These
service properties are not enumerated by the published schema. Unadopted
local-source exclusions still depend on the optional source marker; it must not
be inferred from package names or publication flags. If neither project nor local-source evidence is present, a
package without license evidence is a `no_license` finding.

A file component without license evidence is a finding, even if its parent has a
license. Without a PURL it cannot use a package exception. No license or
first-party classification is inherited or invented.

## Policy and evidence

`allow` contains individual explicit SPDX requirements, including
`Apache-2.0 WITH LLVM-exception` and custom `LicenseRef-*` references. Unknown
names and compound allow-list entries are configuration errors. An empty list
is a deliberate deny-all policy.

The shared parser accepts explicit identifiers, formal GNU postfix-plus notation
(`GPL-2.0+` canonicalizes to `GPL-2.0-or-later`), deprecated formal identifiers,
and exact upper- or lower-case operators (`AND`/`and`, `OR`/`or`, `WITH`/`with`).
It does not guess names such as `apache`, `gpl` or `gnu gpl v2`, change identifier
case, or interpret `/` as an operator. Additional qualified aliases or native
metadata normalization belong to the service. The informational report retains
source text regardless of whether a policy check can interpret it.

| Evidence | Result |
| --- | --- |
| Missing licenses | `no_license` finding; human wording is “license not reported” |
| Explicit expression or `license.id` | Evaluate `OR` using any permitted operand, `AND` using all operands, `WITH` using the complete requirement |
| `license.name` | Try explicit SPDX syntax; otherwise `non_spdx_name` |
| Unknown/malformed expression or slash-separated text | `unparsable_expression` for expression/id, `non_spdx_name` for a name |
| Several license entries | Every entry must pass; conservative policy conjunction |
| Well-formed but disallowed expression | `not_allowed` |

For several entries, the derived check report parenthesizes each original entry
before joining with `AND`. `(MIT OR Apache-2.0) AND (GPL-3.0-only)` describes the
check's all-entries rule, not a publisher-supplied expression. Single-entry text
stays verbatim. `license report` instead preserves separate choices without
inventing a relationship.

Exceptions require an unscoped package URL and a reason. Configured versions,
qualifiers and subpaths are rejected rather than silently discarded. A valid
`pkg:npm/%40scope/name` exception applies to every release of that package;
component versions/qualifiers/subpaths are removed for this package comparison.
No PURL means no package exception. Every applied exception remains visible.
`Policy::new` returns `Result<Policy, PolicyError>` so library callers must handle
invalid policy entries too.

## Output and exits

Human output gives evaluated/skipped counts, violations and reasons, unresolved
projects and applied exceptions. Zero evaluated components explicitly establishes
no license coverage; it does not introduce a new failure rule. An unresolved
`githits:resolutions` project is a finding even without a license violation. Its
path/status/reasons explain what was not evaluated; add the required lockfile or
make an explicit selection decision.

Both generated and offline checks warn on stderr when zero components were
evaluated or `githits:completeness` is `partial_manifest_inventory`. These warnings
and the offline missing-completeness warning remain visible with `--quiet`,
`--json` and output files. They do not change the policy verdict, exit status or
schema-1 JSON; empty input still exits 0 unless it has unresolved projects.
Zero evaluated components includes input containing only excluded project/local
nodes. Known partial completeness warns independently of resolution entries.

Human previews escape controls and bound pathological values. Package identities
have a 160-character budget with up to 64 reserved for supplied qualifiers;
short columns align with a 48-character padding cap. License previews use 80
characters and at most 32 characters of padding. Longer evidence/identity
previews use at most 240 rendered Unicode scalars with explicit abbreviation and
a `--json` pointer. These are scalar budgets, not Unicode terminal-cell widths.
The full reason and policy verdict are never replaced by shortened evidence.

Within repeated name/version coordinates, human violation rows use the shared
[group presentation rules](license-report.md#repeated-group-occurrences).
Equivalent default/develop occurrences occupy one row; differing source,
platform, input, marker or license evidence remains separate. Repeated rows with
native group context show supplied input paths where they still need
attribution. The headline says “occurrence violations” when rows combine, so its
count remains the number of policy findings rather than displayed rows.
`--details` retains every violation's component reference, package URL and own
group context/input paths. Exception summaries show repeated identical labels
once with their occurrence count. Evaluation, exception applicability, counts,
exit status and schema-1 JSON remain per occurrence; presentation never changes
the policy result or the source SBOM.

`--json` keeps schema version 1 and full values: `components`, `local_packages`,
optional `completeness`, `violations` (identity, evidence, reason),
`exceptions_applied` and `unresolved_projects`. Grouping parentheses correct the
existing derived multi-entry expression string; no field is renamed or removed.
This verdict format differs from an SBOM and the experimental license report.

| Exit | Meaning |
| --- | --- |
| 0 | No policy findings or unresolved projects, including a document with zero evaluated components |
| 1 | Violations, unresolved projects, inventory drift or empty upload selection |
| 2 | Invalid/missing policy or selected input, malformed/oversized document, arguments/configuration/credentials/access or caller-action API failure |
| 3 | Other read failures, transport/service/rate-limit/protocol or output failure |

Documents are limited to 16,777,216 bytes. Wrong component/license shapes,
including nested shapes, fail before output rather than silently skipping data.
Progress goes to stderr; JSON suppresses progress while generated runs retain the
final upload summary on stderr. Offline mode still announces
“checking licenses...” for human output and never constructs an HTTP client.

`-o/--output FILE` writes the human or JSON verdict (`-` means stdout). `-q/--quiet` suppresses generation/checking progress and upload summaries, retaining the verdict and warnings. `--details` adds violation component references and package URLs; JSON always retains these fields.

## Verification

Pure tests cover policy validation, explicit syntax, nested traversal, exceptions
and evidence grouping. Binary tests cover token-free input, typed exits,
configuration failures, bounded human output, exact JSON facts and stream
separation. Generation uses the injectable API boundary. CI owns the full lint,
platform and packaging matrix.

## Ownership and references

| Concept | Owner |
| --- | --- |
| Policy validation, SPDX evaluation, exceptions and traversal | `src/license.rs` |
| Source selection and human/JSON check rendering | `src/commands/license.rs` |
| Shared human license previews | `src/commands/license/display.rs` |
| Policy configuration schema | `src/config.rs` |
| Generation and inventory gate | `src/commands/sbom.rs` |

Pure regressions live in `src/license/tests.rs`; binary compatibility coverage
lives in `tests/cli.rs` and its license modules. See [configuration](configuration.md)
for selection rules and [SBOM API contract](sbom-api-contract.md) for upload behavior.

Human `--details` omits empty component references and package URLs and indents
them beneath each component. Resolution statuses/reasons use plain language from the shared command-layer evidence table; repeated translated labels are shown once;
unfamiliar codes are labelled as unrecognized evidence retained in JSON. JSON
retains original status and reason codes.
