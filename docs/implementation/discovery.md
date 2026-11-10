# Repository Discovery and `detect`

## Purpose

This document records how `githits-scan` finds package evidence in a directory tree and how `detect` reports it. The code is `src/discover.rs` (walk and pairing) and `src/commands/detect.rs` (rendering); this page is the rationale.

## Walk Rules

The walk uses the `ignore` crate's `WalkBuilder` with these settings, in the order a reader would question them:

| Setting | Value | Why |
| --- | --- | --- |
| `.gitignore`, `.git/info/exclude`, global excludes | honored | The scan should see what git sees; ignored lockfiles are fixtures, build output, or vendored copies |
| `require_git` | false | A plain export or a CI checkout without `.git` must still honor its `.gitignore` files |
| `.ignore` files | not honored | They are a ripgrep convention with no meaning for an inventory |
| hidden entries | skipped | Covers `.git`, `.tox`, `.bundle`, `.dart_tool`, `.build`, `.swiftpm`, `.yarn`, and every other tool cache |
| symbolic links | not followed | A link could point outside the scanned root; nothing outside it may be named in an upload |
| installed-dependency directories | skipped by the catalog | `node_modules`, `vendor`, and the rest are listed in `package-file-catalog.md` |
| fixture directories | discovered, excluded by default selection | [Configuration](configuration.md#evaluation) owns the overridable fixture policy |

Only cataloged files are stat-ed during discovery. Explicit directory exclusions
ending in `/**` prune matching subtrees before descent, including ignore-file
processing; configured inclusions preserve necessary ancestors, CLI exclusions win.
Installed-dependency directories are also pruned. Walk errors stop the scan with
a path-bearing cause and permissions/repository-relative `--exclude` hint (exit 3), preserving complete
inventory semantics. Detect then runs shared bounded upload preparation offline
to resolve workspace membership and validate selected file reads and API limits.

## Pairing

Files are grouped by project directory and ecosystem. Each lockfile attaches to the manifest that owns it, as the catalog names it (`package-file-catalog.md`). A manifest that owns no lockfile is **uncombined** when its directory holds a lockfile of its ecosystem, **nested** when the nearest ancestor directory holds one, and **manifest-only** otherwise. A lockfile that several manifests could own is **ambiguous**: it is set aside, and those manifests are manifest-only. Consequences:

- `package-lock.json` and `yarn.lock` in one directory both list `package.json` as their companion. The upload set deduplicates.
- A `packages.lock.json` pairs with the only `.csproj` beside it. Beside several, it is ambiguous; `detect` and `sbom generate` warn until an exclude pattern matches it.
- `pyproject.toml` beside `Pipfile.lock`, `Gemfile` beside `gems.locked`, and `build.gradle` beside `gradle.lockfile` are uncombined: they are not cataloged owners of the nearby lockfile, so they are not uploaded by default. Proximity does not prove dependency coverage. `detect` lists them with that explanation.
- `package.json` next to `Cargo.lock` is manifest-only; ecosystems never pair across each other.
- `vcpkg.json` next to `conan.lock` and `go.mod` next to `Gopkg.lock` are manifest-only, as the service requires. Go modules, vcpkg, and Zig have no cataloged lockfile, so `go.mod`, `vcpkg.json`, and `build.zig.zon` are never nested either: a nested Go module is an independent project.
- `crates/core/Cargo.toml` under a root `Cargo.lock` is nested. This is directory containment, not proof of membership. Upload preparation reads the selected lock's owning Cargo manifest and selects native member candidates as described below. Supported npm/Bun members can also be added from declarations; other nested inputs still require explicit configuration. An uncovered manifest may trigger independent registry resolution, so Scan does not upload every nested candidate automatically. The service owns final native association.

## Cargo member evidence

Shared upload preparation adds admitted Rust nested manifests covered by the same
selected lock when an explicit Cargo workspace declares them. This applies with
configuration and under `--lockfiles-only`. Selected owning companions keep their
existing lock scope; omitting another lock does not automatically select its
companion through the ancestor workspace.

The pure `src/discover/cargo.rs` helper interprets already-read bytes: declared
member globs (`*`, `**`, `?`, character classes, literal braces) and recursively
used in-workspace dependency paths. Cargo workspace exclusions use component-wise
path prefixes and literal member-prefix overrides. All dependency tables, including
target-specific normal/development/build dependencies, participate. Inherited
paths are relative to the workspace root and selected only when a package uses
`workspace = true`; unused workspace dependencies are not evidence. A root
package's dependency paths participate too. A package without `[workspace]` does
not turn its path dependencies into workspace members.

Only inventory matches within the workspace and selected lock boundary can be
added. Ignored, hidden and symlinked files stay outside discovery. A differently
owned or independent workspace does not expand through its parent. Absolute declarations, external paths,
`[patch]` and `[replace]` are not automatic workspace-member evidence. Original
malformed input still reaches service validation without invented member matches.

Configuration evaluates exclusions once: CLI member exclusions win, explicit
manifest inclusion overrides file exclusion, otherwise file exclusion suppresses
automatic members. Owning companions follow the same exclusions; excluded owners cannot expand members.
Each selected file is read once. Before another read, the expanded metadata plan
and actual sizes already observed pass the canonical API limits. Final upload
counts and saved selected-manifest paths include the additions. Long upload
summaries report counts instead of an inline path list exceeding 100 characters.

The upload limit remains 256 files. If automatic workspace members exceed it,
preparation stops with usage exit 2 before reading any further file or submitting
a job. The error gives total files and automatic member counts, plus
up to three exact, glob-escaped member-path exclusion examples; these avoid
accidentally removing owning manifests. Broad patterns such as `**/Cargo.toml`
also omit owning manifests and can remove workspace declarations. Partial scans require this explicit choice, and
missing required evidence can still leave the result incomplete.

This is selection of evidence, not native resolution or proof of applicability.
Missing inputs and incompatible local path evidence remain explicit service gaps.
See the [workspace evidence boundary](audit.md#workspace-evidence-boundary).

## JavaScript workspace member evidence

Shared upload preparation adds declared members under selected npm
(`package-lock.json` or `npm-shrinkwrap.json`) and text Bun (`bun.lock`) owners.
This applies to audit, SBOM generation, license checks/reports, diff and detect's
upload preview, including `--lockfiles-only`. pnpm and Yarn locks do not enable
this expansion. Array declarations and `{ "packages": [...] }` objects are supported.

The pure `src/discover/npm.rs` selector reads only the owning `package.json`,
matching admitted member directories relative to that owner. Supported positive
patterns use literals, `*`, `?`, whole-segment `**`, non-negated bracket sets/ranges
and non-nested comma braces with nonempty literal alternatives. Trailing `/**`
includes the base directory. Classes use separate ranges (`[a-z0-9]`); a literal
`-` belongs at a class edge. Matching is case-sensitive and `*`/`?` do not cross
path separators. For npm, a leading run of `/`, optionally preceded by `.`, is root-relative;
even leading `!` parity is positive. Supported npm comment patterns starting with
`#` contribute no members. A leading `!` left after root-prefix removal requires explicit selection.
No package-manager command or lockfile parser runs in Scan.

Bun uses the same bounded positive-pattern selector with its verified differences:
`#` is a literal path character, a leading `/` is unsupported, and comma-brace
alternatives containing `/` are unsupported. The supported constructs were checked
against Bun 1.4.4 using offline, script-free lock generation, including `?`, classes,
ranges, simple braces, middle/repeated `**`, trailing `/**` including its base,
`./` and even leading `!` parity. Odd negation, paths outside the owner and the
other unsupported syntax retain the conservative no-automatic-additions behavior.
Bun's wider native workspace features are not an installation or applicability
claim by Scan; this selects already admitted manifest evidence. See the
[official Bun workspace format](https://bun.com/docs/pm/workspaces).

Character-sensitive patterns (`?` or bracket classes) require ASCII declarations
and admitted member directories. Combining them with Unicode disables automatic
additions for that owner because the matcher counts bytes differently from npm.
Unicode literals and star patterns remain supported.

Any negative or unsupported declaration disables automatic additions for that
owner, preserving explicit selection and original inputs for service validation.
Unsupported forms include extglobs/parentheses, dollar-prefixed braces (`${a,b}`),
numeric brace ranges, POSIX or negated classes, chained class ranges (`[a-c-e]`),
ranges spanning `/` (`[.-0]`), nested/comma-free/empty-alternative braces,
backslashes, non-string entries, internal dot/parent/empty segments and trailing slashes. Missing or
malformed declarations add no guessed members. Negative matching is deferred
because native mapper versions and host case policies differ; case-only positive
matches are not added automatically. Available manifests can be listed in
`[lockfiles].manifests`; service-supplied input gaps remain visible.

Candidates share the nearest lock-owning directory with the selected npm or Bun owner.
Several same-directory JavaScript locks do not change that boundary: an excluded
representative lock cannot hide members of a selected npm or Bun lock. A closer child
lock remains independent even when it is excluded. Each selected owner expands
its own candidates; reading a member never recursively interprets its workspaces.
CLI/config exclusion precedence, admitted walk paths, read-once preparation and
all upload limits follow the existing Cargo selection contract above. `detect`
uses the identical preparation path offline to provide a content-based upload preview.

Paths are relative to the scan root with forward slashes on every platform, which is the filename form the API requires. A cataloged file whose path cannot be expressed that way (a non-UTF-8 directory name) is an error, not a silent omission.

## `detect` Output

- The first line counts selected lockfiles and their ecosystems, with known excluded lockfiles counted separately. Contents of pruned directories are not counted.
- The table lists path, ecosystem, byte size with thousands separators, and the owning manifest in the companion column. Manifest-only rows carry `(no lockfile)` in the companion column.
- Manifest-only projects that a scan would upload are rows of the inventory table. Those it would skip are listed in a separate section headed with the reason: `--lockfiles-only`, or not listed in the configuration. `detect` and `sbom generate` share one manifest-only selection rule (`commands::manifest_selection`), so the report's manifest-only rows match the upload. Selected nested/uncombined manifests have a separate included section; unselected candidates retain classification sections. A configuration that lists a manifest uploads it, and its status column says `included`. Nested manifests are listed last with the nearest ancestor lockfile.
- An empty inventory prints the exact lockfile names the scan would have accepted.
- Uncombined manifests are listed after nested ones with the lockfile beside them; ambiguous lockfiles are listed last, as a warning, with the manifests that could own them. Manifest-only rows displaced by an ambiguous lockfile carry `(ambiguous lockfile)`.
- Test-looking package paths are annotated in a separate human section and the sorted, deduplicated JSON `test_paths[]`: default fixture directories plus `test`, `tests`, `truth`, `eval`, `evals`, and names ending in `_eval`. Directory annotation matching also ignores ASCII case. The annotation does not change selection. Selected paths are suggested when preparation succeeds; blocked previews retain non-excluded candidates for review. Human output is capped at ten with an omitted count and JSON hint. Known file-level exclusions stay visible with status, while pruned subtrees are represented by patterns. Gitignored/hidden/installed-dependency files remain outside the inventory.
- `--json` adds sorted `upload_paths` (exact locally prepared selection) and `excluded_directory_patterns` (subtree patterns, not measured contents), and emits `schema_version: 2`, `root`, `lockfiles_only`, `unsupported[]` (`path`, `hint`), sorted/deduplicated `test_paths[]` (selected package paths, or non-excluded candidates when preparation is blocked), `lockfiles[]` (`path`, `ecosystem` id, `bytes`, `manifests[]` of `path`, `bytes`, and optional canonical `status`), `nested[]` and `uncombined[]` (`path`, `ecosystem`, `bytes`, `lockfile`), `ambiguous[]` (`path`, `ecosystem`, `bytes`, `manifests[]` of paths), and `manifest_only[]` (`path`, `ecosystem`, `bytes`). Entries carry `status` when a configuration, invocation exclude, or default fixture exclusion requires an evaluation. Additive changes keep the version.
- Exit 1 when a scan would upload nothing: no lockfile is selected (none exists, or every one is excluded), no manifest-only project is selected, and no nested or uncombined manifest is selected through the configuration. The report is still printed. `lockfiles_only` is `true` exactly for `--lockfiles-only`; it replaces the inverse version-1 `include_manifests` field.

Color is applied by the command layer only when the caller did not pass `--no-color`, `NO_COLOR` is unset or empty, and stdout is a terminal. Every style is decorative; the plain report carries the same information.

Unsupported `requirements.txt`, `deno.lock` and `pom.xml` paths come from catalog filename recognition and the existing walk. Their contents and metadata are not read; non-UTF-8 names use display replacement characters and do not block supported evidence. Invocation, configuration and default fixture exclusions silence these notices. Detect groups unsupported paths by format hint in a human report section and lists them in JSON; upload commands emit warnings even with quiet. Nested headings group unselected candidates by ecosystem; selected workspace/configured manifests appear separately. First configuration creation prints only the creation result, without an inventory-match claim. `-o` routes the report and `-q` suppresses save-success notes.

The complete field list, including optional `config`, `drift`, and `saved`
metadata, is maintained in [JSON output contracts](json-output.md#detect-schema-2).

## Key Reference Files

| File | Demonstrates |
| --- | --- |
| `src/discover.rs` | Walk settings, pairing, and the synthetic-repository tests |
| `src/commands/detect.rs` | Human and JSON rendering with byte-exact tests |
| `src/commands/mod.rs` | `Outcome` and `ErrorKind`, the contract between handlers and `src/cli.rs` |
| `tests/cli.rs` | Exit codes and stream separation of the real binary |

If local preparation fails, detect still writes the discovered inventory, sets
JSON `upload_paths` to null and supplies `upload_error`; it then reports the typed
error on stderr using the normal usage (2) or execution (3) exit class. The saved
configuration remains written under `--save`. No partial selection is called an
exact preview. Directory pruning changes classification using only visible
inputs: for example, excluding `gradle/**` can leave its formerly owning manifest
as an independent manifest-only project. Exclude that manifest too when desired.

## Git snapshot inputs

Experimental [dependency diff](dependency-diff.md) feeds Git path/size metadata to
the same pure pairing rules and bounded upload selector through an injected reader.
Its enumeration policy intentionally keeps tracked-but-ignored files and skips
ignored untracked files, hidden paths and installed-dependency directories. No
historical tree is checked out or materialized. Configuration is not loaded; its
presence and non-deliberately omitted evidence are stderr diagnostics. Both selected
sides share the paired API upload limits.
