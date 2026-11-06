# Configuration and Strictness

## Purpose

This document records how `githits-scan.toml` turns the exploratory commands into a strict pipeline gate, how the file is evaluated against a scan, and how `detect --save` maintains it. The code is `src/config.rs`; the commands consume it through `config::evaluate`.

## The File

```toml
version = 1

[lockfiles]
include = ["Cargo.lock", "web/package-lock.json"]
exclude = ["examples/**", "benches/fixtures/**"]
manifests = ["services/legacy/package.json"]

[licenses]
allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-3-Clause", "ISC"]

[[licenses.exceptions]]
purl = "pkg:cargo/ring"
reason = "OpenSSL-style license reviewed 2026-09"

[[licenses.exceptions]]
name = "grammar"
git = "https://example.invalid/grammar"
rev = "0123456789abcdef0123456789abcdef01234567"
reason = "Selected source reviewed; license evidence unavailable"

[[audit.ignore]]
id = "RUSTSEC-2024-0436"
reason = "Reviewed for this deployment"
```

- The default location is `githits-scan.toml` in the scanned directory; `--config FILE` points elsewhere. Paths inside the file are always relative to the scanned directory with forward slashes, whatever directory the file lives in, so a repository scanned from CI and from a developer's shell reads the same file the same way.
- `version` must be `1`. Unknown keys anywhere are errors (exit 2) so a typo cannot silently widen policy. `include` and `manifests` entries must satisfy the same path rules as upload filenames.
- `exclude` holds globs; `*` does not cross a directory separator, `**` does. They are compiled once when the file loads.
- `[licenses]` is consumed by `license check`, which rejects invalid `allow`
  requirements and scoped exception PURLs with exit 2 before evaluation or upload. Offline `--sbom` readability and byte limits are checked before policy setup.
  See [policy and evidence](license-check.md#policy-and-evidence).

Implicit default configuration discovery is optional for `detect`, `sbom generate`,
`audit` and `license report`. An explicit `--config FILE` must be readable;
missing or unreadable files are exit-2 errors, except that `detect --save` creates
a missing default or explicit path from the commented template. Existing files
retain their original comments, optional tables and policy.
`license check` requires it: a missing file is an exit-2 error naming the path
and explaining how to create or select one; an existing file without
`[licenses]` instead identifies the table to add. The shared command loader
preserves default-file absence and requires explicit selections. The license
command enforces its own configuration/policy requirement before evaluating or
generating the document, retaining its specific setup diagnostic. Explicit offline
input readability and byte limits are checked first. Generated mode still
validates credentials when constructing the API client before loading policy.

## Policy decisions

License exceptions select either a versionless `purl`, or an exact `name` and
`git` source URL with optional exact `rev`. Both forms require a nonblank reason.
Selectors cannot be mixed. Git matching uses recorded source identity, never a
publisher repository link or inferred registry license. Copy the full URL and
revision from a failing `license check --json`; `--details` shows bounded
previews. Short commit prefixes and URL variants such as adding `.git` do not
match. Omitting `rev`
excepts every recorded revision of that named source. Missing, ambiguous or
unsupported source evidence does not match. See [license policy](license-check.md).
License selector semantics are validated by `license check` before evaluation or
upload, as with the existing SPDX allow list and PURL rules.

`[[audit.ignore]]` requires an exact, case-sensitive reported advisory `id` and a
nonblank `reason`. IDs cannot contain whitespace or repeat. Unknown keys are
errors; expiry is not supported. Aliases do not match. An ignore applies across
all packages carrying that advisory ID. Findings remain in JSON/text as ignored,
with the configured reason; raw vulnerability totals remain intact. Only those
findings stop contributing to exit 1: maintenance findings, input disagreements,
coverage gaps and inconsistent reports still fail. No configuration changes
which checks the service performs. See [audit policy](audit.md#local-advisory-policy).

Both policy blocks and comments survive `detect --save`. Informational
`license report` remains evidence-only and does not apply exceptions.

## Evaluation

`config::evaluate` compares an inventory with the file and gives every detected lockfile and manifest-only manifest a status:

| Detected file | `included` | `excluded` | `unlisted` |
| --- | --- | --- | --- |
| Lockfile | listed in `include` | matches `exclude` | neither; **drift** |
| Manifest-only manifest | listed in `manifests` | matches `exclude` | neither; **drift**, or informational under `--lockfiles-only` |
| Nested manifest | listed in `manifests` | matches `exclude` | no status; may be Cargo or supported npm evidence |

Default fixture exclusions are soft selection policy in `src/config.rs`, not
catalog rejection: exact directory components `fixtures`, `__fixtures__`,
`testdata`, `test-data`, and `test_data`, relative to the scan root.
Matching ignores ASCII case (including Composer-style `Tests/Fixtures`).
They apply to lockfiles, manifest-only projects, ambiguous lockfiles, and
nested/uncombined candidates, including automatic Cargo member selection.
They are reported as `excluded` without drift, even without a config file.
An explicit `include`/`manifests` entry restores a recognized eligible file;
its owning manifests are restored too, unless an explicit exclude matches them. Installed-dependency skips
remain catalog rules and cannot be overridden.

An explicit file entry beats a file `exclude` pattern and the default fixture exclusions. `--exclude` globs on the command line win over those lists, so a one-off run can omit a listed lockfile without editing the file. Entries are matched by role: an `include` entry must name a detected lockfile, and a `manifests` entry must name a manifest-only manifest, a nested or uncombined manifest, or the companion of an *included* lockfile (unless excluded). Anything else listed is **missing**, which is drift, so a path in the wrong list, the companion of an excluded lockfile, or an ambiguous lockfile (never uploaded) in `include` is reported rather than silently ignored. An `exclude` pattern that matches an ambiguous lockfile records the decision and silences its warning. Listing an uncombined manifest uploads it beside a lockfile it does not own. Without a backend-proven association, it can resolve separately from registries; list one only when that extra input is intended. Drift is therefore exactly: unlisted lockfiles, unlisted manifest-only projects unless the run is `--lockfiles-only`, plus missing entries. Invocation excludes are never drift.

`detect` prints the status in a `STATUS` column and lists missing entries in their own section; `--json` adds `config`, a `status` per entry, and `drift.unlisted` and `drift.missing`. Both `detect` and `sbom generate` exit 1 on drift unless `--no-check` is passed; `sbom generate` prints the drift and makes no request.

Directory globs ending in `/**` are compiled to a directory predicate and applied
before descent. Exact configuration inclusions preserve their ancestors; CLI
exclusions always win. Other globs apply to discovered files. Pruned subtrees
have unknown file counts; detect reports their patterns separately. Listed paths
matched by invocation exclusions are excluded even when absent, never missing drift.
`truth` is eligible by default; detect annotates selected test-looking paths instead.

## Selection With a Configuration

`audit`, `sbom generate`, `license report` and generated-input `license check` share one upload selection: included lockfiles with their owning manifests, Cargo and supported npm member evidence covered by those locks, and every manifest listed in `manifests` (manifest-only, nested, or uncombined). Unlisted lockfiles and unlisted manifest-only projects are never uploaded even under `--no-check`: the flag ignores drift, it does not widen the inventory. Excluded files are neither uploaded nor reported as skipped; they are a recorded decision.

Declared Cargo members and used in-workspace path members are added automatically
from admitted nested candidates, even when `manifests` is empty. Supported positive
npm workspace declarations add candidates in the same upload phase. The service
establishes final association from native files; directory nesting alone proves
nothing. A shared workspace does not require fictional member-local lockfiles.
File exclusions suppress automatic members unless explicitly listed in `manifests`;
CLI exclusions win for all files, including owning companions. Companion statuses
are evaluated here once and consumed by upload preparation and detect. See [Cargo](discovery.md#cargo-member-evidence) and
[npm evidence selection](discovery.md#npm-member-evidence) for the exact boundaries; other nested evidence remains an explicit choice.

## `detect --save`

`--save` maintains the discovered inventory; selecting an additional nested or
uncombined manifest remains an explicit configuration choice apart from native
Cargo and supported npm evidence added during upload preparation. A save accepts the
detected reality:

- `include` becomes every detected eligible lockfile, sorted. Existing explicit entries retain their override of configured/default exclusions; invocation `--exclude` still wins. Other excluded lockfiles are omitted.
- `manifests` keeps listed entries that remain eligible after exclusions and adds every non-excluded manifest-only project, unless the run is `--lockfiles-only`. A listed companion is removed when its owning lockfile is excluded, so saving cannot leave a missing companion entry behind.
- A missing default or explicit file is created from a commented template that explains each key and carries a commented-out `[licenses]` skeleton.
- An existing file keeps comments, key order, and license/audit policy. `include` and `manifests` are always rewritten, one path per line. `exclude` is rewritten only when `--exclude` is passed, as the file's patterns plus any new invocation globs.
- Nothing is written when the result equals the current contents, so repeated saves produce no diff. The report says what was created, added, and removed; `--json` carries the same under `saved`.
- `--save` with `--no-check` is a usage error: a save is the resolution of drift, not a way to ignore it. In the code these are the three variants of `DriftPolicy`.

The intended workflow: a pipeline runs `detect` (or `sbom generate`) and fails on drift; a developer who added or removed a project runs `detect --save` and commits the change, which is then reviewed like any other file.

## Ownership

| Concept | Owner |
| --- | --- |
| Schema, parsing, validation, glob compilation | `src/config.rs` |
| Status and drift computation | `src/config.rs` (`evaluate`), called once per command |
| Which file to read (`--config` or the default) | `src/commands/mod.rs` (`config_path`, `load_config`) |
| What `--save` writes (the desired lists) | `src/commands/detect.rs` |
| Writing the file without disturbing the rest | `src/config.rs` (`save`) |
| Rendering statuses, drift, and save notes | the command modules |

## Key Reference Files

| File | Demonstrates |
| --- | --- |
| `src/config.rs` | Schema with `deny_unknown_fields`, evaluation matrix, format-preserving save with byte-exact tests |
| `src/commands/detect.rs` | `DriftPolicy`, the `STATUS` column, `--save` reporting |
| `src/commands/sbom.rs` | The drift gate before any request and config-driven selection |
| `tests/cli.rs` | Exit codes for drift, `--no-check`, `--save`, and invalid files |
