# Live integration fixtures

The contributor runner checks the real Scan binary and deployed jobs with
immutable package inputs. Use it to qualify an ecosystem and investigate changes
in the CLI or service. [Fixture definitions and baselines](../../tests/fixtures/live/)
cover each cataloged ecosystem and lockfile rule, representative parser
revisions and workspace inputs, and a historical npm remediation case.

## Run the fixtures

From the repository root, run these commands. The runner builds the locked debug
binary once per invocation. Supply `--binary PATH` to check another Scan build.

```sh
python3 scripts/live_fixtures.py list
python3 scripts/live_fixtures.py check --fixture go-cobra
python3 scripts/live_fixtures.py check
```

The runner prints its fixture and submission counts before running. It uses
the production origin and privately obtains the current token from the
signed-in production GitHits CLI before each online command. This lets the
CLI refresh its session during long runs. An exported `GITHITS_API_TOKEN`
takes precedence.
For a different `GITHITS_API_URL`, supply a token for that origin. The runner
validates input hashes and Scan's offline inventory before any submission.
Each online SBOM, audit, or license report needs one job. The license policy
check uses the generated SBOM locally.

## Interpret and refresh baselines

Authored expectations live in `fixtures.json`. They tie the input pins and
selected paths to facts that can be checked independently, such as known
locked package versions, supplied license declarations, and the affected copy
and advisories for minimist. The baselines retain locked inventory, input
attribution, relationships, and coverage. Manifest-resolved SBOMs check the
resolved occurrence names and scopes. Their selected versions are observations.
Mixed SBOMs preserve stable versions and relationships for their locked inputs.
The audit baseline retains required coverage and the accounted dependency count for
locked inputs. A stable difference exits 1 and prints the changed evidence.

Advisories, latest versions, qualified recommendations, and selections from
mutable resolution stay visible in observational diffs. A new minimist target
passes when a single complete proposal still addresses both expected advisories
and meets the fixture's requirement and qualification checks. The affected
version, advisory identities and allowed range are authored. The selected
target is recorded as an observation.

For a revision-only locked occurrence with empty license lists, an absent
declaration or missing registry coordinate stays visible as an observation.
The revision, input attribution, both license lists and reported coverage
remain part of the stable comparison.

Refresh after reviewing the reported differences. Select a single fixture or
all fixtures just as with `check`.

```sh
python3 scripts/live_fixtures.py refresh --fixture go-cobra
python3 scripts/live_fixtures.py refresh
```

Refresh writes selected baselines only after every selected command and authored
assertion succeeds. Review the resulting Git diff. Update authored expectations
as a separate decision when source inputs or a supported contract change.
Keep job output, job IDs and credentials out of commits.

The runner uses exit 0 for success, 1 for failed expectations or stable
differences, 2 for invalid invocation or fixture data, and 3 when it cannot
stage an input, authenticate, execute Scan or get a usable document.

## Add coverage

Give each fixture a unique ID, ecosystem and set of checks. Pin a public GitHub
source by full commit and list SHA-256 digests for each selected file. Downloaded
files keep their original relative paths and stage in a temporary directory.
A fixture can name a `project.subdirectory` inside the pinned checkout. The
runner uses it to fetch the files and stages their paths relative to the
fixture project. Add a release label when the pinned commit has a release.
A small committed fixture can exercise a specific historical case with checked
provenance. Pin its bytes and document the contract it exercises. Choose
assertions grounded in those inputs and qualify actual reports before
refreshing and reviewing the first baseline.

### Corpus inputs

The fixture definitions identify the exact upstream paths and commits. The
corpus covers the supported lockfile names, legacy Gradle path layout and
the distinct parser inputs for pnpm, Yarn, Poetry, Swift and Conan. The
catalog's offline test requires a definition and baseline for each lockfile
rule and each ecosystem.

The [authored inputs](../../tests/fixtures/live/inputs/) exercise shapes that
need a small, controlled project. npm 11.20 generated the workspace and
shrinkwrap cases, Bun 1.4.5 generated the text workspace lock and pnpm
8.15.9 generated its v6 lock. Yarn 1.22.22 and Yarn 4.9.2 emitted the
classic and Berry fixtures. Each declares `left-pad 1.3.0`. Cargo
generated a workspace lock for the local `fixture-member` and
`itoa 1.0.18`. The Go 1.27.4 workspace contains two small modules and
their generated workspace checksums. Bundler 1.17.2 generated the lock
for `rake 13.2.1`.

The buildscript and settings fixtures encode the unified Gradle classpath
lock syntax for `org.apache.commons:commons-lang3 3.12.0`. The Conan 2
fixture encodes the ConanCenter `zlib 1.2.12` recipe revision present in
the pinned Conan 1 sample using the 0.5 requires format. The vcpkg and Zig
cases reuse the existing manifest examples.

Set the audit manifest list to the exact uploaded manifest paths. A lock-only
fixture declares an empty list. The Go dep and Conan fixtures require recorded
inventory from SBOM and license reporting, and an exit-1 audit with an
actionable coverage gap. An unassessed audit expectation names the reported
check and status and can specify the affected files.

The Python runner owns acquisition, fixture verification and comparison against
Scan's public JSON. Scan owns discovery, upload selection, authentication of
API requests, report decoding and retry behavior. Ordinary CI runs offline
runner tests. The [release-candidate rehearsal](release-process.md#rehearsal-and-release-gates)
checks the whole corpus against its verified commit before tagging.
