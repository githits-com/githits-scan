# Live integration fixtures

The contributor runner checks the real Scan binary and deployed jobs with
immutable package inputs. Use it to qualify an ecosystem and investigate changes
in the CLI or service. [Fixture definitions and baselines](../../tests/fixtures/live/)
cover the Cargo project fd, the Go module Cobra with its checksum file, and
the historical npm minimist remediation case.

## Run the fixtures

From the repository root, run these commands. The runner builds the locked debug
binary once per invocation. Supply `--binary PATH` to check another Scan build.

```sh
python3 scripts/live_fixtures.py list
python3 scripts/live_fixtures.py check --fixture go-cobra
python3 scripts/live_fixtures.py check
```

The runner prints its fixture and submission counts before running. It uses
the production origin and privately obtains a token from the signed-in
production GitHits CLI. An exported `GITHITS_API_TOKEN` takes precedence.
For a different `GITHITS_API_URL`, supply a token for that origin. The runner
validates input hashes and Scan's offline inventory before any submission.
Each online SBOM, audit, or license report needs one job. The license policy
check uses the generated SBOM locally.

## Interpret and refresh baselines

Authored expectations live in `fixtures.json`. They tie the input pins and
selected paths to facts that can be checked independently, such as known
locked package versions, supplied license declarations, and the affected copy
and advisories for minimist. The SBOM and license report baselines retain
locked inventory, input attribution, relationships, and coverage. The audit
baseline retains required coverage and the accounted dependency count for
locked inputs. A stable difference exits 1 and prints the changed evidence.

Advisories, latest versions, qualified recommendations, and selections from
mutable resolution stay visible in observational diffs. A new minimist target
passes when a single complete proposal still addresses both expected advisories
and meets the fixture's requirement and qualification checks. The affected
version, advisory identities and allowed range are authored. The selected
target is recorded as an observation.

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
A small committed fixture can exercise a specific historical case with checked
provenance. Pin its bytes and document the contract it exercises. Choose
assertions grounded in those inputs and qualify actual reports before
refreshing and reviewing the first baseline.

The Python runner owns acquisition, fixture verification and comparison against
Scan's public JSON. Scan owns discovery, upload selection, authentication of
API requests, report decoding and retry behavior. Ordinary CI runs offline
runner tests. The [release live job](release-process.md#rehearsal-and-release-gates)
continues to exercise its existing ignored smoke tests.
