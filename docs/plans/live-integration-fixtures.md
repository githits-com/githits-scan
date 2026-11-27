# Live integration fixture release verification

Contributors can check or refresh pinned public fixtures against the real Scan
binary and deployed API. The release-candidate rehearsal must qualify the
complete corpus against its verified commit before tagging.

## Implemented

1. The pilot introduced single and full fixture checks, reviewed baselines,
   private credential handling and offline CI tests.
2. The corpus covers every cataloged ecosystem and lockfile rule, with
   representative parser revisions and workspace inputs. The Go dep and Conan
   cases assert the producer's actionable audit coverage limit while checking
   their recorded inventories. The
   [fixture procedure](../implementation/live-integration-fixtures.md) owns
   source pins, usage and baseline semantics.
3. The [release procedure](../implementation/release-process.md#rehearsal-and-release-gates)
   runs the complete corpus in the existing exact-commit live job when
   `release_candidate=true`. Ordinary PR CI checks corpus coverage offline.

## Remaining verification

Before the first release that uses this gate, run the release-candidate
rehearsal on the eligible merged release SHA. The release credential needs
capacity for the offline `list` job count plus the five existing smoke
submissions, accounting for other traffic sharing its principal. The repository
secret is configured. Its effective allowance and rehearsal runtime require
verification in that run.

Completion requires the smoke and full corpus steps to pass and the workflow
link to be recorded on the release PR. Retire this plan according to the
repository's final-push rule after that verification.
