# Release process

The root crate is the distributable application. The unpublished `xtask` member
owns release policy and uses the same locked dependencies and strict checks.
Actions owns testing, native builds and publication. No release command is added
to the shipped scanner.

## Homebrew tap

The public [tap](https://github.com/githits-com/homebrew-tap) owns the source
formula and bottle builds. Install with
`brew install githits-com/tap/githits-scan`. Bottles target macOS 15 ARM64 and Linux
x86_64/ARM64. Other platforms, including Intel macOS, build from source with
Homebrew's Rust build dependency. Intel can also need a Rust/LLVM source build;
that fallback is not exercised by the bottle CI matrix. Scan's minimum Rust
version must remain compatible with Homebrew's Rust formula.

A pushed `vX.Y.Z` tag publishes the GitHub release, then the `homebrew` job hashes
the GitHub tag source tarball and opens a tap PR with a short-lived GitHub App
token. The job runs in the `homebrew-tap` environment, never for manual rehearsals
or `release_candidate` dispatches. The environment currently requires maintainer
approval, so approve that job to continue the tagged release's tap handoff.
Failure is tolerated independently of the already published release. The App
token is passed through the step environment to `gh`; the handoff never puts it
in process arguments or writes it to disk.

The handoff updates only the formula's source URL/checksum, removes prior bottle
metadata and leaves fresh bottles to tap CI. A stable branch per version makes
reruns resume after partial writes. An existing PR, including a closed PR, is
left alone; reopen a deliberately closed PR manually if needed. If tap `main`
already contains that version or a newer one, the handoff does nothing.

After all three bottle jobs succeed, the tap's `workflow_run` publisher selects
only an open PR authored by `githits-homebrew-tap-bumper[bot]`, targeting `main` in
the tap repository, with the exact tested head SHA and only the modified
`Formula/githits-scan.rb`. It then runs the standard `brew pr-pull` publication
and push using the tap's own `GITHUB_TOKEN`. This directly follows the completed
CI workflow: it does not depend on a label added with `GITHUB_TOKEN`, which would
not trigger another workflow. The selection job has read-only permissions;
publishing uses trusted default-branch code and standard `brew pr-pull`, which
applies the selected PR and evaluates its formula Ruby under the write token.
Automatic publication trusts the App and tap writers; manual publication trusts
the maintainer's review. PR workflows and auxiliary scripts are not executed.
`--head-sha` checks the selected commit again before publication. Closed PRs and
stale CI results skip.

Human and Dependabot PRs remain manual: review successful checks and all three
bottle artifacts, then apply `pr-pull`. The initial 0.3.0 PR used this path.
Homebrew test-bot can skip an unbottled dependency while returning success, so
the tap treats skipped formulae as failed checks. `pr-pull` does not enforce the
complete platform set itself; retain the artifact check on the manual path.
Published PRs are closed by `pr-pull`; version branches can remain because
GitHub's automatic branch deletion applies to merges.

The tap keeps Homebrew's default publishing model: no PR-required/checks ruleset
and no App bypass. Its separate no-bypass rule blocks force-push and deletion,
including admins and automation. The tap needs no App secret or protected publish
environment. The App is used only for Scan's version-update PRs.

### One-time maintainer setup

1. Install the GitHub App on **only** `githits-com/homebrew-tap`, with repository
   **Contents: read and write**, **Pull requests: read and write**, and automatic
   **Metadata: read-only**. No organization, Actions, Workflows, Issues or
   Administration permissions are needed. App-authored PRs trigger normal CI.
2. In Scan's `homebrew-tap` environment, set variable `HOMEBREW_TAP_APP_ID` and
   secret `HOMEBREW_TAP_APP_PRIVATE_KEY`. The workflow reads `vars` and `secrets`
   respectively. Restrict deployment refs to release tags and remove required
   reviewer approval only if unattended post-tag delivery is explicitly intended.
   Keeping the current reviewer gate makes the handoff wait for a maintainer.
   The implementation does not change Scan's settings or create environment
   secrets. Never put the key in chat, source, logs or process arguments.
3. Ensure GitHub Actions is enabled on the tap. Review the initial formula PR's
   three successful bottle checks and artifacts, then a maintainer applies `pr-pull`
   for the first publication/merge. Do not merge formula PRs with GitHub's merge
   button before publishing bottles. Once this workflow is on tap `main`, later
   App-authored formula-only bumps publish automatically after successful CI.

After each tagged release, confirm that the tap PR exists: a tolerated handoff
failure can leave the release run green. Diagnose a missing PR in the Homebrew
job, then rerun that job from the original tag workflow. Find its `databaseId`
with `gh run view <run-id> --json jobs --jq '.jobs[] | {name, databaseId}'`, then
use `gh run rerun --job <databaseId>`; the browser URL's job number is not that ID.
Do not recreate the GitHub release or move its tag. For tap CI/publication failures,
inspect the failed job before rerunning; do not label a failed or stale result.
Unmerged formula changes do not affect installed users.

## Preparation and approval

Use the repository-local
[`githits-scan-release` skill](../../.agents/skills/githits-scan-release/SKILL.md)
for release preparation, readiness review, and approved execution. The root
manifest and lockfile identify the single released crate; `xtask` remains
unpublished. This document owns the procedure and the skill guides its use.

A request to audit, prepare, create, cut, or release a version authorizes work
through opening the release PR. It does not authorize merging, enabling
auto-merge, tagging, or publishing. Following a release to completion includes
tracking each stage and requesting its approval when the preceding gate passes.

1. Fetch origin and tags, inspect the working tree, and verify the branch's
   merge base and ahead/behind state against `origin/main`. Identify the last
   published `vX.Y.Z` tag and review its complete delta to HEAD, including merged
   PRs, against every file in `changes/`. Fragments do not replace range review.
   Reconcile omissions, superseded behavior, and impacts before preparation.
2. Run `cargo xtask release audit`. Check impacts against the actual public CLI,
   JSON, configuration, saved-report, library API, runtime-dependency and
   distribution surfaces. Confirm migration and rollback guidance for changes
   requiring callers to adjust. The highest impact determines the bump; before
   1.0, major means minor. None-only fragments do not trigger a release.
3. Run `cargo xtask release prepare --date YYYY-MM-DD` with the UTC preparation
   date. It updates the root `Cargo.toml` and matching `Cargo.lock` version,
   inserts a dated changelog section, and deletes all consumed fragments.
   Entries are grouped by category and sorted by filename. Curate the new notes
   to describe what actually ships; combine overlapping entries. Preserve dated
   historical sections except for blatant, demonstrable factual corrections.
   Leave README's pinned crates.io examples on the published version until the
   new registry publication is verified.
   If main advances while the release PR is open, integrate it under the
   repository's history rules and reconcile newly arrived fragments into the
   pending release section. Consume them and recheck the aggregate bump against
   the last published version. Do not rerun `prepare` on the already bumped
   manifest, which would calculate another bump from the pending version.
4. Validate with `cargo xtask release audit --release --base-ref origin/main`,
   render `cargo xtask release notes`, inspect the full diff, and verify source
   package contents with `cargo package --locked -p githits-scan --allow-dirty --list`.
   Maintainer tooling and `.agents/` skills are excluded from the source crate.
   Run targeted local checks for changed surfaces; PR CI owns the full gate and
   clean-checkout packaging. `scripts/check.sh` packages the working tree with
   `--allow-dirty` when a complete local gate is explicitly needed.
5. Commit and push preparation, then open a release PR labeled `maintenance`.
   Include the previous tag, bump rationale, range/fragment reconciliation,
   compatibility and rollback notes, exact verification results, and remaining
   execution gates. Report the URL and check status. CI also compares the root
   version to the tested commit's first parent: a bump requires matching
   manifest/lock versions, dated notes and no fragments. A root commit in a
   complete checkout skips that comparison; a missing shallow parent fails.
6. Obtain clean review, green required CI, and separate explicit human approval
   identifying the existing release PR before merging. Earlier release requests
   do not satisfy this gate; do not enable auto-merge as a substitute.
7. After the approved merge, record its full main commit SHA and dispatch
   **Release** from `main` with `release_candidate=true`. Dispatch accepts a
   branch or tag name, not a commit SHA:

   ```bash
   gh workflow run release.yml --repo githits-com/githits-scan \
     --ref main -f release_candidate=true
   ```

   Identify the created run and inspect it with
   `gh run view <run-id> --repo githits-com/githits-scan --json headSha,url`.
   Its `headSha` must equal the recorded release commit SHA. If main advanced,
   review the newer commits: when no fragments remain and notes are still
   complete, record the run's `headSha` as the release SHA; otherwise reconcile
   notes and fragments through a release-preparation PR and rehearse again.
   Never use a run's evidence for a different commit.
   The workflow pins every checkout to its resolved SHA and runs every
   publication gate except tag existence and publication itself. Record the
   matching SHA and run URL on the PR and wait for all jobs before tagging.
8. Obtain explicit authorization for tagging and GitHub publication, then create
   and push `vX.Y.Z` at that rehearsed SHA. The tag must match the root manifest,
   resolve to the checked-out commit, and belong to `origin/main`. Merging alone
   publishes nothing in this repository. Follow the tag workflow through asset
   publication and the automatic Homebrew handoff described above. Crates.io
   publication remains a separate approval and dispatch below.

### First automated release and completion

0.3.0 was published manually; 0.4.0 was the first automated release across
GitHub, Homebrew and crates.io.
Before tagging, verify repository-secret presence by name only, release-tag
protection, and the Homebrew App/environment setup described above. Before the
first crates.io workflow publication, verify owners, trusted publisher and the
protected `crates-io` environment as described below. Do not print secret values.
A successful candidate rehearsal validates builds and API access, but does not
exercise the GitHub, Homebrew or crates.io publication credentials.

Follow the release through each approved channel. Verify that GitHub's tag
resolves to the rehearsed SHA, its notes match the reviewed section, and its
assets contain all five archives plus `SHA256SUMS` with matching checksums.
Confirm the Homebrew formula points to that version and all three bottle jobs
and tap publication succeed; the tolerated handoff failure means a green Scan
run alone is insufficient. For crates.io, verify the exact version is publicly
available and can be installed with the documented pinned Cargo command before
updating the installation examples. After the first successful trusted workflow
publication, check the trusted-publishing-only setting.

Record run links, results, and any incomplete gate on the release PR, including
post-merge evidence. Keep execution logs out of implementation docs. Diagnose
failures before recovery; never move/delete a release tag or overwrite a
published version. Recovery that publishes requires approval for that step.

### First public release

The first public release is 0.3.0. The repository is public. Homebrew is the
recommended install. crates.io is a supported alternative and the registry
publication path. The README pins its Cargo and CI examples to a verified
crates.io release.
The 0.2.0 changelog is retained as a clearly marked pre-public baseline, including
its historical flags. It is not a supported public installation target.

`orca.yaml` and `scripts/orca-setup.sh` are optional development-environment
integration, not required by contributors or releases.

## Rehearsal and release gates

`release.yml` supports tag pushes and validation-only manual dispatch. Checkouts
use its resolved exact SHA. Development dispatch uses validated fragments and
unreleased notes without requiring main membership; release-candidate dispatch
requires consolidated notes and main membership. The latter is mandatory after
merge, because another merged change can add fragments after release-PR checks.

Both modes invoke the full reusable CI workflow, all ignored live API tests,
all five native builds, extracted-binary checks, checksum verification, complete
asset-set verification and note rendering. Only tag pushes can publish. GitHub
notes come from the current version's reviewed `CHANGELOG.md` section, including
security entries, rather than PR labels. The publication job requires every gate
and uploads five archives plus `SHA256SUMS`.

The five live cases make five analysis submissions: audit/remediation, combined
npm/Cargo SBOM, Bun SBOM, manifest resolution, and the license report. Shared
assertions and multi-project fixtures retain coverage within the documented
organisation/project default of five submissions per 60-second window. Use an
organisation/project credential with enough admission and daily budget; a
personal credential's default two-submission window cannot run the full gate.
Other traffic sharing the principal can still exhaust its budget. The gate uses
the ordinary binary: short HTTP 429 refusals recover within five retries and
300 seconds of total waiting per live case. Missing, invalid, over-budget or
exhausted Retry-After recovery fails the gate. Recovery never resubmits an accepted
job or bypasses admission. See the
[service admission policy](https://docs.githits.com/api-reference/v1/experimental/generate-an-sbom-from-uploaded-files).

The live job reads `GITHITS_API_TOKEN` from the repository secret only in its test
step and fails closed when absent. Configure it in GitHub settings; never send it
through chat or put it in command arguments. Repository secrets are available to
trusted repository writers in other workflows too; they are not scoped to one
workflow. Fork PR checks receive no secrets. Main protection and administrator-only
release-tag creation constrain release authority.

| Target | Native runner/build baseline | Archive |
| --- | --- | --- |
| x86_64-unknown-linux-gnu | Ubuntu 24.04 | tar.gz |
| aarch64-unknown-linux-gnu | Ubuntu 24.04 ARM | tar.gz |
| x86_64-apple-darwin | macOS 15 Intel | tar.gz |
| aarch64-apple-darwin | macOS 15 ARM | tar.gz |
| x86_64-pc-windows-msvc | Windows Server 2025 | zip |

Archive validation compares README/LICENSE, checks the extracted binary's version,
and runs token-free `detect` against an isolated Cargo.lock fixture. Compatibility
with older OS versions is not verified. Every action remains pinned by SHA.

Do not move/delete a failed release tag. Diagnose and fix the failure before
retrying publication or deciding how to release a corrected version.

## Crates.io publication

Crates.io distributes the source crate; GitHub distributes native binaries.
`githits-scan` is published on crates.io. Before dispatching `publish.yml`,
verify crate ownership and trusted-publisher configuration; each publication
requires separate explicit approval.

`publish.yml` uses trusted publishing, which requires an existing crate and a
matching trusted publisher configured on crates.io.

1. Verify the intended owners, preferably a GitHub team for ongoing operations.
   Named owners must have logged in to crates.io; team owners can publish/yank,
   while individual owners can also manage ownership.
2. Verify or configure a trusted publisher for `githits-com/githits-scan`, workflow
   `publish.yml`, environment `crates-io`. Create/protect that GitHub environment
   with maintainer approval and permit only release tags matching `v*`. Match its
   name exactly in crates.io. No long-lived registry token belongs in GitHub secrets.
3. For later authorized versions, manually dispatch **Publish to crates.io** from
   the release tag, with the same tag as the `tag` input. Set `release_tag` to the
   approved tag, then run:

   ```bash
   gh workflow run publish.yml --repo githits-com/githits-scan \
     --ref "$release_tag" -f tag="$release_tag"
   ```

   Environment tag restrictions evaluate the workflow run's ref, so dispatching
   from `main` and checking out a tag inside the job does not satisfy them.
   After environment approval, tag/main/changelog checks precede OIDC
   authentication and `cargo publish`; the action revokes its short-lived token
   after the job. Verify the registry version and Cargo installation afterward,
   then update README's pinned crates.io Cargo and CI examples to that published
   version. Homebrew formula updates stay on the tap handoff above. Do not
   republish an existing version to test authentication.
4. After the first workflow publication succeeds, enable the crate's
   trusted-publishing-only setting on crates.io, so API tokens can no longer
   publish new versions. Subsequent publications require a configured trusted
   publisher.

Versions cannot be overwritten; yanking prevents new resolution but does not erase
a version. Never put registry credentials in chat, source, logs or process arguments.

See the official [Cargo publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html),
[credential providers](https://doc.rust-lang.org/cargo/reference/registry-authentication.html),
and [crates.io trusted publishing](https://crates.io/docs/trusted-publishing).
