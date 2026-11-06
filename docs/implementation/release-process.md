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
or `release_candidate` dispatches. Failure is tolerated independently of the
already published release. The App token is passed through the step environment
to `gh`; the handoff never puts it in process arguments or writes it to disk.

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
bottle artifacts, then apply `pr-pull`. The initial 0.3.0 PR uses this path.
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
   reviewer approval for unattended post-tag delivery. An approval gate would
   make the handoff wait for a person. The implementation does not change Scan's
   settings or create environment secrets. Never put the key in chat, source,
   logs or process arguments.
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

## Mintlify changelog drafts

After successful tagged GitHub publication, the final job in `release.yml` calls
`mintlify-changelog-trigger.yml`. It does not wait for Homebrew approval and never
runs for release rehearsals or `release_candidate` dispatches. The called workflow
also supports independent `workflow_dispatch`; its optional `version` input is
for logging only and is not sent to Mintlify. Both entrypoints grant no GitHub
token permissions and execute no checked-out repository code.

Configure these in **githits-com/githits-scan > Settings > Secrets and variables >
Actions**, at repository level:

- Secret `MINTLIFY_API_KEY`: a Mintlify admin API key with write scope and an
  expiry. Set its IP allowlist to the same fixed egress ranges used by the CLI
  runner when creating the key; changing the allowlist requires a replacement key.
  See [Mintlify API authentication](https://www.mintlify.com/docs/api/introduction).
- Variable `MINTLIFY_PROJECT_ID`: the same project as githits-cli.
- Variable `MINTLIFY_DRAFT_CHANGELOG_WORKFLOW_ID`: the same Draft changelog
  automation as githits-cli. Scan shares that automation; no separate workflow ID
  is needed. Keep its trigger on a custom schedule, as required by the
  [Mintlify trigger API](https://www.mintlify.com/docs/api/automations/trigger).

Keep all three settings at repository level and configure them before testing.
A repository secret matches the release workflow's
existing API secret setup and avoids an environment approval before even an
unconfigured skip. Neither `crates-io` nor `homebrew-tap` owns this integration;
no new environment is required. Repository writers can use repository secrets in
other workflows too.

The job uses `aks-deployment-runner` for fixed egress allowed by the Mintlify key.
Ensure Scan has access to that runner's group, including access for this public
repository. A missing setting emits a notice and skips the request; HTTP failures
are tolerated with `continue-on-error`, bounded timeouts and retries. Runner
availability is separate: without a matching accessible runner the job can stay
queued and eventually fail the workflow after publication has succeeded.

After this workflow reaches `main`, test without creating a release:

```bash
gh workflow run mintlify-changelog-trigger.yml --repo githits-com/githits-scan \
  --ref main -f version=manual-check
```

This creates a real Mintlify automation run. Inspect the trigger step for a skip
notice or request error and confirm a Draft changelog run appears in Mintlify and
covers Scan. A green GitHub workflow alone does not prove the tolerated request
succeeded. This check also verifies runner access, key allowlisting and the
shared automation's scope.

## Preparation and approval

1. Run `cargo xtask release audit` during development. CI also compares the root
   version to the tested commit's first parent; a version bump requires a complete
   release with matching manifest/lock versions, dated notes and no fragments.
   A root commit in a complete checkout has no earlier version, so the comparison
   is skipped; a shallow checkout without the parent still fails.
2. Run `cargo xtask release prepare --date YYYY-MM-DD`, supplying the UTC date.
   The maximum fragment impact determines the bump; before 1.0, major means minor.
   None-only fragments do not trigger a release. Entries are grouped by category
   and sorted by filename. Review and curate the generated notes to describe the
   behavior that actually ships, then open a release PR; its CI runs the full gate
   and packages a clean checkout. `scripts/check.sh` packages the working tree with
   `--allow-dirty` for a contributor who runs the gate locally.
3. Obtain clean review and green required CI before merging. After merge, dispatch
   **Release** on that exact main commit with `release_candidate=true`. This runs
   every publication gate except tag existence and publication itself. Wait for
   all jobs to pass before creating an immutable version tag.
4. With explicit authorization for tagging and GitHub publication, tag that tested
   commit `vX.Y.Z` and push it. A tag must match the root manifest, resolve to the
   checked-out commit, and belong to `origin/main`.

Preparing a PR alone does not authorize merge, tag or publication. A maintainer's
explicit authorization may cover those steps conditionally on clean review and
successful checks. Crates.io publication is always a separate decision.

### First public release

The first public release is 0.3.0. The repository is public. Homebrew is the
recommended install. crates.io is a supported alternative and the registry
publication path. The README pins its CI example to
[crates.io 0.3.0](https://crates.io/crates/githits-scan/0.3.0).
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
Other traffic sharing the principal can still exhaust its budget. The gate fails
on 429; it does not delay, retry, resubmit or bypass admission. See the
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
`githits-scan` 0.3.0 is published on crates.io. Before dispatching `publish.yml`,
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
