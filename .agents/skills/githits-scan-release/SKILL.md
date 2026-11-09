---
name: githits-scan-release
description: Prepare or review a githits-scan release PR, reconcile changelog impact, or follow an approved release through GitHub, Homebrew, and crates.io.
metadata:
  internal: true
---

# Scan releases

This is a repository-local maintainer workflow, excluded from the published crate.

Read `AGENTS.md`, `docs/implementation/release-process.md`, and `changes/README.md`
from the repository root. The release-process document owns policy; this skill
guides execution. Use the existing `cargo xtask release` commands, not a parallel
version or changelog generator. Only the root `githits-scan` package is released;
`xtask` stays unpublished.

## Prepare the release PR

1. Inspect the working tree, fetch origin and tags, and verify the branch's merge
   base and ahead/behind state against `origin/main`. Preserve unrelated work;
   follow repository authorization rules before rebasing.
2. Identify the last published `vX.Y.Z` tag. Review its complete delta to HEAD
   and the merged PRs against every pending fragment. Resolve missing entries,
   incorrect impacts, superseded behavior, and migration requirements before
   calculating a version. Fragments alone are not the range audit.
3. Run `cargo xtask release audit`. Verify the maximum impact against the public
   CLI, JSON, configuration, saved reports, library API, runtime dependencies,
   and distribution changes. Before 1.0, a major impact becomes a minor bump;
   none-only fragments cannot trigger a release.
4. Run `cargo xtask release prepare --date YYYY-MM-DD` with the UTC preparation
   date. Inspect the manifest and lockfile diff, curate the new changelog section,
   and ensure all consumed fragments are removed. Preserve historical sections
   except for demonstrable factual corrections. Do not advertise a pending
   version in pinned crates.io install examples before registry publication.
5. Run `cargo xtask release audit --release --base-ref origin/main` and
   `cargo xtask release notes`. Verify package contents with
   `cargo package --locked -p githits-scan --allow-dirty --list`; maintainer skills
   and tooling must stay excluded. Use targeted local checks for changed surfaces and leave
   the full workspace/platform checks to PR CI. Documentation and metadata
   changes receive inline review under the repository review guidelines.
6. Commit with a Conventional Commit title and explanatory body, push, and open
   the release PR with the `maintenance` label. Include the previous tag, version
   rationale, range reconciliation, compatibility/rollback guidance, exact
   verification results, and remaining release gates. Report its URL and checks.

Release preparation authorizes delivery through the open PR only. Do not merge
or enable auto-merge without separate explicit approval identifying the existing
PR. Tagging, GitHub publication, and crates.io publication require their own
explicit approvals. A request to follow the release to completion means track
every stage and bring the next approval when ready; it does not bypass a gate.

## Follow the automated release

- Once the approved PR merges, resolve its exact main SHA. Dispatch the **Release**
  workflow at that SHA with `release_candidate=true`; it validates without
  publishing. Wait for every gate, including live API tests and five native
  archives. If main changes, recheck that the selected commit has complete notes
  and no fragments. Record the tested SHA and run URL on the PR.
- Before the first automated publication, verify the configured repository
  secret's presence by name only, release-tag protection, Homebrew App/environment
  wiring, and crates.io ownership/trusted publisher/environment settings. The
  manual 0.3.0 release does not prove those integrations work. Never display
  secret values or acquire credentials just to inspect setup.
- After exact-step approval for tagging and GitHub publication, tag and push
  only the rehearsed SHA. Follow the tag workflow to its published release,
  verify all five archives and `SHA256SUMS`, and compare the public notes with
  the reviewed changelog. Follow the automatic Homebrew handoff and tap bottle
  publication too: its tolerated failure can leave the Scan workflow green.
- Dispatch **Publish to crates.io** only after separate publication approval,
  from the release tag with the matching `tag` input. Follow environment approval,
  trusted authentication, and registry publication. Verify the exact public
  version and a pinned Cargo installation; then update pinned installation
  examples through a normal PR. Check the trusted-publishing-only setting after
  the first successful workflow publication.
- Diagnose a failed stage before retrying. Never move/delete a release tag or
  reuse a published version. Follow the owning document's recovery procedure;
  a rerun that publishes still needs authorization for that publication.

Keep run URLs, approved actions, results, and incomplete gates on the release PR.
Update durable docs only when execution changes the procedure or its constraints.
Completion means the approved distribution channels are verified, not merely
that a workflow returned success. If blocked on approval or external setup,
report the exact remaining action and keep the release task open.
