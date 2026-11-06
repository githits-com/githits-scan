# Release process

The root crate is the distributable application. The unpublished `xtask` member
owns release policy and uses the same locked dependencies and strict checks.
Actions owns testing, native builds and publication. No release command is added
to the shipped scanner.

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
   behavior that actually ships. Update README's pinned crates.io installation
   examples to the new version and open a release PR; its CI runs the full gate
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

The first public release is 0.3.0, available on
[crates.io](https://crates.io/crates/githits-scan/0.3.0). The repository is public,
and the README uses crates.io as the primary Cargo installation method.
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
   and restrict deployment refs to release tags before using it. Match its name
   exactly in crates.io.
3. For later authorized versions, manually dispatch **Publish to crates.io** with
   an actual release tag. Its tag/main/changelog checks precede OIDC authentication
   and `cargo publish`; the action revokes its short-lived token after the job.
4. After the first workflow publication succeeds, enable the crate's
   trusted-publishing-only setting on crates.io, so API tokens can no longer
   publish it and every version comes from `publish.yml`.

Versions cannot be overwritten; yanking prevents new resolution but does not erase
a version. Never put registry credentials in chat, source, logs or process arguments.

See the official [Cargo publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html),
[credential providers](https://doc.rust-lang.org/cargo/reference/registry-authentication.html),
and [crates.io trusted publishing](https://crates.io/docs/trusted-publishing).
