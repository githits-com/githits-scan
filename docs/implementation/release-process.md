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
   behavior that actually ships. Update README's tagged Git installation example
   to the new version and open a release PR; its CI runs the full gate and
   packages a clean checkout. `scripts/check.sh` packages the working tree with
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

The first public release is 0.3.0. The 0.2.0 changelog is retained as a clearly
marked pre-public baseline, including its historical flags. It is not a
supported public installation target.

Repository protection, release secrets, private vulnerability reporting, and
publication environments are GitHub settings; they do not travel with Git files.

`orca.yaml` and `scripts/orca-setup.sh` are optional development-environment
integration retained in the repository, not required by contributors or releases.
They are excluded from the crates.io source package.

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
Crates.io publication always needs separate approval for the exact version.
Versions cannot be overwritten; yanking prevents new resolution but does not
erase a version.

Trusted publishing requires an existing crate. A new crate's first version must
be published manually from its reviewed release tag with a verified-email
maintainer account and local Cargo credentials. Use an operating-system credential
provider or interactive login; never put a token in chat, source, logs or process
arguments. Remove or revoke bootstrap credentials when no longer needed.
Named crate owners can manage ownership; GitHub team owners can publish and yank.

The publishing contract is:

- The crates.io trusted publisher identifies `githits-com/githits-scan`, workflow
  filename `publish.yml`, and environment `crates-io`.
- The GitHub environment `crates-io` requires maintainer approval and permits only
  release tags matching `v*`. Its name must match the crates.io configuration.
- `publish.yml` requests an OIDC token and exchanges it for a short-lived registry
  token. No long-lived crates.io token belongs in GitHub secrets.

For an authorized release:

1. Use an existing release tag whose GitHub release gates passed. Inspect
   `cargo package --locked -p githits-scan` from that tag before publication.
2. Dispatch **Publish to crates.io** from that release tag, with the same tag as
   the `tag` input. For example, set `release_tag` to the approved tag, then run:

   ```bash
   gh workflow run publish.yml --repo githits-com/githits-scan \
     --ref "$release_tag" -f tag="$release_tag"
   ```

   Environment tag restrictions evaluate the workflow run's ref, so dispatching
   from `main` and checking out a tag inside the job does not satisfy them.
3. Approve the environment job. Its tag/main/changelog checks precede OIDC
   authentication and `cargo publish`; the action revokes its short-lived token
   after the job. Verify the registry version and installation afterward, then
   update README's crates.io installation examples to that published version.
   Do not republish an existing version to test authentication.
4. After the first workflow publication succeeds, enable the crate's
   trusted-publishing-only setting on crates.io, so API tokens can no longer
   publish it. This gates subsequent versions on configured trusted publishers.

See the official [Cargo publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html),
[credential providers](https://doc.rust-lang.org/cargo/reference/registry-authentication.html),
and [crates.io trusted publishing](https://crates.io/docs/trusted-publishing).
