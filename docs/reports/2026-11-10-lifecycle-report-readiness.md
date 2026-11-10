# Lifecycle audit report readiness

The readiness investigation is complete; native lifecycle consumer adoption has
not shipped. The producer prerequisite remains absent. Follow-up requirements,
receiving paths and acceptance cases are recorded in the
[repository backlog](../../BACKLOG.md#adopt-native-lifecycle-evidence-after-the-audit-report-contract-exists).

## Qualified boundary

Scan `HEAD` and freshly fetched `origin/main` were identical at
`a4aa952f902fac03ac553757c31b0d895d974d90`; ahead/behind was 0/0. No branch rewrite
or other worktree modification was needed.

The [public OpenAPI](https://api.githits.dev/v1/openapi.json) was fetched without
credentials on 2026-11-10: 1,769,471 bytes, SHA-256
`ac89cfcbb0b18600dc80e5f1ad8f473e3dfe81eee88a1462cc8b9798dae21ad7`.
It exposes audit versions 1/2 and new version-2 submissions, but no native
lifecycle audit findings, independent lifecycle checks, retained warnings or
native event source/scope fields. `AuditDeprecatedFindingV2` contains only
`coordinate`, `paths` and `reason`; version 1 uses `occurrence_ids` instead of paths.
`AuditCoverageV2` contains vulnerabilities, deprecation and outdated checks.
Upgrade reviews likewise expose legacy deprecation evidence, without the native
inspection assessment. The unrelated `DependencyLifecycle` schema describes
dependency groups such as runtime/development, not maintenance or withdrawal.

An authorized read-only review of the then-current service source, exported SDL
and changelog corroborated the missing producer integration: shared preparation
still computes legacy metadata assessments, and the audit projection emits those
legacy findings/coverage. New reports remain version 2. This source review is not
evidence of a production deployment or a submitted audit result.

The current inspection SDL still has `packageInfo.selectedVersion.lifecycle`:
findings, independent checks, retained warnings and content-safety disclosure.
Its category/kind/scope sets and nullable affected/source fields match the supplied
handoff. Both archive checks remain explicitly uncollected. Inspection evidence
does not define an HTTP audit field or a report-version compatibility decision.
The supplied six-case live inspection proof is reused as upstream evidence;
this investigation did not repeat it or claim audit end-to-end verification.

## Publication discrepancy

The fetched public `AuditMetadataCoverage` omits `not_applicable_count` and
`not_applicable_registries`, although the current service contract emits them and
Scan already consumes them optionally. This is a service publication follow-up,
not grounds to remove Scan's existing PyPI applicability support or reinterpret
old reports. Public schemas need to describe the actual producer additions before
contract-dependent generated consumers can rely on them.

## Local verification

The following debug-build regression command executed 12 tests: 12 passed, 762
skipped. These tests protect current behavior; they cannot qualify a lifecycle
report that the producer does not emit.

```sh
cargo nextest run --locked --all-features -E 'test(audit_applicability_) | test(audit_not_applicable_) | test(audit_future_is_identified_and_bad_versions_fail_closed)'
```

The cases cover v1/v2 applicability, mixed checked/NA coverage, retained positive
findings, genuine unknown/failed/uncollected checks, legacy omission, zero
candidates, exact/overflowing partitions, malformed present values, future report
versions and save/offline-replay parity. The investigation record was reviewed
inline against the fetched contract and receiving code. No implementation plan
was declared ready, and no implementation review was claimed.

No runtime source, existing fixture, command flag, exit policy or consumer schema
was changed. No authenticated service request, manual paid analysis, Action
change, merge, release or deployment was performed. There is no adoption PR or
plan-only PR from this investigation.
