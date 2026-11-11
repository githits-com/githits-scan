# Audit v3 consumer readiness

The native lifecycle audit producer is now qualified and verified in development.
Scan adoption remains unshipped: the public experimental job endpoint still
rejects the `report_version=3` request control. The
[backlog](../../BACKLOG.md#adopt-audit-v3-after-public-version-forwarding-is-available)
owns the remaining prerequisite, receiving paths and consumer acceptance cases.
The [earlier receipt](2026-11-10-lifecycle-report-readiness.md) records the prior
inspection-only contract.

## Contract evidence and limits

Read the delivered service contract, audit-v3 schema and minimal producer fixture
in full. Compared the delivered revision to then-current service main: the audit
producer is unchanged, and all 12 relevant v3/lifecycle schema definitions are
identical. The service contract is OpenAPI 1.20.0. It defines explicit audit-only
v3 opt-in, unchanged default v2, returned-version dispatch and immutable v1/v2
compatibility. Its canonical lifecycle subtree replaces coarse deprecation fields.
Events preserve separate source observations and selected affected coordinates/
paths; unknown checks and collection limits have distinct accounting.

The supplied successful development delivery/verification receipt confirms the
deployed service schema, free inspection canaries and deterministic deployed
rendering for v3, unchanged v2, yank deduplication, affected paths, collection
limits and prepared upgrade lifecycle independent of advisory success. This is
upstream evidence, not a paid end-to-end audit or this consumer's live verification.
No new authenticated service call or paid job was submitted here.

Read-only review of current public gateway source confirms that query controls
admit kind/format only, and multipart admits files plus kind/format. Both paths
reject the report-version control before an audit can request v3. Response-side
handling can preserve future-version bytes; it does not supply missing request
admission. Public API updates remain with their separately assigned owner.

The [public OpenAPI](https://api.githits.dev/v1/openapi.json) was fetched without
credentials on 2026-11-11: 1,769,471 bytes, SHA-256
`ac89cfcbb0b18600dc80e5f1ad8f473e3dfe81eee88a1462cc8b9798dae21ad7`.
It still describes audit v1/v2 and lacks report-version admission. The runtime
blocker is verified in input validation, independently of this publication gap.

## Scan boundary

Fetched Scan main is still `a4aa952f902fac03ac553757c31b0d895d974d90`; this branch
contains only its own readiness documentation commits beyond it. No rewrite or
other worktree change was needed.

Scan currently submits kind/format only. Its decoder treats version 3 as a future
report, renders an incomplete unsupported-version result with exit 1, and does
not forward opaque fields. Saved format 1 currently accepts only producer v2.
The backlog names transport, decoder, assessment, shared view, rendering and
save/replay changes needed after gateway qualification. It records the version-2
response case for a v3 request without resubmitting an accepted job.

The following debug-build command ran 3 existing tests: 3 passed, 771 skipped.
They establish current version-3 unsupported/incomplete behavior, malformed-version
rejection and saved-archive compatibility, not native lifecycle support.

```sh
cargo nextest run --locked --all-features -E 'test(audit_future_is_identified_and_bad_versions_fail_closed) | test(audit_binary_future_report_is_incomplete_without_forwarding_unknown_fields) | test(audit_saved_binary_bad_archives_and_selection_use_usage_exit)'
```

Reviewed the readiness delta inline against the qualified contract and receiving
code. No runtime code, fixture, default gate or schema was changed. No adoption
or plan-only PR, Action change, merge, release or deployment was performed.
