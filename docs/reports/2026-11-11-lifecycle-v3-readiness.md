# Audit v3 consumer readiness

The native lifecycle producer and public gateway contracts are qualified. The
gateway admission blocker is removed, with delivery and free inspection smoke
verified in development and production. Scan adoption remains unshipped. The
[implementation plan](../plans/native-lifecycle-audit.md)
owns the remaining consumer work, receiving paths and acceptance cases.
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

Read the deployed gateway's lifecycle contract and admission implementation.
The public experimental job endpoint now accepts audit-only `report_version=2`
or `3` through query or multipart text. Each input is validated independently;
multipart takes precedence only after validation. Omission preserves default v2.
Clients inspect the returned version, including v2 in response to a v3 request;
retained v1/v2/v3 bytes keep their original meanings and future versions 4+ remain
opaque. Native response vocabularies remain open.

The supplied gateway delivery receipt confirms both strict deployed smoke jobs,
free lifecycle inspection smoke in development and production, and matching
served schemas. Audit forwarding/result handling and upgrade lifecycle have
reviewed deterministic router/provider/producer-fixture and CI coverage. This
does not establish a paid live audit, diff or Scan run. No upstream approval is
treated as merge, release, publication or deployment authorization for Scan.

The [public OpenAPI](https://api.githits.dev/v1/openapi.json) was fetched without
credentials on 2026-11-11: 1,804,616 bytes, SHA-256
`ecd39dbc10f8244deb9d7b0a606756b75e6ce4541b349a39ec81388ba27149ea`.
The hash exactly matches the supplied gateway verification receipt. The fetched
document describes query and multipart version controls, audit v3 and opaque
future versions from 4. Runtime admission was independently checked in source.

## Scan boundary

Fetched Scan main is still `a4aa952f902fac03ac553757c31b0d895d974d90`; this branch
contains only its own readiness documentation commits beyond it. No rewrite or
other worktree change was needed.

Scan currently submits kind/format only. Its decoder treats version 3 as a future
report, renders an incomplete unsupported-version result with exit 1, and does
not forward opaque fields. Saved format 1 currently accepts only producer v2.
The implementation plan names transport, decoder, assessment, shared view, rendering and
save/replay changes still needed in Scan. It records the version-2 response case
for a v3 request without resubmitting an accepted job. Explicit consumer version
selection, positive-warning exit policy and archive compatibility are now settled
by Juha's breaking-change direction in that plan; this receipt remains evidence
of the pre-implementation state, not a separate source of product decisions.

Before this gateway evidence update, the following debug-build command ran 3
existing tests: 3 passed, 771 skipped. Runtime code is unchanged, so the tests
were not repeated for this documentation-only update.
They establish current version-3 unsupported/incomplete behavior, malformed-version
rejection and saved-archive compatibility, not native lifecycle support.

```sh
cargo nextest run --locked --all-features -E 'test(audit_future_is_identified_and_bad_versions_fail_closed) | test(audit_binary_future_report_is_incomplete_without_forwarding_unknown_fields) | test(audit_saved_binary_bad_archives_and_selection_use_usage_exit)'
```

Reviewed the readiness delta inline against the qualified contract and receiving
code. No runtime code, fixture, default gate or schema was changed. No adoption
or plan-only PR, Action change, merge, release or deployment was performed.
