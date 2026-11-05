# Audit qualification

## Purpose

Qualify the real command and its consumed evidence before claiming support for an
ecosystem, native workspace or deployed service contract. The consumer contract
lives in [audit design](audit.md); this document owns the verification procedure
and the limits of the conclusions. Execution records belong on the PR that made
the change, not here.

## Reproducible inputs and safe execution

Pin each public checkout's commit and record selected file names, input hashes,
binary revision and API origin in the PR evidence. Distinguish default discovery
from explicitly root-scoped or configured-member selection. Do not execute a
project's install scripts or build hooks merely to scan it. Native validation,
when needed to prove an input shape, needs its own narrow scope.

Use the debug binary for functional checks. Follow [authentication](../../README.md#authentication-and-environment)
for private token acquisition into the Scan child environment; never print or
persist credentials. Match the signed-in CLI environment to Scan's explicit API
origin. A development result does not establish production availability.

One accepted job is one analysis: never automatically resubmit a timed-out or
failed job. Preserve admission failures and `Retry-After`; a later invocation is
a separate run. A 429 with no report is an execution result, not a clean audit.

## Check each claim at its owning boundary

| Claim | Required evidence and limit |
| --- | --- |
| Input admission and package identity | Record exact selected evidence and compare source identities/versions with the returned inventory. Compact audit counts alone cannot prove complete package inventory preservation. |
| Coverage and findings | Reconcile summary counts, emitted rows, exclusions and incomplete checks. A report with no vulnerabilities can still return 1 for maintenance findings or gaps. |
| Fix guidance | Verify complete joint alternatives, blockers, independent checks, addressed/remaining findings, material target warnings and copy references. A proposed version does not prove native resolution or advisory accuracy. |
| Native workspace behavior | Qualify shared/member locks, member manifests and unrelated projects separately. Source paths and successful admission alone do not prove membership or installed-build reachability. |
| Rendering change | Use authored binary regressions for copies, cycles, evidence variants, missing trace and unknown observations. Compare human output, JSON, stderr and exit status; use exact filters with nonzero executed counts. |
| Performance | Use a named release-mode benchmark for the changed path. Debug output line/byte counts describe layout only. |

## Saved-analysis replay

Save each accepted analysis once. Replay without a token, with an invalid API
origin and an invalid current-directory configuration to verify the offline
boundary. Inspect every selected vulnerable coordinate in human and JSON modes;
check the original whole-audit exit status and all retained gap details.

For grouped requests, independently account for every source, target copy,
requirement/evidence variant, requester and repeated item. Check immediate/further
placement, finite cycle handling and distance/tie order. Compare ordinary report
and explanation JSON before and after presentation changes. Preserve evidence
outside the repository until the qualification is complete; temporary captures
are not a durable test baseline or a substitute for committed authored regressions.

## Incomplete inputs and remaining qualification

A rejected fixture can be malformed, empty, unsupported or intentionally invalid;
it is not automatically a producer bug. Use explicit root scoping for unrelated
test projects rather than silently excluding arbitrary directory names or
weakening whole-upload admission.

When the service requests additional supported manifests, qualify explicit
`[lockfiles].manifests` selection before claiming full workspace coverage.
Automatic membership and per-path selection causality remain governed by the
[workspace evidence boundary](audit.md#workspace-evidence-boundary).
Old successful runs do not establish coverage for additional manifests.
