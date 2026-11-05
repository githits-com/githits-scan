# Audit fixtures

`findings.json` is an authored v1 report; `openapi-example.json` is the prior public
v1 example. Retain them to protect the supported v1 path.

`v2-findings.json` is authored synthetic data following the public v2 report
contract. It covers all categories, exact recorded and missing requirements, group-level unattributed
requirements, and distinct advisory/metadata/source/resolution/exclusion gaps.
Shared builders add clean and unsupported/not-collected cases without live data.

The v2 contract was verified against the public OpenAPI 1.1.0 document.
Source strings/fields are open; tests deliberately inject future values and ignored
fields. No token, real account request ID or proprietary input belongs here.

`remediation.json` is an authored optional envelope using the verified service
contract (2026-10-23), with invented coordinates/advisories. It deliberately carries
unused trace/additional data to prove it never enters compact output. Binary cases
mutate it for joint/partial/conflicting records, future values and invalid types
or references. It contains no live account data.

`live-minimist/` is a 665-byte npm v3 input with one direct `minimist@0.0.8`
dependency and a declared `>=0.0.8 <0.3.0` range. npm registry source/integrity
metadata was verified on 2026-10-23. The fixture is never installed or executed.
Its public advisories allow the ignored live audit test to check an available
`0.2.4` candidate under represented requirements; this is not a native resolver
test.

`graph.json` is an authored v2 example with a direct project request, a parent
request and a joint change set. It contains invented packages/advisory text, not
a captured service report. `analysis-v1.json` wraps the same facts in saved format
1 and is a compatibility fixture; new optional projection fields must not make it
unreadable. Both use synthetic evidence and remain compatibility fixtures.
