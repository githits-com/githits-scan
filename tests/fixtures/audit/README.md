# Audit fixtures

`native-findings.json` is authored synthetic audit v3 evidence. It covers native
lifecycle observations, source authority, exact affected coordinates and paths,
common findings, duplicate origins and genuine evidence gaps. Shared builders add
clean, unsupported and collection-limit cases. Lifecycle vocabulary remains open;
tests inject future values and ignored fields. No captured report, token, real
account request ID or proprietary input belongs here.

`remediation.json` is an authored optional envelope using the verified service
contract (2026-10-23), with invented coordinates/advisories. It deliberately carries
unused trace/additional data to prove it never enters compact output. Binary cases
mutate it for joint/partial/conflicting records, future values and invalid types
or references. It contains no live account data.

`blocker.json` is an authored named blocker following the service's optional
`dependency_name` string contract. Binary tests remove the optional field and vary names, requirement status and types. The coordinates are
illustrative; this fixture makes no claim about current advisory applicability.

`live-minimist/` is a 665-byte npm v3 input with one direct `minimist@0.0.8`
dependency and a declared `>=0.0.8 <0.3.0` range. npm registry source/integrity
metadata was verified on 2026-10-23. The fixture is never installed or executed.
Its public advisories allow the ignored live audit test to check an available
`0.2.4` candidate under represented requirements; this is not a native resolver
test.

`graph.json` is an authored v3 example with a direct project request, a parent
request and a joint change set. It contains invented packages/advisory text, not
a captured service report. `analysis.json` wraps the same facts in saved format
2 with producer report 3. Neither fixture contains captured service data.

`change-reasons.json` contains small authored examples of the four known optional
per-change reason variants. Request names deliberately differ from canonical
targets to protect alias/owner distinctions. Tests mutate this data for unknown
codes, malformed consumed fields, omitted trace and partial reason coverage;
these examples make no claim about live advisory applicability.
