# Open backlog

## Dependency diff causal explanations

The service owns dependency type and upgrade-review interpretation. The current
[public contract](https://api.githits.dev/v1/openapi.json) supplies change-side
occurrence IDs, declaration binding statuses, review eligibility reasons and
per-review failure reasons, but no causal reason for an unknown occurrence's
directness. Reconstructing graph/binding decisions in Scan or the Action would
duplicate service semantics and can blame unrelated missing files.

The required service outcome is an explicit cause at each affected occurrence,
with the associated manifest/dependency or required file when known. Existing
change `before_ids`/`after_ids` should identify those explanations within the
correct snapshot, including multiple occurrences; no extra analysis request or
client-side graph interpretation should be necessary. Reasons must distinguish
incomplete root dependency evidence from unavailable/unmatched declarations and
absent root association. An absent side of an addition/removal is not a failure.

Eligible review rows already retain identity, status and reason. Consumers should
use those rows and returned partial-review details now. The generic
`review_failed` category cannot explain the underlying task failure; preserve a
safe bounded cause at the producer if that explanation is required, without
exporting raw exceptions. Do not infer failed reviews from counters alone.

Acceptance: source-backed fixtures distinguish the unknown-directness causes,
retain side/occurrence/manifest/dependency association, and verify that failed,
unstarted and size-omitted reviews retain their exact tuple and supplied cause.
Known direct/transitive cases remain unchanged, and no unknown becomes a safety
claim. This requires service contract work outside the Scan presentation fix;
no service implementation or release is authorized by that fix.
