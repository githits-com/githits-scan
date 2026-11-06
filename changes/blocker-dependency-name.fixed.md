---
"githits-scan": patch
---

- **Identify blocked dependencies** - Audit remediation blockers now show the dependency requested by each owner when the service supplies its name, and preserve `dependency_name` in JSON and saved analyses. Older reports keep their existing blocker structure; provider-bound requirements now use a readable label.
