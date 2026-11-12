---
"githits-scan": minor
---

- **Neutral non-registry coverage** - Explicit non-registry package exclusions appear as coverage notes and alone no longer fail audit; missing inputs, failed checks, inconsistent evidence and advisories still require attention. Audit JSON keeps its actionable fields; `issues[].reason` for these exclusions now uses an explanatory sentence instead of the short label and diff JSON remains unchanged.
