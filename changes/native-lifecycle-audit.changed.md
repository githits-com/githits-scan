---
"githits-scan": minor
---

- **Breaking: native lifecycle audits** - Audit now requests report v3 automatically and preserves native deprecation, withdrawal, source observations and affected paths. Native findings, retained warnings and genuine unknown checks require attention; lifecycle collection limits and not-applicable checks alone do not fail. Audit/explanation JSON and saved analysis advance to format 2. Older reports and archives are no longer read: use their recorded Scan writer for offline replay. Unsupported returned versions fail without output or automatic resubmission.
