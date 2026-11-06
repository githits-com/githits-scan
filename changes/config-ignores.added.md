---
"githits-scan": minor
---

- **Reviewed policy exceptions** - License checks accept exact named Git-source exceptions with optional full revisions and expose safe source selectors in failure details/JSON. Advisory ignores retain findings and reasons in JSON/text and saved replay without causing failure themselves; all other audit categories and evidence gaps remain strict. License-exception reasons must now be nonblank. Remove new configuration entries before using an older binary; older archive readers may return stricter results. No version bump is included.
