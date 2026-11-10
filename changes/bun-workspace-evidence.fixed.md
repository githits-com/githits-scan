---
"githits-scan": minor
---

- **Include Bun workspace evidence** - Declared workspace member manifests now accompany `bun.lock` across upload commands and detect previews, including lockfiles-only scans, so complete monorepos do not become incomplete comparisons solely through omitted members. This expands the default upload selection; existing exclusions and upload limits still apply.
