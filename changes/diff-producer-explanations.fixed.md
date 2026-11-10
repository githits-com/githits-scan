---
"githits-scan": patch
---

- **Explain dependency comparisons clearly** - Human and Markdown reports explain incomplete dependency information, file problems and upgrade-review failures in plain language, with useful context and supported next steps. Internal codes, status tuples and diagnostic counters stay in unchanged JSON; repeated file-wide explanations are grouped.
- **Include Bun workspace evidence** - Declared workspace member manifests now accompany `bun.lock` across commands, including diff and lockfiles-only scans, so complete monorepos do not become incomplete comparisons solely through omitted members.
- **Keep large comparisons readable** - Repeated project-wide advisory uncertainty and identical before/after file problems are grouped without hiding known risks. Empty sections are omitted and ordinary accents and emoji selectors remain readable while controls stay escaped.
