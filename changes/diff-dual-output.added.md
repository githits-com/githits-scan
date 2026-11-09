---
"githits-scan": minor
---

- **Diff JSON and Markdown from one analysis** - Use `diff --output-json diff.json --output-markdown diff.md` to save exact JSON and Scan-rendered Markdown from the same paired report, or either named output alone; `-` selects stdout for at most one destination. Named outputs conflict with `--format`/`--output`; existing invocations remain unchanged.
