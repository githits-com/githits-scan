---
"githits-scan": minor
---

- **Recover from short rate limits** - Retry HTTP 429 up to five times across each scan, honoring Retry-After within five minutes of total waiting, and report every retry on stderr even in quiet or JSON mode. Missing, invalid or over-budget delays still fail promptly.
