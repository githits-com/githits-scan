---
"githits-scan": patch
---

- **Git license exceptions in CycloneDX** - `license check` now uses source-owned
  VCS references to match Git exceptions when a CycloneDX document omits the
  legacy source locations property. A withheld alternative source location
  still blocks the exception.
