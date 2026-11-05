# Unreleased Changelog Fragments

Normal pull requests record each notable user-visible change in a new file
instead of editing `CHANGELOG.md`. Use:

```text
changes/<pr-number-or-unique-slug>.<category>.md
```

Valid categories are `added`, `changed`, `deprecated`, `removed`, `fixed`, and
`security`. Use a lowercase, hyphenated unique name and this exact structure:

```markdown
---
"githits-scan": patch
---

- **Short title** - Describe the user-visible behavior and important rollout or
  compatibility impact.
```

The impact is `none`, `patch`, `minor`, or `major` for the `githits-scan`
binary. Command-line contract changes (flags, exit codes, output streams,
default behavior) are at least `minor` before 1.0 and `major` after it. Keep the
body to one concise Markdown bullet. Normal PRs do not edit another change's fragment. Release-note curation may
merge or rewrite overlapping unreleased fragments to describe the final behavior.
A breaking-change entry may use indented migration subheadings under its bullet.

A pull request that fully reverts an unreleased change removes that change's
fragment instead of adding a release note for behavior that will not ship.

A release PR computes the highest bump across fragments, groups entries by
category into a new versioned `CHANGELOG.md` section, and deletes the consumed
fragments. A fragment with `none` impact documents repository or release
operation changes; it does not trigger a release and is consumed into the next
release.

Run `cargo xtask release audit` to validate fragments. Prepare deterministically
with `cargo xtask release prepare --date YYYY-MM-DD` (UTC date), then review the
result. Malformed inputs are rejected before edits; I/O failures leave a visible
partial diff to inspect. Multi-line bullet continuations must be indented.

Preparing a release PR alone does not authorize merge, tag, or publication.
Those steps require explicit user authorization, which may condition them on
clean review and green checks. See `docs/implementation/release-process.md`.
