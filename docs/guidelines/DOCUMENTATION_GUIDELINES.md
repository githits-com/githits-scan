# Documentation Guidelines

## Audience

Users and API integrators need installation, usage, and contract references.
Contributors need design rationale, ownership, and verifiable procedures.
Write each page so a newcomer can find the relevant facts without knowing
project history or a particular development workflow.

## Writing Principles

### Focus on Intent and Explanation

Explain _why_ patterns exist, not just _how_ they work. A reader should understand:

- What problem the pattern solves
- Why this approach was chosen over alternatives
- When to use it versus other options

Avoid catalogue-style documentation that lists facts without context.

### Frontload Understanding

Put the most important context first:

1. **Purpose**: what this document explains
2. **Background**: why things are the way they are
3. **Decision criteria**: how to choose between options
4. **Implementation details**: the mechanics
5. **References**: files to explore further

A reader who stops halfway should still have gained the core understanding.

### Use References, Not Code Dumps

Point to canonical implementations rather than copy-pasting code:

**Prefer**: "See `src/catalog.rs` for the rule table and classification pattern"

**Avoid**: Embedding 50 lines of code that will drift out of sync

Brief code snippets (under 10 lines) are acceptable when they illustrate a specific concept that's hard to explain in prose. Keep them conceptual; link to canonical files for complete types and implementations instead of maintaining a second implementation in prose.

### Assume Library Familiarity

Readers likely know common Rust libraries (`clap`, `reqwest`, `serde`, `ignore`). Don't explain what these are.

Do explain our patterns and conventions for using them: why redirects and retries are disabled, why the walker skips hidden directories, why the response is read with a byte cap.

### Cite the Contract, Not a Sibling Repository

The GitHits API contract is documented publicly at `https://docs.githits.com` and in `https://api.githits.dev/v1/openapi.json`. Cite those. Never reference a private repository path or quote proprietary source in this public repository's documentation.

### Enable Good Decisions

After reading, a contributor should be able to:

- Choose the appropriate pattern for a new task
- Understand why existing code is structured a certain way
- Know where to look for reference implementations

### Highlight Critical Rules

If there's one thing readers must not forget, call it out explicitly:

> **Never resubmit an accepted analysis automatically.** Only explicit HTTP 429 refusals receive bounded Retry-After recovery; a new accepted submission recomputes and consumes quota.

### Use Tables for Reference Material

Tables work well for information humans will look up later: file names per ecosystem, error codes and actions, environment variables. Keep prose for explanation, tables for enumeration.

## Document Structure

```markdown
# Topic Name

## Purpose

One paragraph: what this document explains and why it matters.

## Background

Context and decision rationale for why current patterns exist.

## [Core Concepts / Patterns / Architecture]

The main content: explanations, decisions, trade-offs.

## How to Choose / When to Use

Decision criteria for the reader.

## Implementation

How to apply the patterns, brief, with references to examples.

## Troubleshooting (if applicable)

Common issues and how to resolve them.

## Related Documentation

Links to related docs.

## Key Reference Files

Table of files to explore, with what each demonstrates.
```

## What to Document

Prioritize topics where:

- Decisions aren't obvious from reading code alone (why `Pipfile` is not uploaded, why `go.mod` is not paired)
- Multiple valid approaches exist and we've chosen one (automatic owning-manifest pairing versus explicit selection of unrelated inputs)
- Decision rationale explains current patterns
- Mistakes are common without guidance

Low-value documentation:

- Restating what code clearly shows
- API references that duplicate rustdoc
- Step-by-step tutorials for simple tasks

## Where Documentation Lives

| Location | Content |
| --- | --- |
| `README.md` | User-facing: what the tool does, usage, authentication, installation |
| Rustdoc (`///`) | Every public item; the crate is a library as well as a binary |
| `docs/implementation/` | Durable decisions: API contract as the client sees it, package-file catalog provenance, repository foundation |
| `docs/plans/` | Current multi-PR scope and open work; compact at phase boundaries, delete after completion |
| `changes/` | Unreleased changelog fragments; consolidated into `CHANGELOG.md` at release |
| `AGENTS.md` | Coding-assistant instructions for contributors using automation |

## Maintenance

Plans and durable documents stay compact by replacing stale content, not by
appending a history of the work.

- **Plans** follow [Keeping Plans Compact](PLANNING_GUIDELINES.md#keeping-plans-compact) and
  [Plan Lifecycle](PLANNING_GUIDELINES.md#plan-lifecycle).
- **Durable docs** explain current behavior, contracts, ownership, and why the
  current design exists. Edit the relevant section in place. Retain a rejected
  alternative only when its rationale still constrains present decisions.
  Do not append per-increment summaries, execution or review transcripts,
  command output, repeated benchmark runs, or superseded designs.
- **Evidence** belongs on the PR that made the change (as a comment even after
  merge), in workflow artifacts, or, when there is no PR, a small receipt under
  `docs/reports/` or `docs/analysis/`. A receipt records the conclusion, exact
  revision, run URL, and hashes needed to verify it. Where that record already
  exists, link a SHA-pinned permalink instead of copying it. Do not copy the
  run history into a plan or implementation doc. A successful run changes no
  durable docs; open a docs PR only when execution reveals a real change to
  architecture, procedures, or operational constraints.
- **Contracts** have one canonical topic document. Contributor instructions retain
  critical invariants and direct readers to the relevant section. Before adding
  a document, check for an existing owner; consolidate overlapping wording and
  link to it rather than maintaining a second full contract.

When code changes, update documentation if:

- The "why" has changed
- Decision criteria are now different
- New options exist that readers should know about

Don't update documentation just because implementation details changed; references to files still work, and the concepts remain valid.

### Stale Reference Prevention

When renaming or deleting a documentation or plan file:

1. Search source code for the old path; rustdoc often references files by name.
2. Search the documentation tree for inbound links and mentions.
3. Update `AGENTS.md`'s project structure and any index.
4. Repeat the search before committing and confirm no stale references remain.

Use `rg` and inspect matches; do not assume a successful rename updates prose references.

<!-- conventions: v2.0.2 -->
