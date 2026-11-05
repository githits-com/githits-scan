# Planning Guidelines

## Purpose

This document explains how to create implementation plans that are complete, actionable, and easy for implementers to follow. Plans exist to surface problems before coding begins; a gap discovered during planning costs far less than one discovered during implementation.

Read this before creating or reviewing any plan.

## What Makes a Good Plan

A good plan answers the questions an implementer will have:

- **What problem are we solving?** Not just the feature, but why it matters to a user of the tool or a reader learning the API.
- **What are the key decisions?** Document choices with rationale so future readers understand the "why."
- **What could go wrong?** Surface risks, edge cases, and failure modes upfront.
- **How will we know it's done?** Acceptance criteria that are measurable and outcome-focused.

> **The core question**: After reading this plan, can an implementer proceed without needing to ask clarifying questions?

## Plan Structure

| Section | Purpose |
|---------|---------|
| Problem statement | What we're solving and why it matters |
| Architecture overview | Types, module boundaries, key decisions; structure, not implementation |
| Open issues | Questions that need answers before implementation |
| Implementation phases | Next one or two increments in detail; a finished phase becomes one or two sentences and a link |
| Acceptance criteria | Verifiable conditions for the next one or two increments |

## Writing Good Phases

Each phase should have a **singular objective**: one clear goal, not multiple interleaved concerns.

- Good: "Discovery module producing a validated upload set, with tests" — one boundary, naturally includes its tests
- Bad: "Discovery, API client, and README" — three unrelated concerns

**Phase scope**: Large enough to be meaningful, small enough to complete in one PR. When in doubt, err toward smaller phases.

**Specific deliverables**: List the files to create or modify.

**Error handling**: Every phase should address what happens when things fail, not just the happy path.

## Writing Good Acceptance Criteria

Acceptance criteria determine when one of the next one or two increments is complete. A finished phase does not keep them. They must be:

- **Outcome-focused**: Describe results, not activities
  - Bad: "Write tests for discovery"
  - Good: "A repository with 257 lockfiles fails before any network call with a message naming the limit; tests cover 256 and 257"
- **Measurable**: An implementer can objectively verify completion
- **Edge-case aware**: Include error scenarios and boundary conditions, using an explicit case matrix when behavior varies by input or state

## Assessment Areas

Plans must address these areas. For each, either document the considerations or explicitly state "No concerns — [brief reason]." Skipping an area without explanation suggests incomplete analysis.

### Ownership and Boundaries

State who naturally owns every new concept, module, helper, or stored value and why that layer has the required data and authority. Name a simpler placement if one exists and explain why it is not being used. Confirm there is one canonical path for each identity, normalization, validation, or policy decision.

For changes that resolve inputs, route work, or serve multiple input/state combinations, include an enumerated case matrix:

| Input or state | Required outcome | Verification |
|----------------|------------------|--------------|
| Each distinct case | Exact result or typed failure | Test, fixture, or user-facing check |

Also enumerate changed command-line flags, exit codes, and public library signatures. Justify optional values as real domain states or material, verified optimizations; avoid widening the contract for convenience.

### Security

This tool holds a bearer token and uploads repository files. Every plan must state: where the token is read, that it never appears in output, which files leave the machine, and how paths are validated. Plans that touch the network boundary must state redirect and retry policy.

### Performance

Estimate file reads, bytes buffered, and request count. The API limits (256 files, 5,242,880 bytes per file, 8,000,000 bytes per body, 16,777,216 bytes per response) are the design envelope; say where each is enforced.

Optimization plans must name the existing benchmark for the code path. If none exists, creating and running a release-mode baseline is the first phase.

### Breaking Changes

The command-line contract is public. Document flag, default, exit-code, and output changes, with the `changes/` fragment impact level, a migration note, and a rollback strategy for every risky change. State how users can return to the prior binary or configuration without losing data.

### Testability

Identify which parts are pure functions (easy to test) versus side-effecting (need the `SbomApi` fake or `tempfile`). Plans should specify test isolation patterns; our philosophy is "if it's not tested, it's likely broken."

### Documentation

Note which `docs/implementation/` document records the decisions and whether `README.md` needs an update.

## Common Deficiencies

| Issue | Problem | Fix |
|-------|---------|-----|
| Activity-based criteria | "Write tests" doesn't verify quality | Specify outcomes |
| Happy-path only | Ignores failure modes | Add error handling to each phase; enumerate API problem codes |
| No case matrix | "Handle edge cases" hides distinct state behavior | Enumerate each input/state, exact outcome, and verification |
| Unclear ownership | A value is threaded through layers that do not own it | Name the owner and move the decision to that boundary |
| Loose boundary | Optional fields or widened APIs admit invalid states | Justify or remove each field and confirm one canonical path |
| Implicit dependencies | Assumes an API behavior without checking the contract | Verify against the OpenAPI document; record in Open Issues |
| Scope creep | Phases that do too much | Split into focused phases |
| Missing rollback | No way to undo a risky contract change | Document rollback as well as migration and fragment impact |
| Unresolved assumptions | Open issues left unaddressed | Resolve before implementation; explicitly defer only later-increment unknowns with rationale |

## When to Create a Plan Document

Plan documents are for **multi-PR efforts** that need coordination across sessions or contributors. They hold the current decisions and open work for that effort.

**Create a plan document for:**
- Multi-PR implementation efforts
- Features requiring coordination across multiple sessions
- Command-line contract changes that benefit from written design review

**Use the PR description instead for:**
- Single-PR changes (even complex ones)
- Bug fixes
- Refactoring with clear scope

## Plan Lifecycle

Plans are temporary working artifacts; implementation and guideline docs are
the durable record. Keep a persistent plan available through final
implementation review so reviewers can verify acceptance criteria for the
increments still detailed in the plan. An active plan keeps its open work.
After a clean review:

1. Transfer durable decisions and operating guidance to the owning docs in
   `docs/implementation/` or `docs/guidelines/`.
2. Delete the completed plan as the final substantive change.
3. Inspect the complete diff and search for stale references to the deleted
   plan before the final commit.

Get all plan and documentation changes into the increment's PR before its final push; every extra PR costs review and CI. If the final code head is already pushed and CI has run, do not trigger another full code-PR CI run solely to delete the plan. Transfer its durable content, then remove it in a separate docs-only PR.

If that final inspection exposes an implementation issue, restore the plan,
fix the issue, and repeat the review before deleting it again.

## Keeping Plans Compact

A plan holds only what an implementer needs next: current scope, verified
assumptions, decisions with rationale, and open work. Detail only the next
one or two increments, including acceptance criteria for those increments.

- At each phase boundary, replace the finished phase with one or two sentences
  of outcome and a link to the durable doc section that now owns it.
- Never append execution, review, rollout, or run histories, dated status
  sections, delivery records, or any recorded status or state. Delivery and
  verification belong in the PR description. Verification without a PR uses a
  receipt. Evidence does not live in `docs/plans/`. The plan keeps only the
  outstanding gate plus a receipt or owner link. See
  [Documentation maintenance](DOCUMENTATION_GUIDELINES.md#maintenance).
- Remove superseded instructions instead of marking them superseded.
- A plan over 100 KB needs compaction before the next increment; one over
  250 KB should be split or retired. Projects may set tighter limits.

When a plan is retired before completion, use the transfer in [Plan Lifecycle](#plan-lifecycle), then delete the plan in that PR.

<!-- conventions: v2.0.2 -->
