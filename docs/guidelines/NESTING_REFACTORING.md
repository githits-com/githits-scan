# Reducing Nesting Depth

## Goal

Keep control-flow nesting inside a function at no more than two levels. The
greenfield lint profile also enforces function line, argument, and structural
nesting tripwires; see `ARCHITECTURAL_GUIDELINES.md` for the canonical settings.

Clippy's nesting count includes item and module structure, so a finding is a
prompt to inspect the boundary, not an instruction to flatten sound modules.
Do not use Clippy's `cognitive_complexity` lint as a quality metric.

## Common Patterns & Fixes

### 1. Nested `match` statements → Expose the next cohesive phase

Only extract a helper when the block has a nameable responsibility and narrow inputs. In [Discovery](../../src/discover.rs), `scan` collects candidates and `pair` turns the grouped candidates into an inventory. Each owns a distinct phase. If a helper needs most of the caller's local state, check ownership before moving lines.

### 2. Nested `Result` chains → Propagate with `?`

[Environment resolution](../../src/env.rs) separates acquisition from validation:

```rust
let token = parse_token(source(TOKEN_VARIABLE))?;
let origin = match source(ORIGIN_VARIABLE) {
    Some(value) => parse_origin(&value.to_string_lossy())?,
    None => parse_origin(api::DEFAULT_ORIGIN)?,
};
Ok(Environment { token, origin })
```

Keep the typed error and useful context; do not add a fallback to flatten control flow.

### 3. Nested conditionals → Use early returns

The private `parse_origin` in [src/env.rs](../../src/env.rs) rejects an invalid authority before parsing:

```rust
if authority.contains(['/', '\\', '?', '#', '@']) {
    return Err(EnvError::InvalidOrigin);
}
```

### 4. Nested `Option` handling → Use `?` and combinators

Use `ok_or` for a required value, as `parse_origin` does:

```rust
let host = url.host().ok_or(EnvError::InvalidOrigin)?;
```

Use `and_then`, `filter`, or `map` for a genuinely optional chain only when it remains clearer than an explicit `match`.

## Quick Checklist

1. **Identify the deepest block and its owner** - decide whether it is a local
   condition, a separate phase, or evidence that the function spans boundaries
2. **Prefer guard clauses first** - remove exceptional paths with early returns
3. **Name helpers by responsibility** - avoid vague names that only relocate code
4. **Pass only the helper's cohesive inputs** - many borrowed locals mean the
   proposed boundary is probably wrong
5. **Use guards in match arms** - `Some(x) if predicate(x)` instead of nested `if`
6. **Prefer `?` for Result/Option propagation** - do not erase useful error context
7. **Use combinators when the chain remains clearer than a loop or `match`**

## Rust-Specific Patterns

### Use `let-else` for early rejection

The private `parse_token` in [src/env.rs](../../src/env.rs) handles absence before processing the value:

```rust
let Some(value) = value else {
    return Err(EnvError::MissingToken);
};
```

### Choose combinators by responsibility

Use `bool::then` or `then_some` for conditional optional construction; the latter eagerly evaluates its value. Use `Iterator::find_map` to stop at the first extracted value. See `select_recommendations` in [Saved-analysis rendering](../../src/commands/audit/saved.rs) for `filter_map` when every matching recommendation must be retained. Do not replace explicit control flow with a harder-to-read chain merely to reduce indentation.

## Running the Check

```bash
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

<!-- conventions: v2.0.2 -->
