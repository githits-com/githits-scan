## Summary

<!-- What changed, and why is this the smallest correct change? -->

## Verification

<!-- List the exact checks run and their results (scripts/check.sh output, targeted tests). -->

## Compatibility and documentation

<!-- Review reports/fixtures for credentials, private paths, and package names before attaching. -->

- [ ] The command-line contract (flags, exit codes, output streams) is unchanged, or the change has a `changes/` fragment and a test in `tests/cli.rs`.
- [ ] Network behavior follows `docs/implementation/sbom-api-contract.md` (no unconditional retries, limits enforced before upload, credentials never logged).
- [ ] Durable implementation documentation is unchanged, or updated with the new decision criteria.
