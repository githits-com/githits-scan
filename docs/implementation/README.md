# Client contracts and design

These documents describe the public client's behavior, architecture, and
maintenance procedures. They are useful for contributors and API integrators;
they do not document the service's implementation. Start with the
[README](../../README.md) for installation and everyday use.

| Topic | Contract |
| --- | --- |
| [Command model](command-model.md) | Commands, streams, exit codes, and ownership |
| [JSON output](json-output.md) | Versioned command reports and replay formats |
| [Discovery](discovery.md) | Walking, pairing, workspace evidence, and detect |
| [Package-file catalog](package-file-catalog.md) | Accepted filenames and deliberate omissions |
| [Configuration](configuration.md) | Selection, exclusions, drift, and saving |
| [API boundary](sbom-api-contract.md) | HTTP requests, credentials, limits, and errors |
| [SBOM generation](sbom-generate.md) | Upload preparation and document output |
| [Dependency diff](dependency-diff.md) | Experimental Git comparison, direct upgrades and evidence gaps |
| [Audit](audit.md) | Findings, coverage, fix evidence, and saved analyses |
| [Audit qualification](audit-qualification.md) | Reproducible live verification procedures |
| [License reports](license-report.md) | Evidence interpretation and offline replay |
| [License checks](license-check.md) | Policy evaluation and applicability |
| [Repository foundation](repository-foundation.md) | Rust tooling, lint policy, and CI |
| [Release process](release-process.md) | Maintainer preparation and publication gates |

[Contributor guidelines](../guidelines/ARCHITECTURAL_GUIDELINES.md) cover code
structure.
Test or release execution records belong on their PRs and workflow runs, rather
than in these contracts.
