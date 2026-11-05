# Package-File Catalog

## Purpose

This document explains which repository files `githits-scan` uploads, why the list is exactly this, and how to change it. The code is `src/catalog.rs`; this page is the provenance.

## Background

The client admits only cataloged filenames and validates upload limits before
sending contents. The catalog is defined in `src/catalog.rs`; service parsing
and resolution are separate from filename recognition. An unusable selected
file can reject the whole upload (`UNUSABLE_MANIFEST`).

Support changes need either a documented public API contract or reproducible
live verification against the production origin. Consult the
[public API docs](https://docs.githits.com/api/overview) and
[OpenAPI contract](https://api.githits.dev/v1/openapi.json); filename recognition
alone does not establish resolution or audit coverage.

## Catalog

Matching is exact and case-sensitive on the final path component, exactly like the service.

Each lockfile is uploaded with the manifest that owns it: the file its tool writes the lockfile from, in the lockfile's project directory.

| Ecosystem | Lockfile (uploaded when found) | Owning manifest (uploaded with it) | Other manifests of the ecosystem |
| --- | --- | --- | --- |
| Rust | `Cargo.lock` | `Cargo.toml` | |
| JavaScript | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, text `bun.lock` | `package.json` | |
| Python | `uv.lock`, `poetry.lock`, `pdm.lock` | `pyproject.toml` | |
| Python | `Pipfile.lock` | none yet: `Pipfile` is not cataloged (see [service pairing changes](#service-pairing-changes)) | `pyproject.toml` |
| Swift | `Package.resolved` | `Package.swift` | |
| Gradle | `gradle.lockfile`, `buildscript-gradle.lockfile`, `settings-gradle.lockfile`, `gradle/dependency-locks/*.lockfile` | none yet: pairing with the build script is not qualified (see [service pairing changes](#service-pairing-changes)) | `build.gradle`, `build.gradle.kts` |
| .NET | `packages.lock.json` | the only `*.csproj` in the directory | |
| Dart | `pubspec.lock` | `pubspec.yaml` | |
| PHP | `composer.lock` | `composer.json` | |
| Elixir | `mix.lock` | `mix.exs` | |
| Ruby | `Gemfile.lock` | `Gemfile` | |
| Ruby | `gems.locked` | none yet: its owner `gems.rb` is not cataloged (see [service pairing changes](#service-pairing-changes)) | `Gemfile` |
| Erlang | `rebar.lock` | `rebar.config` | |
| Conan | `conan.lock` | none | |
| Go dep | `Gopkg.lock` | none | |
| Go | none | | `go.mod` (manifest-only) |
| vcpkg | none | | `vcpkg.json` (manifest-only) |
| Zig | none | | `build.zig.zon` (manifest-only) |

The owner is what makes a pair: automatic pairing attaches only the owning manifest, even when other manifests belong to the same ecosystem. Explicit configuration can add those other manifests. Discovery therefore reports four outcomes for a manifest (see `discovery.md`):

- **Uploaded with its lockfile** when it owns a lockfile in its directory.
- **Uncombined** when its directory holds a lockfile of its ecosystem that it does not own or cannot be combined with, such as `pyproject.toml` beside `Pipfile.lock` or `build.gradle` beside `gradle.lockfile`. Proximity does not prove dependency coverage; an uploaded manifest without a backend-proven association can resolve separately from registries. It is reported with that explanation and uploaded only when the configuration's `manifests` list names it.
- **Nested** when an ancestor directory holds a lockfile of its ecosystem.
- **Manifest-only** otherwise, uploaded by default for the service to resolve from its declared constraints; `--lockfiles-only` leaves it out.

A `packages.lock.json` beside several `.csproj` files cannot be attributed to one project; NuGet gives each project in a shared directory its own `packages.<project_name>.lock.json`, which the scanner does not discover yet (see [service pairing changes](#service-pairing-changes)). Such a lockfile is **ambiguous**: it is not uploaded, its projects become manifest-only, and `detect` and `sbom generate` print a warning until an exclude pattern matches the lockfile.

Ecosystems never pair across each other, which encodes the service's rules that `conan.lock` does not cover `vcpkg.json` and `Gopkg.lock` does not cover `go.mod`. Go modules, vcpkg, and Zig have no cataloged lockfile, so their manifests are always manifest-only projects: reported by `detect` and uploaded for the service to resolve from registries, unless the run is `--lockfiles-only` and the configuration does not list them.

The legacy Gradle rule matches `<name>.lockfile` only when the two nearest parent directories are exactly `gradle/dependency-locks`; such a lockfile belongs to the project two directories up, so that project's build script is uncombined rather than manifest-only. The `.csproj` rule requires a non-empty stem.

### Bun text qualification

Text `bun.lock` uses the existing JavaScript ecosystem and same-directory
`package.json` pairing. The scanner uploads the original UTF-8 bytes, including
JSONC comments and trailing commas; parsing belongs to the service. Binary
`bun.lockb`, differently cased names, and backup suffixes remain excluded.

The ignored `generates_a_recorded_bun_inventory_for_the_fixture` test in
`tests/live.rs` verifies the committed text fixture through the configured API.
It requires recorded-lockfile inventory, the expected locked `left-pad`
version, and one lockfile plus one manifest. With a token for the target origin
already exported:

```bash
cargo nextest run --locked --all-features --run-ignored ignored-only -E 'test(=generates_a_recorded_bun_inventory_for_the_fixture)'
```

Exactly one test must run and pass. Missing credentials or fixtures fail closed.
The default origin is production; another origin requires its matching token.
This fixture does not establish complete source identity or graph coverage for
arbitrary Bun projects.
Execution evidence belongs on the qualifying PR.

### Manifest-only ecosystems

`go.mod`, `vcpkg.json`, and `build.zig.zon` are cataloged independently of
`Gopkg.lock` and `conan.lock`. The ignored
`resolves_go_vcpkg_and_zig_manifest_only_projects` test in `tests/live.rs`
uploads the three committed fixtures and requires expected resolved components.
Run it against the production origin before changing support claims:

```bash
cargo nextest run --locked --all-features --run-ignored ignored-only -E 'test(=resolves_go_vcpkg_and_zig_manifest_only_projects)'
```

Exactly one test must run. Report acceptance, resolution completeness, source
identity, and audit coverage separately; one does not prove the others. Dart and
Swift manifests are also selected without locks, but Scan does not guarantee
complete manifest-only resolution for them. Returned gaps remain visible.

Go fixture modules under `testdata/` follow the overridable
[fixture policy](configuration.md#evaluation). A vcpkg checkout can contain many
cataloged port manifests; review selection and exclude unrelated projects before
uploading. An unusable selected manifest rejects the whole upload.

### Service pairing changes

Potential additions include `Pipfile`, `gems.rb`, Gradle build-script pairing,
and project-named NuGet lockfiles. These are not current catalog owners. Before
adding a pair, verify through the public API that the manifest associates with
recorded lock evidence rather than resolving independently, and identify what
it contributes. Ambiguous NuGet ownership also needs a verified admission rule.

### Excluded directories

Files under these directory names are installed copies of other projects, not evidence about the scanned repository, and are never uploaded regardless of ecosystem: `node_modules`, `vendor`, `site-packages`, `deps`, `_build`, `_checkouts`. Fixture directories are visible in discovery and excluded through [configuration evaluation](configuration.md#evaluation), so a real project there can be explicitly selected. The comparison is exact-case because package managers and toolchains use these names in exactly this spelling; a directory named `Vendor` is a project's own choice and is scanned.

Hidden directories (any component starting with `.`, such as `.tox`, `.bundle`, `.dart_tool`, `.build`, `.swiftpm`, `.yarn`) are skipped by the discovery walker rather than the catalog. That policy also skips `.git`.

## Deliberate Omissions

| File | Reason |
| --- | --- |
| `bun.lockb` | Binary Bun lockfiles are outside the text-upload contract and would fail as `invalid_utf8`; only text `bun.lock` is cataloged |
| `Cartfile.resolved`, `paket.lock`, `glide.lock`, Nebula `dependencies.lock`, Maven `lockfile.json`, clj-nix `deps-lock.json`, `zig.lock`, `zigmod.lock`, `gyro.lock` | Not cataloged; require public API documentation or production qualification before admission |
| `go.sum`, `go.work` | `go.sum` records module checksums, not a version selection; neither file is cataloged |
| `pom.xml`, `build.sbt`, `*.versions.toml`, `*.gemspec`, `deps.edn`, `project.clj` | Not cataloged; require a documented and qualified upload/resolution contract |
| `requirements*.txt`, `constraints.txt`, `Pipfile`, `setup.py`, `setup.cfg` | Not cataloged; `Pipfile` needs qualified pairing (see [service pairing changes](#service-pairing-changes)) |
| `pnpm-lock.env.yaml` | Rare variant; not documented publicly |
| `*.fsproj`, `*.vbproj`, `Directory.Packages.props` | Only `*.csproj` is cataloged as a NuGet manifest; a supported lockfile without a cataloged owner is uploaded alone |
| `.package-lock.json` | Hidden npm cache file; skipped by discovery |
| `flake.lock`, `Podfile.lock`, `packages.config`, `project.assets.json` | Not cataloged |

Unsupported-format notices recognize `requirements.txt`, `deno.lock` and `pom.xml` by exact filename, honoring installed-dependency and walker exclusions. These are diagnostics only, never supported evidence or upload candidates. Python notices suggest supported lockfiles or `pyproject.toml`; Deno and Maven have no supported native input.

## Design Decisions

**Why upload the owning manifest at all?** A manifest supplies project metadata
and declared requirements that a lockfile may omit. The public API example
uploads `Cargo.toml` with `Cargo.lock`. Scan sends both as evidence and leaves
interpretation to the service.

**Why separate catalog pairing from workspace evidence?** Catalog pairing identifies a lockfile's owning manifest from filenames; it does not parse workspace membership. Shared upload preparation separately adds [Cargo](discovery.md#cargo-member-evidence) and [supported npm](discovery.md#npm-member-evidence) member evidence from already-admitted candidates. Additional manifests without a native lock association can resolve independently from registries, so directory nesting alone never selects them. Explicit configuration can supply other intended evidence. A manifest with no cataloged lock above it remains manifest-only by default; `--lockfiles-only` skips that resolution while retaining selected lock companions and their native member evidence.

**Why group by ecosystem rather than by tool?** Ecosystems decide which lockfile covers a nested or uncombined manifest; owners decide which manifest is uploaded with a lockfile. `package.json` owns npm, pnpm, Yarn, and Bun lockfiles alike, so a per-tool enum would force an artificial choice. The service identifies the tool from the file itself. A crate-private catalog lookup separately identifies the qualified Cargo/npm families for automatic member selection; it does not change the public ecosystem classification.

**Why a data table instead of a trait per ecosystem?** There is one behavior (classify a path) and roughly forty facts. A table is reviewable in a diff, has no dispatch, and keeps the whole catalog visible at once.

## Changing the Catalog

1. Confirm the family appears in the public SBOM operation documentation, or qualify acceptance (for a manifest-only ecosystem, resolution) against the default production origin with a live `#[ignore]` fixture test. Development evidence may support a draft increment but must be labeled as such; it does not satisfy the merge/release gate.
2. Add the rule to `RULES` in `src/catalog.rs` and the corresponding case to the exhaustive tests. A lockfile rule names its owner: the manifest its tool writes it from, and only when the service combines the two; otherwise `Owner::Uncombinable`.
3. Update the table above and the README's family list.
4. Add a `changes/` fragment; new families are user-visible.

## Key Reference Files

| File | Demonstrates |
| --- | --- |
| `src/catalog.rs` | The rule table, matchers, exclusions, and exhaustive tests |
| `docs/implementation/sbom-api-contract.md` | Why one unusable file matters and where limits are enforced |
