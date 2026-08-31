# Provenance public toolkit

Public contracts and clients for submitting, inspecting, testing, releasing, and independently verifying Minecraft plugin artifacts.

## Repository areas

- `apps/cli`: Provenance CLI.
- `apps/github-action`: GitHub Action submission client.
- `packages/api-client`: generated public API client.
- `packages/config-schema`: configuration schema package and validators.
- `packages/runner-protocol`: generated TypeScript runner protocol package.
- `packages/test-fixtures`: Paper test and hostile-sandbox fixtures.
- `packages/typescript-sdk`: supported TypeScript SDK.
- `packages/verification`: attestation verification tooling.
- `plugins/paper-probe`: trusted Paper lifecycle and command probe.
- `schemas`: authoritative JSON Schemas.
- `proto`: authoritative public runner protocol.
- `gen/proto`: generated Go runner protocol module.

## Contract development

Install the pinned toolchain with `pnpm install --frozen-lockfile`, then run
`pnpm check`. The check builds the public packages, validates and normalizes the
golden configuration fixtures, validates and independently verifies the
attestation vectors, and formats, lints, and snapshots the runner protocol.

The authoritative contract sources live under `schemas`, `proto`, and `openapi`.
The public HTTP path/operation inventory is checked separately from the OpenAPI
document so endpoint groups cannot silently disappear. `pnpm generate`
reproduces the Protobuf stubs and the typed fetch client; generated artifacts
must never be edited directly.

`pnpm-lock.yaml` is generated only by the pinned pnpm release and is validated
with a frozen install in CI; general-purpose formatters do not rewrite it.

Paper fixtures and the trusted lifecycle probe use the checked-in Gradle wrapper.
`pnpm check` compiles and tests the probe, builds only the bounded fixture set,
and verifies fixture and Paper API artifact hashes. The Paper API dependency
graph is locked, and its mutable upstream snapshot is additionally pinned by
content hash. Hostile fixture builds require an explicit Gradle task and hostile
payload execution requires a separate JVM property.

## Contract releases

Each manually dispatched `vMAJOR.MINOR.PATCH` contract release produces five
independently consumable archives from the reviewed `main` tip:
the configuration schema and parser, attestation schema and verifier, runner
protocol sources and bindings, OpenAPI document, and generated TypeScript API
client. Every archive embeds a manifest of its files, source paths, sizes, and
SHA-256 digests. The release also includes an aggregate manifest and checksum
file, plus a deterministic SPDX 2.3 JSON SBOM covering every file in all five
archives and every Node.js and Go runtime dependency selected by the lockfiles.

Builds require a clean output directory, explicit version and 40-character
source commit, and an RFC 3339 UTC timestamp derived from that commit:

```sh
pnpm check
pnpm run release:contracts --version 1.2.3 --source-commit "$COMMIT" --created-at 2026-08-30T00:00:00Z
pnpm run release:verify --version 1.2.3 --consumers
```

The manual workflow validates its SemVer input before installing dependencies,
pins the build to the reviewed `main` SHA, reruns the complete repository check,
and validates every extracted archive with isolated, offline consumers. A
separate privileged job downloads that immutable workflow artifact, independently
verifies it without executing archive code, creates or safely reuses the
annotated tag, reconciles only missing assets in a matching draft, and never
overwrites a conflicting or published release. The release manifest and release
notes explicitly declare schema, OpenAPI, protocol, CLI, Action, and SDK
compatibility. The workflow uses only the repository
`GITHUB_TOKEN` and GitHub's OIDC identity to create SLSA build-provenance
attestations for all release assets and a dedicated SPDX SBOM attestation for the
five archives; no publishing secret is required. After downloading a release,
verify its checksum file and GitHub attestations:

```sh
sha256sum --check provenance-contracts-1.2.3.sha256
gh attestation verify provenance-config-schema-1.2.3.tar.gz --repo bwmp-dev/provenance
gh attestation verify provenance-config-schema-1.2.3.tar.gz --repo bwmp-dev/provenance --predicate-type https://spdx.dev/Document
```

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
