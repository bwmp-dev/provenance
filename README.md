# Provenance public toolkit

Public contracts and clients for submitting, inspecting, testing, releasing, and independently verifying Minecraft plugin artifacts.

## Repository areas

- `packages/cli-go`: four-verb CLI and offline verifier.
- `packages/action`: immutable bundled GitHub Action submission client.
- `packages/api-client`: generated public API client.
- `packages/config-schema`: configuration schema package and validators.
- `packages/runner-protocol`: generated TypeScript runner protocol package.
- `packages/test-fixtures`: Paper test and hostile-sandbox fixtures.
- `packages/typescript-sdk`: supported TypeScript SDK.
- `packages/verification`: attestation verification tooling.
- `packages/verification-go`: [offline Go envelope and artifact verification](packages/verification-go/README.md), supplied with a trusted public key and caller-owned byte reader.
- `plugins/paper-probe`: trusted Paper lifecycle and command probe.
- `schemas`: authoritative JSON Schemas.
- `proto`: authoritative public runner protocol.
- `gen/proto`: generated Go runner protocol module.
- `examples/consumption`: [complete buildable public/private submission examples](examples/consumption/README.md).

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

Protobuf generation uses local Go plugins pinned to `protoc-gen-go` v1.36.12
and `protoc-gen-go-grpc` v1.6.2, alongside the locked TypeScript generator.
`pnpm generate` bootstraps them into a fresh temporary directory with the Go
toolchain in `.go-version`; no Buf remote-generation quota or credentials are
required. A cold bootstrap still needs access to the Go module proxy/checksum
service (and toolchain download if absent); this is not an offline cold build.

`pnpm-lock.yaml` is generated only by the pinned pnpm release and is validated
with a frozen install in CI; general-purpose formatters do not rewrite it.

Paper fixtures and the trusted lifecycle probe use the checked-in Gradle wrapper.
`pnpm check` compiles and tests the probe, builds and hash-verifies all 14 benign
and hostile fixture JARs, and runs the focused `fork-pid-bomb` unit suite. These
checks never execute hostile payloads. The Paper API dependency graph is locked,
and its mutable upstream snapshot is additionally pinned by content hash. Actual
hostile execution requires `-Dprovenance.fixture.hostile.enabled=true` inside a
disposable, resource-limited Plan 03 runner.

## Contract releases

New manually dispatched `vMAJOR.MINOR.PATCH` contract releases produce seven
archives from the reviewed `main` tip (inventory schema 2):
the configuration schema and parser, attestation schema and verifier, runner
protocol sources and bindings, OpenAPI document, Paper metadata inspector,
generated TypeScript API client, and supported TypeScript SDK. Historical
inventory schema 1 remains six archives/nine assets and is independently tested;
no old release is rewritten. Every archive embeds a manifest of its files, source paths, sizes, and
SHA-256 digests. The release also includes an aggregate manifest and checksum
file, plus a deterministic SPDX 2.3 JSON SBOM covering every file in all seven
archives and every Node.js and Go runtime dependency selected by the lockfiles.
That is ten assets with nine checksum entries (the checksum file excludes itself).
The SDK ships the existing generated/configuration/verification packages under
their original identities with tested local file references. This is archive-only
alpha distribution, not an npm registry publication. See the
[supported SDK installation and explicit trust guide](packages/typescript-sdk/README.md).

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
seven archives; no publishing secret is required. The CLI has a separate
[Linux distribution workflow](docs/cli-distribution.md), and the Action is consumed
at an accepted immutable source commit, not from these contract archives.
Actual publication is established only by inspecting downloaded release assets.
After downloading a release,
verify its checksum file and GitHub attestations:

```sh
sha256sum --check provenance-contracts-1.2.3.sha256
gh attestation verify provenance-config-schema-1.2.3.tar.gz --repo bwmp-dev/provenance
gh attestation verify provenance-config-schema-1.2.3.tar.gz --repo bwmp-dev/provenance --predicate-type https://spdx.dev/Document
```

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
