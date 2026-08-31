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

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
