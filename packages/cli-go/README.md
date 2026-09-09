# Provenance CLI (bounded alpha)

Four commands consume the existing contracts: `auth login`, `test`, `status`,
and `verify`. This does not activate a backend or implement browser confirmation.
The confirmation UI is separately owned. No production origin is built in.

## Build and acceptance

From a complete repository checkout, run:

```sh
pnpm install --frozen-lockfile
pnpm --filter @bwmp-dev/config-schema build
go -C packages/cli-go build -trimpath -o /absolute/output/provenance ./cmd/provenance
pnpm test:cli
bash scripts/test-cli-native-store.sh
```

The explicit sibling Go module replacement binds directly to
`packages/verification-go`; this is a source-checkout build, not a published
nested-module version. The clean-checkout test builds without an ambient Go
workspace. Existing contract archives and release assets are unchanged; this
PR does not publish CLI binaries.

Linux native-store acceptance uses an isolated Docker filesystem, session bus,
and GNOME Secret Service. It tests actual storage and locking, not a mock.
Provisioning the fixture uses the network; execution is network-disabled.
Native Keychain and Windows Credential Manager adapters are selected on their
respective platforms. CI exercises an actual set/get/read/remove round trip,
origin and credential-kind isolation, and a native CLI build on disposable
macOS amd64 and Windows amd64 runners. macOS uses a native cgo build;
cross-compilation is not treated as native-store proof.

## Login

```sh
provenance auth login --origin https://your-explicit-api.example --timeout 10m
```

An existing, unlocked native credential store is required before issuance.
Only Secret Service, Keychain or Windows Credential Manager is allowed: no file,
plaintext, pass or keyctl fallback. Session secrets are scoped by normalized
HTTPS origin and credential kind; device and exchange codes are never persisted.
The CLI displays only the public confirmation URI and user code. Polling obeys
the supplied interval, Retry-After and expiry. A lost one-time response is not
retried speculatively: start a new login. Failed session storage triggers a
bounded best-effort revocation, not a fallback file.

Native APIs are synchronous and may prompt. A command deadline bounds the
caller, not interruption of an already-running OS call. On timeout the process
exits; no background credential-recovery daemon is installed.

## Submit a test

With an existing authorized configuration snapshot:

```sh
provenance test --origin https://your-explicit-api.example --timeout 10m \
  --project project-id --snapshot snapshot-id --config provenance.yml \
  --jar plugin.jar --version 1.2.3
```

Configuration must explicitly select `release.mode: test-only`. The CLI never
rewrites release mode. The normalized local configuration hash is bound to the
selected snapshot by the candidate API. Human sessions do not gain permission
to create snapshots.

To create a snapshot using an explicitly authorized project token, supply
`--auth project-token --project-token-stdin`, omit `--snapshot`, and provide
`--source-commit` and `--source-ref`. Pipe the token from a trusted secret tool
through standard input; never put it in argv. This invocation does not persist
the token. No session-to-project-token substitution occurs.

One retained regular JAR (1 byte to 1 GiB) is independently streamed and hashed,
then uploaded through a separate credential-free client. Upload redirects are
not followed. A changed file, inconsistent hash/size, rejected artifact or
snapshot mismatch stops before candidate success. Artifact readiness polling
is bounded by the explicit command timeout. No mutation is automatically retried
after a lost response, and no resume or publication mode is implied.

## Status and verification

```sh
provenance status --origin https://your-explicit-api.example --timeout 1m \
  --candidate candidate-id
provenance verify --jar plugin.jar --attestation attestation.json \
  --public-key trusted-key.base64url --key-id explicitly-trusted-key-id
```

Status reads the actual candidate and bounded execution/event pages (100 pages,
100 items per page). It does not infer publication or attestation success.
Verification uses the existing streaming verifier, an explicit local attestation
and a separately trusted 32-byte Ed25519 public key encoded as canonical unpadded
base64url. The expected key ID must also be supplied. Historical trusted keys
remain usable; there is no active-key substitution or trust-on-first-use. Remote
attestation/key retrieval is not implemented. Verification reads at most the
signed artifact size plus one byte, as enforced by the shared verifier.

All network commands require HTTPS and an explicit timeout (greater than zero,
at most 24 hours). These are client resource bounds, not server lifetime defaults.
Responses are bounded to 4 MiB; configuration to 1 MiB. Redirects are rejected.
Errors withhold response bodies and submitted secrets. Synthetic HTTP acceptance
does not claim a live developer flow, console acceptance or the Plan 07 exit gate.
