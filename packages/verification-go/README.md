# Offline Go verification

Module: `github.com/bwmp-dev/provenance/packages/verification-go`

This source module implements independent attestation v1 and local-byte verification.
The attestation contract archive layout includes this module under `go/`, with
its embedded schema, module checksums and license. Check the actual published
version's manifest before claiming delivery; source-tree inclusion alone is not
release evidence. There is no separately published module version. It does not
issue attestations or resolve trusted keys.

Release acceptance builds an external consumer against only the extracted module
with `GOWORK=off`. Dependency-cache provisioning happens before offline consumer
execution; this does not promise an offline cold installation.

```go
import (
    "crypto/ed25519"
    "errors"
    "io"

    verification "github.com/bwmp-dev/provenance/packages/verification-go"
)

func verify(rawEnvelope []byte, trustedKey ed25519.PublicKey, jar io.Reader) error {
    identity, err := verification.VerifyArtifact(rawEnvelope, trustedKey, jar)
    if err != nil {
        if errors.Is(err, verification.ErrSignature) {
            // The envelope was not authenticated; jar has not been read.
        }
        return err
    }
    _ = identity.SizeBytes
    _ = identity.SHA256
    return nil
}
```

The caller chooses a trusted 32-byte Ed25519 public key, supplies raw JSON, and
owns the artifact reader. The library does not open files, make network requests,
close readers, discover keys, or accept private-key formats. `VerifyEnvelope`
authenticates the document without consuming artifact bytes; `VerifyArtifact`
authenticates first and then counts and hashes the same stream.

Errors support `errors.Is` with `ErrSchema`, `ErrKey`, `ErrSignature`,
`ErrSize`, `ErrDigest`, and `ErrRead`. `*Error` includes size/digest mismatch
details and preserves an underlying reader error through unwrapping, but its
message does not print reader errors or document contents. Invalid signature
encoding alone is a signature error; mixed schema violations remain schema
errors. Successful results are value-only artifact identities, not mutable
validated document objects.

Input snapshots prevent mutation during later reader callbacks. Do not
concurrently mutate document or key slices during the initial call/copy.
The reader must obey the `io.Reader` contract. Non-EOF errors fail verification
even when returned with bytes; 100 consecutive empty reads fail with
`io.ErrNoProgress`. Blocking reads remain the caller's responsibility: there
are no detached goroutines, background reads, or implicit timeouts.

The parser rejects duplicate object keys (including escaped equivalents), BOM,
malformed UTF-8, lone surrogates, trailing JSON, and non-JSON values. It bounds raw
envelopes to 4 MiB, nesting to 64, values to 100,000, and arrays to 1,000 items.
The complete embedded schema is byte-checked against the authoritative schema.
Canonicalization uses UTF-16 member order and ECMAScript escaping, with v1 safe
integer values; integer-valued decimal/exponent encodings remain interoperable.
The signature binds the exact domain separator, key ID, and canonical statement.
Artifact reads use a fixed 32 KiB buffer and stop after at most signed size + 1
bytes; signed size is itself bounded by schema v1 to 1 GiB.

An authenticated statement is not automatically a passing test, a trusted
runner, or a safe plugin. Callers still assess the supplied key's provenance and
the statement's trust/evidence claim. This module does not prove record issuance,
rotation/key discovery, or the Plan 10 exit gate.

Run `go test -race ./...` and `go vet ./...` in this directory, or
`pnpm run test:go-verifier` from the repository root. Root `pnpm check`
builds, tests, and vulnerability-checks this module on the existing self-hosted
CI runner.
