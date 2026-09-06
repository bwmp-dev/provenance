# Public key discovery v1 (IFC-016)

`GET /.well-known/provenance-keys.json` is anonymous and returns the complete
public-only version 1 snapshot as `application/json`. Every response uses
`Cache-Control: no-store`. No conditional requests, cache lifetime, pagination,
automatic trust bootstrap or stale-response fallback are defined in v1.
An unavailable or invalid configured snapshot returns HTTP 503 with exactly
`{"type":"about:blank","title":"Public keys unavailable","status":503,"code":"public_keys_unavailable"}`
as `application/problem+json`, never a successful empty or truncated snapshot.
Other admission errors use the API's existing ProblemDetails contract.

Validate strict UTF-8 JSON and schema.json before using a key. Reject duplicate
JSON members (including escaped equivalents), BOMs, invalid UTF-8, lone
surrogates, non-JSON numbers and trailing input. JSON Schema cannot enforce
unique key IDs: additionally reject any repeated keyId, even identical entries.
publicKey is the canonical unpadded base64url encoding of 32 raw Ed25519 bytes;
it is not PEM, a private seed, a signature, or a JWK. Unknown fields fail closed.
The repository's validation.py is an offline reference/test helper, not a trust
loader or released library. It uses the repository's requirements-contracts.txt
and caps input at 1 MiB defensively. This release contains schema, semantics and
fixtures only; consumers supply their own strict JSON/schema validation and the
additional semantic checks described here. No Python runtime is shipped.

keyId uses the existing attestation grammar and is matched exactly, with no
case-folding, URL normalization or fragment stripping. It is bound into the
existing attestation signature bytes. Even a URL-shaped keyId never instructs a
verifier to fetch anything. A caller selects a trusted origin independently;
this document cannot establish its own authenticity, continuity or rollback
resistance. Existing offline Go/TypeScript verifiers remain network-free and
continue to accept caller-supplied keys.

There may be multiple active keys or only retired keys. Retirement prohibits
new signing but does not revoke historical signatures or invalidate old records.
Within a snapshot lineage retain every historical ID with unchanged public
bytes and algorithm; never rebind an ID or reactivate a retired ID. New IDs may
be added and active keys may retire. A later snapshot alone does not prove these
rules were followed: continuity checks require a previously trusted snapshot.
Keep the complete history; refuse an over-capacity snapshot rather than dropping
old keys. The 1–1024 bound is this interface's explicit capacity choice, not a
key-retention lifetime. Array order conveys no signing preference.

This interface contains no private key, custody locator, expiry, compromise or
revocation policy, deployment defaults, production key generation or production
rotation procedure. Operational rotation must publish the new public key before
issuing records under it and retain the old public key afterwards; this contract
alone does not prove that deployment ordering. Fixture keys are test-only.
