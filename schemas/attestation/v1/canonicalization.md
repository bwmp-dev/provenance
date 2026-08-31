# Provenance attestation v1 signing input

The signature covers the `statement` member and binds the envelope's `signature.keyId`. Verifiers must first validate the complete envelope against `schema.json`; values that do not validate are never signature candidates.

Canonicalize the statement with the JSON Canonicalization Scheme (JCS), RFC 8785. This means UTF-8 output, lexicographic object-member ordering by UTF-16 code units, ECMAScript JSON string escaping, and no insignificant whitespace. V1 statement numbers are integers only, avoiding cross-runtime floating-point ambiguity. Duplicate keys, lone Unicode surrogates, a byte-order mark, and non-JSON input must be rejected before canonicalization.

Construct the signing input as this exact byte sequence, where `||` is concatenation:

```text
UTF8("Provenance Attestation v1\n") ||
UTF8(signature.keyId) ||
UTF8("\n") ||
JCS(statement)
```

Sign those bytes directly with Ed25519; do not hash or pre-hash them first. Encode the 64-byte signature as unpadded base64url in `signature.value`. The key identifier selects the public key but is also inside the signing input, preventing an envelope from relabeling a valid signature with another key ID. `mediaType`, `algorithm`, and `canonicalization` are schema constants that select these v1 rules.

The fixtures under `schemas/fixtures/attestation/vectors` publish test-only private seeds so independent implementations can reproduce signatures as well as verify them. They must never be used as production keys.
