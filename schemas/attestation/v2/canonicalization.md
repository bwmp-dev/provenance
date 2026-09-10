# Provenance attestation v2 signing input

V2 is a distinct envelope and signature domain, not a reinterpretation of v1.
The v1 schema, fixtures, canonical bytes and signatures remain unchanged.

Validate the complete envelope against this directory's schema before considering
its signature. Apply the same strict JSON and RFC 8785 JCS rules as v1: reject
duplicate keys, lone surrogates, BOMs and non-JSON input; statement numbers remain
integers. Sign the following bytes directly with Ed25519, without prehashing:

```text
UTF8("Provenance Attestation v2\n") ||
UTF8(signature.keyId) || UTF8("\n") || JCS(statement)
```

Signature encoding is the same canonical, unpadded base64url of 64 bytes. The
v2 media type and statement apiVersion must agree. V1 signatures, including those
for statements whose assertion types overlap, are not valid v2 signatures.

V2 adds `console-contains` and permits exact terminal-evidence assertion IDs
(ASCII letters/digits, dot, underscore, colon and hyphen, at most 128 characters).
For example `console-contains:smoke:0` retains its immutable plan identity. It must
not be relabelled `console-regex`, normalized to a different ID or omitted to make
coverage appear complete. Evidence digests bind the retained canonical evidence;
they are not a place for console output, patterns, commands or private metadata.
Absent/default operators are not silently promoted to supported assertions.

The remaining v1 field shapes and limits are retained. Schema validity and a valid
signature establish neither observation truth nor issuance eligibility. Trusted
issuance must reconstruct identities from immutable inputs, validate exact
versioned terminal evidence and cover every configured assertion. Public verifiers
must preserve the distinction between signature validity, matching artifact bytes,
and the reported assertion outcomes and runner trust.

This contract requires explicit consumer support before issuance. Older v1-only
consumers should reject it; never downgrade or rewrite an existing signed record.
