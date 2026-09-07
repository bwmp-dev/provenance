# IFC-019 terminal evidence v1

This is an optional observation contract, not an attestation, signature, public
claim, authorization decision or runtime implementation. Protocol version remains
literal `1`. Feature `TERMINAL_EVIDENCE_V1` is value 6; `execution_evidence` is
field 10 of both `JobCompleted` and `JobFailed`. All previous reservations and
required fields remain unchanged. Cancellation messages are unchanged.

## Bytes and identity

`ExecutionEvidence.canonical_json` MUST be exact RFC 8785 canonical UTF-8 JSON
conforming to `schema.json`. `digest.algorithm` MUST be SHA256 and its value MUST
be the 32-byte SHA-256 of those exact bytes. This is not the attestation Ed25519
domain or a signature. Each assertion's `evidenceSha256` is independently the
lowercase hex SHA-256 of RFC 8785 bytes for its entire `evidence` object.
Canonicalization uses UTF-16 property ordering and ECMAScript escaping. Reject
duplicate keys, non-integer/unsafe numbers, invalid UTF-8/Unicode, BOM, trailing
input, unknown fields and noncanonical encodings even when the supplied digest
matches. No parser may repair hostile input before validation.

`binding` repeats runner, job, execution, lease, attempt ID/number, candidate and
matrix identities. Consumers MUST compare every field with the authenticated
runner and authoritative immutable job/attempt binding. Lease expiration and
connection IDs are deliberately absent: renewal/reconnect cannot change proof.
Each assertion preimage repeats the complete binding and exact ID/type/outcome.
It MUST match the envelope and outer assertion. Assertion IDs and requested
dependencies are sorted ascending by ASCII ID, without duplicates. Dependency
assertions MUST match the independently verified materialized dependency digest
and the immutable requested dependency identity; matching names alone is not proof.

`requested` hashes identify the request ONLY. They do not measure execution.
Consumers MUST independently match artifact, configuration, environment, policy
and dependency hashes to persisted immutable job inputs.

## Observations and predicates

The producer MUST validate event shape, complete applicable ordering, configured
identities, duplicate/contradictory events and failure classifications before
projecting any observation. Boolean fields are derived from those validated
events, not accepted directly from arbitrary plugin details. An absent or
malformed event is unavailable, NEVER an invented false value or failed assertion.

| Type               | Passed                                                                                                                                        | Failed or skipped                                                                                                                                |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| startup-ready      | Ordered server-loaded, stabilization-completed and server-ready events, with requirementsSatisfied true                                       | Same observed sequence with explicit requirementsSatisfied false is failed                                                                       |
| plugin-enabled     | Expected targetId, loaded and enabled                                                                                                         | An explicit validated negative target requirement is failed; enabled without loaded is contradictory                                             |
| dependency-present | Expected dependencyId and verified materialized dependencySha256, loaded and enabled                                                          | An explicit validated negative dependency requirement is failed; enabled without loaded is contradictory                                         |
| console-regex      | Explicitly configured regex operator, exact testId/assertionId, registered, executionCompleted, evaluated and passed, without outputTruncated | Evaluated false/passed false is skipped ONLY with validated truncation; evaluated true/passed false is failed; passed with truncation is invalid |
| clean-shutdown     | Ordered shutdown-request and stopped events, with reportedShutdownRequested true                                                              | Those events with explicit reportedShutdownRequested false are failed                                                                            |

Missing prerequisite events do not establish any row. Contains/default command
operators are unsupported coverage, never console-regex. Commands not executed
after an earlier timeout are unavailable, not inferred skipped. Skipped is only
the explicitly observed console truncation case above. There is no invented clean
boolean or timestamp. Do not project raw output, command/regex text, arbitrary
attributes, exception/error messages, paths, credentials or secret-bearing data.
Configuration-derived IDs still belong to private evidence and require normal
authorization; their presence does not authorize public disclosure.

The sandbox FIFO does not authenticate exclusive probe authorship. Validated
typed observations retain that limitation and are not cryptographic probe proof.

## Runtime and completeness

Runtime MUST be null unless ALL fields are substantiated for this execution:
runner version and measured executable digest; gVisor version and measured
executable digest; effective network mode; and typed rootfs measurement.
The rootfs format `squashfs-image-sha256/v1` means SHA-256 of exact immutable
backing-image bytes independently measured and bound to the execution's mounted
rootfs/reference. A pathname hash without race-resistant mount binding does not
suffice. Caller/operator identity strings, requested image pins and current mutable
capability rows are not measurements. Neither the existing normalized-tar tree
hash nor a read-only bind mount with writable aliases satisfies this format.
This is a FUTURE producer requirement, not a claim about current hosts. Unsupported
process/container runtimes or unverifiable measurements stay null and partial.

`complete` requires non-null measured runtime AND every configured supported
observation, with no unsupported or missing coverage. **Schema validity alone
cannot establish completeness.** Consumers MUST compare the exact assertion
IDs/count/types/selectors with an independently obtained immutable expected plan.
No runner-supplied expected-plan list is authoritative. Partial envelopes can
retain known observations, including with null runtime or no assertions. Complete
does not mean passing, issuance-eligible or publicly trusted. Failed terminal
messages can carry observations but MUST NOT invent missing passes. Issuance,
single/multiple-runner eligibility and public visibility remain separate decisions.

## Bounds and transport

The envelope is at most 32768 bytes with at most 256 assertions, matching the
existing result-count ceiling. Requested dependencies are bounded to 256 entries
for finite parsing; consumers still enforce any tighter configured-job limits.
IDs are 1–128 ASCII identifier characters, versions 1–128 bounded characters,
digests exactly 64 lowercase hex characters and attempt numbers 1–uint32 max.
Shapes are fixed and nonrecursive; the reference rejects depth greater than 12.
These are parser/transport limits, not deployment defaults. The independently
encoded containing RunnerMessage MUST fit 65536 bytes, including other terminal
fields. Count-valid input may exceed the byte limit. Reject it; never truncate
proof into completeness or enlarge the whole-message limit.

Deploy server support before runner advertisement: old gateways reject unknown
features; Authenticated does not acknowledge a feature set. Evidence may be sent
only on a stream that advertised and was admitted with TERMINAL_EVIDENCE_V1.
Legacy absent evidence remains valid but supplies no new proof. Advertised support
does not imply that every failed execution produced usable evidence.

Freeze exact canonical bytes and digest BEFORE durable terminal enqueue. Replay
unchanged across reconnect, response loss and restart. A downgrade MUST retain
queued proof and fail closed, never strip, regenerate or rewrite it as partial.
Same-message/different-proof is a conflict, not an idempotent duplicate. Platform
consumers must atomically persist exact proof/preimages, terminal identity and
receipt/outbox transitions; reject stale/foreign/substituted evidence before any
history change. Those consumers and host measurement are not implemented here.

## References and fixtures

`reference.mjs` is an offline executable contract reference, not a production
SDK. `validateStructure` checks bytes/schema/digests/predicates;
`validateTerminal` additionally requires external immutable expected-plan/binding
test context and the actual encoded whole-message size. Neither observes event
order, authenticates a policy source, measures a host or authorizes issuance.
`fixtures.json` and `vectors.json` are synthetic, never retained host observations.
The existing runner release archive includes this schema, semantics, reference
and vectors; six archive types and attestation signature domains remain unchanged.
