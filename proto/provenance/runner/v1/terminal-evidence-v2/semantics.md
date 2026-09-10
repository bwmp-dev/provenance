# Terminal evidence v2 — inactive contract development

This separate schema does not change v1 bytes, meaning, feature admission or
replay. It is not yet advertised, packaged for release, consumed by production,
projected into attestations or enabled by a runner. No live proof is upgraded.

V2 retains the bounds, binding, canonicalization, predicates, privacy and measured
runtime requirements of [v1](../terminal-evidence/semantics.md), except for the
explicit additions here. Its schemaVersion is `provenance.execution-evidence/v2`.
The reference requires explicit `featureV2Enabled`; v1 admission is insufficient.
Protocol feature `TERMINAL_EVIDENCE_V2` is value 7. The transport wrapper retains
field 10 on completed/failed messages and the existing canonical_json/digest
fields; schemaVersion selects the admitted schema. Server support must precede
advertisement. A stream admitting only v1 must reject v2, even if its assertions
happen to use only v1 types. V2 admission does not implicitly authorize v1; a
runner retaining v1 replay must also advertise and obtain admission for v1.
Unknown features fail closed. No queued version, bytes or digest may be rewritten
on retry, reconnect or downgrade. Production consumer-first rollout remains pending.

`console-contains` is distinct from `console-regex`. It binds only an explicitly
configured literal contains operator to exact immutable testId/assertionId.
It records the provider-validated evaluation of that configured assertion,
including its configured present/absent expectation, not raw substring presence.
Absent/default/unknown operators do not acquire claims implicitly. The immutable
expected plan must supply the correct type; neither runner-supplied type nor
structural validity is authority to change an operator.

The literal claim uses the same closed observation booleans and prerequisite
ordering as console-regex: registered and executionCompleted are mandatory;
evaluated true/passed true without truncation is passed; evaluated true/passed
false is failed; evaluated false/passed false with validated truncation is skipped.
Missing events are unavailable, never inferred skipped. Patterns, output, command
text and arbitrary attributes are forbidden. FIFO authorship limitations remain.

Completeness still requires measured runtime and every configured observation.
This addition does not permit omitting a test, weakening its predicate, inventing
a measurement, issuing a signature or publishing a claim. V1 partial evidence
must remain v1 partial evidence through replay and historical verification.

Current tests reuse explicitly synthetic v1 fixture identities to exercise v2
semantics and cross-version rejection. The frozen v2 vector is checked independently
by Go for its closed-ASCII canonical encoding, envelope and assertion digests.
This check is not a schema/predicate/expected-plan validator. Packaged Go and
TypeScript wire consumers verify unchanged proof bytes and replay through the
generated messages; a separate Draft 2020-12 validator checks the schema/vector.
Archive reproducibility, missing/tampered assets and isolated consumers are tested.
Production feature admission, producer/platform consumers, attestation projection
and real literal-coverage acceptance remain required before activation.
