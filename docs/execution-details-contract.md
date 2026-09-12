# Private execution detail contract

This additive WP-08D slice follows the existing candidate-detail assignment in
[program PR255](https://github.com/bwmp-dev/provenance-program/pull/255).
It is a proposed contract, not released producer/consumer or alpha acceptance.

`GET /v1/release-candidates/{candidateId}/executions/{executionId}/details`
returns exact attempt identity, recorded state, stored timing, bounded technical
failure fields and retained versioned terminal observations. The endpoint accepts
no query fields and no Actions grants. Candidate and execution authorization
precedes query validation; hidden and missing identities share the same 404.

The existing terminal-evidence v1/v2 schemas remain authoritative and unchanged.
No third observation format or inferred outcome is introduced. The producer must
validate the original canonical bytes and digest against the exact immutable job
and accepted lease/message receipt. Historical attempts remain historical: do not
substitute a newer result or use an issuance-only latest-attempt filter to hide
otherwise valid private history. Partial coverage must remain partial; a missing
document is null, while corrupt retained evidence is an unavailable response.
Reported runtime identity is not independent host measurement or hosted trust.

Duration is the floor of stored completion minus stored start in milliseconds,
never updatedAt, log timestamps or the browser clock. It is null when either time
is absent. Reversed times, unsafe durations and contradictions between terminal
evidence and stored execution identities/states fail closed. A structured failure
is allowed only for stored failed executions; unavailable fields are null, never
filled from log text. The raw failure summary is not exposed.

The complete response is bounded to 128 KiB with private/no-store headers,
closed non-reflective errors and no raw logs, commands, patterns, YAML, metadata,
credentials or object locations. Existing candidate, matrix, input, execution-list
and log contracts and the Actions allowlist remain unchanged. Deploy the producer
before the console; rollback disables the consumer first and retains history.

This contract alone does not complete WP-08D, the new-developer flow, publication,
runner trust, or the alpha release gate.
