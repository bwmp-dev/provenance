# IFC-029 durable private release rejection

The two operations add an explicit human rejection without changing any existing
candidate/event enum or response shape. This document is normative. Golden
vectors are synthetic contract examples, not runtime or human acceptance evidence.

## Authorization and validation

Authenticate exactly one supported credential, then resolve the candidate in the
current organization/project before validating query fields, body, key or replay.
Missing and hidden candidates return the same 404 `private_log_not_found` problem.
Actions grants are refused. Read requires private-result viewing capability;
mutation requires release approval capability. No privilege is implied by knowing
a candidate, decision or idempotency identifier. Current authorization is checked
again on replay. Revoked credentials do not retrieve an earlier receipt.

Neither route accepts query fields. POST requires one Idempotency-Key matching
the released syntax and a JSON object conforming to CandidateDecisionRequest.
The complete UTF-8 request is limited to 32768 bytes. A reason is optional, at
most 4096 Unicode code points, without NUL or unpaired surrogates. It is stored
verbatim only in the private audit record; absent and empty reasons normalize
to the same decision request. Unknown/duplicate JSON fields, malformed JSON or
keys, and extra query fields fail with 400 `validation_failed`. A complete body
over the limit fails with 413. All errors use the existing closed private problem
shape; every response, including rate, routing and panic boundaries, is no-store.

## Durable decision and concurrency

Only a candidate currently awaiting_approval can first be rejected. Candidate
state, immutable rejection record, legacy failed event, audit entry, idempotency
receipt and transactional outbox message commit together or not at all. The
record binds decisionId, candidateId, projectId, current generation, decision
rejected and a stored rejectedAt. These identities and timestamp never change.
The legacy candidate state and event remain coarse failed values; they do not
classify a plugin failure and must not be used to infer rejection. Exact artifact,
configuration, dependencies, matrix and terminal observations remain unchanged.

Identical successful request/key replay returns the original 200 document,
including identical decisionId and rejectedAt, without another audit, event or
outbox message. The idempotency scope is rejection-specific and binds the exact
candidate and normalized reason. Changed-request key reuse returns 409
`idempotency_key_conflict`. A different key against a candidate that is no longer
awaiting_approval returns 409 `release_candidate_state_conflict`, even if that
candidate was already rejected. A competing approval, cancellation or rejection
can have only one successful initial state transition. Do not replay a rejection
receipt from a generic failed candidate without the original authorized key.

The outbox transports only bounded database identities and the rejection
decision. It delivers the existing deterministic approval/rejection workflow
update, not a cancellation signal. A lost acknowledgement can be retried without
another decision or external effect. A rejection must prevent infrastructure
retry, attestation issuance and publication admission, including delayed workers
and retries. No reason, raw audit row or credential enters Temporal history.

## Private projection and compatibility

GET returns the stored closed document in at most 4096 UTF-8 JSON bytes. A visible
candidate without a rejection returns 404 `private_log_not_found`, exactly like
a hidden/missing candidate. Absence is neither approval nor permission. A present
record with inconsistent candidate/project/generation/state/audit binding returns
503, not 404 or a reconstructed replacement. The read is bounded and consistent;
it never consults mutable provider state or infers a decision from test results.

New consoles display the explicit rejection separately from coarse failed state
and passing or failing matrix results. Older clients keep their unchanged enums
and closed shapes. Rejection is not cancellation, test incompatibility, execution
failure, independent hosted trust, or evidence of publication. Raw reason, actor
details, logs, credentials and provider metadata are excluded from the document.

Rollout is inspected release, durable migration and tested outbox consumer, API,
then console. Rollback disables the mutation and new UI first and retains the
durable decision; it must never erase rejection or make a candidate publishable.
