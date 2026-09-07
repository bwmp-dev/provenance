# IFC-021 candidate-qualified publication results

This additive version-1 read contract does not activate publishing or select a
deployment policy. Existing candidate states, events and responses are unchanged.
In particular, legacy `published` may describe test-only completion and is not
evidence of remote delivery. The normative wire schema is in provenance.v1.yaml;
publication-result-vectors.json contains synthetic state examples, not live proof.

## Identity, authorization and read isolation

`GET /v1/release-candidates/{candidateId}/publication-result?generation=N`
requires an explicit exact nonnegative safe-integer generation (zero is valid).
Never silently replace it with the current generation or a different composition.
Bind candidate/project, artifact ID and SHA-256, configuration snapshot ID and
SHA-256 to the retained immutable generation. Admitted compositions must agree
with every binding. The response's `version: 1` is a schema version, not a history
cursor or incrementing database revision. No event history or pagination is exposed.

Resolve the existing session/project-token tenant and project visibility first.
The existing release-candidate read capability is required; a visible candidate
without that capability returns 403. Missing/foreign candidates and unavailable
retained generations have identical 404 bodies. Invalid credentials return 401.
GitHub Actions grants remain restricted to their seven released operations: even
a grant authorized to read the candidate does not authorize this operation.
This operation grants no read-all or publication authority. Validate generation
only after visibility; invalid generation/unknown query parameters return 400.
An absent/disabled implementation or inconsistent/unprojectable authoritative
data returns 503, never synthetic success or a partial response.

All status codes carry `Cache-Control: no-store`. Errors use the closed
PublicationResultProblem shape, without dynamic details or candidate identifiers.
Prehandler failures are equally closed: wrong method 405/method_not_allowed,
oversized request 413/request_too_large, admission limiting 429/rate_limited and
unexpected internal failure 500/internal_error. These statuses confer no visibility
or authorization and must not echo the failed request or underlying exception.
The response is one coherent database read snapshot of immutable admission,
decision, target rows and corresponding committed adapter evidence. A GET MUST
NOT invoke providers, reconcile remotely, decrypt credentials, write events,
schedule publication or access custody. Later reads can include later committed
knowledge; a read need not force the scheduler to catch up.

Maximum encoded UTF-8 JSON response size is 16384 bytes, including whitespace.
Reject duplicate JSON object keys, invalid UTF-8, trailing JSON input and unknown
fields; schemas alone do not detect duplicate keys. UUID/hash/identifier and
array bounds apply before serialization. Do not truncate or drop targets to fit.
The four-target/63-character identifier limits come from alpha composition and
configuration; the body ceiling leaves room for every bounded field without
permitting arbitrary provider data. Generations above JavaScript's exact integer
range cannot be projected and return 503, never rounded or clamped.

## Three separate dimensions

`status:not_admitted` requires `composition:null`: no composition was durably
admitted for that exact retained identity. It is not pending publication and says
nothing about out-of-band remote objects. An admitted composition has 1–4 targets
in frozen configured order, unique identifiers and unique types from github,
modrinth, hangar and discord. Never sort by completion time or alphabetically.
Discord dependencies name a unique nonempty subset of preceding primary targets;
primary targets have empty dependency arrays. Identifiers are configuration
labels, not credential/remote project/operation IDs.

`aggregate:null` means no immutable aggregate decision has been committed yet.
Otherwise preserve its first outcome, code and decidedAt exactly, including after
later remote confirmation. Permitted pairs are succeeded/confirmed,
failed/primary_failed, and requirement_unfulfilled/dependency_blocked or
requirement_unfulfilled/budget_exhausted. `confirmed` here is the aggregate's
historical code, NOT a claim that every informational target was delivered.
The two independent frozen selectors are stop_remaining/continue_remaining and
required_for_success/informational. Waiting is finite/indefinite; the read does
not choose or extend deadlines, retry intervals or send budgets.

`disposition` is the retained scheduler row, not a recomputation from the latest
adapter status. pending/active can lag completion; succeeded/failed/skipped/
dependency_blocked/budget_exhausted are terminal and must not be rewritten.
Discord alone can be dependency_blocked or budget_exhausted; primary targets alone
can be failed or skipped. A failed primary prevents aggregate success even when
continue_remaining allows later primary successes. stop_remaining leaves later
unstarted primary targets skipped. Secondary requirements apply only to their
specified preceding primaries. Primary failure has precedence over an unfulfilled
secondary requirement. An informational secondary can remain pending, active or
uncertain after aggregate success. A finite budget can be exhausted while an
already authorized remote effect remains in flight.

`providerState` is null only if no corresponding operation/announcement exists.
Primary states are pending/preflight/uploading/publishing/retryable/succeeded/
permanent/conflict; Discord states are pending/active/retryable/succeeded.
Do not copy provider state into scheduler disposition. In particular, late Discord
confirmation can yield budget_exhausted + providerState:succeeded while the
historical aggregate remains requirement_unfulfilled/budget_exhausted.

Committed succeeded disposition or confirmed knowledge requires a succeeded
provider state; failed primary disposition requires permanent/conflict provider
state. Pending/skipped disposition has no corresponding operation, while active
requires one. Conflict knowledge requires the terminal conflict provider state.
The converse does not generally hold: an active scheduler row can coexist with
a newly succeeded adapter until scheduling catches up. Reject impossible
cross-record combinations rather than rewriting one field to manufacture agreement.

## Remote knowledge: committed evidence only

This field reports retained knowledge, not a live probe and not delivery counts.
Never infer knowledge from retryable alone, claims, lease expiry, claim count,
activity timeout, wake-up events, lack of a response or workflow memory.

| Value        | Required committed evidence                                                                                                                                                                                               |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| not_observed | No stronger qualifying record below; does not assert remote absence or that no out-of-band send occurred.                                                                                                                 |
| uncertain    | Primary mutation_started/mutation_returned/uncertain evidence without a later conclusive record; or Discord send_intent without a committed known message. Send intent authorizes a possible effect, not proof of a send. |
| known        | Discord message_known identity persisted but no confirmed event. The provider ID is intentionally not exposed.                                                                                                            |
| confirmed    | Primary durable succeeded/confirmed observation matching frozen artifact hash/size; or Discord confirmed event matching its committed known message identity.                                                             |
| conflict     | Primary durable conflict observation for the exact frozen publication operation. It does not disclose the conflicting object or imply this operation created it.                                                          |

For Discord, confirmed outranks known, which outranks send_intent uncertainty.
An unavailable/uncertain follow-up does not erase a retained known identity.
For primaries, immutable succeeded/conflict outcomes take precedence over earlier
uncertainty. Preflight availability errors without qualifying records remain
not_observed even when providerState is retryable. Unsupported/contradictory
records fail projection with 503, not an invented fallback enum. A confirmed
absence enum is deliberately not offered: absence at an earlier reconciliation
does not prove a later authorized effect did not happen.

No credential identifiers, authorization tokens, private changelogs, customer
text, raw provider payloads, remote IDs or remote URLs are exposed. The closed
enum `known` is sufficient to distinguish known-ID reconciliation from an
unknown-ID uncertain effect without revealing provider identifiers.

## Precedence examples and compatibility

The vectors cover both independent policy pairs, a pending aggregate, partial
primary success/conflict, skipped and dependency-blocked targets, informational
success with pending/uncertain secondary, and finite exhaustion followed by
known-ID/confirmed knowledge. Compare the paired late-confirmation examples:
aggregate and terminal disposition stay byte-identical; only provider state and
remote knowledge advance. No snapshot recomputes an immutable decision.

These semantics derive from accepted platform composition source 2895950:
publicationcomposition/scheduler.go and migration00035 (immutable decision and
terminal disposition); publishing/worker.go (mutation/confirmation records);
publishing/discord/worker.go and migration00028 (intent, known, confirmed).
The private implementation is provenance, not a public import or network
dependency. A separately scoped platform consumer must validate these semantic
relationships as well as the schema; schema-valid data alone is not proof of
authorization, coherence, target uniqueness or remote confirmation.
