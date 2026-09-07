# IFC-022 — shown-once Actions automation grants

This document and `actions-grant-vectors.json` are normative companions to
`POST /v1/auth/github-actions/grants` (`createGitHubActionsGrant`). They describe
consumer obligations, not an implemented JWT verifier, database, Action or live
GitHub acceptance proof. The legacy `/v1/auth/github-oidc/exchanges`, its
`AccessToken` shape and original-outcome replay promise remain unchanged. Disabling
the new operation must not fall back to legacy exchange or broaden another token.

## Identity and explicit policy

The grant is a distinct `github-actions` automation principal with its own stable
grant ID and audit actor. It is not a session, personal organization, installation
connector, or user API token. No fabricated UserID or inherited connector role is
permitted. Use the existing numeric App/installation/repository/owner and project
authority binding; deny ambiguous, missing, transferred, revoked or suspended
bindings. Names, logins, emails and caller JSON cannot establish authority.

The caller must configure an exact trusted issuer and audience, supported
asymmetric signing algorithms, allowed App identity and current project policy,
repository/owner IDs, ref and workflow restrictions, finite maximum assertion and
grant lifetimes, finite nonnegative skew, and explicit bounded network/request
budgets. Missing or invalid configuration returns `503 unavailable`. No production
values, token custody backend or default permissive policy are selected here.
`none`, symmetric/asymmetric algorithm confusion, unsupported critical headers,
duplicate JWT member names, missing claims and noncanonical identity types fail
closed. Verify signature before trusting payload identity. Require exact issuer,
configured audience membership under an explicit single/multiple-audience policy,
nonempty issuer-unique `jti` (at most 128 UTF-8 bytes), finite integer `iat`, `nbf`, `exp`, sane time
ordering, numeric `repository_id`/`repository_owner_id`, commit `sha`, `ref`, and
the configured workflow claims. Current time must be inside the configured
validity/skew window, and strictly before `exp` to issue a nonexpired grant.

Workflow policy must state which signed `workflow_ref` and/or reusable workflow
`job_workflow_ref` and corresponding immutable SHA claims it requires. When both
are required, validate both; never substitute caller repository trust for reusable
workflow trust. Missing selected claims fail closed. Retain their verified policy
binding privately. Response `workflowRef` is the selected verified primary workflow
reference, not a dump of claims. `sourceCommit` and `sourceRef` are verified job
commit/ref, not a workflow source SHA. Every returned numeric ID is a canonical
positive decimal string (at most 20 digits); unsupported numeric ranges are denied,
never rounded through floating point. All response scope fields are normalized
server-derived authority, not proof that arbitrary resources in that scope can be
read. No permission or requested organization/project fields are accepted.

## Key discovery and bounded parsing

Accept only the configured issuer's explicitly configured HTTPS key-discovery
destination. Never fetch `jku`, `x5u`, `iss`, `kid` or other assertion-controlled
URLs/paths; reject JWT key-location and embedded-key headers. Do not send the
assertion, platform token or provider credentials to key discovery. Disable
redirects; enforce an explicitly configured timeout, response-byte/key-count
limits, bounded cache freshness and single-flight/rate-limited unknown-kid refresh.
Hard discovery ceilings are 262144 response bytes, 32 keys and 128 UTF-8 bytes
per key ID. Configured bounds may be smaller, never absent or unbounded. These
are safety ceilings, not selected deployment timeouts, cache TTLs or request rates.
Unknown or ambiguous key IDs, incompatible key type/use/algorithm, failed refresh,
stale keys or overflow cannot bypass verification. Dependency failure is
`503 unavailable`; an invalid assertion against available keys is `401
invalid_assertion`. No unbounded repeated network work per attacker-supplied key.

Body ceiling is 32768 UTF-8 bytes, assertion ceiling 16384 characters. Reject
malformed UTF-8, duplicate JSON keys, nonobject bodies, unknown properties, invalid
compact JWT syntax, duplicate/invalid idempotency headers and any Authorization,
Cookie or Origin header. Schema validation alone does not verify JWT signatures.
All decoding, crypto and admission concurrency must have explicit finite bounds.

## Issuance and precedence

Apply these ordered checks, including simultaneous-error cases:

1. Wrong method (`405 method_not_allowed`, `Allow: POST`), expired configured
   request-read deadline (`408 request_timeout`), request byte limit (`413`),
   then content type (`415`), then envelope/header/body
   syntax (`400 invalid_request`). Do not echo submitted values.
2. A bounded preverification admission limiter may return `429 rate_limited`
   without assertion parsing or credential issuance. It cannot disclose a receipt.
3. Configuration/dependency readiness (`503`) and assertion verification (`401`).
4. Current authoritative installation/repository/project/workflow policy (`403
policy_denied`), including expiry and revocation checks again under the issuance
   transaction's locks immediately before commit. No HTTP while holding DB locks.
5. In one transaction, scoped key with different request digest => `409
idempotency_conflict`; identical successful key/request => `409
credential_not_replayable`; same assertion replay identity already consumed under
   another key => `409 assertion_replayed`; otherwise atomically consume assertion,
   bind key/request/grant, persist token hash and nonsecret issuance audit, and issue
   exactly one `201`. Key scope is verified issuer + numeric repository + method +
   route. Assertion consumption scope is issuer + jti, independent of key or project.

Thus invalid/expired assertions cannot probe old receipts, and revoked policy wins
over a successful-key conflict. Concurrent different requests using a key cannot
both succeed; concurrent keys sharing an assertion cannot both succeed. An
uncommitted/lost transaction does not consume the assertion. A committed issuance
with lost response is deliberately unrecoverable: an identical retry conflicts.
An uncertain commit must be resolved by durable reads before any reattempt; never
create a second credential on uncertainty. A new attempt after consumed issuance
requires a fresh valid assertion and fresh key, all current policy checks, and does
not renew or resurrect the old grant. A provider re-signing the same jti is not a
fresh assertion. Request equality includes the exact assertion bytes via a digest.

Generate independent 32-byte CSPRNG token bytes; the wire encoding is `pva_` plus
canonical unpadded base64url. Persist only the credential hash, not raw assertions,
raw/recoverable tokens, response bodies containing tokens, private source text or
raw claims. Retain bounded replay identity/digests and normalized authority only.
Assertion consumption receipts and idempotency bindings remain through
`exp + configured skew` at minimum. Store issuer/jti replay identity as a digest,
not raw JWT payload or raw jti text. Recheck authoritative time after
lock waits. Cleanup/clock regression must never make an accepted assertion reusable:
outside the horizon it must already fail verification. Quota exhaustion or inability
to retain safe replay state fails closed. Grant expiry is fixed at issuance and no
later than assertion `exp` or configured grant lifetime. Response loss never changes
it. Revocation is irreversible for that grant. No keepalive or renewal is implied.

Every issuance response is `Cache-Control: no-store`, including prehandler,
rate-limit, unavailable and recovery errors. Only declared statuses and the closed
`{type,title,status,code}` problems are permitted; no 422/default diagnostic payload,
exception message, JWT claim or token reflection. Unexpected exceptions map to
`503 unavailable`. Do not log assertions, bearer values, response credentials,
provider payloads or request bodies. A normalized grant ID is a nonsecret audit
actor, not a credential.

## Submission and observation authority

The following are the only existing operations authorized by this grant. Preserve
their released request/response/error schemas and idempotent outcome semantics;
the new issuance replay rules do not replace mutation replay rules. Every operation
and replay rechecks grant hash, expiry/revocation and current connection/project
authority under its transaction. Credential verification failures remain 401;
authority failures follow existing tenant-blind 403/404 rules. No read can recover
access after expiry. Admission/revocation races must have one serialized result.

| Operation                   | Additional mandatory grant qualification                                                                                                                                                                                                                                                                          |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| createProjectConfigSnapshot | Path project equals grant project; exact verified sourceCommit and sourceRef required; independently derive normalized bytes/hash; durably bind admitted snapshot ID to grant.                                                                                                                                    |
| createArtifactUpload        | Same project; verified declared size/hash and admitted upload/artifact ID bound to grant. A deduplicated byte object is not authority to adopt another grant's upload.                                                                                                                                            |
| completeArtifactUpload      | Only that grant's admitted artifact/upload; exact declared size/hash, independent stored-byte verification unchanged.                                                                                                                                                                                             |
| createReleaseCandidate      | Exact configurationSnapshotId is required for this principal, even though optional for legacy callers. Snapshot/artifact must both be admitted by this grant; source/project/hash must match frozen authority. No same-hash other-source fallback. Create candidate/outbox/audit and grant provenance atomically. |
| getArtifact                 | Only that grant's admitted artifact; verification state/size/hash, not object bytes or other resources.                                                                                                                                                                                                           |
| getReleaseCandidate         | Only that grant's admitted candidate; existing bounded status representation.                                                                                                                                                                                                                                     |
| listReleaseCandidateEvents  | Only that grant's admitted candidate; existing bounded pagination, no private payloads.                                                                                                                                                                                                                           |

Equal object/configuration bytes may be deduplicated physically; authorization is
an independent exact resource admission relation. Retrying an admitted operation
must not issue new ownership or substitute another source. A new grant for the same
commit does not automatically inherit old grant resources. Candidate identity
collisions follow existing conflict behavior. No general `private-results:view`,
project/candidate listing, private logs, approval, retry, cancellation, publication
mutation, integration management or human-session endpoint is authorized. Status
observation does not confer permission to report GitHub checks: that is a separate
trusted reporter/Action acceptance concern. Existing human/project-token behavior
is unchanged. Finite grant expiry may end optional waiting; it does not authorize
silently acquiring broader credentials.

## Acceptance and rollback

Golden vectors are normative examples and a contract model, not evidence that
signature checking, database transactions, clocks, revocation or provider calls
are implemented. A separately reviewed consumer must prove them with real
PostgreSQL/JWT/HTTP/router tests, including concurrent admission, uncertain commit,
post-lock expiry, hash-only retention, hostile input, resource substitution and
same-grant observation. Published schema/client/semantics/vector hashes must be
inspected before consumer implementation. Disable new issuance/admission on
rollback; retain spent-assertion evidence and never reinterpret old grant tokens as
human tokens. No live installation, credential backend or deployment is selected.
