# IFC-020 device login

This is a Provenance JSON contract, not OAuth device-grant wire compatibility.
Contract vectors describe required behavior; they do not prove any deployed service.

## Authority and limits

All three operations reject any Origin header (including empty, null, same-origin
or repeated Origin) with 403 authorization_denied. They are server-to-server
operations. The browser confirmation adapter must keep the forwarded session
credential server-side, validate CSRF and its configured browser Origin, display
the requested login and require an explicit approve/deny action. No GET, lookup,
sign-in or clientName alone approves anything. clientName is untrusted display
text. No caller userId, organizationId, role or capability is accepted.

Decision requires a current unrevoked, unexpired session and binds its actual
internal user, not a GitHub username or a caller assertion. A different live
session for the same user may replay the same decision; a foreign user cannot
replace or discover the existing identity. Approval issues no organization grant.
Current resource membership/capabilities apply independently after login.

Requests are application/json objects at most 4096 UTF-8 bytes; duplicate JSON
keys, malformed UTF-8, trailing values and unknown fields are invalid. Existing
clientName remains optional with its released 1..128-character bound. New device
and exchange secrets are independent canonical base64url encodings of 32 random
bytes (43 characters, no padding). User codes are independently random exact
uppercase XXXX-XXXX from A-H/J-N/P-Z/2-9; no trimming or case normalization.
User codes never redeem a credential. Idempotency keys keep the existing bound.
The authorization response keeps its released fields; issuance additionally obeys
these secret/user-code bounds, intervalSeconds 1..86400 and configured HTTPS
verificationUri of at most 2048 characters, with no code in query or fragment.

Deployment must explicitly configure validated finite authorization lifetime,
exchange-credential lifetime, receipt lifetime, issuance/guessing/polling budgets,
positive polling interval and HTTPS verification URI. No defaults are assigned.
Retry-After on 429 is integer seconds 1..86400, not an HTTP date, and does not
extend a deadline. Limits apply independently to requesters and authorization
records; one code must not bypass global admission controls.

## Frozen deadlines and durable states

Creation freezes authorization expiresAt. Approval never extends it. Credential
issuance freezes its own deadline at min(original authorization expiry,
issuance time + configured credential lifetime). An exact deadline equality is
expired. Replay never extends authorization, credential or receipt lifetimes.
Store only domain-separated hashes of device/user codes, exchange credentials
and idempotency identities; never raw values in durable receipts, audit, logs,
Temporal, attestations or URLs. Retain nonsecret identity, state, deadlines and
request fingerprints for the configured bounded replay period. Once a receipt
is purged, an old secret cannot become valid or recreate an authorization.

States are pending -> approved or denied; approved -> consumed when the exchange
credential is committed. Expired state is determined by the frozen deadline.
Decision binding, consumption and hash-only credential creation are transactional.
Database rollback before commit does not consume a code or produce an outcome;
retry can proceed. A lost commit acknowledgement is resolved from durable state,
never by issuing a second credential. Local session redemption uses the unchanged
one-time session boundary; deviceCode itself is never a session exchangeToken.

## Ordered response precedence

All responses, including middleware errors, have Cache-Control: no-store. Errors
have exactly type=about:blank, title=Device authorization failed, integer status
and a closed code. No arbitrary detail, instance, submitted value or provider
text is permitted. Service/proxy failures must be mapped into this vocabulary.

1. Unsupported media type -> 415; oversized body -> 413; malformed body/key ->
   400 invalid_authorization. Origin rejection -> 403 before identity lookup.
2. Decision session missing/expired/revoked/ambiguous -> 401
   authentication_required. Anonymous exchanges do not accept session authority.
3. Global pre-lookup admission limit -> 429 rate_limited. Required unavailable
   configuration/storage -> 503 authorization_unavailable; no speculative result.
4. Initiation: existing same-key/different-payload receipt -> 409
   idempotency_conflict. Same successful receipt -> 409 credential_not_replayable,
   even after its authorization expires, while receipt retained. A fresh valid
   request commits once and returns 201. Concurrent identical creation permits
   one 201, all others 409 credential_not_replayable.
5. Decision: missing code -> 400 invalid_authorization. For an already bound
   foreign user -> 403 authorization_denied regardless of deadline/decision.
   Same identity/key with different request -> 409 idempotency_conflict.
   At authorization deadline -> 410 authorization_expired (even matching replay).
   Same identity and matching recorded key/request -> 200 original nonsecret
   outcome while live, including after exchange consumption. Any other decision
   after binding -> 409 decision_conflict. Pending -> atomically approved/denied,
   200 {state, expiresAt}. Approval versus denial race has exactly one winner.
6. Exchange: unknown secret -> 400 invalid_authorization. Consumed secret -> 409
   credential_not_replayable while its receipt retained, even after expiry.
   Otherwise at authorization deadline -> 410 authorization_expired. Denied ->
   403 authorization_denied. Only live pending/approved states consult the
   per-authorization polling schedule: early poll -> 429 plus Retry-After.
   Pending -> 202 {state:pending, intervalSeconds, expiresAt}. Approved -> one
   atomic 200 {exchangeToken, expiresAt}; concurrent losers see consumed 409.

Global admission may mask subsequent outcomes; per-code polling must not mask
consumed, expired or denied outcomes. Pending/rejected polls do not slide expiry.
Identical successful initiation replay is an explicit IFC-020 change from the
former generic promise to reproduce the original outcome. The historical
baseline remains immutable and tests register this exact exception; unchanged
session/GitHub/OIDC and shared idempotency definitions are not reinterpreted.

## Consumer and rollback boundaries

CLI login polls using the device secret in a POST body and exchanges the returned
platform credential through POST /v1/auth/sessions. Session cookies remain the
existing authentication mechanism; there is no refresh token or bearer token
conversion. CLI secure storage, confirmation UI, live GitHub configuration and
resource selection are separate work. No raw credential examples are published.

Release contract first, accept transactional platform consumer next, then CLI
and separately owned confirmation adapter. Rollback disables these operations
and initiation if its replay semantics cannot be preserved. Never restore raw
secret receipts or reinterpret device secrets as GitHub authorization codes.
