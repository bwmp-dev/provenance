# IFC-023: Invited alpha administration

All administrative operations require a current human browser session. API tokens,
GitHub Actions grants and organization roles do not grant administrator authority.
`GET /v1/account` reports the authenticated user's current role. Every other
operation checks the current durable platform administrator role. Responses,
including failures before handlers, carry `Cache-Control: no-store`.

Enrollment uses the verified numeric GitHub identity, never the mutable login.
Existing admitted accounts remain admitted. An otherwise unadmitted account must
have an unexpired, unrevoked invitation. `POST /v1/auth/sessions` returns403 with
`invitation_required` if that condition is unmet; no new account, organization,
admission or session may commit. Acceptance and session issuance are atomic.

Only an explicit operator bootstrap may grant the initial administrator role.
No public first-user bootstrap exists. Restart cannot reinstate a removed role.
Invitation creation resolves a GitHub User account to its numeric identity before
persisting a seven-day invitation, and returns201. Organizations and bots cannot
be invited as users. Revocation only affects an unaccepted invitation; it does not
remove an existing admission. Re-revoking an already revoked invitation succeeds
idempotently. Removing the final administrator is refused, including concurrent
removals. All mutations audit actor, action and target without credentials.

A required caller-supplied Idempotency-Key is scoped to the administrator across
all three mutations. Authorization is checked before replay. The same key and
same method, target and payload return the original result, with no repeated
provider request or mutation. A changed request returns409
`idempotency_key_conflict`. These results and audit history are retained during
alpha. After replay lookup, invitation creation refuses an already admitted
account with409 `account_already_admitted`; revocation refuses an accepted
invitation with409 `invitation_not_revocable`; role removal refuses the last
administrator with409 `last_administrator`. These codes are distinct and must not
be inferred from a bare409. Normative examples are in
`alpha-administration-vectors.json`.

Collections default to50 rows and accept1–100. Cursors are opaque to clients and
must be reused with the same filters. Execution history is newest first with a
stable `(createdAt,id)` keyset; active mode includes queued, offered, leased,
preparing, running and orphaned work. Runner activity counts offered, leased,
preparing and running assignments. A last-seen timestamp is an observation, not a
claim that a runner remains connected. Other lists use stable UUID keysets.

Usage is organization-attributed recorded ledger observations within a half-open
`[from,to)` interval of at most31 days. Quantities are exact decimal strings.
Pending ingestion may be absent. This is neither a complete billing assertion nor
per-user attribution of shared workspaces. Empty metrics mean no observations in
that interval. Operational projections exclude keys, tokens, raw logs and provider
payloads. Normal member responses never contain cross-tenant administration data.

Closed admin problems use type `about:blank`, a bounded safe title, status and code:
400 invalid_request;401 authentication_required;403 admin_required;404 not_found;
409 one of the four conflict codes above;429 rate_limited;503 admin_unavailable.
Unexpected failures normalize to503. Invitation admission is the separately
specified session403 `invitation_required`, not a generic interpretation of403.
