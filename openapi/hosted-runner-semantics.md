# Hosted runner lifecycle (IFC-024, unreleased)

These additive endpoints administer platform-owned nodes. They do not change the
self-hosted registration protocol or grant organization members fleet access.

Administrator operations require a current browser session and current platform
administrator role. Node updater operations require a separate node-bound bearer
credential. Connection credentials cannot authorize updater or administrator HTTP
operations. Credential fingerprints are lowercase SHA256 digests of exact UTF-8
credential bytes; the administration API never accepts the plaintext credential.

Administrator mutations require `Idempotency-Key`. Repeating the same key and
request replays its result; changing the request conflicts. Registration assigns a
server UUID, while the client retains its privately generated secrets for retries.
Rotation requires a quiet node and cannot change an active update's credentials.
Revocation prevents future connections and is checked during existing sessions.

Updater polling is deliberately report-idempotent instead of using a new HTTP
idempotency key on every heartbeat. An `idle` request without `operationId` selects
that node's durable active operation. Every non-idle report requires the selected
operation UUID. Repeating a terminal report returns the same terminal operation;
a caller cannot use another node's operation UUID to advance it. A wait response
without an active operation has an empty operation ID and a null release.

Installation profiles contain temporary HTTPS download URLs and must not be
cached or logged. Assets are identified by exact SHA256 and bounded sizes; consumers
verify bytes before installation. Release updates additionally verify the pinned
Ed25519 signature over the canonical manifest, never trust a URL alone, and send
the updater credential only to the exact configured release-download API path.

Every hosted response has `Cache-Control: no-store`. Errors have exactly `type`,
`title`, `status`, and `code`, with status-specific closed codes. Validation does not
reflect request fields, credentials, invalid values or internal diagnostics. An
unauthorized release is indistinguishable from an unavailable release (403).
Unknown server failures become 503. Contract tests exercise all seven operations;
platform tests establish runtime authorization and state-transition behavior.
