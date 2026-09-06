# IFC018: session-bound GitHub connection flows

This is an additive contract, not a deployed GitHub App or console implementation.
IFC017 sign-in and its hash-only, unreplayable exchange credential remain unchanged.

An authenticated server-side client first selects an existing organization and
project using the existing APIs. Discovery authorization and completion obtain an
expiring private metadata snapshot. Snapshot pagination stores no provider token.
After selecting a repository, a separate connection authorization and completion
obtain fresh provider proof and create the durable connection. A client that
already knows the exact identifiers may omit discovery, never the fresh proof.

Both flows require the same initiating platform session, its numeric GitHub user
mapping and current `integrations:manage` capability. Metadata and opaque snapshot
IDs confer no authority. Existing `installationId` remains a platform UUID;
new `githubInstallationId` and `githubRepositoryId` are provider safe integers.
Only the completed connection response uses the existing `GitHubConnection` shape.

The BFF owns same-origin/CSRF checks, binding the browser to its server-side flow,
and server-only state/verifier storage. Platform credentials never enter browser
JavaScript. The caller supplies no App identity, scopes, token endpoint or return
URL. Callback allowlists and finite lifetimes are explicit deployment inputs.

Completion claims precede code exchange. Unknown consumption or discovery overflow
requires a new authorization, never a second exchange of the old code. Successful
nonsecret results replay only within their original retention window after current
local access checks; discovery also requires an unexpired snapshot. Snapshot expiry
does not erase audit/idempotency history, and reads never extend expiry. Consumer
implementations must purge expired private metadata. No provider token is retained
between discovery and selection.

The contract describes, but these schema tests cannot prove, runtime authorization,
atomic claims, cleanup, provider reconciliation or server-side cookie enforcement.
Those require the separately released platform consumer and its integration tests.
Transfer/removal, production custody, live App configuration and console work are
outside this change. Release publication and activation require owner acceptance.
