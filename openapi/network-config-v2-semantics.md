# IFC-030 explicit configuration-v2 HTTP

This additive contract is not backend deployment, network authorization or
runtime enforcement evidence. Existing v1 operation bodies and response schemas
remain unchanged. No old snapshot, job, canonical hash or signed history is
rewritten, and v1-none support does not expire through this introduction.

`POST /v2/projects/{projectId}/config-snapshots` accepts only `schemaVersion: 2`
and `provenance.dev/v2` configuration. The authorized caller, tenant, project and
source restrictions are identical to the corresponding v1 write capability.
No ambient cookies or hosting credentials are accepted. Authenticate and
authorize before inspecting versions, parsing configuration or replaying keys.
Project tokens and Action grants remain independently scoped and cannot replace
their frozen project/source with request fields. A different operation name
does not grant extra capabilities or turn an Action grant into human authority.

Validate raw YAML with the authoritative offline v2 validator. Its canonical
normalization must exactly equal normalizedJson; SHA-256 of those exact UTF-8
bytes must equal configurationHash; every version discriminator must agree.
Require bounded inputs and a valid idempotency key. Identical successful replay
returns the same 201 snapshot and immutable metadata. Changed request content
or conflicting source identity returns private 409, never an overwritten
snapshot or recomputed identity. Invalid configuration/version identity is a
private validation failure; disabled creation returns private 503. No raw YAML,
normalized configuration, private policy contents, credentials or storage
locations appear in response or reflected diagnostics. All responses are no-store.

`GET /v2/release-candidates/{candidateId}/inputs` has the same private-result
authorization and immutable projection as v1, but explicitly preserves snapshot
schema version 1 or 2. Actions submission grants remain refused. Candidate source
and snapshot source are distinct identities. A null dependency resolution means
unavailable, not a zero-dependency result. No mutable dependency lookup or success
inference occurs during reads. Reject query parameters, corrupt or oversized
projections; do not silently omit evidence. Every response is no-store and hidden
and nonexistent candidates have indistinguishable private 404 responses.

The v1 inputs route remains version-1-only. After normal authorization, an
unsupported version-2 descriptor returns the existing private 404 instead of
being relabelled or exposed with a shape old consumers cannot interpret. No
duplicate timing/terminal-evidence endpoint is needed: that existing projection
has no configuration-version descriptor, and its versioned evidence retains
its original semantics.

Rollout: release these contracts and dual-version readers, deploy separately
gated backend validation/persistence with immutable required-feature fences,
then move explicit v2 clients to the new route. Keep CLI/Action v2 submission
refusal until the public HTTP contract is released and the backend gate accepted.
Never retry a v2 refusal through v1 or send v2 bytes labelled as version 1.
Snapshot admission does not enable networking: authenticated five-layer policy,
frozen dispatch identity, negotiated runner enforcement and measured acceptance
are separate prerequisites. Rollback disables v2 creation and dispatch, retains
versioned records and never strips fields, resets budgets or downgrades jobs.
