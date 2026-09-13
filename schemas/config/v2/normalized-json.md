# Configuration v2 migration and canonical identity

`provenance.dev/v2` is an explicit opt-in request version. V1 remains supported;
no automatic migration, rewrite or deadline is imposed on existing v1-none
configurations, frozen jobs or signed history. Never relabel an existing v1
snapshot or recalculate its identity under v2. Unknown versions and fields fail.
V2 validators load the bundled v1 definitions offline; schema URLs are identities,
not permission to fetch documents during configuration loading.

V2 replaces the legacy network hostname/ports list with whole hostname/port/
transport (`tcp` or `udp`) tuples, `maximumConnections` and aggregate
`maximumBytesPerSecond`. Both limits must be positive finite uint32 values for
enabled restricted/allowlist requests. None requires empty permissions and zero
limits and grants no DNS. Unrestricted is unsupported. No implicit transport,
default cap, implicit restricted destination profile or zero-as-unlimited value
is introduced. A caller migrating legacy enabled configuration must choose each
transport and both caps explicitly; a validator must never invent them.

All other fields retain their v1 semantics. The v1 normalized JSON algorithm
applies unchanged: sorted object keys, preserved array order, no whitespace or
Unicode normalization. Permission array order therefore contributes to the
configuration SHA-256. The backend validates and sorts the separately frozen
effective wire grant; it does not mutate the submitted configuration or its
hash. The explicit apiVersion means v2-none has a different hash from v1-none.

This schema is a request, not authority or packet-enforcement evidence. Platform,
runner, organization and project policies independently constrain it. Invalid
or unauthorized sources are refused even when another source requests none.
An empty authorized intersection means no network, including DNS. User inputs
cannot select resolver endpoints, host rules, namespace paths or deny overrides.

Migration window: release dual-version validators first, then deploy backend
v2 persistence/authorization and immutable required-feature fencing, then
capable runners. Creation and dispatch of enabled requests remain disabled
until the complete authenticated enforcement and versioned evidence gates pass.
Schema support alone must not bypass those gates. An old validator refuses v2;
rollback retains snapshots and fences pending v2 jobs from old consumers. Do not
strip v2 fields, downgrade a job to none or reset traffic budgets to resume it.

At this release, the HTTP snapshot contract still specifies `schemaVersion: 1`.
CLI and Action submissions therefore refuse v2 locally before authentication or
upload, including when an existing snapshot ID is supplied. Local validation and
hashing support v2; submission needs the separately accepted HTTP boundary and
server rollout. Never send v2 bytes labelled as schema version 1.
