# IFC-030 tenant network policy management v2

These six additive organization/project operations administer explicit source
policies, not effective jobs. Existing HTTP/configuration/runner contracts retain
their identities. A valid stored policy does not grant workload networking.

Current owner/admin membership and the existing projects:manage capability are
required for all reads and writes. Independently authenticate the token or session,
authorize the exact organization/project, and check current credential scope,
capabilities, role, expiration and revocation. Project-scoped tokens cannot update
organization policy or another project. Actions grants are refused. Do not trust
actor, tenant, source, version or authority claims supplied in the request body.
Authentication/resource authorization precedes body/version parsing and replay.
Session-cookie writes require existing same-origin and CSRF protections.

POST the versions collection with schemaVersion 2, an expectedVersion and a policy,
plus the existing bounded Idempotency-Key. Zero expects no prior explicit version;
positive predecessors must match the current version. Atomically retain immutable
policy bytes, source/version identity, request identity and audit decision. Recheck
authority before commit. Identical retries return their original 201 response even
after successors exist; never reset current policy or adopt another actor's key.
Changed keys/content or stale expected versions conflict with a private 409.
Writes are independently default-disabled; disabled writes return private 409
only after normal authentication/resource authorization. No default is a grant.

GET the network-policy resource for the latest explicit record at its read snapshot,
or GET its versions/{networkPolicyVersionId} resource for one exact immutable record.
Missing history, foreign sources and unknown IDs return private not-found; never
fallback from an unknown version to current, inherited, none or another tenant.
SourceKind and sourceId must agree with the authorized path. Reads remain available
to authorized callers during write rollback; immutable history is not deleted.

Policies use the released v2 whole hostname/port/transport tuples and uint32 caps.
Transport is exactly tcp or udp. Sort unique tuples by hostname, numeric port then
TCP-before-UDP, preserving each tuple together; reject unsorted or duplicate input.
Reuse canonical ASCII dotted hostname rules: no literal/numeric IP aliases,
wildcards, private resolver controls or alternate DNS. Ports 25, 53, 465, 587 and
853 are refused. Enabled restricted/allowlist modes need 1–128 explicit tuples and
positive finite connection and aggregate byte-rate caps. None has no permissions
and exactly zero caps. Unrestricted is not available through these operations.

Map mode none/restricted/allowlist to released protobuf enum 1/2/3 and transport
tcp/udp to enum 1/2 without flattening tuples. networkPolicySha256 hashes complete
deterministic validated NetworkPolicyV2 source bytes. It is NOT an EffectivePolicy
hash, configuration hash, JSON hash, source authority proof or observed enforcement.
Recompute that identity when reading retained versions; unknown protobuf fields or
noncanonical bytes are invalid even if an accompanying hash matches.

All responses are no-store. Bound the entire request and entire response to 64 KiB;
do not truncate into a valid policy. Reject duplicate/unknown JSON keys, trailing
values, invalid Unicode, non-integral/out-of-range numbers and malformed IDs.
Closed errors never reflect input, credentials, SQL, paths, rules or host inventory.
Successful metadata is limited to the declared schema; no raw YAML, credential,
operator inventory, namespace path, packet program or management endpoint appears.

This contract and its golden vectors do not implement authenticated source storage,
job freezing, feature negotiation, DNS/firewall actuation or runtime measurement.
Keep write creation, enabled-job dispatch and runner advertisement separately gated
until their producer and consumer acceptance passes. Never retry an enabled policy
through a legacy-none endpoint. No signed history or full alpha gate is changed.
