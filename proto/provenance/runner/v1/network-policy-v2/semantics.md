# Authenticated network policy v2 (IFC-030)

This additive protocol-`1` representation is not activation, configuration,
attestation or evidence of enforced networking. Existing network-none jobs and
their canonical configuration/evidence bytes are unchanged. Configuration v1
does not acquire permission tuples or caps through this wire addition. An
explicitly versioned public request and evidence contract, authenticated policy
persistence and complete consumer acceptance are prerequisites to enabled jobs.

## Admission and compatibility

`NETWORK_POLICY_V2` (9) is independently negotiated for each authenticated stream
and resets on reconnect. Unknown, unspecified and duplicate feature values are
invalid. Enabled admission also requires durable lease acknowledgements and job
correlation. A runner advertises only when its trusted local maximum, controlled
DNS, IPv4/IPv6 sandbox, finite limits and all cleanup paths are supported and
enabled. A server first learns the feature without enabling scheduling; runners
must not advertise it to an older server that rejects unknown feature values.

Exactly one effective network representation must be present. Legacy `network`
alone keeps its released meaning. A present `network_v2` requires negotiation,
valid correlation and the v2 trusted maximum; it must not coexist with legacy
`network`, even a none fallback. Exactly one maximum representation is present
in capability policy and policy updates. V2 is optional on a negotiated stream
for legacy jobs, but a v2 job is never converted to legacy. An unsupported or
invalid offer is rejected before lease acceptance or sandbox creation.

The gateway checks the immutable job's required feature before scheduling and
serialization, not just whether a decoded optional field exists. Pending v2 jobs
must be fenced from old gateways/workers that cannot interpret their version.
Rollback first disables creation and dispatch, then withdraws/drains enabled
work, retaining exact immutable job identity and evidence. Never drop unknown
fields, strip required features, synthesize none, flatten tuples or reset budgets
to make retained jobs runnable. Protobuf unknown-field preservation alone is not
an admission fence.

## Resolved policy

Mode is exactly none, restricted or allowlist. Unspecified and unrestricted are
invalid, including on self-hosted runners. None has zero permissions and both
caps zero and prohibits all workload network including DNS. Enabled policies
have 1–128 unique whole `(hostname, port, transport)` permissions, sorted by ASCII
hostname, then numeric port, then transport value (TCP 1 before UDP 2). Both caps
are integers in 1–4294967295. Connections are concurrent across both address
families; byte rate is aggregate bytes/second across both families and all
permissions, not per destination. Zero never means unlimited. Overall gateway
messages retain their existing 65536 encoded-byte limit.

Hostnames are lowercase ASCII dotted DNS names, 1–253 bytes, labels 1–63 bytes
of `a-z`, `0-9` and `-`, without edge hyphens or a trailing dot. At least one
letter is required. IP literals, numeric-address alternatives (including mixed
decimal, octal or hexadecimal labels), wildcards, Unicode and search suffixes
are forbidden. Ports are 1–65535 excluding SMTP 25/465/587 and arbitrary DNS
53/853. Transport is exactly TCP or UDP, never unspecified or unknown. Treat
each tuple as indivisible: independent sets would authorize extra combinations.

The backend independently authenticates and authorizes platform, runner,
organization, project and optional job sources, validates every supplied source,
freezes source versions and the intersection, and audits it. Omitted job means
none. Empty intersection means none without DNS. Neither source labels nor a
client-computed digest prove authorization. A runner validates the received
effective permissions and caps against its trusted local maximum before use;
the job cannot replace that maximum. Enabled mode labels do not grant implicit
permissions. Any effective tuple absent from the maximum or either cap above
the maximum is refused, not silently narrowed after job identity was frozen.

## Enforcement obligations

Only the runner's controlled DNS may resolve approved names. Both A and AAAA
answers and complete CNAME chains are validated against trusted mandatory deny
inventory; mixed safe/unsafe answers are refused. Pin short-lived bindings to
this job, reject changed address sets, direct-IP bypass and rebinding, and
withdraw forwarding on expiry before refresh can authorize new traffic. Deny
loopback, private, link-local, metadata, multicast, control-plane, management and
runner-host addresses for both families. The job cannot select resolver
endpoints, namespace/host paths or deny overrides.

All connections and traffic share the finite job budget. Refresh preserves
accounting; cancellation, lease loss, preparation failure, restart and cleanup
failure must withdraw forwarding, including established flows. Quarantine on
unproven cleanup. Job-local isolation must not change host-global routing or
adopt another job's namespace. Public tuple validation is necessary but does
not prove any packet, DNS response, budget or lifecycle action was enforced.
