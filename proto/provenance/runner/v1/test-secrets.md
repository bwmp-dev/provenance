# Ephemeral test-secret delivery v1

This is an additive, explicitly negotiated protocol-1 feature. Publishing
credentials are never test secrets. A schema or protocol release alone does not
enable this feature or establish that a deployment supports it.

Configuration may supply `tests.secrets` as an object mapping safe lowercase
names to explicit immutable version numbers. Names match
`^[a-z][a-z0-9]*([._-][a-z0-9]+)*$` and contain at most 63 ASCII bytes. Versions
are integers from 1 through 9007199254740991. There are at most 64 names. Absent
or empty selection preserves no-secret behavior. Never put values in config.

The backend resolves names strictly within the authorized candidate's project
and organization. It pins secret IDs and versions before job dispatch, sorted
by name. Configuration and job identity must preserve those references across
retries; rotation never changes a pending job's selected version. Unknown,
expired, revoked, unversioned or inaccessible selections fail closed. References
contain no value digest. Secret-bearing jobs require `TEST_SECRETS_V1`, durable
lease acknowledgements and valid job correlation; never strip references to
dispatch to an older consumer.

After a committed lease-acceptance acknowledgement, the runner may send an
ephemeral `TestSecretsRequest`. The gateway reauthorizes the current authenticated
runner, connection, lease, job, execution, attempt, candidate, matrix entry and
tenant/project against authoritative state. Offered-only, replaced, expired,
cancelled, terminal, stale, wrong-stream or otherwise mismatched requests are
refused. No request can select extra names or versions. Delivery requires every
selected version to remain available and unrevoked; the response is all-or-none.
The request receives no durable event acknowledgement. A refused request fails
preparation without exposing the refused value or database details.

`TestSecretsDelivery` echoes the current request message ID and exact authorized
identities. Its values exactly match the immutable offered references, in name
order, without duplicates or extras. Values are nonempty valid UTF-8, each and
in aggregate at most 65536 bytes. At most 64 values are allowed. Only this
negotiated gateway variant permits 98304 encoded bytes to accommodate identity
overhead; runner messages and all other gateway variants retain their existing
limits. Expiry is the minimum of current lease expiry and every selected
version's expiry. Expired input must not be used to start a sandbox.

The runner verifies the entire delivery before use and registers every value
with the bounded redactor before starting a process that could emit it. Mount
each input as a read-only file named after its reference under the fixed
job-private `/run/provenance/test-secrets` directory inside the sandbox. Backing
storage must be tmpfs, inaccessible to other jobs and untrusted host users, and
readable by the non-root test process. No environment-variable injection, host
path selection, shared persistent volume or permission broadening is allowed.
An unsupported sandbox refuses the job rather than writing plaintext to disk.

Plaintext delivery, raw values and derived redaction patterns are never durable
job fields, journals, receipts, logs, Temporal payloads, terminal evidence,
attestations, debug dumps or command arguments. Reconnect requires fresh
authorization and delivery, not persisted plaintext. Process restart must
dispose of orphaned secret-bearing sandboxes before reusing their capacity.
Completion, cancellation, preparation failure, lease loss and cleanup failure
all require destruction of the job-private mount and release of in-memory
references; cleanup failure quarantines the affected slot. Revocation prevents
future delivery but cannot retract a value already supplied to running code.
Bounded known-transform redaction is not arbitrary-exfiltration prevention or
a claim of forensic erasure from the Go heap.

Roll out capability-aware server admission first, then consumers implementing
all validation, isolation, redaction and cleanup rules. Advertise only when
enabled and supported; do not advertise to an older gateway that rejects unknown
feature values. Activate secret-bearing scheduling only after both sides and
the complete failure/reconnect cleanup path have passed acceptance tests.
