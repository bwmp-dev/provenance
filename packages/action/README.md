# Provenance GitHub Action

Submits one exact JAR with IFC-022's short-lived, shown-once Actions grant. This is
an inactive client: a configured platform endpoint, accepted project/repository
connection and explicit server workflow policy must already exist. No deployment
endpoint, credential backend or production policy is selected by this package.

Use `bwmp-dev/provenance/packages/action@<reviewed-full-commit>` after replacing
the placeholder with the reviewed Action distribution commit. Node 24 is the
Action runtime. The committed `dist/index.cjs` includes the existing generated
API client and configuration normalizer; checkout needs no install/build step.

## Inputs and trust

See [action.yml](action.yml) for every input and numerical limit. Required inputs
are artifact/configuration paths, version, project UUID, trusted HTTPS platform
origin, OIDC audience, originating repository/commit/ref, and an explicit maximum
artifact byte budget. Configuration release mode is preserved, including manual
approval. Changelog is sent only to the configured platform and never printed.

Explicit `provenance.dev/v1` and `provenance.dev/v2` configurations use their
matching `/v1` or `/v2` snapshot creation route and schema version. Responses must
match the configuration hash, project, source commit/ref and schema version.
A disabled or refused v2 route fails without retrying through v1; configuration
validation does not grant networking permission. Existing v1 bytes are unchanged.

Only GitHub.com `push` and `workflow_dispatch` contexts are supported initially.
Repository/commit/ref must exactly match runner context; numeric repository and
owner IDs must match the returned grant scope. Pull requests (including forks and
`pull_request_target`), repository dispatch and GHES are deliberately unavailable;
do not add elevated credentials to work around this check. The server independently
verifies signed workflow and repository policy. No assertion claim is local proof.

Request `id-token: write` to obtain the assertion. Opt-in `report: status` requires
an explicitly passed ephemeral repository `github.token` and `statuses: write`.
It uses only GitHub's fixed commit-status API, never an input/provider URL. Reporting
permission failures remain failures, not fabricated success. No API token/PAT
fallback or elevated token mint is implemented. Leave report `none` when no reporting
authority is supplied. See [examples](examples/README.md).

The JAR is opened without following a symlink, read once into an explicit bounded
buffer, hashed and checked against its retained file identity before each resource
operation. The same bytes are uploaded with no platform/GitHub credentials. Only
an allowlist of content/checksum/storage metadata headers and the exact
`If-None-Match: *` immutable-upload condition is accepted. Header names are
case-insensitive; duplicate names and other conditions are refused before upload.
Credential and routing headers remain forbidden; redirects
are rejected for every credential domain, including storage. Resource identity,
hash and byte count are checked against server verification before candidate creation.

## Waiting, replay and truthful reporting

| Observation                                      | Action outcome    | Commit status                       | Process result                |
| ------------------------------------------------ | ----------------- | ----------------------------------- | ----------------------------- |
| Submission only                                  | submitted         | pending                             | success means submission only |
| Candidate needs approval                         | approval_required | pending                             | success means handoff only    |
| Candidate published                              | published         | success                             | success                       |
| Candidate failed                                 | failed            | failure                             | failure                       |
| Candidate canceled                               | canceled          | error                               | failure                       |
| Timeout, expiry, inaccessible or unknown outcome | incomplete        | error if reporting remains possible | failure                       |

`approved`, `test_completed` and `publication_gate_passed` do not prove
publication or compatibility success. The Action waits for the candidate's
terminal state before reporting a published or failed outcome.
Events are bounded identity-checked observations, not a hidden result payload.
Per-target publication results, private logs, lists, approvals, retries and cancel
mutations are outside this grant and are never requested. Client cancellation
stops observation; it does not cancel the durable platform candidate.

Defaults bound client work: 30s/request, 10min total, 2s poll interval, two attempts
per resource operation, ten event pages (1000 retained event identities), and 1MiB
per response. These are client safety defaults, not platform grant lifetimes or
deployment settings. Explicit artifact budget has a 2GiB-minus-one-byte ceiling;
choose a much smaller value appropriate to the build. All time/page bounds have
hard maxima in metadata/source.

### Effective wait ceiling

Grant expiry is fixed at issuance and is no later than the GitHub OIDC assertion
expiry, which is typically about 5 minutes. `timeout-ms` never extends it: the
effective wait ceiling is the earlier of `timeout-ms` (measured from Action start)
and grant expiry. With `wait: "true"`, when `timeout-ms` exceeds the grant's
remaining lifetime the Action logs a warning up front naming `timeout-ms`, the
grant `expiresAt` and the effective ceiling, and polling is bounded at that
ceiling. A candidate that has not settled by then is reported as `incomplete`
with reason `authority_expired`: the outcome is unknown, never success or failure.
The error names the known `candidateId` so its result can be checked in the
Provenance console or with separately authorized access; do not rerun with a new
grant to resume it. Keep `timeout-ms` at or below about `280000` when waiting,
or leave `wait: "false"` and follow the candidate outside the workflow when
tests or approval routinely take longer.

Expiry is measured against the platform's clock: when the grant response
carries an HTTP `Date`, the remaining lifetime is computed on the server clock
and anchored to the local request start minus one second of `Date` resolution,
so runner clock skew neither ends a live grant early nor extends use past
server expiry. Without `Date`, the absolute `expiresAt` is compared locally.

Only the original in-memory grant is used. Resource retries keep the same request
body and idempotency key, within its lifetime. Issuance is never automatically
retried: a lost successful issuance response cannot recover its credential. No
new assertion/grant is requested to resume an old resource. Expiry ends both
mutation replay and observation. Known UUIDs are returned with `incomplete` for
operator follow-up; a later job run cannot inherit those resources. A lost storage
PUT acknowledgement is also incomplete, without blindly reuploading.

Outputs contain only closed outcomes/reasons and known UUIDs. Tokens/assertions
are masked before diagnostic handling; URLs, private payloads/changelog and raw
exceptions never reach logs, annotations, summaries or Action outputs. Already
issued storage capabilities cannot be revoked by this client; server completion
and read admission still independently enforce current authority.

## Development and acceptance limits

`pnpm build` builds dependencies and the deterministic bundle. `pnpm --filter
@bwmp-dev/action test` runs compiled-distribution TLS simulator tests with the real
generated API client and normalizer, plus deterministic rebuild comparison.
`pnpm check` includes these tests via the existing workspace scripts. esbuild is
locked to 0.28.2; dependency notices are included beside the bundle. Test-only
transport injection is exported for fixtures but never selected by Action inputs.

Synthetic HTTP/JWT responses do not prove a real private-repository OIDC flow or
live commit reporting. That remains the separately authorized Plan07 exit gate.
This package does not change released contracts or the contract archive inventory.

Primary runtime references: [GitHub OIDC](https://docs.github.com/en/actions/reference/security/oidc),
[commit statuses](https://docs.github.com/en/rest/commits/statuses#create-a-commit-status),
and [Action metadata](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax).
