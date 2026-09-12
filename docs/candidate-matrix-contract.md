# Private candidate matrix contract

The additive `GET /v1/release-candidates/{candidateId}/matrix` contract is the
first WP-08D detail slice scoped by
[program PR255](https://github.com/bwmp-dev/provenance-program/pull/255).
It does not establish implementation, deployment or full candidate acceptance.

Unlike execution inventory, this collection includes matrix entries that have
not been scheduled, across retained retry generations. Each entry identifies its
generation; the page identifies the candidate's currently observed generation.
Historic results must not be relabeled as current retry outcomes. Each entry binds its immutable requested environment,
required/informational role, stored state and recorded attempt count. The latest
execution ID links to the existing execution/log inventory, but is not a claim
that the attempt passed or was accepted. Requested environment identities are
not independently measured runner trust. Publication is not implied.

The producer must authorize private-result viewing before validating pagination,
reject Actions submission grants, and qualify every read by tenant and candidate.
Signed opaque cursors bind organization, project and candidate; cross-resource
denial precedes expiration. Pages have at most100 entries and1MiB serialized JSON.
Never return partial success after an invalid or oversized row. Unknown/repeated
query fields are errors; missing/hidden candidates are indistinguishable.
All responses are private/no-store. No raw logs, catalog snapshots, credentials,
object keys or signed URLs belong to this projection.

`openapi/candidate-matrix.test.mjs` exercises empty/unstarted and recorded attempts,
closed fields, malformed identities, contradictory attempt references, array and
string bounds, private response headers, generated-client presence and a hash of
the entire prior alpha24 OpenAPI after removing only the new route/three schemas.
The prior digest is derived from source
`d543d107dc1bd660f639a409cf0882963da276d7`; older compatibility fixtures remain
unchanged, with only this explicit new path added to their addition allowlists.

Immutable artifact/source/dependency detail, attempt durations/classified reasons
and structured terminal evidence remain separate required slices. Neither this
contract nor its fixture tests close WP-08D or the alpha gate.
