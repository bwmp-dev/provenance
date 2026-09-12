# Private candidate input identities

This additive private read implements the immutable-input contract slice of the
[assigned WP-08D detail scope](https://github.com/bwmp-dev/provenance-program/pull/255).
It does not itself establish producer, consumer, deployment or full-alpha acceptance.

`GET /v1/release-candidates/{candidateId}/inputs` returns only bounded exact stored
identities: candidate source commit/ref, artifact filename/hash/size, configuration
snapshot ID/hash/schema/source, and the retained resolved dependency identities.
Candidate source and configuration snapshot source are separate; neither may be
silently substituted for the other. A stored source string alone does not assert
GitHub verification. Artifact identity does not assert current storage availability.

`dependencyResolution: null` is unavailable/not yet resolved. A non-null retained
resolution with `items: []` is a resolved zero-dependency result. Its ordered entries
bind declaration/requirement, immutable resolved artifact, exact provider identity,
byte digest/size, plugin name, inspection and registry metadata digests, and resolution
time. The producer must validate stored digest and candidate/configuration/artifact
bindings before returning success, including resolution order contiguous from zero,
unique entry IDs and declaration names, and at most 64 dependencies. Inconsistent,
legacy-incomplete or corrupt evidence must not be silently recast as a successful
empty resolution. No dependency is fetched again or selected from mutable state.

Authentication and private-result capability/resource visibility checks precede
query validation. The operation accepts no query fields or Actions submission
grants. Missing and hidden candidates have the same private 404; all responses
are private/no-store. The complete projection is bounded to 128 KiB serialized JSON;
oversized or malformed evidence is unavailable rather than partially returned.
No control characters may enter displayed identity fields. Raw YAML, changelogs,
registry/inspection metadata, secret values, object keys, storage locations and
signed URLs are excluded. Rollback disables the consumer before making this new
read unavailable; existing candidate, matrix, execution and log contracts remain
unchanged.

Contract tests cover unresolved, resolved-empty and resolved dependency identities,
closed/missing fields and bounds, private headers, generated consumer presence, and
the digest of the complete alpha25 OpenAPI after removing only this route and its
five new schemas. The unchanged prior digest is derived from released source
`04093d2c2799a55b4142b1e3c72b7a5ac019650a`; prior compatibility hashes and grant
allowlists are not expanded to authorize this read.

Attempt duration/reason and structured terminal evidence remain separate required
WP-08D slices. This contract does not accept public compatibility, runner trust,
publishing, onboarding or the integrated first-developer flow.
