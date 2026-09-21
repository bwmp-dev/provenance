# Public verification (WP-10B)

Existing release JSON and badge paths keep their released response shapes. Owner
and project listings and explicit v1/v2 attestation paths are additive. Private
verification-ID endpoints remain authenticated and unchanged.

Only an explicit audited operator publication makes a signed record public.
Project visibility, successful jobs, possession of an ID, and browser credentials
never grant publication. Publication pins the owner/project/version tuple and the
exact stored canonical record digest permanently; the operator must confirm
public disclosure of the entire signed statement (including source, dependency,
runner and test identities). Publishing the same tuple/proof is idempotent;
a different proof for that tuple conflicts. Original private record bytes and
signatures remain immutable. Publication is not marketplace publication.

Every public response uses `Cache-Control: no-store` and `nosniff`. Credentialed
requests, unknown/repeated query parameters, and request bodies are rejected.
No redirects or private-data fallbacks. Private/absent/wrong-version proofs return
404; unavailable or invalid signatures/keys return 503 without proof bytes.
Listings accept only `after` (canonical UUID) and `limit` (1–100, default 20), order
by verification ID, and return `nextAfter` or null. Empty/absent owners and projects
both return empty pages. Listings are bounded, with no snapshot promise across
pages. Existing release/badge endpoints accept no queries.

Every returned release and envelope is based on reverified canonical signed bytes
and the registered historical public key. Public proof is independent of artifact
bytes, private logs and private metadata retention. Active and retired keys remain
available at `/.well-known/provenance-keys.json`; discovery is not trust bootstrap.
An independent verifier must pin an authentic public key and compare a local JAR.

Hosted: “Verified by Provenance”. Self-hosted: “Reported by organization runner”.
The narrow claim is “The exact artifact was observed passing the listed tests and
environments.” Show actual outcomes and required/informational policies; failed
informational rows are not passing observations. No security, universal
compatibility, or freedom-from-defects claim. A signature authenticates a statement;
it does not turn organization reports into hosted evidence.

Alpha SVGs exist only for hosted command-verified proofs: all required environments
passed, each has a passed console-regex or console-contains assertion, and no
assertion in a required environment is failed or skipped. Other results have full
verification pages but return 404 for badges. Never relabel startup-only,
self-hosted, incomplete, or unavailable evidence as command verified. The remaining
badge taxonomy is deferred under ADR-011.
