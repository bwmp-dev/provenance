# Complete benign consumption example

Copy this directory, retaining `examples/consumption/` paths, into your plugin
repository. The Java plugin logs one lifecycle message and does not access files,
network, processes or credentials. Its configuration requests one required Paper
1.20.6 environment in **test-only** mode: submission is not a publication claim.
The Paper API compile dependency is checked against the same exact SHA-256 as
the accepted toolkit probe; API stubs are not used in this build.

## Build and configure

Use Node 24.19.0 and JDK 21.0.12+8.0.LTS. Check out toolkit commit
`7bb028bbad907a0d95e2c23e8e614326091a897b` as `.provenance-toolkit`, then:

```sh
(cd .provenance-toolkit && node scripts/run-gradle.mjs :paper-probe:verifyPaperApiArtifact)
node examples/consumption/plugin/build.mjs .provenance-toolkit/plugins/paper-probe/build/dependency-verification/paper-api
```

This produces `examples/consumption/plugin/build/example-plugin.jar`. Dependency
provisioning may use the public Maven repositories; the builder itself only reads
the hash-checked API and compiles locally. Rebuilding the same sources with the
pinned JDK yields identical JAR bytes. Never include toolkit/API classes in the
plugin archive. Change the plugin version, configuration version and Action input
together when making a new version.

An operator must configure the deployed platform's exact project, installation,
numeric repository/owner binding, and permitted workflow/ref policy first. Set
repository variables `PROVENANCE_ORIGIN` (trusted HTTPS origin),
`PROVENANCE_PROJECT_ID` (UUID), and `PROVENANCE_AUDIENCE` (configured OIDC audience).
No endpoint or policy is selected by this example. Missing configuration fails
closed; a simulator does not establish a real connection.

Choose exactly one workflow, copying `public.workflow.yml` or
`private.workflow.yml` to `.github/workflows/provenance.yml`, and authorize that
exact workflow path on the server. Both work with explicit repository visibility;
visibility alone grants no authority. The public example opts into commit status
reporting with only `contents: read`, `id-token: write`, `statuses: write`. The
private example omits reporting and therefore needs no status permission/token.
Private source checkout uses the ephemeral job token; never persist a Provenance
API secret, PAT or OAuth token. Protect workflow changes and the selected branch.

Only push and workflow_dispatch are supported. Fork PRs, pull_request_target,
repository_dispatch and GHES are intentionally unavailable. Never grant secrets
or broader permissions to make an unsupported context pass.

The Action is pinned to accepted commit `975a854b42f997a6b382b549b65f6e8b2be25158`.
It uses the actual normalized configuration, exact SHA-256 and same JAR bytes.
`wait: false` means **submitted**, not tests passed or published; reporting stays
pending. Set bounded `wait: true` only if desired: approval is still a handoff,
and timeout/grant expiry produces incomplete rather than a fabricated result.
Short grant expiry ends retry and observation. A new grant cannot inherit the
candidate; keep returned UUIDs for an authorized operator. No publication-result
or general private read capability is implied.

## SDK and offline verification

Install the independently verified SDK archive as documented in
[the SDK guide](../../packages/typescript-sdk/README.md). Use the SDK's actual
generated operations with explicit caller credentials, or its configuration and
offline verification exports without any credential. Supply an independently
trusted public key: an attestation's key ID is not a network trust instruction.
Verify signature before reading artifact bytes, then exact size and digest.
Do not print raw private responses, signed upload URLs or credential material.

After installing the SDK package, the included executable offline example is:

```sh
node examples/consumption/sdk-verify.mjs attestation.json plugin.jar trusted-public-key.pem
```

Its output is a closed verification result, never the document, key or private
file paths. It opens the artifact lazily after authenticating the signature.

The CLI is a separately distributed Linux archive, not part of the SDK. Its
concrete inspected release pin and offline command are added only after release
inspection; this source example does not claim a published CLI or SDK release.

The tests build this exact plugin twice and exercise bounded simulated submission
with the compiled accepted Action and SDK. They do not create repositories, make
live provider calls or close the real private-repository Plan 07 acceptance gate.
