# Provenance TypeScript SDK

This explicit-trust facade reuses the generated HTTP client, configuration
parser/normalizer/hash, and independent attestation verifier. It does not obtain,
store, renew or retry credentials and does not sign attestations or discover keys.

Alpha distribution is a GitHub release archive, not an npm registry publication.
Verify the release checksums and provenance before extracting. The archive's
`package` directory includes the original `@bwmp-dev/api-client`,
`@bwmp-dev/config-schema` and `@bwmp-dev/verification` packages under `vendor`.
These copies preserve their package identities; they are not separately published
npm versions. Add the extracted directory using pnpm 11.20.0:

For a fresh application directory, use the verified aggregate release manifest
to pin the same public transitive runtime versions recorded by the SBOM. The
following fails if a workspace policy already exists; merge these exact overrides
deliberately into an existing policy instead of replacing it.

```sh
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const manifest = JSON.parse(readFileSync(process.argv[1], "utf8"));
if (manifest.schemaVersion !== 2) throw new Error("Expected SDK inventory");
const overrides = Object.fromEntries(manifest.dependencies
  .filter(d => d.ecosystem === "npm" && d.bundles.includes("typescript-sdk"))
  .map(d => [d.name, d.version]));
writeFileSync("pnpm-workspace.yaml", JSON.stringify({ overrides }), { flag: "wx" });
' ./verified-release.manifest.json
pnpm add --ignore-scripts ./vendor/provenance-typescript-sdk/package
```

The path is your chosen extraction location. Keep it with the application and
commit its lockfile. The manifest filename and extraction path above are your
verified local copies, not URLs to execute or fetch automatically. Without the
audited overrides, transitive semver ranges can resolve outside the released SBOM.
Ordinary public runtime dependencies need provisioning;
offline installation requires a prewarmed package store. Node 24.19 or later in
the Node 24 line is required. Nested local packages are tested with pnpm; no npm
installation equivalence is claimed.

```ts
import {
  createSDKClient,
  parseConfiguration,
  normalizeConfiguration,
  hashConfiguration,
  verifyAttestedArtifact,
} from "@bwmp-dev/typescript-sdk";

const client = createSDKClient({
  origin: deploymentOrigin, // explicitly trusted HTTPS origin, no path
  transport: fetch, // caller-owned; must honor redirect: manual
  timeoutMs: 10_000,
  maxResponseBytes: 1_048_576,
});
const configuration = parseConfiguration(configurationText);
const normalized = normalizeConfiguration(configuration);
const digest = hashConfiguration(configuration);
// Generated methods retain their exact path, request and response types.
const candidate = await client.GET("/v1/release-candidates/{candidateId}", {
  params: { path: { candidateId } },
  headers: { authorization: `Bearer ${credential}` },
});
const identity = await verifyAttestedArtifact(
  document,
  trustedPublicKey,
  bytes,
);
```

The variables above are caller inputs, not SDK defaults or credential loaders.
Only send a credential appropriate to the operation: an Actions grant may observe
only its own retained resources until expiry. A new grant cannot inherit them.
This SDK grants no additional authority and offers no automatic retry or renewal.
Successful authorized responses contain the caller-requested data; do not log
them indiscriminately. Non-success bodies, provider errors and parse exceptions
are replaced by closed `SDKError` codes and optional numeric HTTP status.

The client rejects cross-origin overrides and redirects, strips response cookies,
and bounds body reading. Generated per-call transport, Request, middleware and
serializer extension hooks are deliberately unavailable (rejected before execution);
they cannot bypass the facade. Caller transports must not ignore redirect instructions
or log credentials. Bounds are explicit: timeout 1–120000 milliseconds and response
budget 1–16777216 bytes. This buffering client is not a private log stream API.
Configuration failures are closed and unknown fields remain invalid.

Verification requires an independently trusted Ed25519 PEM public key or raw
32-byte public key. Signature validation happens before artifact iteration.
Signature, size, digest and reader failures remain failures; a matching hash alone
is not authenticity. The SDK performs no trust-key network lookup.
