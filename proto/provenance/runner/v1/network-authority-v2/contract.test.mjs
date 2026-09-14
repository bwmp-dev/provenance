import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";
import { instant, reconcileAuthority } from "./reference.mjs";
const vectors = JSON.parse(
  readFileSync(new URL("vectors.json", import.meta.url)),
);
const fresh = () => structuredClone(vectors.context);
test("current authority exact identity, finite deadline and harmless stale replay", () => {
  const c = fresh();
  assert.equal(reconcileAuthority(c).action, "current");
  for (const disposition of [1, 2, 3]) {
    c.disposition = disposition;
    assert.equal(reconcileAuthority(c).action, "current");
  }
  c.prior = {
    checkedAt: c.observation.checkedAt,
    expiresAt: c.observation.expiresAt,
    withdrawn: false,
  };
  assert.equal(reconcileAuthority(c).action, "keep");
  c.observation.checkedAt = "2026-09-14T00:00:04Z";
  c.observation.expiresAt = "2026-09-14T00:00:50Z";
  assert.equal(reconcileAuthority(c).expiresAt, c.prior.expiresAt);
  c.observation.checkedAt = "2026-09-14T00:00:06Z";
  assert.equal(reconcileAuthority(c).action, "current");
  c.prior.withdrawn = true;
  assert.equal(reconcileAuthority(c).action, "withdraw");
  c.prior.withdrawn = false;
  c.prior.expiresAt = c.now;
  assert.equal(reconcileAuthority(c).action, "withdraw");
});
test("explicit withdrawal is irreversible and separate from cancellation", () => {
  const c = fresh();
  c.observation.state = 2;
  delete c.observation.expiresAt;
  assert.equal(reconcileAuthority(c).action, "withdraw");
  assert.equal(c.cancelling, false);
  assert.equal(c.status, 3);
  c.observation.expiresAt = "2026-09-14T00:00:40Z";
  assert.equal(reconcileAuthority(c).action, "reject");
});
test("a historical stale receipt cannot erase an independently acknowledged renewal", () => {
  const c = fresh();
  c.disposition = 3;
  c.acknowledgedLeaseExpiresAt = c.lease.expiresAt;
  c.lease.expiresAt = "2026-09-14T00:00:09Z";
  assert.equal(reconcileAuthority(c).action, "current");
  delete c.acknowledgedLeaseExpiresAt;
  assert.equal(reconcileAuthority(c).action, "reject");
});
test("invalid or missing current authority fails closed", () => {
  const cases = {
    absent: (c) => delete c.observation,
    feature: (c) => c.features.pop(),
    dependency: (c) => c.features.splice(1, 1),
    unknownFeature: (c) => c.features.push(99),
    duplicateFeature: (c) => c.features.push(10),
    unspecified: (c) => (c.observation.state = 0),
    unknownState: (c) => (c.observation.state = 99),
    unknownField: (c) => (c.observation.resolver = "caller-selected"),
    unknownDigest: (c) => (c.observation.policy.extra = true),
    changedPolicy: (c) => (c.policySha256 = "11".repeat(32)),
    algorithm: (c) => (c.observation.policy.algorithm = 2),
    shortDigest: (c) => (c.observation.policy.value = "AA=="),
    expiry: (c) => (c.observation.expiresAt = c.now),
    missingExpiry: (c) => delete c.observation.expiresAt,
    futureCheck: (c) => (c.observation.checkedAt = "2026-09-14T00:00:16Z"),
    leaseBound: (c) => (c.lease.expiresAt = "2026-09-14T00:00:39Z"),
    credentialBound: (c) => (c.credentialExpiresAt = "2026-09-14T00:00:39Z"),
    maximumLifetime: (c) => {
      c.lease.expiresAt = c.credentialExpiresAt;
      c.observation.expiresAt = "2026-09-14T00:01:06Z";
    },
    invalidDate: (c) => (c.observation.checkedAt = "2026-02-30T00:00:00Z"),
    sameCheckConflict: (c) =>
      (c.prior = {
        checkedAt: c.observation.checkedAt,
        expiresAt: "2026-09-14T00:00:39Z",
        withdrawn: false,
      }),
    unexpectedNone: (c) => (c.enabled = false),
    unexpectedTerminal: (c) => (c.status = 4),
    unexpectedCancellation: (c) => (c.cancelling = true),
  };
  for (const key of ["leaseId", "jobId", "executionId"])
    cases[key] = (c) => (c.lease[key] = "20000000-0000-4000-8000-000000000001");
  for (const key of ["attemptId", "releaseCandidateId", "matrixEntryId"])
    cases[key] = (c) =>
      (c.attempt[key] = "20000000-0000-4000-8000-000000000001");
  cases.attemptNumber = (c) => (c.attempt.attemptNumber = 2);
  for (const [name, mutate] of Object.entries(cases)) {
    const c = fresh();
    mutate(c);
    assert.equal(reconcileAuthority(c).action, "reject", name);
  }
});
test("legacy none and terminal handling do not gain a new permission", () => {
  const c = fresh();
  c.enabled = false;
  c.features = [1, 3];
  delete c.observation;
  assert.equal(reconcileAuthority(c).action, "no-grant");
  for (const status of [4, 5, 6, 7]) {
    c.status = status;
    assert.equal(reconcileAuthority(c).action, "withdraw");
  }
  c.status = 3;
  c.cancelling = true;
  assert.equal(reconcileAuthority(c).action, "withdraw");
  assert.equal(
    instant("2026-09-14T00:00:00.000000001Z") - instant("2026-09-14T00:00:00Z"),
    1n,
  );
});
test("generated authority wire and field numbers preserve historical reconciliation", async () => {
  const directory =
    process.env.NETWORK_AUTHORITY_PROTOCOL_DIR ||
    fileURLToPath(
      new URL("../../../../../packages/runner-protocol", import.meta.url),
    );
  const require = createRequire(resolve(directory, "package.json"));
  const { fromJson, toBinary, fromBinary } = require("@bufbuild/protobuf");
  const p = await import(pathToFileURL(resolve(directory, "dist/index.js")));
  assert.equal(p.ProtocolFeature.NETWORK_AUTHORITY_V2, 10);
  const observation = fromJson(p.NetworkAuthorityV2Schema, fresh().observation);
  const wire = toBinary(p.NetworkAuthorityV2Schema, observation);
  assert.equal(Buffer.from(wire).toString("hex"), vectors.currentWireHex);
  const legacy = fromJson(p.LeaseReconciliationSchema, {
    lease: fresh().lease,
    attempt: fresh().attempt,
    disposition: 3,
    status: 3,
    phase: 3,
  });
  const original = toBinary(p.LeaseReconciliationSchema, legacy);
  legacy.networkAuthorityV2 = observation;
  const restored = fromBinary(
    p.LeaseReconciliationSchema,
    toBinary(p.LeaseReconciliationSchema, legacy),
  );
  assert.equal(restored.networkAuthorityV2.state, 1);
  restored.networkAuthorityV2 = undefined;
  assert.deepEqual(toBinary(p.LeaseReconciliationSchema, restored), original);
  assert.equal(
    Buffer.from(original).toString("hex"),
    vectors.legacyReconciliationHex,
  );
});
