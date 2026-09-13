import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import test from "node:test";
import { admitV2, hostname, validPolicy, withinMaximum } from "./reference.mjs";

const vectors = JSON.parse(
  readFileSync(new URL("vectors.json", import.meta.url)),
);
const fresh = () => structuredClone(vectors.enabled);

test("full v2 policy hash binds every dimension with independent legacy identity", async () => {
  const directory =
    process.env.NETWORK_POLICY_PROTOCOL_DIR ||
    fileURLToPath(
      new URL("../../../../../packages/runner-protocol", import.meta.url),
    );
  const require = createRequire(resolve(directory, "package.json"));
  const { create, fromJson, toBinary } = require("@bufbuild/protobuf");
  const p = await import(pathToFileURL(resolve(directory, "dist/index.js")));
  const hash = (policy) =>
    createHash("sha256")
      .update(toBinary(p.EffectivePolicySchema, policy))
      .digest("hex");
  const policy = fromJson(p.EffectivePolicySchema, vectors.effectivePolicy);
  assert.equal(
    Buffer.from(toBinary(p.EffectivePolicySchema, policy)).toString("hex"),
    vectors.effectivePolicyWireHex,
  );
  assert.equal(hash(policy), vectors.effectivePolicySha256);
  assert.notEqual(
    createHash("sha256")
      .update(toBinary(p.NetworkPolicyV2Schema, policy.networkV2))
      .digest("hex"),
    vectors.effectivePolicySha256,
  );
  assert.notEqual(
    createHash("sha256")
      .update(JSON.stringify(vectors.effectivePolicy))
      .digest("hex"),
    vectors.effectivePolicySha256,
  );
  for (const mutate of [
    (v) => {
      v.networkV2.permissions[0].hostname = "c.example";
    },
    (v) => {
      v.networkV2.permissions[0].port = 8443;
    },
    (v) => {
      v.networkV2.permissions[0].transport = 2;
    },
    (v) => {
      v.networkV2.maximumConnections--;
    },
    (v) => {
      v.networkV2.maximumBytesPerSecond--;
    },
    (v) => {
      v.resources.cpuMillis--;
    },
    (v) => {
      v.resources.memoryBytes--;
    },
    (v) => {
      v.resources.diskBytes--;
    },
    (v) => {
      v.resources.processCount--;
    },
    (v) => {
      v.preparationTimeout.seconds--;
    },
    (v) => {
      v.executionTimeout.seconds--;
    },
    (v) => {
      v.gracefulShutdownTimeout.seconds--;
    },
    (v) => {
      v.sandbox = 2;
    },
    (v) => {
      v.requirement = 2;
    },
  ]) {
    const changed = fromJson(p.EffectivePolicySchema, vectors.effectivePolicy);
    mutate(changed);
    assert.notEqual(hash(changed), vectors.effectivePolicySha256);
  }
  policy.networkV2 = undefined;
  policy.network = create(p.NetworkPolicySchema, { mode: 1 });
  assert.equal(
    Buffer.from(toBinary(p.EffectivePolicySchema, policy)).toString("hex"),
    vectors.legacyFullPolicyWireHex,
  );
  assert.equal(hash(policy), vectors.legacyFullPolicySha256);
  assert.equal(
    hash(policy),
    "cb70bae1ac8b86e891449ee3224dfc4b7132234983d4b8d22360cbac4d125a08",
  );
});
const context = () => ({
  features: [1, 3, 9],
  effective: fresh(),
  maximum: fresh(),
  legacyPresent: false,
  correlationValid: true,
  messageBytes: 65536,
});

test("network v2 canonical none and enabled profiles", () => {
  assert.equal(validPolicy(vectors.none), true);
  assert.equal(validPolicy(fresh()), true);
  assert.equal(withinMaximum(vectors.none, fresh()), true);
  assert.equal(withinMaximum(fresh(), vectors.none), false);
  for (const mode of [0, 4, 99, "3", null])
    assert.equal(validPolicy({ ...fresh(), mode }), false);
  assert.equal(validPolicy({ ...fresh(), mode: 2 }), true);
  assert.equal(validPolicy({ ...vectors.none, maximumConnections: 1 }), false);
  assert.equal(
    validPolicy({ ...vectors.none, permissions: fresh().permissions }),
    false,
  );
  assert.equal(
    validPolicy({ ...fresh(), resolver: "customer-supplied" }),
    false,
  );
  assert.equal(validPolicy({ ...fresh(), permissions: [] }), false);
});

test("network v2 finite caps and whole tuples do not broaden grants", () => {
  for (const key of ["maximumConnections", "maximumBytesPerSecond"])
    for (const value of [0, -1, 1.5, 4294967296, Infinity, NaN, "8", null])
      assert.equal(validPolicy({ ...fresh(), [key]: value }), false);
  const maximum = fresh();
  for (const patch of [
    { hostname: "b.example" },
    { port: 8443 },
    { transport: 2 },
  ]) {
    const effective = fresh();
    effective.permissions = [{ ...effective.permissions[0], ...patch }];
    assert.equal(validPolicy(effective), true);
    assert.equal(withinMaximum(effective, maximum), false);
  }
  for (const key of ["maximumConnections", "maximumBytesPerSecond"])
    assert.equal(
      withinMaximum({ ...fresh(), [key]: maximum[key] + 1 }, maximum),
      false,
    );
  const lower = fresh();
  lower.permissions.pop();
  lower.maximumConnections = lower.maximumBytesPerSecond = 1;
  assert.equal(withinMaximum(lower, maximum), true);
});

test("network v2 hostname, transport, sorting and bounds refusals", () => {
  for (const name of [
    "localhost",
    "A.example",
    "a.example.",
    "*.example",
    "a..example",
    "-a.example",
    "a-.example",
    "a_foo.example",
    "é.example",
    "127.0.0.1",
    "0x7f.0.0.1",
    "0177.0.0.1",
    "::1",
    "a".repeat(64) + ".example",
    "a.example\n",
    "a.example/",
    null,
  ])
    assert.equal(hostname(name), false, String(name));
  for (const patch of [
    { port: 0 },
    { port: 65536 },
    { port: 1.5 },
    ...[25, 53, 465, 587, 853].map((port) => ({ port })),
    { transport: 0 },
    { transport: 3 },
    { transport: "tcp" },
    { address: "1.1.1.1" },
  ])
    assert.equal(
      validPolicy({
        ...fresh(),
        permissions: [{ ...fresh().permissions[0], ...patch }],
      }),
      false,
    );
  assert.equal(
    validPolicy({ ...fresh(), permissions: fresh().permissions.reverse() }),
    false,
  );
  assert.equal(
    validPolicy({
      ...fresh(),
      permissions: [fresh().permissions[0], fresh().permissions[0]],
    }),
    false,
  );
  const permissions = Array.from({ length: 128 }, (_, i) => ({
    hostname: "a.example",
    port: 1000 + i,
    transport: 1,
  }));
  assert.equal(validPolicy({ ...fresh(), permissions }), true);
  assert.equal(
    validPolicy({
      ...fresh(),
      permissions: [
        ...permissions,
        { hostname: "b.example", port: 443, transport: 1 },
      ],
    }),
    false,
  );
});

test("network v2 rejects downgrade, mixed representation and unauthenticated admission", () => {
  assert.equal(admitV2(context()), true);
  for (const features of [
    [],
    [1, 3],
    [3, 9],
    [1, 9],
    [1, 3, 9, 9],
    [0, 1, 3, 9],
    [1, 3, 9, 99],
  ])
    assert.equal(admitV2({ ...context(), features }), false);
  for (const patch of [
    { legacyPresent: true },
    { correlationValid: false },
    { messageBytes: 65537 },
    { maximum: null },
    { effective: null },
    { maximum: vectors.none },
  ])
    assert.equal(admitV2({ ...context(), ...patch }), false);
  // Reconnect never inherits prior capability admission.
  const reconnected = context();
  reconnected.features = [];
  assert.equal(admitV2(reconnected), false);
});

test("generated network v2 wire preserves explicit policy and legacy none bytes", async () => {
  const directory =
    process.env.NETWORK_POLICY_PROTOCOL_DIR ||
    fileURLToPath(
      new URL("../../../../../packages/runner-protocol", import.meta.url),
    );
  const require = createRequire(resolve(directory, "package.json"));
  const {
    create,
    toBinary,
    fromBinary,
    toJson,
  } = require("@bufbuild/protobuf");
  const p = await import(pathToFileURL(resolve(directory, "dist/index.js")));
  assert.equal(p.ProtocolFeature.NETWORK_POLICY_V2, 9);
  assert.equal(p.NetworkTransportV2.TCP, 1);
  assert.equal(p.NetworkTransportV2.UDP, 2);
  const policy = create(p.NetworkPolicyV2Schema, fresh());
  const wire = toBinary(p.NetworkPolicyV2Schema, policy);
  assert.equal(Buffer.from(wire).toString("hex"), vectors.enabledPolicyHex);
  assert.deepEqual(
    toJson(p.NetworkPolicyV2Schema, fromBinary(p.NetworkPolicyV2Schema, wire), {
      enumAsInteger: true,
    }),
    fresh(),
  );
  const effective = create(p.EffectivePolicySchema, { networkV2: policy });
  const restored = fromBinary(
    p.EffectivePolicySchema,
    toBinary(p.EffectivePolicySchema, effective),
  );
  assert.equal(restored.network, undefined);
  assert.deepEqual(restored.networkV2, policy);
  const maximum = create(p.RunnerPolicySchema, { maximumNetworkV2: policy });
  assert.deepEqual(
    fromBinary(p.RunnerPolicySchema, toBinary(p.RunnerPolicySchema, maximum))
      .maximumNetworkV2,
    policy,
  );
  const legacy = create(p.EffectivePolicySchema, {
    network: { mode: p.NetworkMode.NONE },
  });
  assert.equal(
    Buffer.from(toBinary(p.EffectivePolicySchema, legacy)).toString("hex"),
    vectors.legacyNoneEffectiveHex,
  );
  assert.equal(
    fromBinary(
      p.EffectivePolicySchema,
      toBinary(p.EffectivePolicySchema, legacy),
    ).networkV2,
    undefined,
  );
});
