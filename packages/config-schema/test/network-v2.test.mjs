import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  ConfigurationError,
  hashConfiguration,
  normalizeConfiguration,
  parseConfiguration,
  validateConfiguration,
} from "../dist/index.js";

const vectors = JSON.parse(
  readFileSync(
    new URL(
      "../../../schemas/fixtures/config/v2/vectors.json",
      import.meta.url,
    ),
  ),
);
const fresh = () => JSON.parse(vectors.canonical);

test("explicit configuration v2 reproduces frozen canonical bytes and hash", () => {
  const v = fresh();
  assert.equal(normalizeConfiguration(v), vectors.canonical);
  assert.equal(hashConfiguration(v), vectors.sha256);
  assert.deepEqual(parseConfiguration(vectors.canonical), v);
  const reordered = fresh();
  reordered.network.permissions.reverse();
  assert.doesNotThrow(() => validateConfiguration(reordered));
  assert.notEqual(
    hashConfiguration(reordered),
    vectors.sha256,
    "request order is not silently rewritten",
  );
});

test("versioned request never changes legacy none or accepts a relabelled legacy network", () => {
  const legacy = JSON.parse(
    readFileSync(
      new URL(
        "../../../schemas/fixtures/config/valid/hosted.normalized.json",
        import.meta.url,
      ),
    ),
  );
  const original = hashConfiguration(legacy);
  const enabled = fresh();
  enabled.apiVersion = "provenance.dev/v1";
  assert.throws(() => validateConfiguration(enabled), ConfigurationError);
  legacy.apiVersion = "provenance.dev/v2";
  assert.throws(() => validateConfiguration(legacy), ConfigurationError);
  legacy.network = {
    mode: "none",
    permissions: [],
    maximumConnections: 0,
    maximumBytesPerSecond: 0,
  };
  assert.doesNotThrow(() => validateConfiguration(legacy));
  assert.notEqual(hashConfiguration(legacy), original);
  legacy.network.maximumConnections = 1;
  assert.throws(() => validateConfiguration(legacy), ConfigurationError);
});

test("v2 requires explicit finite tuples and rejects unknown authority inputs", () => {
  const invalid = [
    ["mode", "unrestricted"],
    ["mode", "None"],
    ["permissions", []],
    ["maximumConnections", 0],
    ["maximumConnections", 4294967296],
    ["maximumConnections", 1.5],
    ["maximumBytesPerSecond", 0],
    ["maximumBytesPerSecond", -1],
    ["maximumBytesPerSecond", "65536"],
    ["resolver", "customer.example"],
    ["namespace", "/host/path"],
    ["allowlist", []],
  ];
  for (const [key, value] of invalid) {
    const v = fresh();
    v.network[key] = value;
    assert.throws(() => validateConfiguration(v), ConfigurationError, key);
  }
  for (const key of Object.keys(fresh().network)) {
    const v = fresh();
    delete v.network[key];
    assert.throws(() => validateConfiguration(v), ConfigurationError, key);
  }
  for (const patch of [
    { hostname: "A.example" },
    { hostname: "a.example\n" },
    { hostname: "127.0.0.1" },
    { hostname: "0x7f.0.0.1" },
    { hostname: "0177.0.0.1" },
    { hostname: "*.example" },
    { hostname: "a.example." },
    { hostname: "é.example" },
    { hostname: "localhost" },
    { hostname: "a".repeat(64) + ".example" },
    { hostname: "-a.example" },
    ...[0, 25, 53, 465, 587, 853, 65536].map((port) => ({ port })),
    { transport: "icmp" },
    { transport: "TCP" },
    { transport: 1 },
    { ports: [443] },
  ]) {
    const v = fresh();
    Object.assign(v.network.permissions[0], patch);
    assert.throws(
      () => validateConfiguration(v),
      ConfigurationError,
      JSON.stringify(patch),
    );
  }
  const duplicate = fresh();
  duplicate.network.permissions.push(duplicate.network.permissions[0]);
  assert.throws(() => validateConfiguration(duplicate), ConfigurationError);
  const bounded = fresh();
  bounded.network.permissions = Array.from({ length: 128 }, (_, i) => ({
    hostname: "a.example",
    port: 1000 + i,
    transport: "tcp",
  }));
  bounded.network.maximumConnections =
    bounded.network.maximumBytesPerSecond = 4294967295;
  assert.doesNotThrow(() => validateConfiguration(bounded));
  bounded.network.permissions.push({
    hostname: "b.example",
    port: 443,
    transport: "udp",
  });
  assert.throws(() => validateConfiguration(bounded), ConfigurationError);
  const future = fresh();
  future.apiVersion = "provenance.dev/v3";
  assert.throws(() => validateConfiguration(future), ConfigurationError);
});
