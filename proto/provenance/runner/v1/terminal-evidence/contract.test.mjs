import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  canonical,
  sha256,
  validateStructure,
  validateTerminal,
} from "./reference.mjs";

const fixture = JSON.parse(
  readFileSync(new URL("fixtures.json", import.meta.url)),
);
const vector = JSON.parse(
  readFileSync(new URL("vectors.json", import.meta.url)),
);
const fresh = () => JSON.parse(vector.canonical);
const invalidVectors = JSON.parse(
  readFileSync(new URL("invalid-vectors.json", import.meta.url)),
);
const context = () => ({
  featureEnabled: true,
  wholeMessageBytes: 16000,
  binding: structuredClone(fixture.binding),
  requested: structuredClone(fixture.requested),
  assertions: fixture.observations.map(([id, type, , selector]) => ({
    id,
    type,
    selector: structuredClone(selector),
    supported: true,
  })),
});
const encode = (value) => Buffer.from(canonical(value));
function accept(value, expected = context()) {
  const raw = encode(value);
  return validateTerminal(raw, sha256(raw), expected);
}
function reject(value, expected = context()) {
  assert.throws(
    () => accept(value, expected),
    /^Error: invalid terminal evidence$/,
  );
}
function resign(value) {
  for (const a of value.assertions) {
    a.evidenceSha256 = sha256(canonical(a.evidence));
  }
}

test("IFC019 frozen canonical vector and immutable-plan binding", () => {
  assert.equal(sha256(vector.canonical), vector.sha256);
  assert.equal(canonical(fresh()), vector.canonical);
  assert.deepEqual(accept(fresh()), fresh());
  for (const key of Object.keys(fixture.binding)) {
    const expected = context();
    expected.binding[key] = key === "attemptNumber" ? 2 : "other";
    reject(fresh(), expected);
  }
  for (const key of [
    "artifactSha256",
    "configurationSha256",
    "environmentSha256",
    "policySha256",
  ]) {
    const expected = context();
    expected.requested[key] = "f".repeat(64);
    reject(fresh(), expected);
  }
  const x = fresh();
  x.assertions[0].evidence.binding.attemptId = "other";
  resign(x);
  reject(x);
  const other = accept(fresh());
  other.binding.runnerId = "changed";
  assert.equal(accept(fresh()).binding.runnerId, fixture.binding.runnerId);
});

test("IFC019 shared invalid vectors remain rejected with recomputed outer hashes", () => {
  for (const fixture of invalidVectors) {
    const x = fresh();
    let target = x;
    for (const key of fixture.path.slice(0, -1)) target = target[key];
    target[fixture.path.at(-1)] = fixture.value;
    reject(x);
  }
  const x = fresh();
  x.completeness = "partial";
  x.assertions = Array.from({ length: 100 }, (_, i) => {
    const a = structuredClone(x.assertions[0]);
    a.id = a.evidence.id = `assertion-${String(i).padStart(3, "0")}`;
    return a;
  });
  resign(x);
  const raw = encode(x);
  assert.ok(raw.length > 32768);
  assert.ok(x.assertions.length < 256);
  assert.throws(() => validateStructure(raw, sha256(raw)));
});

test("IFC019 exact predicates; negatives are not missing observations", () => {
  for (const [index, key] of [
    [0, "requirementsSatisfied"],
    [1, "enabled"],
    [2, "enabled"],
    [3, "passed"],
    [4, "reportedShutdownRequested"],
  ]) {
    const x = fresh(),
      a = x.assertions[index];
    a.evidence.observation[key] = false;
    a.outcome = a.evidence.outcome = "failed";
    resign(x);
    accept(x);
    a.outcome = a.evidence.outcome = "passed";
    resign(x);
    reject(x);
  }
  for (const [index, key] of [
    [0, "serverLoaded"],
    [0, "stabilizationCompleted"],
    [0, "serverReady"],
    [3, "registered"],
    [3, "executionCompleted"],
    [4, "shutdownRequested"],
    [4, "serverStopped"],
  ]) {
    const x = fresh();
    x.assertions[index].evidence.observation[key] = false;
    resign(x);
    reject(x);
  }
  for (const index of [1, 2]) {
    const x = fresh();
    x.assertions[index].evidence.observation.loaded = false;
    resign(x);
    reject(x);
  }
  const x = fresh(),
    a = x.assertions[3];
  a.evidence.observation.evaluated = false;
  a.evidence.observation.passed = false;
  a.evidence.observation.outputTruncated = true;
  a.outcome = a.evidence.outcome = "skipped";
  resign(x);
  accept(x);
  a.evidence.observation.outputTruncated = false;
  resign(x);
  reject(x);
  a.evidence.observation.outputTruncated = true;
  a.evidence.observation.passed = true;
  resign(x);
  reject(x);
  const y = fresh();
  y.assertions[3].evidence.observation.outputTruncated = true;
  resign(y);
  reject(y);
});

test("IFC019 coverage is external; legacy and unsupported operators supply no complete proof", () => {
  const x = fresh();
  x.runtime = null;
  reject(x);
  x.completeness = "partial";
  accept(x);
  x.assertions = [];
  accept(x);
  for (const kind of ["contains", "default", "unexecuted"]) {
    const expected = context();
    expected.assertions[3].type = kind;
    expected.assertions[3].supported = false;
    reject(fresh(), expected);
    const p = fresh();
    p.completeness = "partial";
    p.assertions.splice(3, 1);
    accept(p, expected);
  }
  const missing = fresh();
  missing.assertions.pop();
  reject(missing);
  missing.completeness = "partial";
  accept(missing);
  const expected = context();
  expected.assertions[0].id = "00-other";
  reject(fresh(), expected);
  for (const index of [1, 2, 3]) {
    const e = context();
    const key = Object.keys(e.assertions[index].selector)[0];
    e.assertions[index].selector[key] = "other";
    reject(fresh(), e);
  }
  const disabled = context();
  disabled.featureEnabled = false;
  reject(fresh(), disabled);
  // Downgrade cannot transform a frozen queued message: serializer/replay owners
  // retain these exact bytes, rather than re-creating a weaker partial envelope.
  const frozen = encode(fresh());
  assert.throws(() => validateTerminal(frozen, sha256(frozen), disabled));
  assert.equal(frozen.toString(), vector.canonical);
});

test("IFC019 strict canonical JSON and digest failures never disclose hostile text", () => {
  for (const raw of [
    Buffer.from("\ufeff" + vector.canonical),
    Buffer.from(vector.canonical + " "),
    Buffer.from(vector.canonical + "{}"),
    Buffer.from('{"x":1,"x":2}'),
    Buffer.from(vector.canonical.replace('"complete"', '"complet\\u0065"')),
    Buffer.from('{"x":"\\ud800"}'),
    Buffer.from([0xff]),
    Buffer.from('{"x":1.5}'),
    Buffer.from('{"x":NaN}'),
    Buffer.from("[".repeat(14) + "0" + "]".repeat(14)),
  ]) {
    assert.throws(
      () => validateStructure(raw, sha256(raw)),
      /^Error: invalid terminal evidence$/,
    );
  }
  const raw = encode(fresh());
  assert.throws(() => validateStructure(raw, "f".repeat(64)));
  for (const mutate of [
    (x) => {
      x.secret = "HOSTILE_SECRET";
    },
    (x) => {
      x.binding.unknown = 1;
    },
    (x) => {
      x.assertions[0].evidence.observation.output = "HOSTILE_SECRET";
    },
    (x) => {
      x.runtime.rootfs.format = "operator-tar-sha256";
    },
    (x) => {
      x.runtime.sandboxKind = "container";
    },
    (x) => {
      x.runtime.sandboxKind = "process";
    },
    (x) => {
      x.binding.attemptNumber = 4294967296;
    },
    (x) => {
      x.binding.attemptNumber = 0;
    },
    (x) => {
      x.assertions[0].evidenceSha256 = "A".repeat(64);
    },
    (x) => {
      x.assertions.reverse();
    },
    (x) => {
      x.assertions.push(x.assertions[0]);
    },
    (x) => {
      x.assertions[0].evidence.id = "other";
    },
    (x) => {
      x.assertions[0].evidence.outcome = "failed";
    },
  ]) {
    const x = fresh();
    mutate(x);
    reject(x);
  }
});

test("IFC019 count/byte/whole-message boundaries and schema shapes", () => {
  const x = fresh();
  x.assertions = Array(257).fill(x.assertions[0]);
  reject(x);
  assert.throws(() =>
    validateStructure(Buffer.alloc(32769, 32), sha256(Buffer.alloc(32769, 32))),
  );
  const expected = context();
  expected.wholeMessageBytes = 65536;
  accept(fresh(), expected);
  expected.wholeMessageBytes++;
  reject(fresh(), expected);
  expected.wholeMessageBytes = 1;
  reject(fresh(), expected);
  const schema = JSON.parse(
    readFileSync(new URL("schema.json", import.meta.url)),
  );
  assert.equal(schema.properties.assertions.maxItems, 256);
  assert.equal(
    schema.$defs.binding.properties.attemptNumber.maximum,
    4294967295,
  );
  for (const [index, a] of fresh().assertions.entries())
    for (const key of Object.keys(a.evidence.observation)) {
      const y = fresh();
      delete y.assertions[index].evidence.observation[key];
      resign(y);
      reject(y);
    }
});
