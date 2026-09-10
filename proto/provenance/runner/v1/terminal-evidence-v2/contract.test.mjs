import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  canonical,
  sha256,
  validateStructure,
  validateTerminal,
} from "./reference.mjs";
import { validateStructure as legacy } from "../terminal-evidence/reference.mjs";

const fixture = JSON.parse(
  readFileSync(new URL("../terminal-evidence/fixtures.json", import.meta.url)),
);
const vector = JSON.parse(
  readFileSync(new URL("../terminal-evidence/vectors.json", import.meta.url)),
);
function fresh(contains = true) {
  const value = JSON.parse(vector.canonical);
  value.schemaVersion = "provenance.execution-evidence/v2";
  const expected = {
    featureV2Enabled: true,
    wholeMessageBytes: 16000,
    binding: structuredClone(fixture.binding),
    requested: structuredClone(fixture.requested),
    assertions: fixture.observations.map(([id, type, , selector]) => ({
      id,
      type,
      selector: structuredClone(selector),
      supported: true,
    })),
  };
  if (contains) {
    for (const a of value.assertions)
      if (a.type === "console-regex") {
        const plan = expected.assertions.find((p) => p.id === a.id);
        a.type = a.evidence.type = plan.type = "console-contains";
        a.id =
          a.evidence.id =
          plan.id =
            a.id.replace("console-regex", "console-contains");
      }
  }
  value.assertions.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  expected.assertions.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return { value, expected };
}
function encode(value) {
  for (const a of value.assertions)
    a.evidenceSha256 = sha256(Buffer.from(canonical(a.evidence)));
  return Buffer.from(canonical(value));
}
function accept({ value, expected }) {
  const raw = encode(value);
  return validateTerminal(raw, sha256(raw), expected);
}

test("frozen v2 bytes and independent Go canonical/digest check", () => {
  const golden = JSON.parse(
    readFileSync(new URL("vectors.json", import.meta.url)),
  );
  const data = fresh();
  assert.equal(encode(data.value).toString(), golden.canonical);
  assert.equal(sha256(encode(data.value)), golden.sha256);
  accept(data);
  const result = spawnSync(
    "go",
    [
      "run",
      fileURLToPath(new URL("golden-check.go", import.meta.url)),
      fileURLToPath(new URL("vectors.json", import.meta.url)),
    ],
    {
      encoding: "utf8",
      timeout: 60000,
      maxBuffer: 65536,
      env: { ...process.env, GOTOOLCHAIN: "local" },
    },
  );
  assert.equal(result.status, 0, "independent golden check failed");
  assert.equal(result.stdout.trim(), golden.sha256);
});

test("generated v2 wire preserves exact proof, replay and legacy absence", () => {
  const result = spawnSync(
    process.execPath,
    [
      fileURLToPath(new URL("wire-consumer.mjs", import.meta.url)),
      process.env.TERMINAL_EVIDENCE_PROTOCOL_DIR ||
        fileURLToPath(
          new URL("../../../../../packages/runner-protocol", import.meta.url),
        ),
    ],
    { encoding: "utf8", timeout: 30000, maxBuffer: 65536 },
  );
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test("independent Draft 2020-12 validator checks the v2 schema and vector", () => {
  const result = spawnSync(
    "python",
    [
      "-c",
      [
        "import json,pathlib,sys",
        "from jsonschema import Draft202012Validator",
        "root=pathlib.Path(sys.argv[1])",
        "schema=json.loads((root/'schema.json').read_text())",
        "Draft202012Validator.check_schema(schema)",
        "v=Draft202012Validator(schema)",
        "d=json.loads(json.loads((root/'vectors.json').read_text())['canonical'])",
        "v.validate(d)",
        "assert any(a['type']=='console-contains' for a in d['assertions'])",
        "assert not v.is_valid(dict(d,secret='forbidden'))",
        "assert not v.is_valid(dict(d,schemaVersion='provenance.execution-evidence/v1'))",
      ].join("\n"),
      fileURLToPath(new URL(".", import.meta.url)),
    ],
    { encoding: "utf8", timeout: 30000, maxBuffer: 65536 },
  );
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test("v2 retains canonical, digest, envelope and transport bounds", () => {
  const data = fresh();
  const raw = encode(data.value);
  for (const bad of [
    Buffer.concat([raw, Buffer.from("\n")]),
    Buffer.from('{"schemaVersion":"duplicate",' + raw.toString().slice(1)),
    Buffer.from([0xff]),
    Buffer.alloc(32769, 32),
  ]) {
    assert.throws(() => validateStructure(bad, sha256(bad)));
  }
  assert.throws(() => validateStructure(raw, "0".repeat(64)));
  for (const size of [raw.length - 1, 65537, 1.5]) {
    assert.throws(() =>
      accept({
        value: data.value,
        expected: { ...data.expected, wholeMessageBytes: size },
      }),
    );
  }
  const tooMany = fresh();
  tooMany.value.assertions = Array.from({ length: 257 }, () =>
    structuredClone(tooMany.value.assertions[0]),
  );
  assert.throws(() => accept(tooMany));
  const absent = fresh();
  absent.value.assertions.pop();
  assert.throws(() => accept(absent));
});

test("v1 history is unchanged; versions cannot be substituted", () => {
  const old = Buffer.from(vector.canonical);
  legacy(old, sha256(old));
  assert.throws(() => validateStructure(old, sha256(old)));
  for (const contains of [false, true]) {
    const data = fresh(contains);
    accept(data);
    const raw = encode(data.value);
    assert.throws(() => legacy(raw, sha256(raw)));
  }
});
test("v1 feature admission never authorizes v2 evidence", () => {
  const data = fresh();
  delete data.expected.featureV2Enabled;
  data.expected.featureEnabled = true;
  assert.throws(() => accept(data));
});
test("literal assertion requires its exact immutable type and selectors", () => {
  for (const mutation of [
    (p) => (p.type = "console-regex"),
    (p) => (p.selector.assertionId = "foreign"),
    (p) => (p.selector.testId = "foreign"),
    (p) => (p.supported = false),
  ]) {
    const data = fresh();
    mutation(
      data.expected.assertions.find((p) => p.type === "console-contains"),
    );
    assert.throws(() => accept(data));
  }
});
test("literal outcomes preserve closed evaluated and truncation predicates", () => {
  for (const [evaluated, passed, truncated, outcome, valid] of [
    [true, true, false, "passed", true],
    [true, false, false, "failed", true],
    [false, false, true, "skipped", true],
    [false, false, false, "skipped", false],
    [true, true, true, "passed", false],
    [false, true, true, "passed", false],
  ]) {
    const data = fresh();
    const a = data.value.assertions.find((a) => a.type === "console-contains");
    a.outcome = a.evidence.outcome = outcome;
    Object.assign(a.evidence.observation, {
      evaluated,
      passed,
      outputTruncated: truncated,
    });
    if (valid) accept(data);
    else assert.throws(() => accept(data));
  }
});
test("literal observations cannot carry raw patterns/output or omit prerequisites", () => {
  for (const mutation of [
    (o) => (o.output = "private"),
    (o) => (o.pattern = "secret"),
    (o) => (o.registered = false),
    (o) => (o.executionCompleted = false),
  ]) {
    const data = fresh();
    mutation(
      data.value.assertions.find((a) => a.type === "console-contains").evidence
        .observation,
    );
    assert.throws(() => accept(data));
  }
});
