import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import test from "node:test";
import { parse } from "yaml";

const doc = parse(
  await readFile(new URL("provenance.v1.yaml", import.meta.url), "utf8"),
);
const require = createRequire(
  new URL("../packages/verification/package.json", import.meta.url),
);
const Ajv = require("ajv/dist/2020.js");
const ajv = new Ajv({ strict: false });
require("ajv-formats")(ajv);
const base = "https://contract.test/openapi/provenance.v1.yaml";
const vectors = [];
for (const [version, folder] of [
  [1, "terminal-evidence"],
  [2, "terminal-evidence-v2"],
]) {
  const path = `../proto/provenance/runner/v1/${folder}/schema.json`;
  ajv.addSchema(
    JSON.parse(await readFile(new URL(path, import.meta.url))),
    new URL(`./execution-evidence-v${version}.json`, base).href,
  );
  vectors.push(
    JSON.parse(
      await readFile(
        new URL(
          `../proto/provenance/runner/v1/${folder}/vectors.json`,
          import.meta.url,
        ),
      ),
    ),
  );
}
test("OpenAPI evidence mirrors are byte-identical to their authoritative versioned schemas", async () => {
  for (const [version, folder] of [
    [1, "terminal-evidence"],
    [2, "terminal-evidence-v2"],
  ]) {
    assert.deepEqual(
      await readFile(
        new URL(`execution-evidence-v${version}.json`, import.meta.url),
      ),
      await readFile(
        new URL(
          `../proto/provenance/runner/v1/${folder}/schema.json`,
          import.meta.url,
        ),
      ),
    );
  }
});
ajv.addSchema({ $id: base, components: doc.components });
const valid = (value) =>
  ajv.validate(
    { $ref: base + "#/components/schemas/CandidateExecutionDetails" },
    value,
  );
const route =
  "/v1/release-candidates/{candidateId}/executions/{executionId}/details";
const schemas = [
  "CandidateExecutionDetails",
  "CandidateExecutionTiming",
  "CandidateExecutionFailure",
  "CandidateExecutionTerminalEvidence",
];
const id = "11111111-1111-4111-8111-111111111111";
const value = {
  candidateId: id,
  projectId: id,
  matrixEntryId: id,
  executionId: id,
  attemptNumber: 1,
  state: "queued",
  timing: { startedAt: null, completedAt: null, durationMs: null },
  failure: null,
  terminalEvidence: null,
};

test("execution details preserve the entire released alpha26 OpenAPI", () => {
  const legacy = structuredClone(doc);
  delete legacy.paths[route];
  for (const name of schemas) delete legacy.components.schemas[name];
  assert.equal(
    createHash("sha256").update(JSON.stringify(legacy)).digest("hex"),
    "467de88d3a60dac94fdeecbbfa5a90d765b266916f69c7a3fc5bf12a2da559ca",
  );
});
test("execution details preserve absent timing and both unchanged versioned terminal shapes", () => {
  assert.ok(valid(value), JSON.stringify(ajv.errors));
  for (const vector of vectors) {
    // Golden documents are synthetic schema vectors, not evidence that their
    // binding matches this API fixture; producers must additionally prove binding.
    const details = {
      ...value,
      state: "succeeded",
      timing: {
        startedAt: "2026-09-12T00:00:00Z",
        completedAt: "2026-09-12T00:00:01.234Z",
        durationMs: 1234,
      },
      terminalEvidence: {
        sha256: vector.sha256,
        recordedAt: "2026-09-12T00:00:01.234Z",
        document: JSON.parse(vector.canonical),
      },
    };
    assert.ok(valid(details), JSON.stringify(ajv.errors));
    const partial = structuredClone(details);
    partial.terminalEvidence.document.completeness = "partial";
    partial.terminalEvidence.document.assertions = [];
    assert.ok(valid(partial), JSON.stringify(ajv.errors));
  }
  assert.ok(
    valid({
      ...value,
      state: "failed",
      failure: {
        category: "infrastructure",
        stage: "execution",
        code: "runner_restarted",
        retryable: true,
      },
    }),
  );
});
test("execution details reject unknown fields, malformed identities and unbounded failure metadata", () => {
  const invalid = [
    { ...value, secret: "synthetic" },
    { ...value, candidateId: "wrong" },
    { ...value, attemptNumber: 0 },
    { ...value, attemptNumber: 2147483648 },
    { ...value, state: "compatible" },
    ...[
      { durationMs: -1 },
      { durationMs: 0.1 },
      { durationMs: Number.MAX_SAFE_INTEGER + 1 },
      { startedAt: "yesterday" },
      { elapsedSeconds: 2 },
    ].map((patch) => ({ ...value, timing: { ...value.timing, ...patch } })),
    ...[
      { code: "bad..code" },
      { code: "x".repeat(65) },
      { code: "bad\ncode" },
      { category: "unknown" },
      { stage: "unknown" },
      { summary: "private" },
    ].map((patch) => ({
      ...value,
      state: "failed",
      failure: {
        category: null,
        stage: null,
        code: null,
        retryable: null,
        ...patch,
      },
    })),
    {
      ...value,
      terminalEvidence: {
        sha256: "a".repeat(64),
        recordedAt: "2026-09-12T00:00:00Z",
        document: {},
      },
    },
  ];
  for (const item of invalid) assert.equal(valid(item), false);
  for (const key of Object.keys(value)) {
    const missing = { ...value };
    delete missing[key];
    assert.equal(valid(missing), false, key);
  }
  for (const vector of vectors) {
    const document = JSON.parse(vector.canonical);
    document.assertions[0].evidence.observation.rawLog = "private";
    assert.equal(
      valid({
        ...value,
        terminalEvidence: {
          sha256: vector.sha256,
          recordedAt: "2026-09-12T00:00:00Z",
          document,
        },
      }),
      false,
    );
  }
});
test("execution details remain a private no-query read outside the Actions allowlist", async () => {
  const operation = doc.paths[route].get;
  assert.equal(operation.operationId, "getReleaseCandidateExecutionDetails");
  assert.deepEqual(operation.security, [
    { BearerAuth: [] },
    { SessionCookie: [] },
  ]);
  assert.equal(operation.parameters, undefined);
  assert.deepEqual(doc.paths[route].parameters, [
    { $ref: "#/components/parameters/CandidateId" },
    { $ref: "#/components/parameters/ExecutionId" },
  ]);
  assert.equal(
    operation.responses["200"].headers["Cache-Control"].$ref,
    "#/components/headers/PrivateNoStore",
  );
  assert.equal(
    operation.responses["404"].$ref,
    "#/components/responses/PrivateLogNotFound",
  );
  assert.match(operation.description, /Actions submission grants/);
  assert.match(operation.description, /128|canonical digest/);
  const client = await readFile(
    new URL("../packages/api-client/src/gen/schema.d.ts", import.meta.url),
    "utf8",
  );
  assert.ok(client.includes("getReleaseCandidateExecutionDetails"));
});
