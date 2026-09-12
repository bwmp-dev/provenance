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
ajv.addSchema({ $id: "matrix", components: doc.components });
const valid = (value) =>
  ajv.validate(
    { $ref: "matrix#/components/schemas/CandidateMatrixPage" },
    value,
  );
const id = "11111111-1111-4111-8111-111111111111";
test("matrix addition preserves the entire released alpha24 contract", () => {
  const legacy = structuredClone(doc);
  delete legacy.paths[
    "/v1/release-candidates/{candidateId}/executions/{executionId}/details"
  ];
  for (const name of [
    "CandidateExecutionDetails",
    "CandidateExecutionTiming",
    "CandidateExecutionFailure",
    "CandidateExecutionTerminalEvidence",
  ])
    delete legacy.components.schemas[name];
  delete legacy.paths["/v1/release-candidates/{candidateId}/inputs"];
  for (const name of [
    "CandidateInputs",
    "CandidateInputArtifact",
    "CandidateInputConfiguration",
    "CandidateDependencyResolution",
    "CandidateResolvedDependency",
  ])
    delete legacy.components.schemas[name];
  delete legacy.paths["/v1/release-candidates/{candidateId}/matrix"];
  for (const name of [
    "CandidateMatrixPage",
    "CandidateMatrixEntry",
    "CandidateMatrixEnvironment",
  ])
    delete legacy.components.schemas[name];
  // Parsed complete OpenAPI at d543d107dc1bd660f639a409cf0882963da276d7.
  assert.equal(
    createHash("sha256").update(JSON.stringify(legacy)).digest("hex"),
    "160159755ed1539553893a0fe06d1f8934fb920f35559aa66900f19c7d02c735",
  );
});
const entry = {
  id,
  generation: 0,
  environment: {
    provider: "paper",
    providerVersion: "1.21.4",
    serverBuild: "232",
    javaVersion: "21.0.8+9",
    runnerImageDigest: `sha256:${"a".repeat(64)}`,
    sha256: "b".repeat(64),
  },
  requirement: "required",
  state: "pending",
  attemptCount: 0,
  latestExecutionId: null,
  createdAt: "2026-09-12T00:00:00Z",
  updatedAt: "2026-09-12T00:00:00Z",
};
const page = {
  candidateId: id,
  currentGeneration: 0,
  items: [entry],
  page: { hasMore: false, nextCursor: null },
};

test("candidate matrix includes unstarted environments and preserves explicit stored identities", () => {
  assert.ok(valid(page), JSON.stringify(ajv.errors));
  assert.ok(valid({ ...page, items: [] }));
  for (const state of doc.components.schemas.CandidateMatrixEntry.properties
    .state.enum) {
    assert.ok(
      valid({
        ...page,
        items: [
          {
            ...entry,
            state,
            requirement: "informational",
            attemptCount: 2,
            latestExecutionId: id,
          },
        ],
      }),
    );
  }
});

test("candidate matrix rejects missing, unknown, malformed and oversized fields", () => {
  for (const field of Object.keys(entry)) {
    const item = structuredClone(entry);
    delete item[field];
    assert.equal(valid({ ...page, items: [item] }), false, field);
  }
  for (const patch of [
    { id: "wrong" },
    { state: "compatible" },
    { requirement: "optional" },
    { attemptCount: -1 },
    { attemptCount: 1.5 },
    { latestExecutionId: "wrong" },
    { completeLog: "private" },
    { createdAt: "yesterday" },
  ])
    assert.equal(valid({ ...page, items: [{ ...entry, ...patch }] }), false);
  for (const patch of [
    { sha256: "A".repeat(64) },
    { provider: "" },
    { javaVersion: "x".repeat(129) },
    { runnerImageDigest: "x".repeat(513) },
    { objectKey: "private" },
  ])
    assert.equal(
      valid({
        ...page,
        items: [{ ...entry, environment: { ...entry.environment, ...patch } }],
      }),
      false,
    );
  assert.equal(valid({ ...page, items: Array(101).fill(entry) }), false);
  assert.equal(valid({ ...page, secret: "private" }), false);
  for (const generation of [-1, 0.5, 9007199254740992]) {
    assert.equal(valid({ ...page, currentGeneration: generation }), false);
    assert.equal(valid({ ...page, items: [{ ...entry, generation }] }), false);
  }
  assert.equal(
    valid({ ...page, items: [{ ...entry, latestExecutionId: id }] }),
    false,
  );
  assert.equal(
    valid({ ...page, items: [{ ...entry, attemptCount: 1 }] }),
    false,
  );
});

test("candidate matrix is a bounded private read with no-store responses and explicit authorization order", () => {
  const path = doc.paths["/v1/release-candidates/{candidateId}/matrix"];
  assert.deepEqual(Object.keys(path), ["parameters", "get"]);
  assert.equal(path.get.operationId, "listReleaseCandidateMatrix");
  assert.deepEqual(path.get.security, [
    { BearerAuth: [] },
    { SessionCookie: [] },
  ]);
  assert.deepEqual(
    path.get.parameters.map((p) => p.$ref),
    ["#/components/parameters/Cursor", "#/components/parameters/PageSize"],
  );
  assert.match(path.get.description, /authorization precede query validation/);
  assert.match(
    path.get.description,
    /Actions submission grants are not accepted/,
  );
  assert.match(
    path.get.description,
    /wrong-resource cursors return 404 before expiry/,
  );
  assert.equal(
    doc.components.schemas.CandidateMatrixPage["x-provenance-max-json-bytes"],
    1048576,
  );
  for (const value of Object.values(path.get.responses)) {
    const response = value.$ref
      ? doc.components.responses[value.$ref.split("/").at(-1)]
      : value;
    assert.equal(
      response.headers["Cache-Control"].$ref,
      "#/components/headers/PrivateNoStore",
    );
  }
});

test("generated client exposes the new matrix projection without changing legacy descriptors", async () => {
  const generated = await readFile(
    new URL("../packages/api-client/src/gen/schema.d.ts", import.meta.url),
    "utf8",
  );
  assert.match(generated, /listReleaseCandidateMatrix:/);
  assert.match(generated, /CandidateMatrixPage:/);
  assert.equal(
    doc.components.schemas.ExecutionLogDescriptor.properties.environment,
    undefined,
  );
  assert.equal(
    doc.components.schemas.ReleaseCandidate.properties.matrix,
    undefined,
  );
});
