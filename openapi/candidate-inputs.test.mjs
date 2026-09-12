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
ajv.addSchema({ $id: "inputs", components: doc.components });
const valid = (value) =>
  ajv.validate({ $ref: "inputs#/components/schemas/CandidateInputs" }, value);
const route = "/v1/release-candidates/{candidateId}/inputs";
const schemas = [
  "CandidateInputs",
  "CandidateInputArtifact",
  "CandidateInputConfiguration",
  "CandidateDependencyResolution",
  "CandidateResolvedDependency",
];
const id = "11111111-1111-4111-8111-111111111111";
const hash = "a".repeat(64);
const dependency = {
  id,
  artifactId: id,
  declaredName: "helper",
  required: false,
  resolutionOrder: 0,
  sourceType: "modrinth",
  sourceId: "project-id",
  sourceVersion: "exact-version-id",
  pluginName: "Helper",
  sha256: hash,
  sizeBytes: 42,
  inspectionSha256: hash,
  registryMetadataSha256: hash,
  resolvedAt: "2026-09-12T00:00:00Z",
};
const resolution = {
  sha256: hash,
  targetInspectionSha256: hash,
  resolvedAt: "2026-09-12T00:00:00Z",
  items: [dependency],
};
const inputs = {
  candidateId: id,
  projectId: id,
  sourceCommit: "b".repeat(40),
  sourceRef: "refs/heads/main",
  artifact: { id, fileName: "fixture.jar", sha256: hash, sizeBytes: 42 },
  configuration: {
    id,
    sha256: hash,
    schemaVersion: 1,
    sourceCommit: "c".repeat(40),
    sourceRef: null,
  },
  dependencyResolution: resolution,
};
test("input addition preserves the entire released alpha25 contract", () => {
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
  delete legacy.paths[route];
  for (const name of schemas) delete legacy.components.schemas[name];
  assert.equal(
    createHash("sha256").update(JSON.stringify(legacy)).digest("hex"),
    "6a61e95b7b295b0080c6851fa80af3a6cb560a93427530e8fe5abfa83eb4c508",
  );
});
test("input identities preserve distinct sources and unresolved versus resolved empty dependencies", () => {
  for (const dependencyResolution of [
    null,
    resolution,
    { ...resolution, items: [] },
  ])
    assert.ok(
      valid({ ...inputs, dependencyResolution }),
      JSON.stringify(ajv.errors),
    );
  assert.ok(valid({ ...inputs, sourceRef: null }));
  assert.notEqual(inputs.sourceCommit, inputs.configuration.sourceCommit);
});
test("private inputs reject missing, unknown, malformed and oversized fields", () => {
  for (const key of Object.keys(inputs)) {
    const value = { ...inputs };
    delete value[key];
    assert.equal(valid(value), false, key);
  }
  for (const patch of [
    { candidateId: "wrong" },
    { sourceCommit: "" },
    { sourceCommit: "x".repeat(129) },
    { sourceRef: "" },
    { sourceRef: "x".repeat(513) },
    { rawYaml: "private" },
  ])
    assert.equal(valid({ ...inputs, ...patch }), false);
  for (const patch of [
    { sha256: "A".repeat(64) },
    { sizeBytes: -1 },
    { sizeBytes: 1.5 },
    { fileName: "x".repeat(513) },
    { objectKey: "private" },
  ])
    assert.equal(
      valid({ ...inputs, artifact: { ...inputs.artifact, ...patch } }),
      false,
    );
  for (const patch of [
    { schemaVersion: 2 },
    { sourceRef: "" },
    { sourceCommit: null },
    { rawYaml: "private" },
  ])
    assert.equal(
      valid({
        ...inputs,
        configuration: { ...inputs.configuration, ...patch },
      }),
      false,
    );
  for (const patch of [
    { resolvedAt: "yesterday" },
    { items: Array(65).fill(dependency) },
    { sha256: "bad" },
    { registryMetadata: {} },
  ])
    assert.equal(
      valid({ ...inputs, dependencyResolution: { ...resolution, ...patch } }),
      false,
    );
  for (const patch of [
    { sourceType: "url" },
    { resolutionOrder: 64 },
    { sizeBytes: 0 },
    { sizeBytes: 1073741825 },
    { required: "false" },
    { pluginName: "../secret" },
    { inspectionSha256: "bad" },
    { registryMetadata: {} },
    { signedUrl: "https://private.invalid" },
  ])
    assert.equal(
      valid({
        ...inputs,
        dependencyResolution: {
          ...resolution,
          items: [{ ...dependency, ...patch }],
        },
      }),
      false,
    );
  for (const key of Object.keys(dependency)) {
    const value = { ...dependency };
    delete value[key];
    assert.equal(
      valid({
        ...inputs,
        dependencyResolution: { ...resolution, items: [value] },
      }),
      false,
      key,
    );
  }
});
test("input route is bounded private read with generated consumer and no Actions grant expansion", async () => {
  const operation = doc.paths[route].get;
  assert.equal(operation.operationId, "getReleaseCandidateInputs");
  assert.deepEqual(operation.security, [
    { BearerAuth: [] },
    { SessionCookie: [] },
  ]);
  assert.equal(operation.parameters, undefined);
  assert.equal(
    operation.responses["200"].headers["Cache-Control"].$ref,
    "#/components/headers/PrivateNoStore",
  );
  assert.equal(
    operation.responses["404"].$ref,
    "#/components/responses/PrivateLogNotFound",
  );
  assert.equal(
    operation.responses.default.$ref,
    "#/components/responses/PrivateProblem",
  );
  assert.equal(
    doc.components.schemas.CandidateInputs["x-provenance-max-json-bytes"],
    131072,
  );
  for (const name of schemas)
    assert.equal(doc.components.schemas[name].additionalProperties, false);
  const generated = await readFile(
    new URL("../packages/api-client/src/gen/schema.d.ts", import.meta.url),
    "utf8",
  );
  assert.match(generated, /getReleaseCandidateInputs:/);
  assert.match(generated, /CandidateInputs:/);
});
