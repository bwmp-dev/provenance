import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import { parse } from "yaml";
import { beforeNetworkConfigV2 } from "./network-config-v2-compat.mjs";

const doc = parse(
  readFileSync(new URL("provenance.v1.yaml", import.meta.url), "utf8"),
);
const vectors = JSON.parse(
  readFileSync(new URL("network-config-v2-vectors.json", import.meta.url)),
);
const require = createRequire(
  new URL("../packages/verification/package.json", import.meta.url),
);
const Ajv = require("ajv/dist/2020.js");
const ajv = new Ajv({ strict: false });
require("ajv-formats")(ajv);
ajv.addSchema({ $id: "network-http-v2", components: doc.components });
const valid = (name, value) =>
  ajv.validate({ $ref: `network-http-v2#/components/schemas/${name}` }, value);

test("IFC030 HTTP additions preserve every prior operation and schema", () => {
  assert.equal(
    createHash("sha256")
      .update(JSON.stringify(beforeNetworkConfigV2(doc)))
      .digest("hex"),
    "c354a7c3c4d6b546cee58cfee9c87ae402a78bacc67b1dc05e85a2993384323b",
  );
  assert.equal(
    doc.components.schemas.CreateProjectConfigSnapshotRequest.properties
      .schemaVersion.const,
    1,
  );
  assert.equal(
    doc.components.schemas.ProjectConfigSnapshot.properties.schemaVersion.const,
    1,
  );
  assert.equal(
    doc.components.schemas.CandidateInputConfiguration.properties.schemaVersion
      .const,
    1,
  );
});

test("v2 snapshot identities are closed and cannot be relabelled", () => {
  assert.equal(vectors.contract, "IFC-030-http");
  assert.equal(vectors.runtimeEvidence, false);
  for (const [name, value] of [
    ["CreateProjectConfigSnapshotRequestV2", vectors.request],
    ["ProjectConfigSnapshotV2", vectors.snapshot],
  ]) {
    assert.equal(valid(name, value), true, JSON.stringify(ajv.errors));
    assert.equal(valid(name, { ...value, schemaVersion: 1 }), false);
    assert.equal(valid(name, { ...value, schemaVersion: "2" }), false);
    assert.equal(valid(name, { ...value, authority: "user-supplied" }), false);
    for (const key of doc.components.schemas[name].required) {
      const missing = { ...value };
      delete missing[key];
      assert.equal(valid(name, missing), false, key);
    }
  }
  assert.equal(
    valid("CreateProjectConfigSnapshotRequest", vectors.request),
    false,
  );
  assert.equal(valid("ProjectConfigSnapshot", vectors.snapshot), false);
});

test("v2 input reads preserve version 1 or 2 without altering legacy projections", () => {
  for (const version of [1, 2]) {
    const value = structuredClone(vectors.inputs);
    value.configuration.schemaVersion = version;
    assert.equal(
      valid("CandidateInputsV2", value),
      true,
      JSON.stringify(ajv.errors),
    );
    assert.equal(valid("CandidateInputs", value), version === 1);
  }
  for (const version of [0, 3, "2", null]) {
    const value = structuredClone(vectors.inputs);
    value.configuration.schemaVersion = version;
    assert.equal(valid("CandidateInputsV2", value), false);
  }
  for (const key of [
    "rawYaml",
    "normalizedJson",
    "policy",
    "objectKey",
    "secret",
  ]) {
    const value = structuredClone(vectors.inputs);
    value.configuration[key] = "forbidden";
    assert.equal(valid("CandidateInputsV2", value), false, key);
  }
});

test("new route authorization, no-store and versioned response boundaries are explicit", () => {
  const post = doc.paths["/v2/projects/{projectId}/config-snapshots"].post;
  const get = doc.paths["/v2/release-candidates/{candidateId}/inputs"].get;
  assert.equal(post.operationId, "createProjectConfigSnapshotV2");
  assert.equal(get.operationId, "getReleaseCandidateInputsV2");
  assert.deepEqual(post.security, [{ BearerAuth: [] }]);
  assert.deepEqual(get.security, [{ BearerAuth: [] }, { SessionCookie: [] }]);
  assert.equal(post.requestBody.required, true);
  assert.equal(
    post.requestBody.content["application/json"].schema.$ref,
    "#/components/schemas/CreateProjectConfigSnapshotRequestV2",
  );
  assert.equal(
    post.responses[201].content["application/json"].schema.$ref,
    "#/components/schemas/ProjectConfigSnapshotV2",
  );
  assert.equal(
    get.responses[200].content["application/json"].schema.$ref,
    "#/components/schemas/CandidateInputsV2",
  );
  for (const [op, status] of [
    [post, 201],
    [get, 200],
  ]) {
    assert.equal(
      op.responses[status].headers["Cache-Control"].$ref,
      "#/components/headers/PrivateNoStore",
    );
    for (const code of [400, 401, 403, 404, "default"])
      assert.ok(op.responses[code]);
    assert.match(op.description, /network-config-v2-semantics.md/);
  }
  assert.ok(post.responses[409]);
  assert.ok(post.responses[422]);
  assert.ok(post.responses[503]);
  assert.deepEqual(post.parameters, [
    { $ref: "#/components/parameters/IdempotencyKey" },
  ]);
  assert.match(get.description, /Actions submission grants are refused/);
  assert.match(get.description, /v1 route remains version-1-only/);
});
