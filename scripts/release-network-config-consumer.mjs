import assert from "node:assert/strict";
import { createHash } from "node:crypto";

// Independent extracted-artifact check, not a platform authorization simulation.
export function verifyNetworkConfigV2Consumer(
  document,
  semantics,
  vectors,
  configuration,
) {
  assert.match(semantics, /^# IFC-030 explicit configuration-v2 HTTP/);
  for (const text of [
    "All responses are no-store",
    "never retry",
    "v1 inputs route remains version-1-only",
  ])
    assert.ok(semantics.toLowerCase().includes(text.toLowerCase()), text);
  assert.equal(vectors.contract, "IFC-030-http");
  assert.equal(vectors.runtimeEvidence, false);
  const s = document.components.schemas;
  for (const name of [
    "CreateProjectConfigSnapshotRequest",
    "ProjectConfigSnapshot",
  ]) {
    assert.equal(s[name].properties.schemaVersion.const, 1);
    const expected = structuredClone(s[name]);
    expected.properties.schemaVersion.const = 2;
    const actual = structuredClone(s[name + "V2"]);
    delete actual.description;
    delete expected.description;
    assert.deepEqual(actual, expected);
  }
  const input = structuredClone(s.CandidateInputs);
  input.properties.configuration.$ref =
    "#/components/schemas/CandidateInputConfigurationV2";
  assert.deepEqual(s.CandidateInputsV2, input);
  const descriptor = structuredClone(s.CandidateInputConfiguration);
  assert.equal(descriptor.properties.schemaVersion.const, 1);
  delete descriptor.properties.schemaVersion.const;
  descriptor.properties.schemaVersion.enum = [1, 2];
  assert.deepEqual(s.CandidateInputConfigurationV2, descriptor);
  const post = document.paths["/v2/projects/{projectId}/config-snapshots"].post;
  const get = document.paths["/v2/release-candidates/{candidateId}/inputs"].get;
  assert.equal(post.operationId, "createProjectConfigSnapshotV2");
  assert.equal(get.operationId, "getReleaseCandidateInputsV2");
  assert.deepEqual(post.security, [{ BearerAuth: [] }]);
  assert.deepEqual(get.security, [{ BearerAuth: [] }, { SessionCookie: [] }]);
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
  assert.deepEqual(post.parameters, [
    { $ref: "#/components/parameters/IdempotencyKey" },
  ]);
  assert.equal(
    post.responses[409].$ref,
    "#/components/responses/ConfigSnapshotV2Conflict",
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
  }
  const request = vectors.request;
  assert.equal(request.schemaVersion, 2);
  const normalized = configuration.normalizeConfiguration(
    configuration.parseConfiguration(request.rawYaml),
  );
  assert.equal(normalized, request.normalizedJson);
  assert.equal(JSON.parse(normalized).apiVersion, "provenance.dev/v2");
  assert.equal(
    createHash("sha256").update(normalized).digest("hex"),
    request.configurationHash,
  );
  assert.equal(vectors.snapshot.schemaVersion, 2);
  assert.equal(vectors.snapshot.configurationHash, request.configurationHash);
  assert.equal(vectors.inputs.configuration.schemaVersion, 2);
  assert.equal(vectors.inputs.configuration.sha256, request.configurationHash);
  assert.equal(vectors.inputs.configuration.id, vectors.snapshot.id);
  assert.equal(vectors.inputs.projectId, vectors.snapshot.projectId);
  for (const field of ["sourceCommit", "sourceRef"]) {
    assert.equal(vectors.snapshot[field], request[field]);
    assert.equal(vectors.inputs.configuration[field], vectors.snapshot[field]);
  }
}
