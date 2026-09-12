import assert from "node:assert/strict";

// Independent archive consumer: no source-tree schema, vectors or docs imported.
export function verifyRejectionConsumer(specification, semantics, vectors) {
  assert.ok(semantics.includes("# IFC-029 durable private release rejection"));
  for (const required of [
    "Current authorization",
    "not a cancellation signal",
    "attestation issuance",
    "publication admission",
    "32768",
    "4096",
  ])
    assert.ok(semantics.includes(required));
  assert.equal(vectors.contract, "IFC-029");
  assert.equal(vectors.runtimeEvidence, false);
  assert.deepEqual(vectors.rejection, {
    decisionId: "10000000-0000-4000-8000-000000000001",
    candidateId: "20000000-0000-4000-8000-000000000001",
    projectId: "30000000-0000-4000-8000-000000000001",
    generation: 0,
    decision: "rejected",
    rejectedAt: "2026-09-12T00:00:00.123456Z",
  });
  const outcomes = Object.fromEntries(
    vectors.cases.map(({ id, status }) => [id, status]),
  );
  assert.equal(Object.keys(outcomes).length, 15);
  assert.equal(outcomes["identical-key-request-replay"], 200);
  assert.equal(outcomes["approval-won-race"], 409);
  assert.equal(outcomes["read-without-rejection"], 404);
  assert.equal(outcomes["inconsistent-retained-rejection"], 503);
  assert.equal(
    vectors.cases.find(({ id }) => id === "identical-key-request-replay")
      .writes,
    0,
  );
  const schema = specification.components.schemas.ReleaseCandidateRejection;
  assert.equal(schema.type, "object");
  assert.equal(schema.additionalProperties, false);
  const fields = [
    "decisionId",
    "candidateId",
    "projectId",
    "generation",
    "decision",
    "rejectedAt",
  ];
  assert.deepEqual(schema.required, fields);
  assert.deepEqual(Object.keys(schema.properties), fields);
  for (const field of fields.slice(0, 3))
    assert.deepEqual(schema.properties[field], {
      type: "string",
      format: "uuid",
    });
  assert.deepEqual(schema.properties.decision, {
    type: "string",
    enum: ["rejected"],
  });
  assert.deepEqual(schema.properties.generation, {
    type: "integer",
    minimum: 0,
    maximum: 9007199254740991,
  });
  assert.deepEqual(schema.properties.rejectedAt, {
    $ref: "#/components/schemas/LogTimestamp",
  });
  const timestamp = specification.components.schemas.LogTimestamp;
  assert.equal(timestamp.type, "string");
  assert.equal(timestamp.format, "date-time");
  assert.equal(timestamp.minLength, 20);
  assert.equal(timestamp.maxLength, 35);
  assert.equal(schema["x-provenance-max-json-bytes"], 4096);
  for (const [leaf, method, operationId] of [
    ["reject", "post", "rejectReleaseCandidate"],
    ["rejection", "get", "getReleaseCandidateRejection"],
  ]) {
    const op =
      specification.paths[`/v1/release-candidates/{candidateId}/${leaf}`][
        method
      ];
    assert.equal(op.operationId, operationId);
    assert.deepEqual(op.security, [{ BearerAuth: [] }, { SessionCookie: [] }]);
    assert.equal(
      op.responses[200].content["application/json"].schema.$ref,
      "#/components/schemas/ReleaseCandidateRejection",
    );
    assert.equal(
      op.responses[200].headers["Cache-Control"].$ref,
      "#/components/headers/PrivateNoStore",
    );
  }
}
