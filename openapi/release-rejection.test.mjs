import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import test from "node:test";
import { parse } from "yaml";
import { beforeReleaseRejection } from "./release-rejection-compat.mjs";

const doc = parse(
  await readFile(new URL("provenance.v1.yaml", import.meta.url), "utf8"),
);
const vectors = JSON.parse(
  await readFile(
    new URL("release-rejection-vectors.json", import.meta.url),
    "utf8",
  ),
);
const require = createRequire(
  new URL("../packages/verification/package.json", import.meta.url),
);
const Ajv = require("ajv/dist/2020.js");
const ajv = new Ajv({ strict: false });
require("ajv-formats")(ajv);
ajv.addSchema({ $id: "rejection", components: doc.components });
const valid = ajv.compile({
  $ref: "rejection#/components/schemas/ReleaseCandidateRejection",
});

test("IFC-029 preserves every existing alpha28 field, operation and closed enum", () => {
  assert.equal(
    createHash("sha256")
      .update(JSON.stringify(beforeReleaseRejection(doc)))
      .digest("hex"),
    "6a23f535b82a5b4b98ccd67ca3bd4716b2f2877d2da7873aeac24b33f3ad564f",
  );
});
test("rejection is a closed immutable decision, not cancellation or a failure classification", () => {
  assert.equal(vectors.contract, "IFC-029");
  assert.equal(vectors.runtimeEvidence, false);
  assert.ok(valid(vectors.rejection));
  for (const field of Object.keys(vectors.rejection)) {
    const missing = { ...vectors.rejection };
    delete missing[field];
    assert.equal(valid(missing), false, field);
  }
  for (const patch of [
    { decision: "approved" },
    { decision: "canceled" },
    { decision: "failed" },
    { generation: -1 },
    { generation: 0.5 },
    { generation: 9007199254740992 },
    { rejectedAt: null },
    { rejectedAt: "tomorrow" },
    { decisionId: "other" },
    { candidateId: "other" },
    { projectId: "other" },
    { reason: "private audit text" },
    { actorId: "private" },
    { unknown: true },
  ])
    assert.equal(
      valid({ ...vectors.rejection, ...patch }),
      false,
      JSON.stringify(patch),
    );
  assert.ok(valid({ ...vectors.rejection, generation: 9007199254740991 }));
  assert.equal(
    doc.components.schemas.ReleaseCandidateRejection[
      "x-provenance-max-json-bytes"
    ],
    4096,
  );
});
test("both rejection routes have explicit private authorization and refusal boundaries", () => {
  for (const [leaf, method, operationId] of [
    ["reject", "post", "rejectReleaseCandidate"],
    ["rejection", "get", "getReleaseCandidateRejection"],
  ]) {
    const path = doc.paths[`/v1/release-candidates/{candidateId}/${leaf}`];
    assert.deepEqual(path.parameters, [
      { $ref: "#/components/parameters/CandidateId" },
    ]);
    const op = path[method];
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
    for (const status of [400, 401, 403, 404, "default"])
      assert.ok(op.responses[status]);
    assert.match(op.description, /Actions submission grants are refused/);
    assert.match(op.description, /release-rejection-semantics.md/);
  }
  const mutation =
    doc.paths["/v1/release-candidates/{candidateId}/reject"].post;
  assert.deepEqual(mutation.parameters, [
    { $ref: "#/components/parameters/IdempotencyKey" },
  ]);
  assert.equal(
    mutation.requestBody.$ref,
    "#/components/requestBodies/CandidateDecision",
  );
  assert.ok(mutation.responses[409]);
  const conflict = doc.components.responses.ReleaseCandidateRejectionConflict;
  assert.equal(
    conflict.headers["Cache-Control"].$ref,
    "#/components/headers/PrivateNoStore",
  );
  assert.equal(
    conflict.content["application/problem+json"].schema.$ref,
    "#/components/schemas/PrivateProblemDetails",
  );
});
test("normative rejection examples retain replay, race and private absence distinctions", async () => {
  const ids = vectors.cases.map((item) => item.id);
  assert.equal(new Set(ids).size, 15);
  for (const id of [
    "identical-key-request-replay",
    "changed-key-request",
    "new-key-already-rejected",
    "new-key-plugin-failed",
    "approval-won-race",
    "read-without-rejection",
    "revoked-session-replay",
    "inconsistent-retained-rejection",
  ])
    assert.ok(ids.includes(id));
  assert.equal(
    vectors.cases.find((item) => item.id === "identical-key-request-replay")
      .writes,
    0,
  );
  const semantics = await readFile(
    new URL("release-rejection-semantics.md", import.meta.url),
    "utf8",
  );
  for (const marker of [
    "# IFC-029 durable private release rejection",
    "32768",
    "4096",
    "not a cancellation signal",
    "immutable rejection record",
    "Current authorization",
    "attestation issuance",
    "publication admission",
  ])
    assert.ok(semantics.includes(marker), marker);
});
