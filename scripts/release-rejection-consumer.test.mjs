import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parse } from "yaml";
import { verifyRejectionConsumer } from "./release-rejection-consumer.mjs";

const root = new URL("../openapi/", import.meta.url);
const spec = parse(await readFile(new URL("provenance.v1.yaml", root), "utf8"));
const semantics = await readFile(
  new URL("release-rejection-semantics.md", root),
  "utf8",
);
const vectors = JSON.parse(
  await readFile(new URL("release-rejection-vectors.json", root), "utf8"),
);
test("independent rejection consumer accepts the closed release artifacts", () =>
  verifyRejectionConsumer(spec, semantics, vectors));
test("missing or substituted rejection schemas and semantics cannot pass consumption", () => {
  const missing = structuredClone(spec);
  delete missing.components.schemas.ReleaseCandidateRejection;
  assert.throws(() => verifyRejectionConsumer(missing, semantics, vectors));
  assert.throws(() => verifyRejectionConsumer(spec, "", vectors));
  for (const change of [
    (copy) => {
      copy.components.schemas.ReleaseCandidateRejection.additionalProperties = true;
    },
    (copy) => {
      copy.components.schemas.ReleaseCandidateRejection.properties.reason = {
        type: "string",
      };
    },
    (copy) => {
      copy.components.schemas.ReleaseCandidateRejection.properties.decision.enum =
        ["canceled"];
    },
    (copy) => {
      copy.paths["/v1/release-candidates/{candidateId}/reject"].post.security =
        [];
    },
  ]) {
    const copy = structuredClone(spec);
    change(copy);
    assert.throws(() => verifyRejectionConsumer(copy, semantics, vectors));
  }
});
test("altered replay, identity or runtime-evidence vectors fail independent consumption", () => {
  for (const change of [
    (copy) => {
      copy.runtimeEvidence = true;
    },
    (copy) => {
      copy.rejection.decisionId = "different";
    },
    (copy) => {
      copy.cases[1].writes = 1;
    },
    (copy) => {
      copy.cases = [];
    },
  ]) {
    const copy = structuredClone(vectors);
    change(copy);
    assert.throws(() => verifyRejectionConsumer(spec, semantics, copy));
  }
});
