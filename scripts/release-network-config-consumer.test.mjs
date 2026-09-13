import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "yaml";
import * as configuration from "../packages/config-schema/dist/index.js";
import { verifyNetworkConfigV2Consumer as verify } from "./release-network-config-consumer.mjs";
const doc = parse(
  readFileSync(
    new URL("../openapi/provenance.v1.yaml", import.meta.url),
    "utf8",
  ),
);
const semantics = readFileSync(
  new URL("../openapi/network-config-v2-semantics.md", import.meta.url),
  "utf8",
);
const vectors = JSON.parse(
  readFileSync(
    new URL("../openapi/network-config-v2-vectors.json", import.meta.url),
  ),
);

test("independent v2 HTTP consumer verifies authority shapes and canonical version binding", () => {
  assert.doesNotThrow(() => verify(doc, semantics, vectors, configuration));
});
test("independent v2 HTTP consumer refuses changed authority, versions, hash and runtime claims", () => {
  for (const mutate of [
    (d) => {
      d.components.schemas.CreateProjectConfigSnapshotRequestV2.properties.schemaVersion.const = 1;
    },
    (d) => {
      d.components.schemas.ProjectConfigSnapshotV2.additionalProperties = true;
    },
    (d) => {
      d.components.schemas.CandidateInputConfigurationV2.properties.schemaVersion.enum.push(
        3,
      );
    },
    (d) => {
      d.paths["/v2/projects/{projectId}/config-snapshots"].post.security = [];
    },
    (d) => {
      delete d.paths["/v2/release-candidates/{candidateId}/inputs"].get
        .responses[200].headers;
    },
  ]) {
    const bad = structuredClone(doc);
    mutate(bad);
    assert.throws(() => verify(bad, semantics, vectors, configuration));
  }
  for (const mutate of [
    (v) => {
      v.runtimeEvidence = true;
    },
    (v) => {
      v.request.schemaVersion = 1;
    },
    (v) => {
      v.request.configurationHash = "0".repeat(64);
    },
    (v) => {
      v.request.normalizedJson = "{}";
    },
    (v) => {
      v.snapshot.schemaVersion = 1;
    },
    (v) => {
      v.inputs.configuration.schemaVersion = 1;
    },
    (v) => {
      v.inputs.configuration.id = "different";
    },
    (v) => {
      v.snapshot.sourceCommit = "b".repeat(40);
    },
    (v) => {
      v.snapshot.sourceRef = "refs/heads/other";
    },
    (v) => {
      v.inputs.configuration.sourceCommit = "b".repeat(40);
    },
    (v) => {
      v.inputs.configuration.sourceRef = "refs/heads/other";
    },
  ]) {
    const bad = structuredClone(vectors);
    mutate(bad);
    assert.throws(() => verify(doc, semantics, bad, configuration));
  }
  assert.throws(() => verify(doc, "", vectors, configuration));
});
