import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import { parse } from "yaml";
import * as protocol from "../packages/runner-protocol/dist/index.js";
import { validPolicy } from "../proto/provenance/runner/v1/network-policy-v2/reference.mjs";
import { verifyNetworkPolicyManagementV2Consumer as verify } from "./release-network-policy-management-consumer.mjs";
const require = createRequire(
  new URL("../packages/runner-protocol/package.json", import.meta.url),
);
const { create, toBinary } = require("@bufbuild/protobuf");
const modules = { create, toBinary, protocol, validPolicy };
const doc = parse(
  readFileSync(
    new URL("../openapi/provenance.v1.yaml", import.meta.url),
    "utf8",
  ),
);
const semantics = readFileSync(
  new URL(
    "../openapi/network-policy-management-v2-semantics.md",
    import.meta.url,
  ),
  "utf8",
);
const vectors = JSON.parse(
  readFileSync(
    new URL(
      "../openapi/network-policy-management-v2-vectors.json",
      import.meta.url,
    ),
  ),
);

test("independent tenant management consumer verifies complete contract and generated source identity", () => {
  assert.doesNotThrow(() => verify(doc, semantics, vectors, modules));
});
test("independent consumer refuses altered authority, constraints, vectors and claimed runtime evidence", () => {
  for (const mutate of [
    (d) => {
      d.paths[
        "/v2/projects/{projectId}/network-policy/versions"
      ].post.security = [];
    },
    (d) => {
      delete d.paths["/v2/organizations/{organizationId}/network-policy"].get
        .responses[200].headers;
    },
    (d) => {
      d.components.schemas.NetworkPolicyV2.additionalProperties = true;
    },
    (d) => {
      d.components.schemas.NetworkPolicyV2.properties.maximumBytesPerSecond
        .maximum++;
    },
    (d) => {
      d.components.schemas.CreateNetworkPolicyVersionRequestV2.properties
        .expectedVersion.maximum++;
    },
  ]) {
    const bad = structuredClone(doc);
    mutate(bad);
    assert.throws(() => verify(bad, semantics, vectors, modules));
  }
  for (const mutate of [
    (v) => {
      v.runtimeEvidence = true;
    },
    (v) => {
      v.vectors[0].request.schemaVersion = 1;
    },
    (v) => {
      v.vectors[1].response.sourceId = "10000000-0000-4000-8000-000000000001";
    },
    (v) => {
      v.vectors[1].response.networkPolicySha256 = "0".repeat(64);
    },
    (v) => {
      v.vectors[1].wireHex = "0801";
    },
    (v) => {
      v.vectors[1].request.policy.permissions[0].transport = "udp";
    },
    (v) => {
      v.vectors[0].response.version++;
    },
    (v) => {
      v.vectors[1].response.secret = "forbidden";
    },
  ]) {
    const bad = structuredClone(vectors);
    mutate(bad);
    assert.throws(() => verify(doc, semantics, bad, modules));
  }
  assert.throws(() => verify(doc, "", vectors, modules));
});
