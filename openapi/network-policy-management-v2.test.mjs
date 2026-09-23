import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import { parse } from "yaml";
import { beforePublicationGateEventDocument } from "./alpha-compat.mjs";
import {
  beforeNetworkPolicyManagementV2,
  networkPolicyManagementOperations,
} from "./network-policy-management-v2-compat.mjs";
import { validPolicy } from "../proto/provenance/runner/v1/network-policy-v2/reference.mjs";

const document = parse(
  readFileSync(new URL("provenance.v1.yaml", import.meta.url), "utf8"),
);
const vectors = JSON.parse(
  readFileSync(
    new URL("network-policy-management-v2-vectors.json", import.meta.url),
  ),
);
const require = createRequire(
  new URL("../packages/verification/package.json", import.meta.url),
);
const Ajv = require("ajv/dist/2020.js");
const ajv = new Ajv({ strict: false });
require("ajv-formats")(ajv);
ajv.addSchema({ $id: "network-management", components: document.components });
const valid = (name, value) =>
  ajv.validate(
    { $ref: `network-management#/components/schemas/${name}` },
    value,
  );
const wireInput = (policy) => ({
  ...policy,
  mode: { none: 1, restricted: 2, allowlist: 3 }[policy.mode],
  permissions: policy.permissions.map((p) => ({
    ...p,
    transport: { tcp: 1, udp: 2 }[p.transport],
  })),
});

test("tenant policy HTTP additions preserve the complete alpha31 document", () => {
  assert.equal(
    createHash("sha256")
      .update(
        JSON.stringify(
          beforeNetworkPolicyManagementV2(
            beforePublicationGateEventDocument(document),
          ),
        ),
      )
      .digest("hex"),
    "20bec81d13c65c37d128921f7be1bf69154740167f7a13e38cbf9c9232d8eb88",
  );
});

test("HTTP policy constraints remain identical to the released configuration profile", () => {
  const definitions = JSON.parse(
    readFileSync(new URL("../schemas/config/v2/schema.json", import.meta.url)),
  ).$defs;
  const network = structuredClone(definitions.network);
  network.properties.permissions.items = {
    $ref: "#/components/schemas/NetworkPermissionV2",
  };
  assert.deepEqual(
    document.components.schemas.NetworkPermissionV2,
    definitions.permission,
  );
  assert.deepEqual(document.components.schemas.NetworkPolicyV2, network);
});

test("tenant policy HTTP vectors reproduce actual generated whole-tuple wire", async () => {
  const protocolRequire = createRequire(
    new URL("../packages/runner-protocol/package.json", import.meta.url),
  );
  const { create, toBinary } = protocolRequire("@bufbuild/protobuf");
  const protocol = await import("../packages/runner-protocol/dist/index.js");
  assert.equal(vectors.runtimeEvidence, false);
  for (const vector of vectors.vectors) {
    assert.equal(
      valid("CreateNetworkPolicyVersionRequestV2", vector.request),
      true,
      JSON.stringify(ajv.errors),
    );
    assert.equal(
      valid("NetworkPolicyVersionV2", vector.response),
      true,
      JSON.stringify(ajv.errors),
    );
    const input = wireInput(vector.request.policy);
    assert.equal(validPolicy(input), true);
    const wire = toBinary(
      protocol.NetworkPolicyV2Schema,
      create(protocol.NetworkPolicyV2Schema, input),
    );
    assert.equal(Buffer.from(wire).toString("hex"), vector.wireHex);
    assert.equal(
      createHash("sha256").update(wire).digest("hex"),
      vector.response.networkPolicySha256,
    );
    assert.equal(vector.response.version, vector.request.expectedVersion + 1);
    assert.deepEqual(vector.response.policy, vector.request.policy);
  }
});

test("closed policy and version schemas reject malformed or widening payloads", () => {
  const original = vectors.vectors[1].request;
  for (const mutate of [
    (r) => {
      r.schemaVersion = 1;
    },
    (r) => {
      r.schemaVersion = "2";
    },
    (r) => {
      r.expectedVersion = -1;
    },
    (r) => {
      r.expectedVersion = 9007199254740991;
    },
    (r) => {
      r.expectedVersion = 0.5;
    },
    (r) => {
      r.actor = "owner";
    },
    (r) => {
      r.policy.mode = "unrestricted";
    },
    (r) => {
      r.policy.permissions = [];
    },
    (r) => {
      r.policy.maximumConnections = 0;
    },
    (r) => {
      r.policy.maximumBytesPerSecond = 4294967296;
    },
    (r) => {
      r.policy.resolver = "private";
    },
    (r) => {
      r.policy.permissions[0].hostname = "127.0.0.1";
    },
    (r) => {
      r.policy.permissions[0].hostname = "0x100000000000000000.0x7f";
    },
    (r) => {
      r.policy.permissions[0].hostname = "*.example.com";
    },
    (r) => {
      r.policy.permissions[0].transport = "quic";
    },
    (r) => {
      r.policy.permissions[0].port = 53;
    },
    (r) => {
      r.policy.permissions[0].port = 65536;
    },
    (r) => {
      r.policy.permissions.push(structuredClone(r.policy.permissions[0]));
    },
  ]) {
    const r = structuredClone(original);
    mutate(r);
    assert.equal(
      valid("CreateNetworkPolicyVersionRequestV2", r),
      false,
      JSON.stringify(r),
    );
  }
  const unsorted = wireInput(original.policy);
  unsorted.permissions.reverse();
  assert.equal(validPolicy(unsorted), false);
  for (const vector of vectors.vectors) {
    for (const key of document.components.schemas.NetworkPolicyVersionV2
      .required) {
      const r = structuredClone(vector.response);
      delete r[key];
      assert.equal(valid("NetworkPolicyVersionV2", r), false, key);
    }
    for (const key of [
      "credential",
      "namespacePath",
      "rawYaml",
      "hostInventory",
    ]) {
      assert.equal(
        valid("NetworkPolicyVersionV2", {
          ...vector.response,
          [key]: "forbidden",
        }),
        false,
      );
    }
  }
});

test("six exact operations retain administrator authority and private bounded responses", () => {
  assert.equal(networkPolicyManagementOperations.length, 6);
  for (const {
    path,
    method,
    operationId,
  } of networkPolicyManagementOperations) {
    const operation = document.paths[path][method];
    const status = method === "post" ? 201 : 200;
    assert.equal(operation.operationId, operationId);
    assert.deepEqual(operation.security, [
      { BearerAuth: [] },
      { SessionCookie: [] },
    ]);
    for (const text of [
      "network-policy-management-v2-semantics.md",
      "owner/admin",
      "projects:manage",
      "Actions grants are refused",
      "64 KiB",
    ]) {
      assert.ok(operation.description.includes(text), text);
    }
    assert.equal(
      operation.responses[status].headers["Cache-Control"].$ref,
      "#/components/headers/PrivateNoStore",
    );
    assert.equal(
      operation.responses[status].content["application/json"].schema.$ref,
      "#/components/schemas/NetworkPolicyVersionV2",
    );
    for (const code of [400, 401, 403, 404, 429, 503, "default"]) {
      assert.ok(operation.responses[code]);
    }
    if (method === "post") {
      assert.deepEqual(operation.parameters, [
        { $ref: "#/components/parameters/IdempotencyKey" },
      ]);
      assert.equal(operation.requestBody.required, true);
      assert.ok(operation.responses[409]);
      assert.match(operation.description, /default-disabled/);
    }
  }
});
