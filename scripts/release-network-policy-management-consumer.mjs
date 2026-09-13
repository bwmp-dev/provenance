import assert from "node:assert/strict";
import { createHash } from "node:crypto";

export function networkPolicyManagementProjection(document) {
  const paths = {};
  for (const [kind, id] of [
    ["organizations", "organizationId"],
    ["projects", "projectId"],
  ]) {
    const root = `/v2/${kind}/{${id}}/network-policy`;
    for (const suffix of [
      "",
      "/versions",
      "/versions/{networkPolicyVersionId}",
    ]) {
      paths[root + suffix] = document.paths[root + suffix];
    }
  }
  return {
    paths,
    parameters: {
      NetworkPolicyVersionId:
        document.components.parameters.NetworkPolicyVersionId,
    },
    responses: {
      NetworkPolicyVersionConflict:
        document.components.responses.NetworkPolicyVersionConflict,
    },
    schemas: Object.fromEntries(
      [
        "NetworkPermissionV2",
        "NetworkPolicyV2",
        "CreateNetworkPolicyVersionRequestV2",
        "NetworkPolicyVersionV2",
      ].map((name) => [name, document.components.schemas[name]]),
    ),
  };
}

// Checks extracted contract and real generated wire, not live authorization or
// runtime enforcement. The verifier supplies independently extracted modules.
export function verifyNetworkPolicyManagementV2Consumer(
  document,
  semantics,
  vectors,
  { create, toBinary, protocol, validPolicy },
) {
  assert.equal(
    createHash("sha256")
      .update(JSON.stringify(networkPolicyManagementProjection(document)))
      .digest("hex"),
    "bf799f8104443bb008bad5f75c95bb0b4d900e139a787a94a5a819fa06e4d076",
  );
  assert.match(semantics, /^# IFC-030 tenant network policy management v2/);
  for (const text of [
    "All responses are no-store",
    "Actions grants are refused",
    "CSRF protections",
    "NOT an EffectivePolicy",
    "64 KiB",
    "default-disabled",
    "never reset current policy",
  ]) {
    assert.ok(semantics.includes(text), text);
  }
  assert.equal(vectors.contract, "IFC-030-network-policy-management-v2");
  assert.equal(vectors.runtimeEvidence, false);
  assert.equal(vectors.vectors.length, 2);
  for (const [
    index,
    { request, response, wireHex },
  ] of vectors.vectors.entries()) {
    assert.deepEqual(Object.keys(request).sort(), [
      "expectedVersion",
      "policy",
      "schemaVersion",
    ]);
    assert.deepEqual(Object.keys(response).sort(), [
      "createdAt",
      "id",
      "networkPolicySha256",
      "organizationId",
      "policy",
      "schemaVersion",
      "sourceId",
      "sourceKind",
      "version",
    ]);
    assert.equal(request.schemaVersion, 2);
    assert.equal(response.schemaVersion, 2);
    assert.equal(request.expectedVersion, index);
    assert.equal(response.version, index + 1);
    assert.equal(response.sourceKind, index === 0 ? "organization" : "project");
    assert.deepEqual(request.policy, response.policy);
    assert.match(response.createdAt, /^2026-09-13T00:00:00Z$/);
    assert.equal(
      response.organizationId,
      "10000000-0000-4000-8000-000000000001",
    );
    assert.equal(
      response.sourceId,
      index === 0
        ? response.organizationId
        : "20000000-0000-4000-8000-000000000001",
    );
    assert.equal(
      response.id,
      `30000000-0000-4000-8000-00000000000${index + 1}`,
    );
    const policy = request.policy;
    const input = {
      ...policy,
      mode: { none: 1, restricted: 2, allowlist: 3 }[policy.mode],
      permissions: policy.permissions.map((p) => ({
        ...p,
        transport: { tcp: 1, udp: 2 }[p.transport],
      })),
    };
    assert.equal(validPolicy(input), true);
    const wire = toBinary(
      protocol.NetworkPolicyV2Schema,
      create(protocol.NetworkPolicyV2Schema, input),
    );
    assert.equal(Buffer.from(wire).toString("hex"), wireHex);
    assert.equal(
      createHash("sha256").update(wire).digest("hex"),
      response.networkPolicySha256,
    );
    assert.equal(
      wireHex,
      index === 0
        ? "0801"
        : "080312100a09612e6578616d706c6510bb03180112100a09622e6578616d706c6510fb411802180820808004",
    );
  }
}
