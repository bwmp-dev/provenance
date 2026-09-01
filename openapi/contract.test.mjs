import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parse } from "yaml";

const root = new URL("./", import.meta.url);
const document = parse(
  await readFile(new URL("provenance.v1.yaml", root), "utf8"),
);
const inventory = JSON.parse(
  await readFile(new URL("operation-inventory.json", root), "utf8"),
);
const methods = new Set([
  "delete",
  "get",
  "head",
  "options",
  "patch",
  "post",
  "put",
]);
const mutations = new Set(["delete", "patch", "post", "put"]);

const operations = Object.entries(document.paths).flatMap(([path, pathItem]) =>
  Object.entries(pathItem)
    .filter(([method]) => methods.has(method))
    .map(([method, operation]) => ({ method, operation, path })),
);

test("operation and path inventory matches the public v1 skeleton", () => {
  const actual = operations
    .map(({ method, operation, path }) => ({
      method,
      operationId: operation.operationId,
      path,
      tag: operation.tags?.[0],
    }))
    .sort(compareInventory);
  const expected = [...inventory].sort(compareInventory);

  assert.deepEqual(actual, expected);
  assert.equal(
    new Set(actual.map(({ operationId }) => operationId)).size,
    actual.length,
  );
  assert.ok(actual.every(({ path }) => path.startsWith("/v1/")));
  assert.deepEqual(
    new Set(actual.map(({ tag }) => tag)),
    new Set([
      "artifacts",
      "authentication",
      "github",
      "integrations",
      "organizations-projects",
      "release-candidates",
      "runners",
      "usage",
      "verification",
    ]),
  );
});

test("every operation exposes structured failure responses", () => {
  for (const { operation } of operations) {
    assert.equal(
      operation.responses.default?.$ref,
      "#/components/responses/Problem",
      operation.operationId,
    );
  }

  const problem = document.components.schemas.ProblemDetails;
  assert.deepEqual(problem.required, ["type", "title", "status"]);
  assert.equal(problem.properties.status.minimum, 400);
  assert.equal(problem.properties.status.maximum, 599);
  assert.equal(
    document.components.responses.Problem.content["application/problem+json"]
      .schema.$ref,
    "#/components/schemas/ProblemDetails",
  );
});

test("every mutation has deterministic idempotency semantics", () => {
  for (const { method, operation, path } of operations.filter(({ method }) =>
    mutations.has(method),
  )) {
    const parameter = operation.parameters
      ?.map(resolveParameter)
      .find(({ name }) => name === "Idempotency-Key");
    assert.ok(
      parameter,
      `${method.toUpperCase()} ${path} lacks Idempotency-Key`,
    );
    const conflictReference = operation.responses["409"]?.$ref;
    assert.match(
      conflictReference,
      /^#\/components\/responses\/[A-Za-z0-9]+$/,
      operation.operationId,
    );
    const conflict =
      document.components.responses[conflictReference.split("/").at(-1)];
    assert.match(conflict.description, /idempotency/i, operation.operationId);
    assert.equal(
      conflict.content["application/problem+json"].schema.$ref,
      "#/components/schemas/ProblemDetails",
      operation.operationId,
    );
    if (operation.operationId !== "receiveGitHubWebhook") {
      assert.equal(parameter.required, true, operation.operationId);
    }
  }

  const key = document.components.parameters.IdempotencyKey;
  assert.match(
    key.description,
    /same key and request returns the original outcome/,
  );
  assert.match(key.description, /different request conflicts/);

  const keySchema = document.components.schemas.IdempotencyKey;
  assert.equal(keySchema.minLength, 8);
  assert.equal(keySchema.maxLength, 128);
  assert.equal(keySchema.pattern, "^[A-Za-z0-9._:-]{8,128}$");
});

test("session creation fails closed when a credential cannot be replayed", () => {
  const createSession = operation("createSession");
  const parameter = createSession.parameters
    .map(resolveParameter)
    .find(({ name }) => name === "Idempotency-Key");
  const conflict =
    document.components.responses[
      createSession.responses["409"].$ref.split("/").at(-1)
    ];

  assert.equal(
    createSession.parameters[0].$ref,
    "#/components/parameters/SessionCreationIdempotencyKey",
  );
  assert.match(parameter.description, /retains only a hash/i);
  assert.match(parameter.description, /credential_not_replayable/);
  assert.match(parameter.description, /new one-time exchange token/i);
  assert.match(conflict.description, /idempotency_key_conflict/);
  assert.match(conflict.description, /credential_not_replayable/);
  assert.match(conflict.description, /does not mint a replacement credential/i);
  assert.equal(
    conflict.content["application/problem+json"].schema.$ref,
    "#/components/schemas/ProblemDetails",
  );
});

test("project creation matches the platform wire contract", () => {
  const createProject = operation("createProject");
  const createRequest = document.components.schemas.CreateProjectRequest;
  const project = document.components.schemas.Project;

  assert.deepEqual(createRequest.required, [
    "slug",
    "displayName",
    "visibility",
  ]);
  assert.equal(createRequest.properties.name, undefined);
  assert.equal(createRequest.properties.displayName.maxLength, 200);
  assert.ok(project.required.includes("displayName"));
  assert.ok(project.required.includes("updatedAt"));
  assert.equal(project.properties.name, undefined);
  assert.equal(project.properties.displayName.maxLength, 200);
  assert.equal(
    document.components.schemas.Slug.pattern,
    "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
  );

  const location = createProject.responses["201"].headers.Location;
  assert.equal(location.required, true);
  assert.equal(location.schema.type, "string");
  assert.equal(location.schema.format, "uri-reference");
});

test("configuration snapshot creation preserves canonical source identity", () => {
  const createSnapshot = operation("createProjectConfigSnapshot");
  const request =
    document.components.schemas.CreateProjectConfigSnapshotRequest;
  const snapshot = document.components.schemas.ProjectConfigSnapshot;

  assert.deepEqual(createSnapshot.security, [{ BearerAuth: [] }]);
  assert.deepEqual(request.required, [
    "sourceCommit",
    "rawYaml",
    "normalizedJson",
    "schemaVersion",
    "configurationHash",
  ]);
  assert.equal(request.additionalProperties, false);
  assert.equal(
    request.properties.sourceCommit.pattern,
    "^(?:[a-f0-9]{40}|[a-f0-9]{64})$",
  );
  assert.equal(request.properties.sourceRef.maxLength, 512);
  assert.equal(request.properties.rawYaml.maxLength, 1_048_576);
  assert.equal(request.properties.normalizedJson.maxLength, 1_048_576);
  assert.equal(
    request.properties.normalizedJson.contentMediaType,
    "application/json",
  );
  assert.match(
    request.properties.normalizedJson.description,
    /canonical UTF-8 JSON text whose SHA-256 is configurationHash/,
  );
  assert.equal(request.properties.schemaVersion.const, 1);
  assert.equal(
    request.properties.configurationHash.$ref,
    "#/components/schemas/Sha256Digest",
  );
  assert.equal(snapshot.additionalProperties, false);
  assert.deepEqual(snapshot.required, [
    "id",
    "projectId",
    "sourceCommit",
    "schemaVersion",
    "configurationHash",
    "createdAt",
  ]);
  assert.equal(snapshot.properties.schemaVersion.const, 1);
  assert.equal(createSnapshot.responses["201"].headers, undefined);
  assert.equal(
    createSnapshot.responses["422"].$ref,
    "#/components/responses/Problem",
  );

  const createCandidate =
    document.components.schemas.CreateReleaseCandidateRequest;
  assert.ok(!createCandidate.required.includes("configurationSnapshotId"));
  assert.equal(
    createCandidate.properties.configurationSnapshotId.allOf[0].$ref,
    "#/components/schemas/StableId",
  );
  assert.match(
    createCandidate.properties.configurationSnapshotId.description,
    /must identify a snapshot in the path project whose hash equals configurationHash/,
  );
  assert.match(
    createCandidate.properties.configurationSnapshotId.description,
    /zero or multiple matches fail with HTTP 409/,
  );
  assert.equal(
    document.components.schemas.ReleaseCandidate.properties
      .configurationSnapshotId,
    undefined,
  );

  const candidateConflict =
    document.components.responses.ReleaseCandidateConflict;
  assert.equal(
    operation("createReleaseCandidate").responses["409"].$ref,
    "#/components/responses/ReleaseCandidateConflict",
  );
  for (const code of [
    "configuration_snapshot_not_found",
    "configuration_snapshot_mismatch",
    "configuration_snapshot_ambiguous",
  ]) {
    assert.match(candidateConflict.description, new RegExp(code));
  }
  assert.match(candidateConflict.description, /exactly one snapshot/);
  assert.match(
    candidateConflict.description,
    /All listed conflicts use HTTP 409/,
  );
});

test("authentication, pagination, identifiers, timestamps, and states stay stable", () => {
  assert.deepEqual(Object.keys(document.components.securitySchemes).sort(), [
    "BearerAuth",
    "GitHubWebhookSignature",
    "SessionCookie",
  ]);
  assert.deepEqual(document.security, [
    { BearerAuth: [] },
    { SessionCookie: [] },
  ]);
  assert.deepEqual(
    operation("createProject").security,
    [{ BearerAuth: [] }],
    "project creation is bearer-only for tenant/capability-scoped callers",
  );

  for (const { operation: listOperation } of operations.filter(
    ({ operation: candidate }) => candidate.operationId.startsWith("list"),
  )) {
    const names = listOperation.parameters
      .map(resolveParameter)
      .map(({ name }) => name);
    assert.ok(names.includes("cursor"), listOperation.operationId);
    assert.ok(names.includes("limit"), listOperation.operationId);
  }

  assert.equal(document.components.schemas.StableId.format, "uuid");
  assert.equal(document.components.schemas.Timestamp.format, "date-time");
  assert.deepEqual(
    Object.fromEntries(
      [
        "ArtifactState",
        "IntegrationState",
        "ReleaseCandidateState",
        "RunnerState",
        "SessionState",
        "VerificationState",
      ].map((name) => [name, document.components.schemas[name].enum]),
    ),
    {
      ArtifactState: [
        "pending",
        "uploaded",
        "verifying",
        "ready",
        "rejected",
        "deleted",
      ],
      IntegrationState: ["active", "disabled", "error"],
      ReleaseCandidateState: [
        "pending",
        "testing",
        "awaiting_approval",
        "approved",
        "canceled",
        "failed",
        "publishing",
        "published",
      ],
      RunnerState: ["offline", "idle", "busy", "draining"],
      SessionState: ["active", "expired", "revoked"],
      VerificationState: ["pending", "verified", "failed"],
    },
  );

  for (const schema of Object.values(document.components.schemas)) {
    for (const [name, property] of Object.entries(schema.properties ?? {})) {
      if (name.endsWith("At") || name === "from" || name === "to") {
        assert.equal(property.$ref, "#/components/schemas/Timestamp", name);
      }
    }
  }
});

function operation(operationId) {
  return operations.find(
    ({ operation: candidate }) => candidate.operationId === operationId,
  ).operation;
}

function resolveParameter(parameter) {
  if (!parameter.$ref) return parameter;
  const name = parameter.$ref.split("/").at(-1);
  return document.components.parameters[name];
}

function compareInventory(left, right) {
  return (
    left.path.localeCompare(right.path) ||
    left.method.localeCompare(right.method) ||
    left.operationId.localeCompare(right.operationId)
  );
}
