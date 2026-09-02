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
        assert.ok(
          [
            "#/components/schemas/Timestamp",
            "#/components/schemas/LogTimestamp",
          ].includes(property.$ref),
          name,
        );
      }
    }
  }
});

test("IFC-010 exposes only bounded candidate execution log operations", () => {
  const executionList = operation("listReleaseCandidateExecutions");
  const liveLogs = operation("readExecutionLogs");
  const completeLog = operation("downloadCompleteExecutionLog");
  const requiredSecurity = [{ BearerAuth: [] }, { SessionCookie: [] }];

  for (const candidate of [executionList, liveLogs, completeLog]) {
    assert.deepEqual(candidate.security, requiredSecurity);
    assert.equal(
      candidate.responses["401"].$ref,
      "#/components/responses/AuthenticationRequired",
    );
    assert.equal(
      candidate.responses["404"].$ref,
      "#/components/responses/PrivateLogNotFound",
    );
    assert.equal(
      candidate.responses.default.$ref,
      "#/components/responses/Problem",
    );
  }

  assert.match(executionList.description, /same HTTP 404 response/i);
  assert.deepEqual(
    executionList.parameters.map(resolveParameter).map(({ name }) => name),
    ["cursor", "limit"],
  );
  assert.equal(
    executionList.responses["200"].content["application/json"].schema.$ref,
    "#/components/schemas/ExecutionLogDescriptorPage",
  );

  const descriptor = document.components.schemas.ExecutionLogDescriptor;
  assert.equal(descriptor.additionalProperties, false);
  assert.deepEqual(descriptor.required, [
    "candidateId",
    "matrixEntryId",
    "executionId",
    "attemptId",
    "attemptNumber",
    "state",
    "liveState",
    "completeLog",
    "createdAt",
    "updatedAt",
  ]);
  for (const identity of ["candidateId", "matrixEntryId", "executionId"]) {
    assert.equal(
      descriptor.properties[identity].$ref,
      "#/components/schemas/BoundedStableId",
    );
  }
  assert.equal(
    document.components.schemas.ExecutionLogDescriptorPage.properties.items
      .maxItems,
    100,
  );
  assert.equal(
    document.components.schemas.ExecutionLogDescriptorPage[
      "x-provenance-max-json-bytes"
    ],
    262_144,
  );
});

test("IFC-010 cursor negotiation and SSE grammar are unambiguous", () => {
  const liveLogs = operation("readExecutionLogs");
  const parameterNames = liveLogs.parameters
    .map(resolveParameter)
    .map(({ name }) => name);
  assert.deepEqual(parameterNames, ["cursor", "limit", "Last-Event-ID"]);
  assert.match(liveLogs.description, /application\/json.*is the default/is);
  assert.match(liveLogs.description, /explicitly the most preferred/i);
  assert.match(liveLogs.description, /Last-Event-ID.*takes precedence/is);
  assert.match(liveLogs.description, /byte-for-byte equal/i);
  assert.match(liveLogs.description, /last_event_id_not_applicable/);
  assert.match(liveLogs.description, /never promise\s+replay of missed bytes/i);
  assert.match(
    liveLogs.description,
    /structured results and assertions are\s+separate/i,
  );

  const cursor = document.components.schemas.LogCursor;
  assert.equal(cursor.minLength, 16);
  assert.equal(cursor.maxLength, 1024);
  assert.match(
    document.components.parameters.LogCursor.description,
    /short-lived/,
  );
  assert.match(
    document.components.parameters.LogLastEventId.description,
    /reauthorized on every reconnect/,
  );
  assert.equal(
    liveLogs.responses["400"].$ref,
    "#/components/responses/LogCursorConflict",
  );

  const success = liveLogs.responses["200"];
  assert.deepEqual(Object.keys(success.content), [
    "application/json",
    "text/event-stream",
  ]);
  assert.match(success.description, /id: <opaque cursor>/);
  assert.match(success.description, /event:.*log-entry.*log-gap.*log-state/s);
  assert.match(success.description, /compact single-line JSON/);
  assert.match(success.description, /retry:.*1000.*30000/s);
  assert.match(success.description, /heartbeat every 15 to 30 seconds/);
  assert.match(success.description, /: heartbeat/);
  assert.match(success.description, /never log or terminal evidence/);
  assert.match(success.description, /frame exceeds 65536 encoded bytes/);
  assert.match(
    success.description,
    /batches of at most 100 data events and 1 MiB/,
  );
  assert.match(
    success.description,
    /same bounds to the\s+per-connection queue/,
  );
  assert.match(
    success.description,
    /do not\s+assemble the complete response in\s+memory/,
  );
  assert.equal(
    success.content["text/event-stream"].schema["x-provenance-streaming"],
    true,
  );
  assert.equal(
    success.content["text/event-stream"].schema["x-provenance-max-event-bytes"],
    65_536,
  );
  assert.equal(
    liveLogs.responses["429"].$ref,
    "#/components/responses/LogRateLimited",
  );
  assert.equal(
    liveLogs.responses["503"].$ref,
    "#/components/responses/LogRelayUnavailable",
  );
  assert.equal(
    liveLogs.responses["406"].$ref,
    "#/components/responses/LogRepresentationNotAcceptable",
  );
});

test("IFC-010 live entries and reconciliation make every loss state explicit", () => {
  const schemas = document.components.schemas;
  const page = schemas.ExecutionLogPage;
  const entry = schemas.ExecutionLogEntryEvent;
  const gap = schemas.ExecutionLogGapEvent;
  const state = schemas.ExecutionLogStateEvent;

  assert.equal(page.additionalProperties, false);
  assert.equal(page.properties.events.maxItems, 100);
  assert.equal(page["x-provenance-max-json-bytes"], 1_048_576);
  assert.equal(entry.additionalProperties, false);
  assert.deepEqual(entry.properties.stream.enum, [
    "stdout",
    "stderr",
    "runner",
    "probe",
  ]);
  assert.equal(entry.properties.data.maxLength, 16_384);
  assert.equal(entry.properties.data["x-provenance-max-utf8-bytes"], 16_384);
  assert.match(entry.properties.data.description, /normalized UTF-8/);
  assert.match(
    entry.properties.data.description,
    /Invalid source bytes are replaced/,
  );
  assert.ok(entry.required.includes("partial"));
  assert.ok(entry.required.includes("redacted"));
  assert.equal(entry["x-provenance-max-json-bytes"], 65_536);

  assert.deepEqual(gap.properties.reason.enum, [
    "runner_dropped",
    "relay_evicted",
    "relay_restarted",
    "disconnected",
  ]);
  assert.equal(gap.properties.liveRecovery.const, "unavailable");
  assert.match(gap.properties.liveRecovery.description, /never be recovered/);
  assert.deepEqual(gap.properties.completeLogState.enum, [
    "pending",
    "available",
    "failed",
    "expired",
    "unavailable",
  ]);
  assert.ok(gap.required.includes("sequence"));
  assert.equal(
    gap.properties.droppedCount.$ref,
    "#/components/schemas/DroppedLogCount",
  );
  assert.ok(state.required.includes("sequence"));
  assert.deepEqual(schemas.LiveLogState.enum, [
    "waiting",
    "live",
    "disconnected",
    "terminal",
    "expired",
    "unavailable",
  ]);
  assert.equal(
    schemas.CompleteLogAvailable.properties.wasRedacted.type,
    "boolean",
  );
  assert.equal(
    schemas.CompleteLogAvailable.properties.wasTruncated.type,
    "boolean",
  );

  for (const name of [
    "ExecutionLogEntryEvent",
    "ExecutionLogGapEvent",
    "ExecutionLogStateEvent",
    "ExecutionCompleteLogStateEvent",
  ]) {
    const event = schemas[name];
    for (const identity of [
      "candidateId",
      "matrixEntryId",
      "executionId",
      "attemptId",
    ]) {
      assert.equal(
        event.properties[identity].$ref,
        "#/components/schemas/BoundedStableId",
        `${name}.${identity}`,
      );
    }
    assert.ok(event.required.includes("attemptNumber"), name);
    assert.ok(event.required.includes("sequence"), name);
    assert.equal(event["x-provenance-max-json-bytes"], 65_536, name);
  }
});

test("IFC-010 complete-log handoff is immutable, bounded, and capability-free", () => {
  const schemas = document.components.schemas;
  assert.deepEqual(schemas.CompleteLogState.oneOf, [
    { $ref: "#/components/schemas/CompleteLogPending" },
    { $ref: "#/components/schemas/CompleteLogAvailable" },
    { $ref: "#/components/schemas/CompleteLogFailed" },
    { $ref: "#/components/schemas/CompleteLogExpired" },
    { $ref: "#/components/schemas/CompleteLogUnavailable" },
  ]);

  const available = schemas.CompleteLogAvailable;
  assert.equal(available.additionalProperties, false);
  assert.equal(
    available.properties.sha256.$ref,
    "#/components/schemas/Sha256Digest",
  );
  assert.equal(available.properties.compressedSizeBytes.maximum, 269_484_032);
  assert.equal(available.properties.uncompressedSizeBytes.maximum, 268_435_456);
  assert.equal(available.properties.contentType.const, "application/gzip");
  assert.match(
    available.properties.downloadPath.description,
    /same-origin authenticated API path/i,
  );
  assert.match(
    available.properties.downloadPath.description,
    /not an object key/i,
  );
  assert.match(available.properties.downloadPath.description, /presigned URL/i);

  const completeLog = operation("downloadCompleteExecutionLog");
  assert.match(completeLog.description, /never redirects to object storage/i);
  assert.match(completeLog.description, /Content-Encoding MUST be absent/);
  assert.match(
    completeLog.description,
    /stream at most 269484032 compressed bytes/,
  );
  assert.match(completeLog.description, /do not buffer the object in\s+memory/);
  assert.equal(
    completeLog.responses["425"].$ref,
    "#/components/responses/CompleteLogNotReady",
  );
  assert.equal(
    completeLog.responses["410"].$ref,
    "#/components/responses/CompleteLogExpired",
  );
  assert.equal(
    completeLog.responses["409"].$ref,
    "#/components/responses/CompleteLogUnavailable",
  );
  assert.equal(
    completeLog.responses["200"].content["application/gzip"].schema[
      "x-provenance-max-bytes"
    ],
    269_484_032,
  );
  assert.deepEqual(Object.keys(completeLog.responses["200"].headers).sort(), [
    "Cache-Control",
    "Content-Digest",
    "Content-Disposition",
    "Content-Length",
  ]);
  assert.equal(
    document.components.headers.CompleteLogContentDigest.schema.pattern,
    "^sha-256=:[A-Za-z0-9+/]{43}=:$",
  );
  assert.equal(
    document.components.headers.CompleteLogContentDigest.schema.maxLength,
    54,
  );
  assert.equal(
    document.components.headers.CompleteLogContentLength.schema.maximum,
    269_484_032,
  );

  const forbiddenField =
    /(?:objectKey|storageCredential|presigned|downloadUrl|url)$/i;
  for (const name of [
    "CompleteLogPending",
    "CompleteLogAvailable",
    "CompleteLogFailed",
    "CompleteLogExpired",
    "CompleteLogUnavailable",
  ]) {
    assert.ok(
      Object.keys(schemas[name].properties).every(
        (property) => !forbiddenField.test(property),
      ),
      name,
    );
  }
});

test("IFC-010 introduced schemas bound arrays, strings, and serialized events", () => {
  const schemas = document.components.schemas;
  assert.equal(schemas.BoundedStableId.maxLength, 36);
  assert.equal(schemas.LogTimestamp.maxLength, 35);
  assert.equal(schemas.LogSequence.maxLength, 20);
  assert.equal(schemas.DroppedLogCount.maxLength, 20);
  assert.equal(schemas.LogCursor.maxLength, 1024);

  for (const name of [
    "ExecutionLogDescriptorPage",
    "ExecutionLogDescriptor",
    "CompleteLogPending",
    "CompleteLogAvailable",
    "CompleteLogFailed",
    "CompleteLogExpired",
    "CompleteLogUnavailable",
    "ExecutionLogPage",
    "ExecutionLogEntryEvent",
    "ExecutionLogGapEvent",
    "ExecutionLogStateEvent",
    "ExecutionCompleteLogStateEvent",
  ]) {
    assert.equal(schemas[name].additionalProperties, false, name);
  }

  for (const schema of Object.values(schemas).filter(
    (candidate) => candidate["x-provenance-max-json-bytes"],
  )) {
    assert.ok(schema["x-provenance-max-json-bytes"] <= 1_048_576);
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
