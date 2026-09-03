import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
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
const alpha5Compatibility = JSON.parse(
  await readFile(new URL("alpha5-compat.snapshot.json", root), "utf8"),
);
const generatedClient = await readFile(
  new URL("../packages/api-client/src/gen/schema.d.ts", root),
  "utf8",
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
const privateLogOperationIds = new Set([
  "listReleaseCandidateExecutions",
  "readExecutionLogs",
  "downloadCompleteExecutionLog",
]);

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
      privateLogOperationIds.has(operation.operationId)
        ? "#/components/responses/PrivateProblem"
        : "#/components/responses/Problem",
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
      problemBaseSchema(conflict),
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

test("WP-08C exposes a bounded deterministic project candidate list", () => {
  const list = operation("listReleaseCandidates");
  const schemas = document.components.schemas;

  assert.deepEqual(list.security, [{ BearerAuth: [] }, { SessionCookie: [] }]);
  assert.equal(createPath(list), "/v1/projects/{projectId}/release-candidates");
  assert.deepEqual(
    list.parameters.map(resolveParameter).map(({ name }) => name),
    ["cursor", "limit"],
  );
  assert.equal(document.components.schemas.Cursor.maxLength, 2048);
  assert.deepEqual(document.components.parameters.PageSize.schema, {
    type: "integer",
    minimum: 1,
    maximum: 100,
    default: 50,
  });
  assert.match(
    list.description,
    /descending keyset order by\s+`\(createdAt, id\)`/i,
  );
  assert.match(list.description, /resumes strictly\s+after that key/i);
  assert.match(
    list.description,
    /clients must not parse or synthesize cursors/i,
  );
  assert.match(
    list.description,
    /nonexistent project.*outside the caller's\s+tenant.*same HTTP 404/is,
  );
  assert.match(
    list.description,
    /visibility are resolved before cursor\s+validation/i,
  );
  assert.match(
    list.description,
    /lacks\s+the release-candidate read capability receives HTTP 403/i,
  );
  assert.match(
    list.description,
    /differently scoped cursor receives HTTP 400/i,
  );

  for (const status of ["400", "401", "403", "404", "422", "500"]) {
    assert.equal(
      list.responses[status].$ref,
      "#/components/responses/Problem",
      status,
    );
  }
  assert.equal(
    list.responses["200"].content["application/json"].schema.$ref,
    "#/components/schemas/ReleaseCandidatePage",
  );

  const page = schemas.ReleaseCandidatePage;
  assert.equal(page.additionalProperties, false);
  assert.deepEqual(page.required, ["items", "page"]);
  assert.equal(page.properties.items.maxItems, 100);
  assert.equal(
    page.properties.items.items.$ref,
    "#/components/schemas/ReleaseCandidateSummary",
  );
  assert.equal(page.properties.page.$ref, "#/components/schemas/PageInfo");
  assert.equal(page["x-provenance-max-json-bytes"], 262_144);

  const summary = schemas.ReleaseCandidateSummary;
  assert.equal(summary.additionalProperties, false);
  assert.deepEqual(summary.required, [
    "id",
    "projectId",
    "artifactId",
    "configurationHash",
    "version",
    "state",
    "createdAt",
    "updatedAt",
  ]);
  for (const identity of ["id", "projectId", "artifactId"]) {
    assert.equal(
      summary.properties[identity].$ref,
      "#/components/schemas/BoundedStableId",
      identity,
    );
  }
  assert.equal(
    summary.properties.configurationHash.$ref,
    "#/components/schemas/Sha256Digest",
  );
  assert.equal(summary.properties.version.minLength, 1);
  assert.equal(summary.properties.version.maxLength, 128);
  assert.equal(
    summary.properties.state.$ref,
    "#/components/schemas/ReleaseCandidateState",
  );
  for (const timestamp of ["createdAt", "updatedAt"]) {
    assert.equal(
      summary.properties[timestamp].$ref,
      "#/components/schemas/BoundedTimestamp",
      timestamp,
    );
  }
  assert.equal(schemas.BoundedTimestamp.maxLength, 35);
  assert.equal(
    schemas.BoundedTimestamp.allOf[0].$ref,
    "#/components/schemas/Timestamp",
  );
  assert.match(generatedClient, /listReleaseCandidates/);
  assert.match(generatedClient, /ReleaseCandidateSummary/);
});

test("authentication, pagination, identifiers, timestamps, and states stay stable", () => {
  assert.deepEqual(Object.keys(document.components.securitySchemes).sort(), [
    "BearerAuth",
    "GitHubWebhookSignature",
    "RunnerRegistrationToken",
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
        "RunnerCredentialLifecycleState",
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
      RunnerCredentialLifecycleState: [
        "registering",
        "active",
        "quarantined",
        "revoked",
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
            "#/components/schemas/BoundedTimestamp",
            "#/components/schemas/LogTimestamp",
          ].includes(property.$ref),
          name,
        );
      }
    }
  }
});

test("IFC-011 defines bounded hash-only enrollment and credential lifecycle", () => {
  const schemas = document.components.schemas;
  const create = operation("createRunnerRegistration");
  const redeem = operation("redeemRunnerRegistration");
  const rotate = operation("rotateRunnerCredentials");
  const revoke = operation("revokeRunnerCredentials");

  for (const secretOperation of [create, redeem, rotate]) {
    const parameter = secretOperation.parameters
      .map(resolveParameter)
      .find(({ name }) => name === "Idempotency-Key");
    assert.match(parameter.description, /stores only|retains only/i);
    assert.match(parameter.description, /credential_not_replayable/);
    assert.match(parameter.description, /idempotency_key_conflict/);
    assert.match(secretOperation.description, /credential_not_replayable/);
  }

  assert.deepEqual(redeem.security, [{ RunnerRegistrationToken: [] }]);
  assert.equal(
    document.components.securitySchemes.RunnerRegistrationToken.bearerFormat,
    "prr_v1",
  );
  assert.deepEqual(
    Object.fromEntries(
      ["401", "409", "410", "422"].map((status) => [
        status,
        redeem.responses[status].$ref,
      ]),
    ),
    {
      401: "#/components/responses/RegistrationTokenInvalid",
      409: "#/components/responses/RegistrationRedemptionConflict",
      410: "#/components/responses/RegistrationTokenExpired",
      422: "#/components/responses/RegistrationProofInvalid",
    },
  );
  for (const [response, code] of [
    ["RegistrationTokenInvalid", "registration_token_invalid"],
    ["RegistrationTokenExpired", "registration_token_expired"],
    ["RegistrationProofInvalid", "registration_proof_invalid"],
    ["RegistrationRedemptionConflict", "registration_token_consumed"],
  ]) {
    assert.match(
      document.components.responses[response].description,
      new RegExp(code),
    );
  }
  assert.match(
    document.components.responses.RegistrationTokenInvalid.description,
    /without disclosing runner or tenant identity/,
  );

  const redemptionOrder = [
    "registration_token_invalid",
    "idempotency_key_conflict",
    "credential_not_replayable",
    "registration_token_expired",
    "registration_token_consumed",
    "registration_proof_invalid",
    "runner_key_conflict",
  ].map((code) => redeem.description.indexOf(`\`${code}\``));
  assert.ok(redemptionOrder.every((index) => index >= 0));
  assert.deepEqual(
    redemptionOrder,
    [...redemptionOrder].sort((a, b) => a - b),
  );

  assert.deepEqual(
    document.components.schemas.RegistrationRedemptionConflictProblem.allOf[1]
      .properties.code.enum,
    [
      "idempotency_key_conflict",
      "credential_not_replayable",
      "registration_token_consumed",
      "runner_key_conflict",
    ],
  );
  assert.equal(
    document.components.schemas.RegistrationTokenInvalidProblem.allOf[1]
      .properties.code.const,
    "registration_token_invalid",
  );
  assert.equal(
    document.components.schemas.RegistrationTokenExpiredProblem.allOf[1]
      .properties.code.const,
    "registration_token_expired",
  );
  assert.equal(
    document.components.schemas.RegistrationProofInvalidProblem.allOf[1]
      .properties.code.const,
    "registration_proof_invalid",
  );

  assert.deepEqual(
    [
      [
        "RunnerRegistrationToken",
        50,
        "^prr_v1_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$",
      ],
      [
        "RunnerConnectionCredential",
        50,
        "^prc_v1_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$",
      ],
      ["Ed25519PublicKey", 43, "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"],
      ["Ed25519Signature", 86, "^[A-Za-z0-9_-]{85}[AQgw]$"],
      ["PublicKeyFingerprint", 71, "^sha256:[a-f0-9]{64}$"],
    ].map(([name, length, pattern]) => ({
      length: [schemas[name].minLength, schemas[name].maxLength],
      name,
      pattern: schemas[name].pattern,
    })),
    [
      {
        length: [50, 50],
        name: "RunnerRegistrationToken",
        pattern: "^prr_v1_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$",
      },
      {
        length: [50, 50],
        name: "RunnerConnectionCredential",
        pattern: "^prc_v1_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$",
      },
      {
        length: [43, 43],
        name: "Ed25519PublicKey",
        pattern: "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$",
      },
      {
        length: [86, 86],
        name: "Ed25519Signature",
        pattern: "^[A-Za-z0-9_-]{85}[AQgw]$",
      },
      {
        length: [71, 71],
        name: "PublicKeyFingerprint",
        pattern: "^sha256:[a-f0-9]{64}$",
      },
    ],
  );
  assert.deepEqual(
    [
      schemas.RegistrationTokenTtlSeconds.minimum,
      schemas.RegistrationTokenTtlSeconds.maximum,
      schemas.RunnerCredentialTtlSeconds.minimum,
      schemas.RunnerCredentialTtlSeconds.maximum,
      schemas.RunnerCredentialOverlapSeconds.minimum,
      schemas.RunnerCredentialOverlapSeconds.maximum,
    ],
    [60, 900, 300, 3600, 30, 300],
  );

  for (const name of [
    "CreateRunnerRegistrationRequest",
    "RunnerRegistration",
    "RedeemRunnerRegistrationRequest",
    "RunnerRegistrationRedemption",
    "UpdateRunnerRequest",
    "RotateRunnerCredentialRequest",
    "RevokeRunnerCredentialsRequest",
    "RunnerCredential",
    "RunnerCredentialRevocation",
  ]) {
    assert.equal(schemas[name].additionalProperties, false, name);
  }
  assert.deepEqual(schemas.RedeemRunnerRegistrationRequest.required, [
    "publicKey",
    "possessionProof",
    "credentialTtlSeconds",
  ]);
  assert.ok(!("publicKey" in schemas.Runner.properties));
  assert.ok(!("credential" in schemas.Runner.properties));
  assert.equal(
    schemas.Runner.properties.publicKeyFingerprint.allOf[0].$ref,
    "#/components/schemas/PublicKeyFingerprint",
  );
  assert.equal(
    schemas.UpdateRunnerRequest.properties.quarantined.type,
    "boolean",
  );
  assert.equal(
    schemas.RunnerCredentialRevocation.properties.state.const,
    "revoked",
  );
  assert.match(revoke.description, /terminates active streams/);
  assert.match(revoke.description, /Audit identities/);
  assert.match(rotate.description, /feature-gated runner\s+stream/);
  assert.match(
    schemas.RunnerCredential.description,
    /stores only its SHA-256\s+hash/,
  );
  assert.match(
    schemas.RunnerCredential.description,
    /encrypted protocol-delivery\s+envelope/,
  );
  assert.match(schemas.RunnerRegistration.description, /returned exactly once/);
  assert.deepEqual(schemas.RunnerState.enum, [
    "offline",
    "idle",
    "busy",
    "draining",
  ]);
  assert.match(schemas.RunnerState.description, /alpha\.5/);
  assert.match(
    schemas.RunnerCredentialLifecycleState.description,
    /`registering`/,
  );
  assert.match(
    schemas.RunnerCredentialLifecycleState.description,
    /`revoked` is terminal/,
  );
  assert.equal(
    schemas.Runner.properties.credentialLifecycleState.$ref,
    "#/components/schemas/RunnerCredentialLifecycleState",
  );

  const rotateBody =
    document.components.requestBodies[
      rotate.requestBody.$ref.split("/").at(-1)
    ];
  assert.equal(rotateBody.required, false);
  assert.equal(schemas.RotateRunnerCredentialRequest.required, undefined);
  assert.equal(schemas.RunnerCredentialTtlSeconds.default, 900);
  assert.equal(schemas.RunnerCredentialOverlapSeconds.default, 120);
  assert.match(rotate.description, /absent body and `\{\}`/);
  assert.match(rotate.description, /leaves the predecessor unchanged/);
  assert.match(rotate.description, /delivery attempt durably/);
  const rotationCodes = [
    "idempotency_key_conflict",
    "credential_not_replayable",
    "rotation_id_conflict",
    "rotation_pending",
  ];
  assert.deepEqual(rotationCodes, [
    "idempotency_key_conflict",
    "credential_not_replayable",
    "rotation_id_conflict",
    "rotation_pending",
  ]);
  assert.deepEqual(rotate["x-provenance-conflict-codes"], rotationCodes);
  assert.deepEqual(create["x-provenance-conflict-codes"], [
    "idempotency_key_conflict",
    "credential_not_replayable",
  ]);
  const rotationOrder = rotationCodes.map((code) =>
    rotate.description.indexOf(`\`${code}\``),
  );
  assert.ok(rotationOrder.every((index) => index >= 0));
  assert.deepEqual(
    rotationOrder,
    [...rotationOrder].sort((a, b) => a - b),
  );

  const organizationId = "00000000-0000-0000-0000-000000000011";
  const runnerId = "50000000-0000-0000-0000-000000000011";
  const token = "prr_v1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
  const tokenHash =
    "227d5c86d147a519fa4caf435bb5cc85acbc20f709b94af9371122eaa6e6bbf9";
  const publicKey = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
  const signature =
    "gfTLqWihY048vNn-hZvs81xk7pmEdsM2WmCPGimPDrOoU8Gl1YW5BFg5lsh4ZYZiAGlv3XUzoH5oholxRcVDAQ";
  assert.equal(
    Buffer.from(token.slice("prr_v1_".length), "base64url").length,
    32,
  );
  assert.equal(Buffer.from(publicKey, "base64url").length, 32);
  assert.equal(Buffer.from(signature, "base64url").length, 64);
  assert.equal(createHash("sha256").update(token).digest("hex"), tokenHash);
  for (const [name, valid] of [
    ["RunnerRegistrationToken", token],
    ["RunnerConnectionCredential", `prc_v1_${"A".repeat(43)}`],
    ["Ed25519PublicKey", publicKey],
    ["Ed25519Signature", signature],
    ["PublicKeyFingerprint", `sha256:${"a".repeat(64)}`],
  ]) {
    const schema = schemas[name];
    const pattern = new RegExp(schema.pattern);
    assert.equal(pattern.test(valid), true, name);
    assert.equal(pattern.test(`${valid}A`), false, `${name} upper boundary`);
    assert.equal(
      pattern.test(valid.slice(0, -1)),
      false,
      `${name} lower boundary`,
    );
  }
  for (const [name, canonical, alias, prefixLength] of [
    ["RunnerRegistrationToken", token, `${token.slice(0, -1)}9`, 7],
    [
      "RunnerConnectionCredential",
      `prc_v1_${"A".repeat(43)}`,
      `prc_v1_${"A".repeat(42)}B`,
      7,
    ],
    ["Ed25519PublicKey", publicKey, `${publicKey.slice(0, -1)}p`, 0],
    ["Ed25519Signature", signature, `${signature.slice(0, -1)}R`, 0],
  ]) {
    const pattern = new RegExp(schemas[name].pattern);
    assert.equal(pattern.test(alias), false, `${name} rejects pad-bit alias`);
    assert.ok(
      Buffer.from(canonical.slice(prefixLength), "base64url").equals(
        Buffer.from(alias.slice(prefixLength), "base64url"),
      ),
      `${name} adversarial vector must decode to the same bytes`,
    );
    assert.equal(
      Buffer.from(canonical.slice(prefixLength), "base64url").toString(
        "base64url",
      ),
      canonical.slice(prefixLength),
      `${name} round trip`,
    );
  }
  const proofMessage =
    `provenance.runner.registration.v1\n` +
    `organization_id:${organizationId}\n` +
    `runner_id:${runnerId}\n` +
    `registration_token_sha256:${tokenHash}\n` +
    `public_key_base64url:${publicKey}\n`;
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const verifier = createPublicKey({
    format: "der",
    key: Buffer.concat([spkiPrefix, Buffer.from(publicKey, "base64url")]),
    type: "spki",
  });
  assert.equal(
    verify(
      null,
      Buffer.from(proofMessage),
      verifier,
      Buffer.from(signature, "base64url"),
    ),
    true,
  );
  for (const value of [
    organizationId,
    runnerId,
    token,
    tokenHash,
    publicKey,
    signature,
  ]) {
    assert.match(redeem.description, new RegExp(value.replaceAll("-", "\\-")));
  }

  for (const operationId of [
    "createRunnerRegistration",
    "redeemRunnerRegistration",
    "rotateRunnerCredentials",
    "revokeRunnerCredentials",
  ]) {
    assert.match(generatedClient, new RegExp(operationId));
  }
});

test("IFC-011 is deeply additive to the released alpha.5 HTTP surface", () => {
  assert.equal(
    alpha5Compatibility.sourceCommit,
    "5e17ca9299f354b55a5cb82c6c9d06d1382549d9",
  );
  assert.equal(
    compatibilityHash(alpha5Compatibility.modified),
    alpha5Compatibility.modifiedSha256,
  );
  assert.equal(
    compatibilityHash(
      [
        "openapi",
        "info",
        "jsonSchemaDialect",
        "servers",
        "security",
        "tags",
      ].map((name) => [name, document[name]]),
    ),
    alpha5Compatibility.topLevelSha256,
  );

  const operationById = new Map(
    operations.map(({ method, operation: candidate, path }) => [
      candidate.operationId,
      { method, operation: candidate, path },
    ]),
  );
  assert.equal(
    compatibilityHash(
      alpha5Compatibility.operations.names.map((name) => [
        name,
        operationById.get(name),
      ]),
    ),
    alpha5Compatibility.operations.sha256,
  );
  for (const [category, snapshot] of Object.entries(
    alpha5Compatibility.components,
  )) {
    assert.equal(
      compatibilityHash(
        snapshot.names.map((name) => [
          name,
          document.components[category][name],
        ]),
      ),
      snapshot.sha256,
      category,
    );
  }

  assert.deepEqual(
    Object.keys(alpha5Compatibility.modified.operations).sort(),
    ["createRunnerRegistration", "rotateRunnerCredentials"],
  );
  for (const [name, released] of Object.entries(
    alpha5Compatibility.modified.operations,
  )) {
    assertAlpha5OperationCompatible(name, released, operationById.get(name));
  }
  assert.deepEqual(Object.keys(alpha5Compatibility.modified.schemas).sort(), [
    "CreateRunnerRegistrationRequest",
    "Runner",
    "RunnerCredential",
    "RunnerRegistration",
    "RunnerState",
    "UpdateRunnerRequest",
  ]);
  for (const [name, released] of Object.entries(
    alpha5Compatibility.modified.schemas,
  )) {
    assertAlpha5SchemaCompatible(
      name,
      released,
      document.components.schemas[name],
    );
  }

  const schemas = document.components.schemas;
  for (const releasedState of ["offline", "idle", "busy", "draining"]) {
    assert.ok(schemas.RunnerState.enum.includes(releasedState));
  }
  assert.deepEqual(schemas.Runner.required, [
    "id",
    "organizationId",
    "name",
    "state",
    "trust",
    "createdAt",
    "updatedAt",
  ]);
  for (const property of [
    "id",
    "organizationId",
    "name",
    "state",
    "trust",
    "createdAt",
    "updatedAt",
  ]) {
    assert.ok(schemas.Runner.properties[property], property);
  }
  assert.deepEqual(schemas.CreateRunnerRegistrationRequest.required, ["name"]);
  assert.equal(
    schemas.CreateRunnerRegistrationRequest.properties.name.maxLength,
    128,
  );
  for (const property of ["runnerId", "registrationToken", "expiresAt"]) {
    assert.ok(schemas.RunnerRegistration.required.includes(property), property);
  }
  assert.equal(schemas.UpdateRunnerRequest.properties.name.maxLength, 128);
  assert.equal(schemas.UpdateRunnerRequest.properties.draining.type, "boolean");
  for (const property of ["credential", "expiresAt"]) {
    assert.ok(schemas.RunnerCredential.required.includes(property), property);
  }
  assert.equal(
    createPath(operation("createRunnerRegistration")),
    "/v1/organizations/{organizationId}/runners",
  );
  assert.equal(
    createPath(operation("rotateRunnerCredentials")),
    "/v1/runners/{runnerId}/credentials/rotate",
  );
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
      "#/components/responses/PrivateProblem",
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
  assert.match(
    liveLogs.description,
    /For JSON,\s+any `Last-Event-ID`.*last_event_id_not_applicable/is,
  );
  assert.match(
    liveLogs.description,
    /For SSE, `limit`.*limit_not_applicable/is,
  );
  assert.match(liveLogs.description, /differing query `cursor`.*conflict/is);
  assert.match(liveLogs.description, /equal values are treated as one cursor/i);
  assert.match(liveLogs.description, /last_event_id_not_applicable/);
  assert.match(liveLogs.description, /invalid_log_cursor/);
  assert.match(liveLogs.description, /different tenant.*HTTP 404/is);
  assert.match(liveLogs.description, /expired cursor.*HTTP 410/is);
  assert.match(liveLogs.description, /log_cursor_expired/);
  assert.match(
    liveLogs.description,
    /current lease\s+attempt in offered, accepted, or active state, otherwise its most\s+recently created lease attempt/is,
  );
  assert.match(liveLogs.description, /earliest retained\s+event/i);
  assert.match(
    liveLogs.description,
    /cursor for any attempt that belongs\s+to the execution selects that attempt/is,
  );
  assert.match(
    liveLogs.description,
    /`log-gap` event is the\s+first data event/i,
  );
  assert.match(liveLogs.description, /ascending opaque relay order/i);
  assert.match(
    liveLogs.description,
    /`limit` counts\s+every `ExecutionLogEvent`/is,
  );
  assert.match(
    liveLogs.description,
    /empty response\s+echoes a supplied cursor byte-for-byte without advancing/is,
  );
  assert.match(liveLogs.description, /empty\s+terminal pages/i);
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
    /reconnect independently reauthorizes/,
  );
  assert.equal(
    liveLogs.responses["400"].$ref,
    "#/components/responses/LogRequestInvalid",
  );
  assert.equal(
    liveLogs.responses["410"].$ref,
    "#/components/responses/LogCursorExpired",
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

test("IFC-010 private responses are bounded, non-cacheable, and challenge Bearer clients", () => {
  const schemas = document.components.schemas;
  const responses = document.components.responses;
  const privateNoStore = "#/components/headers/PrivateNoStore";

  for (const operationId of privateLogOperationIds) {
    const candidate = operation(operationId);
    for (const [status, responseReference] of Object.entries(
      candidate.responses,
    )) {
      const response = responseReference.$ref
        ? resolveResponse(responseReference)
        : responseReference;
      assert.equal(
        response.headers?.["Cache-Control"]?.$ref,
        privateNoStore,
        `${operationId} ${status}`,
      );
    }
  }

  assert.equal(
    responses.AuthenticationRequired.headers["WWW-Authenticate"].$ref,
    "#/components/headers/BearerChallenge",
  );
  assert.equal(
    document.components.headers.BearerChallenge.schema.const,
    'Bearer realm="provenance"',
  );
  assert.equal(
    document.components.headers.BearerChallenge.schema.maxLength,
    25,
  );
  assert.deepEqual(schemas.PrivateProblemDetails.required, [
    "type",
    "title",
    "status",
    "code",
  ]);
  assert.equal(schemas.PrivateProblemDetails.additionalProperties, false);
  assert.equal(schemas.PrivateProblemDetails.properties.detail.maxLength, 4096);
  assert.equal(schemas.PrivateProblemDetails.properties.errors.maxItems, 32);
  assert.equal(
    schemas.PrivateProblemDetails["x-provenance-max-json-bytes"],
    16384,
  );
  assert.deepEqual(
    schemas.LogRequestInvalidProblem.allOf[1].properties.code.enum,
    [
      "last_event_id_not_applicable",
      "limit_not_applicable",
      "log_cursor_conflict",
      "invalid_log_cursor",
    ],
  );
  assert.equal(
    schemas.LogCursorExpiredProblem.allOf[1].properties.code.const,
    "log_cursor_expired",
  );

  assert.match(
    generatedClient,
    /"WWW-Authenticate": components\["headers"\]\["BearerChallenge"\]/,
  );
  assert.match(
    generatedClient,
    /default: components\["responses"\]\["PrivateProblem"\]/,
  );
  assert.match(
    generatedClient,
    /410: components\["responses"\]\["LogCursorExpired"\]/,
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
    "PrivateProblemDetails",
    "PrivateProblemFieldError",
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

function resolveResponse(response) {
  const name = response.$ref.split("/").at(-1);
  return document.components.responses[name];
}

function compareInventory(left, right) {
  return (
    left.path.localeCompare(right.path) ||
    left.method.localeCompare(right.method) ||
    left.operationId.localeCompare(right.operationId)
  );
}

function compatibilityHash(value) {
  return createHash("sha256")
    .update(JSON.stringify(canonicalize(value)))
    .digest("hex");
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

function createPath(candidate) {
  return operations.find(({ operation: current }) => current === candidate)
    .path;
}

function assertAlpha5OperationCompatible(name, released, current) {
  assert.ok(current, name);
  assert.equal(current.path, released.path, name);
  assert.equal(current.method, released.method, name);
  assert.equal(current.operation.operationId, released.operation.operationId);
  assert.equal(current.operation.summary, released.operation.summary);
  assert.deepEqual(current.operation.tags, released.operation.tags);

  for (const releasedParameter of released.operation.parameters ?? []) {
    const releasedName = releasedParameter.$ref.split("/").at(-1);
    const releasedShape = document.components.parameters[releasedName];
    const currentShape = current.operation.parameters
      .map(resolveParameter)
      .find((candidate) => candidate.name === releasedShape.name);
    assert.ok(currentShape, `${name}.${releasedShape.name}`);
    for (const property of ["name", "in", "required", "schema"]) {
      assert.deepEqual(
        currentShape[property],
        releasedShape[property],
        `${name}.${releasedShape.name}.${property}`,
      );
    }
  }

  if (released.operation.requestBody) {
    assert.deepEqual(
      current.operation.requestBody,
      released.operation.requestBody,
      `${name}.requestBody`,
    );
  } else if (current.operation.requestBody) {
    const requestBodyName = current.operation.requestBody.$ref
      .split("/")
      .at(-1);
    assert.notEqual(
      document.components.requestBodies[requestBodyName].required,
      true,
      `${name}.requestBody must remain optional`,
    );
  }

  for (const [status, releasedResponse] of Object.entries(
    released.operation.responses,
  )) {
    const currentResponse = current.operation.responses[status];
    assert.ok(currentResponse, `${name}.${status}`);
    if (!releasedResponse.$ref) {
      assert.equal(currentResponse.description, releasedResponse.description);
      assert.deepEqual(
        currentResponse.content,
        releasedResponse.content,
        `${name}.${status}.content`,
      );
      continue;
    }
    const releasedResolved = resolveResponse(releasedResponse);
    const currentResolved = resolveResponse(currentResponse);
    assert.equal(
      problemBaseSchema(currentResolved),
      problemBaseSchema(releasedResolved),
      `${name}.${status}.problem base`,
    );
  }
}

function assertAlpha5SchemaCompatible(name, released, current) {
  assert.ok(current, name);
  assert.equal(current.type, released.type, `${name}.type`);
  assert.equal(
    current.additionalProperties,
    released.additionalProperties,
    `${name}.additionalProperties`,
  );
  if (name === "RunnerState") {
    assert.deepEqual(current.enum, released.enum, `${name}.enum`);
    return;
  }

  for (const required of released.required ?? []) {
    assert.ok(current.required?.includes(required), `${name}.${required}`);
  }
  if (["Runner", "CreateRunnerRegistrationRequest"].includes(name)) {
    assert.deepEqual(current.required, released.required, `${name}.required`);
  }
  if (name === "UpdateRunnerRequest") {
    assert.equal(current.required, undefined, `${name}.required`);
  }

  for (const [property, releasedProperty] of Object.entries(
    released.properties ?? {},
  )) {
    const currentProperty = current.properties[property];
    assert.ok(currentProperty, `${name}.${property}`);
    if (releasedProperty.$ref) {
      assert.equal(
        currentProperty.$ref,
        releasedProperty.$ref,
        `${name}.${property}`,
      );
      continue;
    }
    const resolvedCurrent = currentProperty.$ref
      ? document.components.schemas[currentProperty.$ref.split("/").at(-1)]
      : currentProperty;
    for (const key of ["type", "format", "const", "maxLength"]) {
      if (releasedProperty[key] !== undefined) {
        assert.deepEqual(
          resolvedCurrent[key],
          releasedProperty[key],
          `${name}.${property}.${key}`,
        );
      }
    }
    if (releasedProperty.minLength !== undefined) {
      assert.ok(
        resolvedCurrent.minLength >= releasedProperty.minLength,
        `${name}.${property}.minLength`,
      );
    }
  }
}

function problemBaseSchema(response) {
  const schema = response.content["application/problem+json"].schema;
  if (schema.$ref) {
    const referenced =
      document.components.schemas[schema.$ref.split("/").at(-1)];
    return referenced?.allOf?.[0]?.$ref ?? schema.$ref;
  }
  return schema.allOf?.[0]?.$ref;
}
