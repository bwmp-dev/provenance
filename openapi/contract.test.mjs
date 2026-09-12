import "./hosted-runner-updates.test.mjs";
import "./hosted-catalog-reconciliation.test.mjs";
import "./automatic-paper-runtime.test.mjs";
import {
  beforeAlphaAdmission,
  beforeFailureClassification,
} from "./alpha-compat.mjs";
import "./alpha-administration.test.mjs";
import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import test from "node:test";
import "./device-login.test.mjs";
import "./actions-grant.test.mjs";
import "./publication-result.test.mjs";
import "./candidate-matrix.test.mjs";
import "./candidate-inputs.test.mjs";

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

test("attestation HTTP endpoints preserve explicit v1 and v2 selection", async () => {
  const response =
    document.paths["/v1/verifications/{verificationId}/attestation"].get
      .responses["200"];
  assert.deepEqual(response.content["application/json"].schema, {
    $ref: "../schemas/attestation/v1/schema.json",
  });
  assert.deepEqual(
    document.paths["/v1/verifications/{verificationId}/attestations/v2"].get
      .responses["200"].content["application/json"].schema,
    {
      $ref: "../schemas/attestation/v2/schema.json",
    },
  );
  for (const version of [1, 2]) {
    const schema = JSON.parse(
      await readFile(
        new URL(`../schemas/attestation/v${version}/schema.json`, root),
        "utf8",
      ),
    );
    assert.equal(
      schema.properties.mediaType.const,
      `application/vnd.provenance.attestation.v${version}+json`,
    );
    assert.equal(
      schema.$defs.statement.properties.apiVersion.const,
      `provenance.dev/attestation/v${version}`,
    );
    assert.ok(
      generatedClient.includes(
        `application/vnd.provenance.attestation.v${version}+json`,
      ),
    );
    assert.ok(
      generatedClient.includes(`provenance.dev/attestation/v${version}`),
    );
  }
});
const hostedUpdateOperations = new Set([
  "getHostedCatalogs",
  "changeHostedCatalog",
  "pollHostedCatalog",
  "downloadHostedCatalogAsset",
  "getHostedRunnerUpdates",
  "listHostedRunners",
  "changeHostedRunner",
  "getHostedRunnerInstallProfile",
  "downloadHostedRunnerRelease",
  "changeHostedRunnerUpdate",
  "pollHostedRunnerUpdate",
]);
const mutations = new Set(["delete", "patch", "post", "put"]);
const deviceOperations = new Set([
  "createDeviceAuthorization",
  "decideDeviceAuthorization",
  "exchangeDeviceAuthorization",
]);
const deviceInitiationBaseline = JSON.parse(
  await readFile(new URL("device-initiation-baseline.json", root), "utf8"),
);

const githubAuthOperations = new Set([
  "createGitHubAuthorization",
  "completeGitHubAuthorization",
]);
const githubConnectionOperations = new Set([
  "createGitHubDiscoveryAuthorization",
  "completeGitHubDiscoveryAuthorization",
  "createGitHubConnectionAuthorization",
  "completeGitHubConnectionAuthorization",
  "listGitHubDiscoveryRepositories",
]);
const verificationRequire = createRequire(
  new URL("../packages/verification/package.json", import.meta.url),
);
const Ajv2020 = verificationRequire("ajv/dist/2020.js");
const addFormats = verificationRequire("ajv-formats");

test("IFC018 leaves every released alpha14 path and component unchanged", async () => {
  const baseline = JSON.parse(
    await readFile(new URL("alpha14-compat.hashes.json", root), "utf8"),
  );
  const hash = (value) =>
    createHash("sha256").update(JSON.stringify(value)).digest("hex");
  assert.equal(baseline.source, "d293559778d1bf2e346ddcd63f1089cddb0dbac5");
  for (const [path, digest] of Object.entries(baseline.paths))
    assert.equal(
      hash(
        path === "/v1/auth/device-authorizations"
          ? deviceInitiationBaseline
          : beforeAlphaAdmission(path, document.paths[path]),
      ),
      digest,
      path,
    );
  for (const [kind, entries] of Object.entries(baseline.components)) {
    for (const [name, digest] of Object.entries(entries))
      assert.equal(
        hash(
          beforeFailureClassification(
            kind,
            name,
            document.components[kind][name],
          ),
        ),
        digest,
        `${kind}/${name}`,
      );
  }
});

test("IFC018 strict selections, safe provider IDs and private snapshot pages", () => {
  const ajv = new Ajv2020({ strict: false });
  addFormats(ajv);
  ajv.addSchema({
    $id: "connection-contract",
    components: document.components,
  });
  const valid = (name, value) =>
    ajv.validate(
      { $ref: `connection-contract#/components/schemas/${name}` },
      value,
    );
  const uuid = "11111111-1111-4111-8111-111111111111";
  const opaque = Buffer.alloc(32).toString("base64url");
  const discovery = {
    organizationId: uuid,
    projectId: uuid,
    redirectUri: "https://bff.example/callback",
    codeChallenge: opaque,
    codeChallengeMethod: "S256",
  };
  const connection = {
    ...discovery,
    githubInstallationId: 1,
    githubRepositoryId: 9007199254740991,
    repositoryFullName: "owner/repo",
  };
  for (const [schema, input] of [
    ["CreateGitHubDiscoveryAuthorizationRequest", discovery],
    ["CreateGitHubConnectionAuthorizationRequest", connection],
  ]) {
    assert.equal(valid(schema, input), true, JSON.stringify(ajv.errors));
    for (const key of Object.keys(input)) {
      const incomplete = { ...input };
      delete incomplete[key];
      assert.equal(valid(schema, incomplete), false, key);
    }
    for (const extra of [
      "token",
      "installationId",
      "authority",
      "scope",
      "clientId",
      "returnUrl",
    ])
      assert.equal(
        valid(schema, { ...input, [extra]: "forbidden" }),
        false,
        extra,
      );
    for (const challenge of [opaque + "=", opaque.slice(0, -1) + "B"])
      assert.equal(
        valid(schema, { ...input, codeChallenge: challenge }),
        false,
      );
    assert.equal(
      valid(schema, { ...input, codeChallengeMethod: "plain" }),
      false,
    );
    assert.equal(
      valid(schema, { ...input, redirectUri: "http://bff.example/callback" }),
      false,
    );
  }
  for (const id of [0, -1, 1.5, 9007199254740992, "1", uuid])
    assert.equal(valid("GitHubProviderId", id), false);
  const row = {
    githubInstallationId: 1,
    githubAccountId: 2,
    githubRepositoryId: 3,
    accountType: "Organization",
    accountLogin: "owner",
    repositoryName: "repo",
    repositoryFullName: "owner/repo",
    isPrivate: true,
  };
  assert.equal(valid("GitHubDiscoveryRepository", row), true);
  assert.equal(
    valid("GitHubDiscoveryRepository", { ...row, accountType: "Enterprise" }),
    false,
  );
  assert.equal(
    valid("GitHubDiscoveryRepository", { ...row, isPrivate: "true" }),
    false,
  );
  assert.equal(
    valid("GitHubDiscoveryRepository", { ...row, accessToken: "secret" }),
    false,
  );
  for (const page of [
    { hasMore: true, nextCursor: "opaque" },
    { hasMore: false },
    { hasMore: false, nextCursor: null },
  ])
    assert.equal(
      valid("GitHubDiscoveryRepositoryPage", { items: [row], page }),
      true,
      JSON.stringify(ajv.errors),
    );
  for (const page of [
    { hasMore: true },
    { hasMore: true, nextCursor: null },
    { hasMore: false, nextCursor: "opaque" },
    { hasMore: true, nextCursor: "" },
  ])
    assert.equal(
      valid("GitHubDiscoveryRepositoryPage", { items: [row], page }),
      false,
    );
  assert.equal(
    valid("GitHubDiscoveryRepositoryPage", {
      items: Array.from({ length: 101 }, (_, i) => ({
        ...row,
        githubRepositoryId: i + 1,
      })),
      page: { hasMore: false },
    }),
    false,
  );
  assert.equal(
    valid("GitHubDiscoverySnapshot", {
      snapshotId: opaque,
      expiresAt: "2026-09-06T23:00:00Z",
    }),
    true,
  );
  assert.equal(
    valid("GitHubDiscoverySnapshot", {
      snapshotId: uuid,
      expiresAt: "2026-09-06T23:00:00Z",
    }),
    false,
  );
});

test("IFC018 session-only flows retain bounded replay, expiry and no-store failures", () => {
  const ajv = new Ajv2020({ strict: false });
  addFormats(ajv);
  ajv.addSchema({ $id: "connection-errors", components: document.components });
  for (const id of githubConnectionOperations) {
    const op = operation(id);
    assert.deepEqual(op.security, [{ SessionCookie: [] }]);
    assert.match(op.description, /integrations:manage/);
    assert.match(op.description, /session/);
    for (const response of Object.values(op.responses)) {
      const resolved = response.$ref
        ? document.components.responses[response.$ref.split("/").at(-1)]
        : response;
      assert.equal(
        resolved.headers["Cache-Control"].$ref,
        "#/components/headers/GitHubAuthNoStore",
      );
      const schema = resolved.content?.["application/problem+json"]?.schema;
      if (!schema) continue;
      const status = schema.properties.status.const ?? 500;
      const code =
        schema.properties.code.const ?? schema.properties.code.enum[0];
      const validate = ajv.compile({
        ...schema,
        components: document.components,
      });
      const problem = {
        type: "about:blank",
        title: "GitHub connection authorization failed",
        status,
        code,
      };
      assert.equal(validate(problem), true, JSON.stringify(validate.errors));
      for (const key of [
        "detail",
        "instance",
        "token",
        "codeVerifier",
        "providerError",
      ])
        assert.equal(validate({ ...problem, [key]: "private" }), false);
      assert.equal(
        validate({ ...problem, code: "credential_not_replayable" }),
        false,
      );
    }
    assert.ok(generatedClient.includes(id));
  }
  const completion =
    document.components.parameters.GitHubConnectionCompletionIdempotencyKey;
  assert.match(completion.description, /Successful nonsecret results replay/);
  assert.match(
    completion.description,
    /After retention expiry return authorization_expired/,
  );
  const discover = operation("completeGitHubDiscoveryAuthorization");
  assert.match(
    discover.description,
    /never a partial snapshot or another exchange/,
  );
  assert.match(discover.description, /purged without erasing audit/);
  const connect = operation("completeGitHubConnectionAuthorization");
  assert.match(
    connect.description,
    /Discovery is optional and never authority/,
  );
  assert.match(
    connect.description,
    /without another exchange, binding or audit/,
  );
  assert.equal(
    connect.responses["200"].content["application/json"].schema.$ref,
    "#/components/schemas/GitHubConnection",
  );
  const list = operation("listGitHubDiscoveryRepositories");
  assert.deepEqual(list.parameters.slice(1), [
    { $ref: "#/components/parameters/Cursor" },
    { $ref: "#/components/parameters/PageSize" },
  ]);
  assert.match(list.description, /before revealing expiry/);
});

test("IFC017 strict auth shapes and canonical PKCE encodings", () => {
  const ajv = new Ajv2020({ strict: false });
  addFormats(ajv);
  ajv.addSchema({ $id: "auth-contract", components: document.components });
  const validate = (name, value) =>
    ajv.validate({ $ref: `auth-contract#/components/schemas/${name}` }, value);
  const opaque = Buffer.alloc(32, 255).toString("base64url");
  assert.equal(validate("GitHubAuthorizationOpaque32", opaque), true);
  for (const bad of [
    opaque + "=",
    opaque.slice(1),
    opaque.slice(0, -1) + "9",
    opaque + "\n",
  ]) {
    assert.equal(validate("GitHubAuthorizationOpaque32", bad), false, bad);
  }
  // Exhaust every last sextet: exactly the zero-pad-bit encodings are allowed.
  for (const [index, char] of [
    ..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
  ].entries()) {
    assert.equal(
      validate("GitHubAuthorizationOpaque32", "A".repeat(42) + char),
      index % 4 === 0,
    );
  }
  const start = {
    redirectUri: "https://bff.example/callback",
    codeChallenge: opaque,
    codeChallengeMethod: "S256",
  };
  const finish = {
    state: opaque,
    code: "opaque-code",
    codeVerifier: "a".repeat(43),
  };
  for (const [name, value] of [
    ["CreateGitHubAuthorizationRequest", start],
    ["CompleteGitHubAuthorizationRequest", finish],
    [
      "GitHubAuthorization",
      {
        authorizationId: opaque,
        state: opaque,
        providerUrl:
          "https://github.com/login/oauth/authorize?client_id=configured&state=example",
        expiresAt: "2026-09-06T12:00:00Z",
      },
    ],
    [
      "GitHubAuthorizationCompletion",
      { exchangeToken: "platform-only", expiresAt: "2026-09-06T12:00:00Z" },
    ],
  ]) {
    assert.equal(validate(name, value), true, name);
    assert.equal(
      validate(name, { ...value, access_token: "forbidden" }),
      false,
    );
    for (const field of Object.keys(value)) {
      const missing = { ...value };
      delete missing[field];
      assert.equal(validate(name, missing), false, field);
    }
  }
  for (const redirectUri of [
    "http://bff.example/callback",
    "https://user@bff.example/callback",
    "https://bff.example/callback#fragment",
    "https://bff.example/ space",
    "https://bff.example/" + "a".repeat(2048),
  ]) {
    assert.equal(
      validate("CreateGitHubAuthorizationRequest", { ...start, redirectUri }),
      false,
    );
  }
  for (const codeChallengeMethod of ["plain", "s256", ""]) {
    assert.equal(
      validate("CreateGitHubAuthorizationRequest", {
        ...start,
        codeChallengeMethod,
      }),
      false,
    );
  }
  for (const codeVerifier of [
    "a".repeat(42),
    "a".repeat(129),
    "a".repeat(42) + "+",
    "a".repeat(43) + "\n",
  ]) {
    assert.equal(
      validate("CompleteGitHubAuthorizationRequest", {
        ...finish,
        codeVerifier,
      }),
      false,
    );
  }
  assert.equal(
    validate("CompleteGitHubAuthorizationRequest", {
      ...finish,
      codeVerifier: "a".repeat(128),
      code: "x".repeat(4096),
    }),
    true,
  );
  for (const code of [
    "",
    "x".repeat(4097),
    "x\n",
    "x\u0000",
    "x\u007f",
    "x\u0085",
  ]) {
    assert.equal(
      validate("CompleteGitHubAuthorizationRequest", { ...finish, code }),
      false,
    );
  }
});

test("IFC017 preserves server-only no-store and fail-closed replay semantics", () => {
  for (const id of githubAuthOperations) {
    const op = operation(id);
    assert.deepEqual(op.security, []);
    assert.equal(op["x-provenance-interface"], "IFC-017");
    for (const response of Object.values(op.responses)) {
      const resolved = response.$ref
        ? document.components.responses[response.$ref.split("/").at(-1)]
        : response;
      const header = resolved.headers["Cache-Control"];
      const value = document.components.headers[header.$ref.split("/").at(-1)];
      assert.equal(value.required, true);
      assert.equal(value.schema.const, "no-store");
    }
    assert.ok(generatedClient.includes(id));
  }
  const complete = operation("completeGitHubAuthorization");
  const parameter = resolveParameter(complete.parameters[0]);
  assert.match(parameter.description, /retains only a hash/);
  for (const code of [
    "credential_not_replayable",
    "authorization_completion_uncertain",
    "authorization_in_progress",
    "idempotency_key_conflict",
  ]) {
    assert.match(parameter.description, new RegExp(code));
  }
  assert.match(
    complete.description,
    /lease expiry never authorizes retrying the code/,
  );
  assert.match(
    complete.description,
    /before revealing state-specific outcomes/,
  );
  assert.match(complete.description, /unchanged POST \/v1\/auth\/sessions/);
  assert.equal(
    document.components.schemas.CompleteGitHubAuthorizationRequest.properties
      .code.writeOnly,
    true,
  );
  assert.equal(
    document.components.schemas.CompleteGitHubAuthorizationRequest.properties
      .codeVerifier.writeOnly,
    true,
  );
  assert.equal(
    document.components.schemas.CompleteGitHubAuthorizationRequest.properties
      .state.writeOnly,
    true,
  );
  const startKey = resolveParameter(
    operation("createGitHubAuthorization").parameters[0],
  );
  assert.match(startKey.description, /without extension/);
});

test("IFC017 problems are closed and cannot carry provider or request secrets", () => {
  const ajv = new Ajv2020({ strict: false });
  addFormats(ajv);
  ajv.addSchema({ $id: "auth-problems", components: document.components });
  for (const id of githubAuthOperations) {
    const op = operation(id);
    for (const [status, response] of Object.entries(op.responses)) {
      if (!response.$ref) continue;
      const name = response.$ref.split("/").at(-1);
      const schema =
        document.components.responses[name].content["application/problem+json"]
          .schema;
      const constraints = schema.allOf[1].properties;
      const sample = {
        type: "about:blank",
        title: constraints.title.const,
        status: status === "default" ? 500 : Number(status),
        code: constraints.code.const ?? constraints.code.enum[0],
      };
      const validate = ajv.compile({
        $ref: `auth-problems#/components/responses/${name}/content/application~1problem+json/schema`,
      });
      assert.equal(validate(sample), true, name);
      for (const key of [
        "detail",
        "state",
        "codeVerifier",
        "access_token",
        "providerResponse",
        "instance",
      ]) {
        assert.equal(validate({ ...sample, [key]: "forbidden" }), false, key);
      }
      assert.equal(
        validate({ ...sample, title: "raw provider response" }),
        false,
      );
      assert.equal(
        validate({ ...sample, code: "raw provider response" }),
        false,
      );
    }
  }
});

test("IFC016 discovery is anonymous, bounded, public-only and no-store", async () => {
  const route = document.paths["/.well-known/provenance-keys.json"].get;
  assert.equal(route.operationId, "getProvenanceKeys");
  assert.deepEqual(route.security, []);
  assert.equal(
    route.responses["200"].content["application/json"].schema.$ref,
    "../schemas/key-discovery/v1/schema.json",
  );
  for (const code of ["200", "503"]) {
    assert.equal(
      route.responses[code].headers["Cache-Control"].schema.const,
      "no-store",
    );
    assert.equal(route.responses[code].headers["Cache-Control"].required, true);
  }
  const failure =
    route.responses["503"].content["application/problem+json"].schema;
  assert.equal(failure.additionalProperties, false);
  assert.deepEqual(
    Object.fromEntries(
      Object.entries(failure.properties).map(([key, value]) => [
        key,
        value.const,
      ]),
    ),
    {
      type: "about:blank",
      title: "Public keys unavailable",
      status: 503,
      code: "public_keys_unavailable",
    },
  );
  const schema = JSON.parse(
    await readFile(
      new URL("../schemas/key-discovery/v1/schema.json", root),
      "utf8",
    ),
  );
  assert.equal(schema.properties.keys.minItems, 1);
  assert.equal(schema.properties.keys.maxItems, 1024);
  assert.equal(schema.additionalProperties, false);
  assert.equal(schema.properties.keys.items.additionalProperties, false);
  assert.deepEqual(schema.properties.keys.items.required, [
    "keyId",
    "algorithm",
    "publicKey",
    "status",
  ]);
  assert.ok(generatedClient.includes('"/.well-known/provenance-keys.json"'));
  assert.ok(generatedClient.includes("getProvenanceKeys"));
});
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
  assert.ok(
    actual.every(
      ({ path, method, operationId }) =>
        path.startsWith("/v1/") ||
        (path === "/.well-known/provenance-keys.json" &&
          method === "get" &&
          operationId === "getProvenanceKeys"),
    ),
  );
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
    if (hostedUpdateOperations.has(operation.operationId)) {
      assert.equal(
        operation.responses.default?.$ref,
        [
          "pollHostedRunnerUpdate",
          "downloadHostedRunnerRelease",
          "pollHostedCatalog",
          "downloadHostedCatalogAsset",
        ].includes(operation.operationId)
          ? "#/components/responses/HostedUpdaterProblem503"
          : "#/components/responses/HostedProblem503",
      );
      continue;
    }
    if (
      deviceOperations.has(operation.operationId) ||
      operation.operationId === "createGitHubActionsGrant" ||
      operation.operationId === "getReleaseCandidatePublicationResult"
    ) {
      assert.equal(
        operation.responses.default,
        undefined,
        "device statuses are explicitly closed and separately tested",
      );
      continue;
    }
    assert.equal(
      operation.responses.default?.$ref,
      operation.operationId.includes("Alpha")
        ? "#/components/responses/AlphaProblem503"
        : privateLogOperationIds.has(operation.operationId) ||
            [
              "listReleaseCandidateMatrix",
              "getReleaseCandidateInputs",
            ].includes(operation.operationId)
          ? "#/components/responses/PrivateProblem"
          : githubAuthOperations.has(operation.operationId)
            ? "#/components/responses/GitHubAuthProblem"
            : githubConnectionOperations.has(operation.operationId)
              ? "#/components/responses/GitHubConnectionProblem"
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
    if (hostedUpdateOperations.has(operation.operationId)) {
      const key = operation.parameters
        ?.map(resolveParameter)
        .find((p) => p.name === "Idempotency-Key");
      assert.equal(
        Boolean(key?.required),
        [
          "changeHostedRunnerUpdate",
          "changeHostedRunner",
          "changeHostedCatalog",
        ].includes(operation.operationId),
      );
      assert.ok(operation.responses["409"]);
      continue; // Node polling uses durable operation identity; hosted-runner-updates.test.mjs pins the normative rules, and platform lifecycle integration tests verify replay.
    }
    if (operation.operationId === "exchangeDeviceAuthorization") {
      assert.equal(
        operation.parameters,
        undefined,
        "polling is bound by device secret, not an idempotency header",
      );
      assert.equal(
        operation.responses["409"].$ref,
        "#/components/responses/DeviceLogin409",
      );
      continue;
    }
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
    if (
      deviceOperations.has(operation.operationId) ||
      operation.operationId === "createGitHubActionsGrant" ||
      operation.operationId.includes("Alpha")
    ) {
      assert.equal(parameter.required, true);
      assert.equal(
        (conflict.content["application/problem+json"].schema.$ref
          ? document.components.schemas[
              conflict.content["application/problem+json"].schema.$ref
                .split("/")
                .at(-1)
            ]
          : conflict.content["application/problem+json"].schema
        ).additionalProperties,
        false,
      );
      continue;
    }
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

test("IFC-013 exposes a bounded deterministic project candidate list", () => {
  const list = operation("listReleaseCandidates");
  const schemas = document.components.schemas;

  assert.equal(list["x-provenance-interface"], "IFC-013");
  assert.match(list.description, /IFC-013/);
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
    /descending keyset order\s+by `\(createdAt, id\)`/i,
  );
  assert.match(
    list.description,
    /`createdAt` primary key compares RFC 3339\s+instants after normalization to UTC/i,
  );
  assert.match(
    list.description,
    /equal\s+instants use canonical lowercase UUID text for the `id` tie-break/i,
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
    /differently scoped cursor.*receives HTTP 400/is,
  );
  assert.match(list.description, /`limit` outside 1 through\s+100.*HTTP 400/is);

  assert.deepEqual(Object.keys(list.responses).sort(), [
    "200",
    "400",
    "401",
    "403",
    "404",
    "500",
    "default",
  ]);
  assert.equal(list.responses["422"], undefined);
  for (const status of ["400", "401", "403", "404", "500"]) {
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
    "HostedRunnerUpdater",
    "RunnerRegistrationToken",
    "SessionCookie",
  ]);
  assert.deepEqual(document.security, [
    { BearerAuth: [] },
    { SessionCookie: [] },
  ]);
  assert.deepEqual(
    operation("createProject").security,
    [{ BearerAuth: [] }, { SessionCookie: [] }],
    "project creation accepts tenant/capability-authorized tokens or sessions",
  );

  for (const { operation: listOperation } of operations.filter(
    ({ operation: candidate }) =>
      candidate.operationId.startsWith("list") &&
      !["listHostedRunners", "listPaperVersions", "listPaperBuilds"].includes(
        candidate.operationId,
      ),
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
          (property.anyOf ?? [property])
            .filter((value) => value.type !== "null")
            .every((value) =>
              [
                "#/components/schemas/Timestamp",
                "#/components/schemas/BoundedTimestamp",
                "#/components/schemas/LogTimestamp",
              ].includes(value.$ref),
            ),
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
        name === "createDeviceAuthorization"
          ? {
              ...operationById.get(name),
              operation: deviceInitiationBaseline.post,
            }
          : name === "listReleaseCandidateExecutions"
            ? {
                ...operationById.get(name),
                operation: beforeAlphaAdmission(operationById.get(name).path, {
                  get: operationById.get(name).operation,
                }).get,
              }
            : name === "createSession" || name === "createProject"
              ? {
                  ...operationById.get(name),
                  operation: beforeAlphaAdmission(
                    operationById.get(name).path,
                    {
                      post: operationById.get(name).operation,
                    },
                  ).post,
                }
              : operationById.get(name),
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
          beforeFailureClassification(
            category,
            name,
            document.components[category][name],
          ),
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

test("IFC025 preserves legacy descriptors and bounds opt-in classification", () => {
  const ajv = new Ajv2020({ strict: false });
  addFormats(ajv);
  ajv.addSchema({
    $id: "failure-classification",
    components: document.components,
  });
  const validate = ajv.compile({
    $ref: "failure-classification#/components/schemas/ExecutionLogDescriptor",
  });
  const legacy = {
    candidateId: "10000000-0000-4000-8000-000000000001",
    matrixEntryId: "20000000-0000-4000-8000-000000000001",
    executionId: "30000000-0000-4000-8000-000000000001",
    attemptId: "40000000-0000-4000-8000-000000000001",
    attemptNumber: 1,
    state: "failed",
    liveState: "terminal",
    completeLog: { state: "pending", retryAfterSeconds: 5 },
    createdAt: "2026-09-12T00:00:00Z",
    updatedAt: "2026-09-12T00:00:01Z",
  };
  assert.equal(validate(legacy), true, JSON.stringify(validate.errors));
  for (const failureCategory of ["plugin", "infrastructure", "policy", null]) {
    assert.equal(validate({ ...legacy, failureCategory }), true);
  }
  for (const failureCategory of [
    "",
    "unknown",
    "succeeded",
    1,
    {},
    ["plugin"],
  ]) {
    assert.equal(validate({ ...legacy, failureCategory }), false);
  }
  for (const key of ["failureSummary", "failureCode", "details", "secret"]) {
    assert.equal(
      validate({ ...legacy, failureCategory: "plugin", [key]: "private" }),
      false,
    );
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
      "#/components/responses/PrivateProblem",
    );
  }

  assert.match(executionList.description, /same HTTP 404 response/i);
  assert.deepEqual(
    executionList.parameters.map(resolveParameter).map(({ name }) => name),
    ["cursor", "limit", "includeFailureClassification"],
  );
  const flag = executionList.parameters
    .map(resolveParameter)
    .find(({ name }) => name === "includeFailureClassification");
  assert.equal(flag.required, false);
  assert.deepEqual(flag.schema, { type: "boolean", default: false });
  assert.match(flag.description, /Absent\/false preserves the legacy/);
  assert.equal(
    executionList.responses["200"].content["application/json"].schema.$ref,
    "#/components/schemas/ExecutionLogDescriptorPage",
  );

  const descriptor = document.components.schemas.ExecutionLogDescriptor;
  assert.equal(descriptor.additionalProperties, false);
  assert.deepEqual(descriptor.properties.failureCategory.enum, [
    "plugin",
    "infrastructure",
    "policy",
    null,
  ]);
  assert.equal(descriptor.required.includes("failureCategory"), false);
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

test("hosted fleet administration is session scoped and never accepts node secrets", () => {
  const registration = document.paths["/v1/admin/hosted-runners"];
  assert.deepEqual(registration.post.security, [{ SessionCookie: [] }]);
  assert.equal(registration.post.operationId, "changeHostedRunner");
  const request = document.components.schemas.HostedRunnerRequest;
  assert.deepEqual(request.properties.action.enum, [
    "create",
    "rotate",
    "drain",
    "resume",
    "revoke",
  ]);
  assert.ok(request.properties.credentialSha256);
  assert.ok(request.properties.updaterCredentialSha256);
  assert.equal(request.properties.credential, undefined);
  assert.equal(request.properties.organizationId, undefined);
  assert.equal(request.additionalProperties, false);
  assert.equal(
    document.paths["/v1/admin/hosted-runners/install-profile"].get.operationId,
    "getHostedRunnerInstallProfile",
  );
  assert.deepEqual(
    document.paths["/v1/runner-releases/{sha256}"].get.security,
    [{ HostedRunnerUpdater: [] }],
  );
});
