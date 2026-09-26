import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import { parse } from "yaml";
import { beforePublicationGateEventDocument } from "./alpha-compat.mjs";
import {
  beforeProjectApiTokens,
  projectApiTokenPath,
  projectApiTokenSchemas,
  projectApiTokensPath,
} from "./project-api-tokens-compat.mjs";

const document = parse(
  readFileSync(new URL("provenance.v1.yaml", import.meta.url), "utf8"),
);
const inventory = JSON.parse(
  readFileSync(new URL("operation-inventory.json", import.meta.url), "utf8"),
);
const generated = readFileSync(
  new URL("../packages/api-client/src/gen/schema.d.ts", import.meta.url),
  "utf8",
);
const require = createRequire(
  new URL("../packages/verification/package.json", import.meta.url),
);
const Ajv = require("ajv/dist/2020.js");
const ajv = new Ajv({ strict: false });
require("ajv-formats")(ajv);
ajv.addSchema({ $id: "project-api-tokens", components: document.components });
const validator = (name) => (value) =>
  ajv.validate(
    { $ref: `project-api-tokens#/components/schemas/${name}` },
    value,
  );
const validRequest = validator("CreateProjectApiTokenRequest");
const validCreated = validator("CreatedProjectApiToken");
const validList = validator("ProjectApiTokenList");

const security = [{ BearerAuth: [] }, { SessionCookie: [] }];
const problem = { $ref: "#/components/responses/Problem" };
const metadata = {
  id: "11111111-1111-4111-8111-111111111111",
  organizationId: "22222222-2222-4222-8222-222222222222",
  projectId: "33333333-3333-4333-8333-333333333333",
  createdByUserId: "44444444-4444-4444-8444-444444444444",
  name: "ci",
  capabilities: ["private-results:view", "release:submit"],
  expiresAt: "2026-10-26T00:00:00Z",
  createdAt: "2026-09-26T00:00:00Z",
};
const secret = "A".repeat(42) + "_";

test("WP-07D project API tokens are purely additive to the merged IFC-033 contract", () => {
  // Parsed complete OpenAPI at 1d4e399d (merged IFC-033 main) after the
  // established publication-gate projection. Removing exactly the WP-07D
  // paths and components must reproduce every earlier path and component.
  assert.equal(
    createHash("sha256")
      .update(
        JSON.stringify(
          beforeProjectApiTokens(beforePublicationGateEventDocument(document)),
        ),
      )
      .digest("hex"),
    "268d1c44e5a87f267cb14244fa8a8d0f7611be8da8c4dbab23696cae577dd181",
  );
  const projected = beforeProjectApiTokens(document);
  assert.deepEqual(
    Object.keys(document.paths).filter(
      (path) => projected.paths[path] === undefined,
    ),
    [projectApiTokensPath, projectApiTokenPath],
  );
  for (const name of projectApiTokenSchemas)
    assert.equal(projected.components.schemas[name], undefined);
});

test("WP-07D operations match the platform paths, methods, security and statuses", () => {
  const collection = document.paths[projectApiTokensPath];
  const item = document.paths[projectApiTokenPath];
  assert.deepEqual(Object.keys(collection).sort(), [
    "get",
    "parameters",
    "post",
  ]);
  assert.deepEqual(Object.keys(item).sort(), ["delete", "parameters"]);
  assert.deepEqual(collection.parameters, [
    { $ref: "#/components/parameters/ProjectId" },
  ]);
  assert.deepEqual(item.parameters, [
    { $ref: "#/components/parameters/ProjectId" },
    { $ref: "#/components/parameters/ProjectApiTokenId" },
  ]);
  assert.equal(
    document.components.parameters.ProjectApiTokenId.name,
    "tokenId",
  );

  const expected = {
    createProjectApiToken: [
      collection.post,
      "201",
      ["400", "401", "403", "404", "409", "422", "500"],
    ],
    listProjectApiTokens: [
      collection.get,
      "200",
      ["401", "403", "404", "422", "500"],
    ],
    revokeProjectApiToken: [
      item.delete,
      "204",
      ["401", "403", "404", "422", "500"],
    ],
  };
  for (const [operationId, [operation, success, failures]] of Object.entries(
    expected,
  )) {
    assert.equal(operation.operationId, operationId);
    assert.deepEqual(operation.tags, ["organizations-projects"]);
    assert.deepEqual(operation.security, security);
    assert.equal(operation.parameters, undefined);
    assert.deepEqual(
      Object.keys(operation.responses).sort(),
      [success, ...failures, "default"].sort(),
    );
    for (const status of [...failures, "default"])
      assert.deepEqual(operation.responses[status], problem);
  }
  assert.deepEqual(item.delete.responses["204"], {
    $ref: "#/components/responses/NoContent",
  });
  assert.equal(collection.get.requestBody, undefined);
  assert.equal(item.delete.requestBody, undefined);
  assert.equal(collection.post.requestBody.required, true);
  assert.equal(
    collection.post.requestBody.content["application/json"].schema.$ref,
    "#/components/schemas/CreateProjectApiTokenRequest",
  );

  for (const [operation, status, schema] of [
    [collection.post, "201", "CreatedProjectApiToken"],
    [collection.get, "200", "ProjectApiTokenList"],
  ]) {
    const response = operation.responses[status];
    assert.equal(
      response.headers["Cache-Control"].$ref,
      "#/components/headers/ProjectApiTokenNoStore",
    );
    assert.equal(
      response.content["application/json"].schema.$ref,
      `#/components/schemas/${schema}`,
    );
  }
  const header = document.components.headers.ProjectApiTokenNoStore;
  assert.equal(header.required, true);
  assert.equal(header.schema.const, "no-store");

  const inventoried = inventory.filter((entry) =>
    [projectApiTokensPath, projectApiTokenPath].includes(entry.path),
  );
  assert.deepEqual(inventoried, [
    {
      method: "post",
      operationId: "createProjectApiToken",
      path: projectApiTokensPath,
      tag: "organizations-projects",
    },
    {
      method: "get",
      operationId: "listProjectApiTokens",
      path: projectApiTokensPath,
      tag: "organizations-projects",
    },
    {
      method: "delete",
      operationId: "revokeProjectApiToken",
      path: projectApiTokenPath,
      tag: "organizations-projects",
    },
  ]);
});

test("WP-07D descriptions fix shown-once, authority and problem semantics", () => {
  const create = document.paths[projectApiTokensPath].post.description;
  for (const clause of [
    /`token` secret in the 201 response is shown once/,
    /never returned by any later read, list, revocation or\s+replay/,
    /from 300\s+seconds \(5 minutes\) through 7776000 seconds \(90 days\)/,
    /no\s+non-expiring project token/,
    /`projects:manage`/,
    /Project-scoped API tokens.*GitHub Actions grants receive\s+HTTP 403 `forbidden`/s,
    /HTTP 403\s+`capability_not_held`/,
    /at most 50 active/,
    /HTTP 409\s+`token_limit_reached`/,
    /HTTP 401\s+`unauthenticated`/,
    /HTTP 404\s+`not_found`/,
    /HTTP 422/,
    /HTTP 400\s+`invalid_request`/,
    /`Cache-Control: no-store`/,
  ])
    assert.match(create, clause);
  assert.match(
    document.paths[projectApiTokensPath].get.description,
    /never includes a token secret or hash/,
  );
  assert.match(
    document.paths[projectApiTokenPath].delete.description,
    /idempotent.*also return HTTP 204 without another event/s,
  );
  assert.match(
    document.components.schemas.CreatedProjectApiToken.properties.token
      .description,
    /^Shown once\./,
  );
});

test("WP-07D schemas are closed and bounded", () => {
  assert.deepEqual(document.components.schemas.ProjectApiTokenCapability.enum, [
    "private-results:view",
    "release:cancel",
    "release:submit",
  ]);
  const metadataShape = document.components.schemas.ProjectApiToken;
  for (const name of Object.keys(metadataShape.properties))
    assert.doesNotMatch(name, /token|secret|hash/i);

  assert.ok(
    validRequest({ capabilities: ["release:submit"], expiresInSeconds: 300 }),
  );
  assert.ok(
    validRequest({
      name: "n".repeat(100),
      capabilities: [
        "private-results:view",
        "release:cancel",
        "release:submit",
      ],
      expiresInSeconds: 7776000,
    }),
  );
  for (const invalid of [
    { capabilities: ["release:submit"] },
    { expiresInSeconds: 3600 },
    { capabilities: [], expiresInSeconds: 3600 },
    { capabilities: ["release:submit"], expiresInSeconds: 299 },
    { capabilities: ["release:submit"], expiresInSeconds: 7776001 },
    {
      capabilities: ["release:submit", "release:submit"],
      expiresInSeconds: 3600,
    },
    { capabilities: ["projects:manage"], expiresInSeconds: 3600 },
    {
      capabilities: ["release:submit"],
      expiresInSeconds: 3600,
      name: "n".repeat(101),
    },
    { capabilities: ["release:submit"], expiresInSeconds: 3600, extra: true },
  ])
    assert.equal(validRequest(invalid), false, JSON.stringify(invalid));

  assert.ok(validCreated({ ...metadata, token: secret }));
  assert.ok(
    validCreated({
      ...metadata,
      lastUsedAt: "2026-09-26T01:00:00Z",
      token: secret,
    }),
  );
  for (const invalid of [
    metadata,
    { ...metadata, token: "short" },
    { ...metadata, token: secret, extra: true },
  ])
    assert.equal(validCreated(invalid), false);

  assert.ok(validList({ items: [] }));
  assert.ok(validList({ items: [metadata] }));
  for (const invalid of [
    {},
    { items: [{ ...metadata, token: secret }] },
    { items: [metadata], page: { hasMore: false } },
    { items: Array.from({ length: 51 }, () => metadata) },
  ])
    assert.equal(validList(invalid), false);
});

test("generated client exposes the WP-07D operations", () => {
  for (const name of [
    "createProjectApiToken:",
    "listProjectApiTokens:",
    "revokeProjectApiToken:",
    "CreatedProjectApiToken:",
    "ProjectApiTokenList:",
    '"/v1/projects/{projectId}/api-tokens":',
    '"/v1/projects/{projectId}/api-tokens/{tokenId}":',
  ])
    assert.ok(generated.includes(name), name);
});
