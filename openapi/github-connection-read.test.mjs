import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import { parse } from "yaml";
import { beforePublicationGateEventDocument } from "./alpha-compat.mjs";
import {
  beforeGitHubConnectionRead,
  githubConnectionReadPath,
} from "./github-connection-read-compat.mjs";

const document = parse(
  readFileSync(new URL("provenance.v1.yaml", import.meta.url), "utf8"),
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
ajv.addSchema({ $id: "github-read", components: document.components });
const validPage = (value) =>
  ajv.validate(
    { $ref: "github-read#/components/schemas/GitHubConnectionPage" },
    value,
  );

const project = "11111111-1111-4111-8111-111111111111";
const connection = {
  id: "22222222-2222-4222-8222-222222222222",
  projectId: project,
  installationId: "33333333-3333-4333-8333-333333333333",
  repositoryId: 42,
  repositoryFullName: "owner/repository",
  createdAt: "2026-09-23T00:00:00Z",
};

test("IFC-033 is purely additive to the merged WP-10B contract", () => {
  // Parsed complete OpenAPI at fd5302c1 (merged WP-09F/WP-10B main) after the
  // established publication-gate projection. Removing exactly the IFC-033
  // path and page schema must reproduce every earlier path and component.
  assert.equal(
    createHash("sha256")
      .update(
        JSON.stringify(
          beforeGitHubConnectionRead(
            beforePublicationGateEventDocument(document),
          ),
        ),
      )
      .digest("hex"),
    "3c25359525fec58459c4c0e562fd30ae7b0daab74f87626ef0185899905a3a32",
  );
  const projected = beforeGitHubConnectionRead(document);
  assert.equal(projected.paths[githubConnectionReadPath], undefined);
  assert.equal(projected.components.schemas.GitHubConnectionPage, undefined);
  assert.deepEqual(
    projected.components.schemas.GitHubConnection,
    document.components.schemas.GitHubConnection,
  );
  assert.deepEqual(
    Object.keys(document.paths).filter(
      (path) => projected.paths[path] === undefined,
    ),
    [githubConnectionReadPath],
  );
});

test("IFC-033 project GitHub connection read is tenant scoped, bounded and non-cacheable", () => {
  const item = document.paths[githubConnectionReadPath];
  assert.deepEqual(Object.keys(item).sort(), ["get", "parameters"]);
  assert.deepEqual(item.parameters, [
    { $ref: "#/components/parameters/ProjectId" },
  ]);
  const read = item.get;
  assert.equal(read.operationId, "listProjectGitHubConnections");
  assert.equal(read["x-provenance-interface"], "IFC-033");
  assert.deepEqual(read.tags, ["github"]);
  assert.deepEqual(read.security, [{ BearerAuth: [] }, { SessionCookie: [] }]);
  assert.deepEqual(read.parameters, [
    { $ref: "#/components/parameters/Cursor" },
    { $ref: "#/components/parameters/PageSize" },
  ]);
  assert.equal(read.requestBody, undefined);
  assert.deepEqual(Object.keys(read.responses).sort(), [
    "200",
    "400",
    "401",
    "404",
    "500",
    "default",
  ]);
  for (const status of ["400", "401", "404", "500", "default"])
    assert.equal(read.responses[status].$ref, "#/components/responses/Problem");
  const ok = read.responses["200"];
  assert.equal(
    ok.headers["Cache-Control"].$ref,
    "#/components/headers/PrivateNoStore",
  );
  assert.equal(
    ok.content["application/json"].schema.$ref,
    "#/components/schemas/GitHubConnectionPage",
  );
  for (const clause of [
    /active \(unrevoked\) GitHub\s+repository connections bound to the path project/,
    /never contacts GitHub/,
    /never includes installation tokens, user tokens/,
    /empty `items`\s+array means the project currently has no active repository\s+connection/,
    /ascending keyset order by `\(createdAt, id\)`/,
    /Clients must not parse or synthesize\s+cursors/,
    /nonexistent project.*outside the\s+caller's tenant.*not a current member of.*same HTTP 404 status/s,
    /resolved before\s+cursor validation/,
    /`limit` outside 1 through 100, receives HTTP 400/,
  ])
    assert.match(read.description, clause);
});

test("IFC-033 page reuses the closed GitHubConnection shape without credentials", () => {
  const page = document.components.schemas.GitHubConnectionPage;
  assert.equal(page.additionalProperties, false);
  assert.deepEqual(page.required, ["items", "page"]);
  assert.equal(page.properties.items.maxItems, 100);
  assert.equal(
    page.properties.items.items.$ref,
    "#/components/schemas/GitHubConnection",
  );
  assert.equal(page.properties.page.$ref, "#/components/schemas/PageInfo");
  assert.equal(page["x-provenance-max-json-bytes"], 131072);
  const shape = document.components.schemas.GitHubConnection;
  assert.equal(shape.additionalProperties, false);
  for (const name of Object.keys(shape.properties))
    assert.doesNotMatch(name, /token|secret|key|credential|code|state/i);

  assert.ok(validPage({ items: [], page: { hasMore: false } }));
  assert.ok(
    validPage({
      items: [connection],
      page: { hasMore: true, nextCursor: "opaque" },
    }),
  );
  for (const invalid of [
    { items: [] },
    { items: [], page: { hasMore: false }, extra: true },
    { items: [{ ...connection, token: "ghs_x" }], page: { hasMore: false } },
    {
      items: [{ ...connection, repositoryFullName: "no-slash" }],
      page: { hasMore: false },
    },
    {
      items: Array.from({ length: 101 }, () => connection),
      page: { hasMore: false },
    },
  ])
    assert.equal(validPage(invalid), false);
});

test("generated client exposes the IFC-033 read", () => {
  assert.match(generated, /listProjectGitHubConnections:/);
  assert.match(generated, /GitHubConnectionPage:/);
  assert.match(
    generated,
    /"\/v1\/projects\/\{projectId\}\/github-connections":/,
  );
});
