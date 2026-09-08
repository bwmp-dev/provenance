import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "yaml";
const doc = parse(
  readFileSync(new URL("./provenance.v1.yaml", import.meta.url), "utf8"),
);
const paths = Object.entries(doc.paths).filter(
  ([p]) => p === "/v1/account" || p.startsWith("/v1/admin/"),
);
const resolve = (value) =>
  value.$ref
    ? value.$ref
        .slice(2)
        .split("/")
        .reduce((o, k) => o[k], doc)
    : value;
const properties = {
  AlphaAccount: [
    "userId",
    "displayName",
    "githubUserId",
    "isAdmin",
    "inviteOnly",
  ],
  AlphaUser: [
    "id",
    "displayName",
    "githubUserId",
    "isAdmin",
    "createdAt",
    "personalOrganizationId",
    "organizationCount",
  ],
  AlphaInvitation: [
    "id",
    "githubUserId",
    "githubLogin",
    "createdAt",
    "expiresAt",
    "acceptedAt",
    "revokedAt",
  ],
  AlphaRunner: [
    "id",
    "organizationId",
    "organizationName",
    "trust",
    "state",
    "version",
    "lastSeenAt",
    "capacity",
    "activeExecutions",
  ],
  AlphaExecution: [
    "id",
    "organizationId",
    "projectId",
    "projectName",
    "candidateId",
    "runnerId",
    "state",
    "attempt",
    "createdAt",
    "startedAt",
    "completedAt",
  ],
  AlphaUsage: ["organizationId", "organizationName", "metrics"],
};
test("IFC023 all admin outcomes are private and operational projections are closed", () => {
  assert.equal(paths.length, 8);
  for (const [, item] of paths)
    for (const [method, op] of Object.entries(item)) {
      assert.deepEqual(op.security, [{ SessionCookie: [] }]);
      for (const [status, value] of Object.entries(op.responses)) {
        const r = resolve(value);
        assert.equal(
          resolve(r.headers["Cache-Control"]).schema.const,
          "no-store",
          op.operationId + "/" + status,
        );
        if (Number(status) < 300)
          assert.match(
            r.content["application/json"].schema.$ref,
            /^#\/components\/schemas\/Alpha/,
          );
      }
      if (method !== "get")
        assert.ok(
          op.parameters.some(
            (p) => p.$ref === "#/components/parameters/IdempotencyKey",
          ),
        );
    }
  for (const [name, expected] of Object.entries(properties)) {
    const s = doc.components.schemas[name];
    assert.equal(s.additionalProperties, false);
    assert.deepEqual(Object.keys(s.properties), expected);
    assert.deepEqual(s.required, expected);
  }
  for (const name of ["User", "Runner", "Execution", "Invitation", "Usage"]) {
    const s = doc.components.schemas["Alpha" + name + "Page"];
    assert.equal(s.additionalProperties, false);
    assert.equal(s.properties.items.maxItems, 100);
    assert.deepEqual(Object.keys(s.properties), ["items", "nextCursor"]);
  }
  const usage = doc.paths["/v1/admin/usage"].get;
  for (const p of usage.parameters.filter(
    (p) => p.name === "from" || p.name === "to",
  ))
    assert.equal(p.schema.$ref, "#/components/schemas/Timestamp");
  assert.equal(
    doc.components.schemas.AlphaUsage.properties.metrics.items.properties
      .quantity.type,
    "string",
  );
  assert.ok(doc.paths["/v1/admin/invitations"].post.responses["201"]);
});
test("IFC023 refusal vectors distinguish admission, last-admin, accepted-invite and idempotency", () => {
  const vectors = JSON.parse(
    readFileSync(
      new URL("./alpha-administration-vectors.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(vectors.length, 5);
  const operations = Object.values(doc.paths)
    .flatMap((item) => Object.values(item))
    .filter((x) => x.operationId);
  for (const v of vectors) {
    const op = operations.find((o) => o.operationId === v.operationId);
    const schema = resolve(
      resolve(op.responses[String(v.status)]).content[
        "application/problem+json"
      ].schema,
    );
    assert.equal(schema.additionalProperties, false);
    assert.equal(schema.properties.status.const, v.status);
    const code = schema.properties.code;
    assert.ok(code.const === v.code || code.enum?.includes(v.code));
  }
  assert.equal(
    resolve(doc.paths["/v1/auth/sessions"].post.responses["403"]).headers[
      "Cache-Control"
    ].$ref,
    "#/components/headers/AlphaNoStore",
  );
  assert.deepEqual(
    doc.components.schemas.AlphaConflictProblem.properties.code.enum,
    [
      "idempotency_key_conflict",
      "last_administrator",
      "invitation_not_revocable",
      "account_already_admitted",
    ],
  );
});
