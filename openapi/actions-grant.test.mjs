import { beforeAlphaAdmission } from "./alpha-compat.mjs";
const alphaPaths = [
  "/v1/admin/organizations",
  "/v1/account",
  "/v1/admin/users",
  "/v1/admin/invitations",
  "/v1/admin/runners",
  "/v1/admin/executions",
  "/v1/admin/usage",
  "/v1/admin/invitations/{invitationId}",
  "/v1/admin/users/{userId}/administrator",
];
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import test from "node:test";
import { parse } from "yaml";

const root = new URL("./", import.meta.url);
const doc = parse(await readFile(new URL("provenance.v1.yaml", root), "utf8"));
const baseline = JSON.parse(
  await readFile(new URL("alpha17-compat.hashes.json", root), "utf8"),
);
const vectors = JSON.parse(
  await readFile(new URL("actions-grant-vectors.json", root), "utf8"),
);
const semantics = await readFile(
  new URL("actions-grant-semantics.md", root),
  "utf8",
);
const require = createRequire(
  new URL("../packages/verification/package.json", import.meta.url),
);
const Ajv = require("ajv/dist/2020.js");
const ajv = new Ajv({ strict: false });
require("ajv-formats")(ajv);
ajv.addSchema({ $id: "actions-grant", components: doc.components });
const valid = (name, value) =>
  ajv.validate({ $ref: `actions-grant#/components/schemas/${name}` }, value);
const op = doc.paths["/v1/auth/github-actions/grants"].post;
const uuid = "11111111-1111-4111-8111-111111111111";
const response = {
  grantId: uuid,
  principalType: "github-actions",
  accessToken: "pva_" + Buffer.alloc(32).toString("base64url"),
  tokenType: "Bearer",
  expiresAt: "2026-09-07T01:00:00Z",
  scope: {
    organizationId: uuid,
    projectId: uuid,
    appId: "1",
    installationId: "2",
    repositoryId: "3",
    repositoryOwnerId: "4",
    sourceCommit: "a".repeat(40),
    sourceRef: "refs/heads/main",
    workflowRef: "example/repo/.github/workflows/build.yml@refs/heads/main",
  },
};

test("IFC022 is additive to every alpha17 path and component", () => {
  const hash = (v) =>
    createHash("sha256").update(JSON.stringify(v)).digest("hex");
  assert.equal(baseline.source, "9bd0db6dc6e1a9b16d237661816eba1cb27c0554");
  for (const [path, digest] of Object.entries(baseline.paths))
    assert.equal(
      hash(beforeAlphaAdmission(path, doc.paths[path])),
      digest,
      path,
    );
  for (const [family, names] of Object.entries(baseline.components))
    for (const [name, digest] of Object.entries(names))
      assert.equal(
        hash(doc.components[family][name]),
        digest,
        `${family}/${name}`,
      );
  assert.deepEqual(
    Object.keys(doc.paths).filter(
      (p) =>
        !baseline.paths[p] &&
        !alphaPaths.includes(p) &&
        ![
          "/v1/admin/runner-updates",
          "/v1/runner-updater/{runnerId}/poll",
        ].includes(p),
    ),
    [
      "/v1/release-candidates/{candidateId}/publication-result",
      "/v1/auth/github-actions/grants",
    ],
  );
  assert.equal(op.operationId, "createGitHubActionsGrant");
  assert.deepEqual(op.security, []);
  assert.match(
    doc.components.parameters.IdempotencyKey.description,
    /returns the original/,
  );
  assert.equal(
    doc.paths["/v1/auth/github-oidc/exchanges"].post.parameters[0].$ref,
    "#/components/parameters/IdempotencyKey",
  );
});

test("IFC022 operation and closed grant types reach the generated SDK", async () => {
  const generated = await readFile(
    new URL("../packages/api-client/src/gen/schema.d.ts", root),
    "utf8",
  );
  for (const name of [
    "/v1/auth/github-actions/grants",
    "createGitHubActionsGrant",
    "CreateGitHubActionsGrantRequest",
    "GitHubActionsGrantScope",
    "credential_not_replayable",
    "assertion_replayed",
  ])
    assert.ok(generated.includes(name), name);
});

test("IFC022 request and shown-once normalized response are closed and bounded", () => {
  const request = { assertion: "aaaaaaaa.bbbbbbbb.cccccccc" };
  assert.equal(valid("CreateGitHubActionsGrantRequest", request), true);
  for (const value of [
    null,
    [],
    {},
    { ...request, projectId: uuid },
    { ...request, capabilities: ["private-results:view"] },
    { ...request, assertion: "a".repeat(16385) },
    { assertion: "a.b.c\n" },
    { assertion: "x.y.z" },
  ])
    assert.equal(valid("CreateGitHubActionsGrantRequest", value), false);
  assert.equal(valid("GitHubActionsGrant", response), true);
  for (const value of [
    { ...response, userId: uuid },
    { ...response, principalType: "session" },
    { ...response, accessToken: response.accessToken + "=" },
    { ...response, accessToken: response.accessToken.slice(0, -1) + "B" },
    { ...response, scope: { ...response.scope, claims: {} } },
    { ...response, scope: { ...response.scope, repositoryId: 3 } },
    { ...response, scope: { ...response.scope, repositoryOwnerId: "04" } },
    { ...response, scope: { ...response.scope, repositoryId: "1".repeat(21) } },
    { ...response, scope: { ...response.scope, sourceCommit: "B".repeat(40) } },
    { ...response, scope: { ...response.scope, sourceRef: "x\ny" } },
    {
      ...response,
      scope: { ...response.scope, workflowRef: "x".repeat(1025) },
    },
  ])
    assert.equal(valid("GitHubActionsGrant", value), false);
});

test("IFC022 all outcomes including prehandlers are closed no-store", () => {
  assert.deepEqual(Object.keys(op.responses).sort(), [
    "201",
    "400",
    "401",
    "403",
    "405",
    "408",
    "409",
    "413",
    "415",
    "429",
    "503",
  ]);
  assert.equal(
    op.parameters[0].$ref,
    "#/components/parameters/ActionsGrantIdempotencyKey",
  );
  for (const [status, raw] of Object.entries(op.responses)) {
    const r = raw.$ref
      ? doc.components.responses[raw.$ref.split("/").at(-1)]
      : raw;
    assert.equal(
      r.headers["Cache-Control"].$ref,
      "#/components/headers/ActionsGrantNoStore",
    );
    if (status === "201") continue;
    const s = r.content["application/problem+json"].schema;
    assert.equal(s.additionalProperties, false);
    assert.deepEqual(s.required, ["type", "title", "status", "code"]);
    const p = {
      type: "about:blank",
      title: "Automation grant failed",
      status: +status,
      code: s.properties.code.enum[0],
    };
    assert.equal(ajv.validate(s, p), true);
    for (const bad of [
      { ...p, detail: "credential" },
      { ...p, claims: {} },
      { ...p, status: 500 },
      { ...p, title: "provider message" },
      { ...p, code: "raw_error" },
    ])
      assert.equal(ajv.validate(s, bad), false);
  }
});

// This executable model checks normative precedence only. Input booleans are
// hypothetical outcomes, NOT implementations or evidence of JWT/DB validation.
function issuance(v) {
  if (v.method === false) return [405, "method_not_allowed"];
  if (v.requestTimeout) return [408, "request_timeout"];
  if (v.bodyTooLarge) return [413, "request_too_large"];
  if (v.mediaType === false) return [415, "unsupported_media_type"];
  if (v.syntax === false) return [400, "invalid_request"];
  if (v.limited) return [429, "rate_limited"];
  if (v.ready === false) return [503, "unavailable"];
  if (v.assertionValid === false) return [401, "invalid_assertion"];
  if (v.policyAllowed === false || v.commitCurrent === false)
    return [403, "policy_denied"];
  if (v.key === "different") return [409, "idempotency_conflict"];
  if (v.key === "identical") return [409, "credential_not_replayable"];
  if (v.assertionSpent) return [409, "assertion_replayed"];
  return [201, "issued"];
}
test("IFC022 normative issuance and serialized-winner vectors", () => {
  assert.equal(vectors.contract, "IFC-022");
  assert.equal(vectors.schemaVersion, 1);
  assert.equal(
    new Set(vectors.issuance.map((v) => v.id)).size,
    vectors.issuance.length,
  );
  for (const v of vectors.issuance) {
    const [status, code] = issuance(v.input);
    assert.deepEqual({ status, code }, v.expected, v.id);
    if (status !== 201)
      assert.ok(
        doc.components.responses[`ActionsGrant${status}`].content[
          "application/problem+json"
        ].schema.properties.code.enum.includes(code),
      );
  }
  for (const v of vectors.concurrency) {
    const second =
      v.id === "same-assertion-same-key"
        ? { key: "identical", assertionSpent: true }
        : v.id === "same-assertion-different-keys"
          ? { assertionSpent: true }
          : { key: "different" };
    const outcomes = [issuance({})[1], issuance(second)[1]];
    assert.deepEqual(outcomes, v.outcomes);
    assert.equal(outcomes.filter((x) => x === "issued").length, v.grants);
  }
});

test("IFC022 resource vectors never grant general private-project access", () => {
  const permitted = new Set([
    "createProjectConfigSnapshot",
    "createArtifactUpload",
    "completeArtifactUpload",
    "createReleaseCandidate",
    "getArtifact",
    "getReleaseCandidate",
    "listReleaseCandidateEvents",
  ]);
  const inventory = new Set(
    Object.values(doc.paths).flatMap((path) =>
      Object.values(path)
        .filter((operation) => operation?.operationId)
        .map((operation) => operation.operationId),
    ),
  );
  const contextFields = [
    "grantCurrent",
    "sameProject",
    "sameGrant",
    "exactSource",
    "exactSnapshot",
    "exactBytes",
  ];
  for (const v of vectors.resources) {
    assert.ok(inventory.has(v.operation), `unknown operation ${v.operation}`);
    for (const field of contextFields) {
      assert.equal(
        typeof v[field],
        "boolean",
        `${v.id}/${field} must be explicit`,
      );
      if (v.id.startsWith("deny-"))
        assert.equal(v[field], true, `${v.id} must isolate operation denial`);
    }
    const allowed =
      permitted.has(v.operation) &&
      v.grantCurrent === true &&
      v.sameProject === true &&
      v.sameGrant === true &&
      v.exactSource === true &&
      v.exactSnapshot === true &&
      v.exactBytes === true;
    assert.equal(allowed, v.expected, v.id);
  }
  assert.equal(vectors.resources.filter((v) => v.expected).length, 7);
  for (const term of [
    "No fabricated UserID",
    "exp + configured skew",
    "No HTTP while holding DB locks",
    "same assertion replay identity",
    "private-results:view",
    "configurationSnapshotId",
    "No permission or requested organization/project",
    "not evidence that",
  ])
    assert.ok(semantics.includes(term), term);
});
