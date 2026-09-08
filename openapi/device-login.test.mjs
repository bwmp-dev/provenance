import { beforeAlphaAdmission } from "./alpha-compat.mjs";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import test from "node:test";
import { parse } from "yaml";

const root = new URL("./", import.meta.url);
const doc = parse(await readFile(new URL("provenance.v1.yaml", root), "utf8"));
const baseline = JSON.parse(
  await readFile(new URL("device-initiation-baseline.json", root), "utf8"),
);
const vectors = JSON.parse(
  await readFile(new URL("device-login-states.json", root), "utf8"),
);
const semantics = await readFile(
  new URL("device-login-semantics.md", root),
  "utf8",
);
const require = createRequire(
  new URL("../packages/verification/package.json", root),
);
const Ajv = require("ajv/dist/2020.js");
const ajv = new Ajv({ strict: false });
require("ajv-formats")(ajv);
ajv.addSchema({ $id: "device", components: doc.components });
const valid = (name, value) =>
  ajv.validate({ $ref: `device#/components/schemas/${name}` }, value);
const prefix = "/v1/auth/device-authorizations";
const ops = [
  doc.paths[prefix].post,
  doc.paths[`${prefix}/decisions`].post,
  doc.paths[`${prefix}/exchanges`].post,
];

test("IFC020 registers only the explicit initiation replay change", () => {
  const before = baseline.post,
    after = ops[0];
  for (const key of [
    "operationId",
    "summary",
    "tags",
    "security",
    "requestBody",
  ])
    assert.deepEqual(after[key], before[key], key);
  assert.deepEqual(after.responses[201].content, before.responses[201].content);
  assert.deepEqual(after.parameters, [
    { $ref: "#/components/parameters/DeviceLoginIdempotencyKey" },
  ]);
  assert.deepEqual(
    Object.keys(after).sort(),
    [...Object.keys(before), "description"].sort(),
  );
  assert.match(
    after.description,
    /explicitly changes identical successful initiation replay/,
  );
  assert.match(
    doc.components.parameters.IdempotencyKey.description,
    /returns the original/,
  );
  assert.match(
    doc.components.parameters.DeviceLoginIdempotencyKey.description,
    /credential_not_replayable/,
  );
});

test("IFC020 all outcomes have closed four-field problems and no-store", () => {
  const retrySchema = doc.components.headers.DeviceLoginRetryAfter.schema;
  for (const value of ["1", "60", "86399", "86400"])
    assert.equal(ajv.validate(retrySchema, value), true);
  for (const value of [
    "0",
    "01",
    "86401",
    "99999",
    "1\n",
    "Mon, 01 Jan 2026",
    1,
  ])
    assert.equal(ajv.validate(retrySchema, value), false);
  assert.deepEqual(ops[1].security, [{ SessionCookie: [] }]);
  assert.deepEqual(ops[2].security, []);
  assert.equal(ops[2].parameters, undefined);
  for (const op of ops) {
    assert.match(op.description, /4096/);
    assert.match(op.description, /Origin/);
    for (const [status, raw] of Object.entries(op.responses)) {
      const response = raw.$ref
        ? doc.components.responses[raw.$ref.split("/").at(-1)]
        : raw;
      assert.equal(
        response.headers["Cache-Control"].$ref,
        "#/components/headers/DeviceLoginNoStore",
      );
      if (+status < 400) continue;
      const schema = response.content["application/problem+json"].schema;
      assert.deepEqual(schema.required, ["type", "title", "status", "code"]);
      assert.equal(schema.additionalProperties, false);
      assert.equal(schema.properties.status.const, +status);
      const good = {
        type: "about:blank",
        title: "Device authorization failed",
        status: +status,
        code: schema.properties.code.enum[0],
      };
      assert.equal(ajv.validate(schema, good), true);
      for (const bad of [
        { ...good, detail: "forbidden" },
        { ...good, code: "provider_error" },
        { ...good, status: 500 },
        { ...good, title: "submitted-value" },
      ])
        assert.equal(ajv.validate(schema, bad), false);
      assert.equal(Boolean(response.headers["Retry-After"]), status === "429");
    }
  }
});

test("IFC020 rejects authority injection, malformed codes and open states", () => {
  const code = Buffer.alloc(32).toString("base64url");
  const good = { userCode: "ABCD-EFGH", decision: "approve" };
  assert.equal(valid("DeviceLoginDecisionRequest", good), true);
  for (const field of [
    "userId",
    "organizationId",
    "projectId",
    "role",
    "capabilities",
    "deviceCode",
    "returnUrl",
  ])
    assert.equal(
      valid("DeviceLoginDecisionRequest", { ...good, [field]: "forbidden" }),
      false,
    );
  for (const userCode of [
    "abcd-efgh",
    " ABCD-EFGH",
    "ABCD-EFGI",
    code,
    "",
    "ABCD-EFGH\n",
  ])
    assert.equal(
      valid("DeviceLoginDecisionRequest", { ...good, userCode }),
      false,
    );
  for (const decision of ["approved", "lookup", true, null])
    assert.equal(
      valid("DeviceLoginDecisionRequest", { ...good, decision }),
      false,
    );
  assert.equal(valid("DeviceLoginExchangeRequest", { deviceCode: code }), true);
  for (const deviceCode of [
    "ABCD-EFGH",
    code + "=",
    code.slice(0, -1) + "B",
    "",
    "a".repeat(4097),
    code + "\n",
  ])
    assert.equal(valid("DeviceLoginExchangeRequest", { deviceCode }), false);
  assert.equal(
    valid("DeviceLoginExchangeRequest", {
      deviceCode: code,
      userCode: good.userCode,
    }),
    false,
  );
  for (const name of [
    "DeviceLoginDecisionRequest",
    "DeviceLoginExchangeRequest",
  ])
    assert.equal(valid(name, {}), false);
  const pending = {
    state: "pending",
    intervalSeconds: 1,
    expiresAt: "2026-01-01T00:00:00Z",
  };
  assert.equal(valid("DeviceLoginPending", pending), true);
  for (const intervalSeconds of [0, -1, 1.1, 86401, "1"])
    assert.equal(
      valid("DeviceLoginPending", { ...pending, intervalSeconds }),
      false,
    );
  assert.equal(
    valid("DeviceLoginPending", { ...pending, state: "approved" }),
    false,
  );
  assert.equal(
    valid("DeviceLoginPending", { ...pending, exchangeToken: code }),
    false,
  );
  assert.equal(
    valid("DeviceLoginExchange", {
      exchangeToken: code,
      expiresAt: pending.expiresAt,
    }),
    true,
  );
  assert.equal(
    valid("DeviceLoginExchange", {
      exchangeToken: code,
      expiresAt: pending.expiresAt,
      accessToken: code,
    }),
    false,
  );
});

// A declarative conformance oracle, not a service or runtime acceptance test.
function outcome(v) {
  if (v.admission === "global-limit") return [429, "rate_limited"];
  if (v.operation === "initiation")
    return v.state === "different"
      ? [409, "idempotency_conflict"]
      : v.state === "same"
        ? [409, "credential_not_replayable"]
        : [201, "created"];
  if (v.operation === "decision") {
    if (v.state === "foreign") return [403, "authorization_denied"];
    if (v.state === "different") return [409, "idempotency_conflict"];
    if (v.deadline === "expired") return [410, "authorization_expired"];
    if (["same", "consumed-same"].includes(v.state))
      return [200, "original_decision"];
    if (v.state === "bound-new-key") return [409, "decision_conflict"];
    return [200, v.state === "pending-deny" ? "denied" : "approved"];
  }
  if (v.state === "unknown") return [400, "invalid_authorization"];
  if (v.state === "consumed") return [409, "credential_not_replayable"];
  if (v.deadline === "expired") return [410, "authorization_expired"];
  if (v.state === "denied") return [403, "authorization_denied"];
  if (v.admission === "early") return [429, "rate_limited"];
  return v.state === "pending" ? [202, "pending"] : [200, "credential"];
}
test("IFC020 published state vectors freeze replay/expiry/rate precedence", () => {
  assert.equal(vectors.contract, "IFC-020");
  assert.equal(vectors.runtimeEvidence, false);
  assert.equal(
    new Set(vectors.cases.map((v) => v.id)).size,
    vectors.cases.length,
  );
  assert.ok(vectors.cases.length >= 20);
  for (const v of vectors.cases)
    assert.deepEqual(outcome(v), [v.status, v.outcome], v.id);
  for (const phrase of [
    "deadline equality",
    "before commit",
    "lost commit",
    "concurrent",
    "foreign user",
    "CSRF",
    "never raw",
    "Rollback disables",
  ])
    assert.ok(semantics.includes(phrase), phrase);
});

test("IFC020 bounded response shapes reach the generated consumer", async () => {
  const generated = await readFile(
    new URL("../packages/api-client/src/gen/schema.d.ts", root),
    "utf8",
  );
  for (const name of [
    "decideDeviceAuthorization",
    "exchangeDeviceAuthorization",
    "DeviceLoginPending",
    "DeviceLoginDecision",
    "DeviceLoginExchange",
  ])
    assert.ok(generated.includes(name), name);
  for (const [name, value] of [
    [
      "DeviceLoginDecision",
      { state: "approved", expiresAt: "2026-01-01T00:00:00Z" },
    ],
    [
      "DeviceLoginPending",
      {
        state: "pending",
        intervalSeconds: 86400,
        expiresAt: "2026-01-01T00:00:00Z",
      },
    ],
    [
      "DeviceLoginExchange",
      {
        exchangeToken: Buffer.alloc(32).toString("base64url"),
        expiresAt: "2026-01-01T00:00:00Z",
      },
    ],
  ]) {
    assert.equal(valid(name, value), true);
    for (const field of Object.keys(value)) {
      const bad = { ...value };
      delete bad[field];
      assert.equal(valid(name, bad), false);
    }
    for (const field of ["credential", "userId", "providerResponse", "detail"])
      assert.equal(valid(name, { ...value, [field]: "forbidden" }), false);
    assert.equal(valid(name, { ...value, expiresAt: "tomorrow" }), false);
  }
  assert.equal(
    /(?:deviceCode|exchangeToken)\s*[:=]\s*["'][A-Za-z0-9_-]{43}/.test(
      semantics,
    ),
    false,
    "no credential-valued documentation examples",
  );
});
