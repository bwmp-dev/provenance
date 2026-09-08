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
test("alpha administration requires human sessions, bounded collections and private responses", () => {
  assert.equal(paths.length, 8);
  for (const [, item] of paths)
    for (const [method, op] of Object.entries(item)) {
      assert.deepEqual(op.security, [{ SessionCookie: [] }]);
      assert.equal(
        op.responses["200"].headers["Cache-Control"].schema.const,
        "no-store",
      );
      assert.ok(op.responses["401"]);
      assert.ok(op.responses["403"]);
      if (method !== "get")
        assert.ok(
          op.parameters.some(
            (p) => p.$ref === "#/components/parameters/IdempotencyKey",
          ),
        );
    }
  for (const name of ["User", "Runner", "Execution", "Invitation", "Usage"]) {
    const schema = doc.components.schemas["Alpha" + name + "Page"];
    assert.equal(schema.additionalProperties, false);
    assert.equal(schema.properties.items.maxItems, 100);
    assert.ok(schema.required.includes("nextCursor"));
  }
  for (const [name, schema] of Object.entries(doc.components.schemas).filter(
    ([n]) => n.startsWith("Alpha"),
  )) {
    assert.equal(schema.additionalProperties, false, name);
    assert.doesNotMatch(
      JSON.stringify(schema),
      /accessToken|privateKey|publicKey|sessionCredential|failureSummary|rawLog/,
    );
    for (const [key, value] of Object.entries(schema.properties ?? {}))
      if (key.endsWith("At"))
        assert.ok(
          value.format === "date-time" ||
            value.anyOf?.some((s) => s.format === "date-time"),
          name + "." + key,
        );
  }
  assert.equal(
    doc.components.schemas.AlphaInvitationRequest.properties.githubLogin
      .maxLength,
    39,
  );
  assert.equal(
    doc.components.schemas.AlphaUsage.properties.metrics.items.properties
      .quantity.type,
    "string",
    "exact decimal observations remain strings",
  );
});
