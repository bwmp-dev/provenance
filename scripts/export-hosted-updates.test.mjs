import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
const script = new URL("./export-hosted-updates.mjs", import.meta.url);
test("hosted projection dereferences nested schemas and canonical parameters", () => {
  const dir = mkdtempSync(join(tmpdir(), "hosted-export-"));
  try {
    const path = join(dir, "projection.json");
    const r = spawnSync(process.execPath, [script.pathname, path], {
      encoding: "utf8",
    });
    assert.equal(r.status, 0, r.stderr);
    const raw = readFileSync(path, "utf8"),
      doc = JSON.parse(raw);
    assert.equal(Object.keys(doc.paths).length, 8);
    assert.ok(!raw.includes('"$ref"'));
    const admin = doc.paths["/v1/admin/runner-updates"];
    assert.equal(admin.post.parameters[0].name, "Idempotency-Key");
    assert.equal(
      admin.post.parameters[0].schema.pattern,
      "^[A-Za-z0-9._:-]{8,128}$",
    );
    assert.equal(
      admin.get.responses[200].content["application/json"].schema.properties
        .releases.items.properties.signature.pattern,
      "^[A-Za-z0-9+/]{86}==$",
    );
    assert.equal(
      doc.paths["/v1/admin/hosted-runners"].get.responses[200].content[
        "application/json"
      ].schema.properties.truncated.type,
      "boolean",
    );
    assert.equal(
      doc.paths["/v1/admin/hosted-catalogs"].post.requestBody.content[
        "application/json"
      ].schema.properties.runnerIds.maxItems,
      200,
    );
    assert.equal(
      doc.paths["/v1/runner-catalog-assets/{sha256}/{filename}"].get
        .parameters[0].schema.pattern,
      "^[a-f0-9]{64}$",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
test("hosted exporter requires an explicit output path", () => {
  const r = spawnSync(process.execPath, [script.pathname], {
    encoding: "utf8",
  });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /Output path is required/);
});
