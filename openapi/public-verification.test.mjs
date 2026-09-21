import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import test from "node:test";
import { parse } from "yaml";
import {
  beforePublicVerification,
  publicVerificationPaths,
} from "./public-verification-compat.mjs";
const document = parse(
  readFileSync(new URL("provenance.v1.yaml", import.meta.url), "utf8"),
);
test("WP-10B adds public discovery and proofs without changing existing contracts", () => {
  assert.equal(
    createHash("sha256")
      .update(JSON.stringify(beforePublicVerification(document)))
      .digest("hex"),
    "7ecf4a2f944a17223c9ab66f7f5b415d3a1b35cf45bea8cc0e499d6261368352",
  );
});
test("public proof operations never inherit private credentials or mix schema versions", () => {
  for (const path of publicVerificationPaths) {
    const operation = document.paths[path].get;
    assert.deepEqual(operation.security, []);
    assert.equal(
      operation.responses[200].headers["Cache-Control"].schema.const,
      "no-store",
    );
    assert.ok(operation.description.includes("permanently published"));
  }
  for (const [suffix, version] of [
    ["attestation", 1],
    ["attestations/v2", 2],
  ]) {
    assert.deepEqual(
      document.paths[
        `/v1/public/{ownerSlug}/{projectSlug}/versions/{version}/${suffix}`
      ].get.responses[200].content["application/json"].schema,
      { $ref: `../schemas/attestation/v${version}/schema.json` },
    );
  }
  assert.equal(
    document.components.schemas.PublicVerificationPage.properties.items
      .maxItems,
    100,
  );
  assert.equal(
    document.components.schemas.PublicVerificationPage.additionalProperties,
    false,
  );
});
