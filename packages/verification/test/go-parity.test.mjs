import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  canonicalizeStatement,
  createSigningInput,
  verifyAttestationSignature,
  verifyAttestedArtifact,
} from "../dist/index.js";

const fixtures = new URL(
  "../../../schemas/fixtures/attestation/interop/",
  import.meta.url,
);
test("shared Go/TypeScript Unicode and integer canonicalization vectors", async () => {
  const vectors = JSON.parse(
    await readFile(new URL("raw-json.json", fixtures), "utf8"),
  );
  // TS accepts object inputs, not raw JSON. Duplicate-key/BOM/UTF-8 parser
  // rejection vectors apply to the new Go raw-JSON entry point only.
  for (const vector of vectors.filter((item) => item.valid)) {
    assert.equal(
      canonicalizeStatement(JSON.parse(vector.json)).toString("utf8"),
      vector.canonical,
      vector.name,
    );
  }
});
test("shared signed local artifact verifies with identical signing bytes", async () => {
  const vector = JSON.parse(
    await readFile(new URL("small-artifact.json", fixtures), "utf8"),
  );
  const key = Buffer.from(vector.publicKeyHex, "hex");
  assert.equal(
    canonicalizeStatement(vector.document.statement).toString("utf8"),
    vector.canonicalStatement,
  );
  assert.equal(
    createHash("sha256")
      .update(createSigningInput(vector.document))
      .digest("hex"),
    vector.signingInputSha256,
  );
  assert.equal(verifyAttestationSignature(vector.document, key), true);
  const bytes = Buffer.from(vector.artifactHex, "hex");
  const result = await verifyAttestedArtifact(vector.document, key, [
    bytes.subarray(0, 1),
    bytes.subarray(1),
  ]);
  assert.equal(result.sizeBytes, bytes.length);
  assert.equal(
    result.digest.value,
    vector.document.statement.subject.digest.value,
  );
});
