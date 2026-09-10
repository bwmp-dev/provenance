import assert from "node:assert/strict";
import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  AttestationSchemaError,
  canonicalizeStatement,
  createSigningInput,
  verifyAttestationSignature,
  verifyAttestedArtifact,
} from "../dist/index.js";

const fixtures = new URL(
  "../../../schemas/fixtures/attestation/",
  import.meta.url,
);
const small = JSON.parse(
  await readFile(new URL("interop/small-artifact.json", fixtures), "utf8"),
);
const vector = JSON.parse(
  await readFile(new URL("vectors/hosted.json", fixtures), "utf8"),
);
const privateKey = createPrivateKey({
  key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(vector.privateKeySeedHex, "hex"),
  ]),
  format: "der",
  type: "pkcs8",
});
const publicKey = Buffer.from(small.publicKeyHex, "hex");

test("shared v2 golden bytes match Go and Python signing inputs", async () => {
  const vector = JSON.parse(
    await readFile(new URL("interop/small-artifact-v2.json", fixtures), "utf8"),
  );
  const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
  const canonical = canonicalizeStatement(vector.document.statement);
  const input = createSigningInput(vector.document);
  assert.equal(canonical.toString("utf8"), vector.canonicalStatement);
  assert.equal(hash(canonical), vector.canonicalStatementSha256);
  assert.equal(hash(input), vector.signingInputSha256);
  assert.equal(
    sign(null, input, privateKey).toString("base64url"),
    vector.signatureBase64Url,
  );
  assert.equal(vector.document.signature.value, vector.signatureBase64Url);
  const key = Buffer.from(vector.publicKeyHex, "hex");
  assert.equal(verifyAttestationSignature(vector.document, key), true);
  await verifyAttestedArtifact(vector.document, key, [
    Buffer.from(vector.artifactHex, "hex"),
  ]);
});

function v2(literal = true) {
  const doc = structuredClone(small.document);
  doc.mediaType = "application/vnd.provenance.attestation.v2+json";
  doc.statement.apiVersion = "provenance.dev/attestation/v2";
  if (literal) {
    doc.statement.assertions[0].type = "console-contains";
    doc.statement.assertions[0].id = "console-contains:smoke:0";
  }
  doc.signature.value = sign(
    null,
    createSigningInput(doc),
    privateKey,
  ).toString("base64url");
  return doc;
}

test("v2 literal signature and exact artifact bytes verify", async () => {
  const doc = v2();
  assert.equal(verifyAttestationSignature(doc, publicKey), true);
  const artifact = Buffer.from(small.artifactHex, "hex");
  const result = await verifyAttestedArtifact(doc, publicKey, [artifact]);
  assert.equal(result.sizeBytes, artifact.length);
  assert.equal(
    result.digest.value,
    small.document.statement.subject.digest.value,
  );
});

test("v2 rejects v1 domain and relabelling even with overlapping assertion types", () => {
  const doc = v2();
  const wrongInput = Buffer.concat([
    Buffer.from("Provenance Attestation v1\n" + doc.signature.keyId + "\n"),
    canonicalizeStatement(doc.statement),
  ]);
  doc.signature.value = sign(null, wrongInput, privateKey).toString(
    "base64url",
  );
  assert.equal(verifyAttestationSignature(doc, publicKey), false);
  const overlap = v2(false);
  overlap.mediaType = "application/vnd.provenance.attestation.v1+json";
  overlap.statement.apiVersion = "provenance.dev/attestation/v1";
  assert.equal(verifyAttestationSignature(overlap, publicKey), false);
});

test("v2 refuses mixed envelopes and malformed literal IDs", () => {
  const mixed = v2();
  mixed.statement.apiVersion = "provenance.dev/attestation/v1";
  assert.throws(() => createSigningInput(mixed), AttestationSchemaError);
  for (const id of ["literal\n", "literal/unsafe", "a".repeat(129)]) {
    const doc = v2();
    doc.statement.assertions[0].id = id;
    assert.throws(() => createSigningInput(doc), AttestationSchemaError);
  }
});
