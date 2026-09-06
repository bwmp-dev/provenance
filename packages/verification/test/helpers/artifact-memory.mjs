// Isolate live backing-store measurement from other tests and V8 GC scheduling.
import assert from "node:assert/strict";
import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  AttestationSignatureError,
  createSigningInput,
  verifyAttestedArtifact,
} from "../../dist/index.js";

assert.equal(typeof globalThis.gc, "function", "requires --expose-gc");
const mode = process.argv[2];
assert.ok(["streaming", "retaining-negative-control"].includes(mode));
const fixtureRoot = new URL(
  "../../../../schemas/fixtures/attestation/",
  import.meta.url,
);
const document = JSON.parse(
  await readFile(new URL("valid/hosted.json", fixtureRoot), "utf8"),
);
const vector = JSON.parse(
  await readFile(new URL("vectors/hosted.json", fixtureRoot), "utf8"),
);
const privateKey = createPrivateKey({
  format: "der",
  type: "pkcs8",
  key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(vector.privateKeySeedHex, "hex"),
  ]),
});
const publicKey = Buffer.from(vector.publicKeyHex, "hex");
const sizeBytes = 128 * 1024 * 1024;
const boundBytes = 96 * 1024 * 1024;
const chunkSize = 256 * 1024;
const chunkCount = sizeBytes / chunkSize;
const hash = createHash("sha256");
// Every yielded chunk has distinct contents as well as a distinct backing store.
const template = Buffer.alloc(chunkSize);
for (let index = 0; index < chunkCount; index += 1) {
  template.fill(index & 0xff);
  template.writeUInt32LE(index);
  hash.update(template);
}
document.statement.subject.sizeBytes = sizeBytes;
document.statement.subject.digest.value = hash.digest("hex");
document.signature.value = sign(
  null,
  createSigningInput(document),
  privateKey,
).toString("base64url");
const invalid = structuredClone(document);
invalid.statement.subject.digest.value = "00".repeat(32);
let invalidRead = false;
await assert.rejects(
  verifyAttestedArtifact(invalid, publicKey, {
    async *[Symbol.asyncIterator]() {
      invalidRead = true;
      yield Buffer.alloc(1);
    },
  }),
  AttestationSignatureError,
);
assert.equal(invalidRead, false);

globalThis.gc();
const baseline = process.memoryUsage().arrayBuffers;
let maximum = baseline;
let activeSamples = 0;
let generatedChunks = 0;
let completed = false;
async function* generatedArtifact() {
  for (let index = 0; index < chunkCount; index += 1) {
    const chunk = Buffer.alloc(chunkSize, index & 0xff);
    chunk.writeUInt32LE(index);
    generatedChunks += 1;
    yield chunk;
    if (generatedChunks % 16 === 0) {
      // Sampling happens before iteration completes, never after verification
      // returns: a buffering implementation cannot discard its data first.
      assert.equal(completed, false);
      globalThis.gc();
      maximum = Math.max(maximum, process.memoryUsage().arrayBuffers);
      activeSamples += 1;
    }
  }
}
const retained = [];
async function* retainingConsumer() {
  for await (const chunk of generatedArtifact()) {
    retained.push(chunk);
    yield chunk;
  }
}
const result = await verifyAttestedArtifact(
  document,
  publicKey,
  mode === "streaming" ? generatedArtifact() : retainingConsumer(),
);
completed = true;
assert.equal(result.sizeBytes, sizeBytes);
assert.equal(result.digest.value, document.statement.subject.digest.value);
// Keep the negative control strongly reachable throughout all active samples.
assert.equal(retained.length, mode === "streaming" ? 0 : chunkCount);
const growthBytes = maximum - baseline;
const withinBound = growthBytes < boundBytes;
console.log(
  JSON.stringify({
    mode,
    sizeBytes,
    boundBytes,
    generatedChunks,
    activeSamples,
    growthBytes,
    withinBound,
    verified: true,
    signatureRejectedBeforeReading: !invalidRead,
  }),
);
process.exitCode = withinBound ? 0 : 1;
