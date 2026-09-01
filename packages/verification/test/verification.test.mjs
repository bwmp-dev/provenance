import assert from "node:assert/strict";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  AttestationDigestError,
  AttestationError,
  AttestationKeyError,
  AttestationSchemaError,
  AttestationSignatureError,
  AttestationSizeError,
  canonicalizeStatement,
  createSigningInput,
  validateAttestation,
  verifyAttestedArtifact,
  verifyAttestationSignature,
} from "../dist/index.js";

const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fixtures = resolve(
  packageDirectory,
  "../../schemas/fixtures/attestation",
);
const rawEd25519PrivatePrefix = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

async function readJson(path) {
  return JSON.parse(await readFile(resolve(fixtures, path), "utf8"));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function setPath(document, path, value) {
  let target = document;
  for (const part of path.slice(0, -1)) {
    target = target[part];
  }
  target[path.at(-1)] = value;
}

function privateKeyFromVector(vector) {
  return createPrivateKey({
    format: "der",
    key: Buffer.concat([
      rawEd25519PrivatePrefix,
      Buffer.from(vector.privateKeySeedHex, "hex"),
    ]),
    type: "pkcs8",
  });
}

function signDocument(document, privateKey) {
  document.signature.value = sign(
    null,
    createSigningInput(document),
    privateKey,
  ).toString("base64url");
  return document;
}

function artifactDocument(original, bytes, privateKey) {
  const document = structuredClone(original);
  document.statement.subject.sizeBytes = bytes.byteLength;
  document.statement.subject.digest.value = sha256(bytes);
  return signDocument(document, privateKey);
}

async function* chunks(bytes, boundaries) {
  let offset = 0;
  let index = 0;
  while (offset < bytes.byteLength) {
    const size = boundaries[index % boundaries.length];
    yield bytes.subarray(offset, Math.min(offset + size, bytes.byteLength));
    offset += size;
    index += 1;
  }
}

for (const name of ["hosted", "self-hosted"]) {
  test(`${name} vector validates, reproduces, and verifies`, async () => {
    const document = await readJson(`valid/${name}.json`);
    const vector = await readJson(`vectors/${name}.json`);
    const canonical = canonicalizeStatement(document.statement);
    const input = createSigningInput(document);
    const privateKey = privateKeyFromVector(vector);

    assert.equal(sha256(canonical), vector.canonicalStatementSha256);
    assert.equal(sha256(input), vector.signingInputSha256);
    assert.equal(
      sign(null, input, privateKey).toString("base64url"),
      vector.signatureBase64Url,
    );
    assert.equal(
      verifyAttestationSignature(
        document,
        Buffer.from(vector.publicKeyHex, "hex"),
      ),
      true,
    );

    await assert.rejects(
      verifyAttestedArtifact(
        document,
        Buffer.from(vector.publicKeyHex, "hex"),
        chunks(Buffer.alloc(document.statement.subject.sizeBytes), [8191]),
      ),
      AttestationDigestError,
    );

    const tampered = structuredClone(document);
    tampered.statement.subject.sizeBytes += 1;
    assert.equal(
      verifyAttestationSignature(
        tampered,
        Buffer.from(vector.publicKeyHex, "hex"),
      ),
      false,
    );

    const relabeled = structuredClone(document);
    relabeled.signature.keyId += "-rotated";
    assert.equal(
      verifyAttestationSignature(
        relabeled,
        Buffer.from(vector.publicKeyHex, "hex"),
      ),
      false,
    );
  });
}

test("invalid golden mutations fail with the expected keyword and path", async () => {
  const original = await readJson("valid/hosted.json");
  const cases = await readJson("invalid/cases.json");

  for (const fixture of cases) {
    const document = structuredClone(original);
    setPath(document, fixture.path, fixture.value);
    assert.throws(
      () => validateAttestation(document),
      (error) =>
        error instanceof AttestationError &&
        error.errors.some(
          (issue) =>
            issue.keyword === fixture.validator &&
            issue.instancePath ===
              (fixture.errorPath.length === 0
                ? ""
                : `/${fixture.errorPath.join("/")}`),
        ),
      fixture.name,
    );
  }
});

test("streaming verification accepts varied chunk boundaries", async () => {
  const original = await readJson("valid/hosted.json");
  const vector = await readJson("vectors/hosted.json");
  const publicKey = Buffer.from(vector.publicKeyHex, "hex");
  const privateKey = privateKeyFromVector(vector);
  const bytes = Buffer.allocUnsafe(257 * 1024 + 19);
  for (let index = 0; index < bytes.byteLength; index += 1) {
    bytes[index] = (index * 31 + 17) & 0xff;
  }
  const document = artifactDocument(original, bytes, privateKey);
  const publicKeyObject = createPublicKey(privateKey);

  for (const boundaries of [
    [1],
    [2, 3, 5, 7, 11],
    [4096],
    [65537, 13, 8192],
    [bytes.byteLength],
  ]) {
    const result = await verifyAttestedArtifact(
      document,
      publicKey,
      chunks(bytes, boundaries),
    );
    assert.deepEqual(result, {
      sizeBytes: bytes.byteLength,
      digest: { algorithm: "sha256", value: sha256(bytes) },
    });
  }

  await verifyAttestedArtifact(document, publicKeyObject, [bytes]);
});

test("artifact byte tampering and a signature-valid wrong JAR fail by digest", async () => {
  const original = await readJson("valid/hosted.json");
  const vector = await readJson("vectors/hosted.json");
  const publicKey = Buffer.from(vector.publicKeyHex, "hex");
  const privateKey = privateKeyFromVector(vector);
  const expected = Buffer.from("signed artifact bytes\n".repeat(4096));
  const document = artifactDocument(original, expected, privateKey);
  const wrongJar = Buffer.from(expected);
  wrongJar[wrongJar.byteLength - 1] ^= 0x80;

  await assert.rejects(
    verifyAttestedArtifact(document, publicKey, chunks(wrongJar, [17, 4093])),
    (error) =>
      error instanceof AttestationDigestError &&
      error.code === "ERR_ATTESTATION_DIGEST" &&
      error.expectedDigest === sha256(expected) &&
      error.observedDigest === sha256(wrongJar),
  );
});

test("truncation and appended bytes report precise sizes and stop reading", async () => {
  const original = await readJson("valid/hosted.json");
  const vector = await readJson("vectors/hosted.json");
  const publicKey = Buffer.from(vector.publicKeyHex, "hex");
  const privateKey = privateKeyFromVector(vector);
  const expected = Buffer.alloc(16 * 1024, 0x5a);
  const document = artifactDocument(original, expected, privateKey);

  await assert.rejects(
    verifyAttestedArtifact(
      document,
      publicKey,
      chunks(expected.subarray(0, -7), [1024]),
    ),
    (error) =>
      error instanceof AttestationSizeError &&
      error.code === "ERR_ATTESTATION_SIZE" &&
      error.reason === "truncated" &&
      error.expectedSizeBytes === expected.byteLength &&
      error.observedSizeBytes === expected.byteLength - 7,
  );

  let chunksRequested = 0;
  let iteratorClosed = false;
  async function* appendedArtifact() {
    try {
      chunksRequested += 1;
      yield expected;
      chunksRequested += 1;
      yield Buffer.from([0x00]);
      chunksRequested += 1;
      yield Buffer.alloc(1024 * 1024);
    } finally {
      iteratorClosed = true;
    }
  }

  await assert.rejects(
    verifyAttestedArtifact(document, publicKey, appendedArtifact()),
    (error) =>
      error instanceof AttestationSizeError &&
      error.reason === "exceeded" &&
      error.expectedSizeBytes === expected.byteLength &&
      error.observedSizeBytes === expected.byteLength + 1,
  );
  assert.equal(chunksRequested, 2);
  assert.equal(iteratorClosed, true);
});

test("incorrect signed size and digest fail after valid signature verification", async () => {
  const original = await readJson("valid/hosted.json");
  const vector = await readJson("vectors/hosted.json");
  const publicKey = Buffer.from(vector.publicKeyHex, "hex");
  const privateKey = privateKeyFromVector(vector);
  const bytes = Buffer.from("the local artifact");

  const wrongSize = artifactDocument(original, bytes, privateKey);
  wrongSize.statement.subject.sizeBytes += 3;
  signDocument(wrongSize, privateKey);
  await assert.rejects(
    verifyAttestedArtifact(wrongSize, publicKey, [bytes]),
    AttestationSizeError,
  );

  const wrongDigest = artifactDocument(original, bytes, privateKey);
  wrongDigest.statement.subject.digest.value = "00".repeat(32);
  signDocument(wrongDigest, privateKey);
  await assert.rejects(
    verifyAttestedArtifact(wrongDigest, publicKey, [bytes]),
    AttestationDigestError,
  );
});

test("schema, public-key, and signature failures are distinct and consume no bytes", async () => {
  const original = await readJson("valid/hosted.json");
  const vector = await readJson("vectors/hosted.json");
  const publicKey = Buffer.from(vector.publicKeyHex, "hex");

  let bytesRequested = 0;
  async function* observedBytes() {
    bytesRequested += 1;
    yield Buffer.alloc(original.statement.subject.sizeBytes);
  }

  const invalidEnvelope = structuredClone(original);
  invalidEnvelope.untrusted = true;
  await assert.rejects(
    verifyAttestedArtifact(invalidEnvelope, publicKey, observedBytes()),
    (error) =>
      error instanceof AttestationSchemaError &&
      error instanceof AttestationError &&
      error.code === "ERR_ATTESTATION_SCHEMA" &&
      error.errors.some((issue) => issue.keyword === "additionalProperties"),
  );
  assert.equal(bytesRequested, 0);

  const malformedSignature = structuredClone(original);
  malformedSignature.signature.value = "AAAA==";
  await assert.rejects(
    verifyAttestedArtifact(malformedSignature, publicKey, observedBytes()),
    (error) =>
      error instanceof AttestationSignatureError &&
      error.code === "ERR_ATTESTATION_SIGNATURE" &&
      error.reason === "malformed" &&
      error.errors.some((issue) => issue.instancePath === "/signature/value") &&
      error.cause instanceof AttestationSchemaError,
  );
  assert.equal(bytesRequested, 0);

  const mixedInvalidEnvelope = structuredClone(malformedSignature);
  mixedInvalidEnvelope.untrusted = true;
  await assert.rejects(
    verifyAttestedArtifact(mixedInvalidEnvelope, publicKey, observedBytes()),
    (error) =>
      error instanceof AttestationSchemaError &&
      error.errors.some((issue) => issue.instancePath === "") &&
      error.errors.some((issue) => issue.instancePath === "/signature/value"),
  );
  assert.equal(bytesRequested, 0);

  await assert.rejects(
    verifyAttestedArtifact(original, Buffer.alloc(31), observedBytes()),
    (error) =>
      error instanceof AttestationKeyError &&
      error.code === "ERR_ATTESTATION_KEY" &&
      error.cause instanceof Error,
  );
  assert.equal(bytesRequested, 0);

  const wrongSignature = structuredClone(original);
  wrongSignature.signature.value = `${
    wrongSignature.signature.value[0] === "A" ? "B" : "A"
  }${wrongSignature.signature.value.slice(1)}`;
  await assert.rejects(
    verifyAttestedArtifact(wrongSignature, publicKey, observedBytes()),
    (error) =>
      error instanceof AttestationSignatureError &&
      error.code === "ERR_ATTESTATION_SIGNATURE" &&
      error.reason === "mismatch",
  );
  assert.equal(bytesRequested, 0);
});

test("verification is bound to bytes, not the signed filename", async () => {
  const original = await readJson("valid/hosted.json");
  const vector = await readJson("vectors/hosted.json");
  const publicKey = Buffer.from(vector.publicKeyHex, "hex");
  const privateKey = privateKeyFromVector(vector);
  const bytes = Buffer.from("artifact identity is its exact byte sequence");
  const document = artifactDocument(original, bytes, privateKey);
  document.statement.subject.name = "unrelated-display-name.jar";
  signDocument(document, privateKey);

  await verifyAttestedArtifact(document, publicKey, chunks(bytes, [4, 9]));
});

test("large generated artifacts are verified with bounded memory", async () => {
  const original = await readJson("valid/hosted.json");
  const vector = await readJson("vectors/hosted.json");
  const publicKey = Buffer.from(vector.publicKeyHex, "hex");
  const privateKey = privateKeyFromVector(vector);
  const sizeBytes = 128 * 1024 * 1024;
  const chunkSize = 256 * 1024;
  const chunkCount = sizeBytes / chunkSize;
  const template = Buffer.alloc(chunkSize, 0xa5);
  const expectedHash = createHash("sha256");
  for (let index = 0; index < chunkCount; index += 1) {
    expectedHash.update(template);
  }

  const document = structuredClone(original);
  document.statement.subject.sizeBytes = sizeBytes;
  document.statement.subject.digest.value = expectedHash.digest("hex");
  signDocument(document, privateKey);

  const baselineArrayBuffers = process.memoryUsage().arrayBuffers;
  let maximumArrayBuffers = baselineArrayBuffers;
  let generatedChunks = 0;
  async function* generatedArtifact() {
    for (let index = 0; index < chunkCount; index += 1) {
      const chunk = Buffer.alloc(chunkSize, 0xa5);
      generatedChunks += 1;
      yield chunk;
      maximumArrayBuffers = Math.max(
        maximumArrayBuffers,
        process.memoryUsage().arrayBuffers,
      );
    }
  }

  const result = await verifyAttestedArtifact(
    document,
    publicKey,
    generatedArtifact(),
  );
  assert.equal(result.sizeBytes, sizeBytes);
  assert.equal(generatedChunks, chunkCount);
  assert.ok(
    maximumArrayBuffers - baselineArrayBuffers < 96 * 1024 * 1024,
    `array-buffer growth was ${maximumArrayBuffers - baselineArrayBuffers} bytes`,
  );
});
