import assert from "node:assert/strict";
import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  AttestationError,
  canonicalizeStatement,
  createSigningInput,
  validateAttestation,
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

for (const name of ["hosted", "self-hosted"]) {
  test(`${name} vector validates, reproduces, and verifies`, async () => {
    const document = await readJson(`valid/${name}.json`);
    const vector = await readJson(`vectors/${name}.json`);
    const canonical = canonicalizeStatement(document.statement);
    const input = createSigningInput(document);
    const privateKey = createPrivateKey({
      format: "der",
      key: Buffer.concat([
        rawEd25519PrivatePrefix,
        Buffer.from(vector.privateKeySeedHex, "hex"),
      ]),
      type: "pkcs8",
    });

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
