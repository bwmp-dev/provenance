import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const directory = dirname(fileURLToPath(import.meta.url));
const fixtures = resolve(directory, "../fixtures/attestation");
const domain = Buffer.from("Provenance Attestation v1\n", "utf8");

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError("attestation v1 numbers must be safe integers");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  throw new TypeError(`unsupported JSON value: ${typeof value}`);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

const vectors = ["hosted.json", "self-hosted.json"];
for (const name of vectors) {
  const vectorPath = join(fixtures, "vectors", name);
  const vector = JSON.parse(await readFile(vectorPath, "utf8"));
  const document = JSON.parse(await readFile(resolve(dirname(vectorPath), vector.fixture), "utf8"));
  const canonical = Buffer.from(canonicalize(document.statement), "utf8");
  const payload = Buffer.concat([
    domain,
    Buffer.from(document.signature.keyId, "utf8"),
    Buffer.from("\n", "utf8"),
    canonical,
  ]);
  const publicKey = createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(vector.publicKeyHex, "hex"),
    ]),
    format: "der",
    type: "spki",
  });
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(vector.privateKeySeedHex, "hex"),
    ]),
    format: "der",
    type: "pkcs8",
  });
  const signature = Buffer.from(vector.signatureBase64Url, "base64url");

  if (sha256(canonical) !== vector.canonicalStatementSha256) {
    throw new Error(`canonical statement changed for ${name}`);
  }
  if (sha256(payload) !== vector.signingInputSha256) {
    throw new Error(`signing input changed for ${name}`);
  }
  if (!verify(null, payload, publicKey, signature)) {
    throw new Error(`signature verification failed for ${name}`);
  }
  if (!sign(null, payload, privateKey).equals(signature)) {
    throw new Error(`signature reproduction failed for ${name}`);
  }
}

console.log(`independently reproduced and verified ${vectors.length} Ed25519 vectors with Node.js`);
