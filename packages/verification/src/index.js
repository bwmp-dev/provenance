import { createPublicKey, verify } from "node:crypto";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import schema from "./schema.json" with { type: "json" };

const domain = Buffer.from("Provenance Attestation v1\n", "utf8");
const rawEd25519Prefix = Buffer.from("302a300506032b6570032100", "hex");
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(schema);

export class AttestationError extends Error {
  constructor(message, errors = []) {
    super(message);
    this.name = "AttestationError";
    this.errors = errors;
  }
}

function assertUnicodeScalarValue(value) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw new AttestationError(
          "strings must not contain lone Unicode surrogates",
        );
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new AttestationError(
        "strings must not contain lone Unicode surrogates",
      );
    }
  }
}

function canonicalize(value) {
  if (value === null || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    assertUnicodeScalarValue(value);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new AttestationError(
        "attestation v1 numbers must be safe integers",
      );
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => {
        assertUnicodeScalarValue(key);
        return `${JSON.stringify(key)}:${canonicalize(value[key])}`;
      })
      .join(",")}}`;
  }
  throw new AttestationError("attestation values must use the JSON data model");
}

function publicKeyObject(publicKey) {
  if (Buffer.isBuffer(publicKey) || publicKey instanceof Uint8Array) {
    const bytes = Buffer.from(publicKey);
    if (bytes.length !== 32) {
      throw new AttestationError(
        "an Ed25519 raw public key must contain 32 bytes",
      );
    }
    return createPublicKey({
      format: "der",
      key: Buffer.concat([rawEd25519Prefix, bytes]),
      type: "spki",
    });
  }
  return createPublicKey(publicKey);
}

export function validateAttestation(document) {
  if (!validate(document)) {
    throw new AttestationError("attestation does not satisfy schema v1", [
      ...validate.errors,
    ]);
  }
  return document;
}

export function canonicalizeStatement(statement) {
  return Buffer.from(canonicalize(statement), "utf8");
}

export function createSigningInput(document) {
  validateAttestation(document);
  return Buffer.concat([
    domain,
    Buffer.from(document.signature.keyId, "utf8"),
    Buffer.from("\n", "utf8"),
    canonicalizeStatement(document.statement),
  ]);
}

export function verifyAttestationSignature(document, publicKey) {
  const input = createSigningInput(document);
  const signature = Buffer.from(document.signature.value, "base64url");
  if (signature.length !== 64) {
    return false;
  }
  return verify(null, input, publicKeyObject(publicKey), signature);
}

export { schema };
