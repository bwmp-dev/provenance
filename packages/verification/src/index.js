import {
  createHash,
  createPrivateKey,
  createPublicKey,
  KeyObject,
  verify,
} from "node:crypto";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import schema from "./schema.json" with { type: "json" };

const domain = Buffer.from("Provenance Attestation v1\n", "utf8");
const rawEd25519Prefix = Buffer.from("302a300506032b6570032100", "hex");
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayBuffer = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  "buffer",
).get;
const typedArrayByteLength = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  "byteLength",
).get;
const typedArrayByteOffset = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  "byteOffset",
).get;
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(schema);

export class AttestationError extends Error {
  constructor(message, errors = [], options = undefined) {
    super(message, options);
    this.name = "AttestationError";
    this.code = "ERR_ATTESTATION";
    this.errors = errors;
  }
}

export class AttestationSchemaError extends AttestationError {
  constructor(errors) {
    super("attestation does not satisfy schema v1", errors);
    this.name = "AttestationSchemaError";
    this.code = "ERR_ATTESTATION_SCHEMA";
  }
}

export class AttestationKeyError extends AttestationError {
  constructor(message, options = undefined) {
    super(message, [], options);
    this.name = "AttestationKeyError";
    this.code = "ERR_ATTESTATION_KEY";
  }
}

export class AttestationSignatureError extends AttestationError {
  constructor(
    message = "attestation signature verification failed",
    errors = [],
    options = undefined,
  ) {
    super(message, errors, options);
    this.name = "AttestationSignatureError";
    this.code = "ERR_ATTESTATION_SIGNATURE";
    this.reason = errors.length === 0 ? "mismatch" : "malformed";
  }
}

export class AttestationSizeError extends AttestationError {
  constructor(expectedSizeBytes, observedSizeBytes) {
    const comparison =
      observedSizeBytes > expectedSizeBytes ? "exceeds" : "differs from";
    super(
      `artifact size ${comparison} signed size: expected ${expectedSizeBytes} bytes, observed ${observedSizeBytes} bytes`,
    );
    this.name = "AttestationSizeError";
    this.code = "ERR_ATTESTATION_SIZE";
    this.reason =
      observedSizeBytes > expectedSizeBytes ? "exceeded" : "truncated";
    this.expectedSizeBytes = expectedSizeBytes;
    this.observedSizeBytes = observedSizeBytes;
  }
}

export class AttestationDigestError extends AttestationError {
  constructor(expectedDigest, observedDigest) {
    super(
      `artifact SHA-256 differs from signed digest: expected ${expectedDigest}, observed ${observedDigest}`,
    );
    this.name = "AttestationDigestError";
    this.code = "ERR_ATTESTATION_DIGEST";
    this.algorithm = "sha256";
    this.expectedDigest = expectedDigest;
    this.observedDigest = observedDigest;
  }
}

function loneUnicodeSurrogateIndex(value) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        return index;
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return index;
    }
  }
  return -1;
}

function assertUnicodeScalarValue(value) {
  if (loneUnicodeSurrogateIndex(value) !== -1) {
    throw new AttestationError(
      "strings must not contain lone Unicode surrogates",
    );
  }
}

function jsonPointerToken(value) {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function collectUnicodeScalarErrors(value, instancePath = "", errors = []) {
  if (typeof value === "string") {
    const index = loneUnicodeSurrogateIndex(value);
    if (index !== -1) {
      errors.push({
        instancePath,
        schemaPath: "#/unicodeScalarValue",
        keyword: "unicodeScalarValue",
        params: { index },
        message: "must not contain lone Unicode surrogates",
      });
    }
    return errors;
  }

  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      collectUnicodeScalarErrors(
        value[index],
        `${instancePath}/${index}`,
        errors,
      );
    }
    return errors;
  }

  if (value && typeof value === "object") {
    for (const [key, member] of Object.entries(value)) {
      const memberPath = `${instancePath}/${jsonPointerToken(key)}`;
      if (loneUnicodeSurrogateIndex(key) !== -1) {
        errors.push({
          instancePath: memberPath,
          schemaPath: "#/unicodeScalarValue",
          keyword: "unicodeScalarValue",
          params: { propertyName: key },
          message: "property names must not contain lone Unicode surrogates",
        });
      }
      collectUnicodeScalarErrors(member, memberPath, errors);
    }
  }

  return errors;
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
  try {
    let key;
    if (Buffer.isBuffer(publicKey) || publicKey instanceof Uint8Array) {
      const bytes = Buffer.from(publicKey);
      if (bytes.length !== 32) {
        throw new TypeError("a raw public key must contain exactly 32 bytes");
      }
      key = createPublicKey({
        format: "der",
        key: Buffer.concat([rawEd25519Prefix, bytes]),
        type: "spki",
      });
    } else if (publicKey instanceof KeyObject) {
      if (publicKey.type !== "public") {
        throw new TypeError("the supplied key is not a public key");
      }
      key = publicKey;
    } else {
      let containsPrivateMaterial = true;
      try {
        createPrivateKey(publicKey);
      } catch {
        containsPrivateMaterial = false;
      }
      if (containsPrivateMaterial) {
        throw new TypeError("the supplied key contains private key material");
      }
      key = createPublicKey(publicKey);
    }

    if (key.asymmetricKeyType !== "ed25519") {
      throw new TypeError("the public key is not an Ed25519 key");
    }
    return key;
  } catch (cause) {
    throw new AttestationKeyError("invalid Ed25519 public key", { cause });
  }
}

export function validateAttestation(document) {
  const errors = validate(document) ? [] : [...validate.errors];
  const unicodeErrors = collectUnicodeScalarErrors(document);
  errors.push(...unicodeErrors);
  if (errors.length > 0) {
    throw new AttestationSchemaError(errors);
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

/**
 * Verify a signed attestation against artifact bytes supplied as an iterable or
 * async iterable of Uint8Array chunks. This function does not resolve key IDs,
 * open paths, inspect filenames, or perform network access.
 */
export async function verifyAttestedArtifact(
  document,
  publicKey,
  artifactBytes,
) {
  try {
    validateAttestation(document);
  } catch (error) {
    if (
      error instanceof AttestationSchemaError &&
      error.errors.length > 0 &&
      error.errors.every((issue) => issue.instancePath === "/signature/value")
    ) {
      throw new AttestationSignatureError(
        "attestation signature encoding is malformed",
        error.errors,
        { cause: error },
      );
    }
    throw error;
  }

  if (!verifyAttestationSignature(document, publicKey)) {
    throw new AttestationSignatureError();
  }

  if (
    artifactBytes === null ||
    artifactBytes === undefined ||
    (typeof artifactBytes[Symbol.asyncIterator] !== "function" &&
      typeof artifactBytes[Symbol.iterator] !== "function")
  ) {
    throw new TypeError(
      "artifact bytes must be an iterable or async iterable of Uint8Array chunks",
    );
  }

  const expectedSizeBytes = document.statement.subject.sizeBytes;
  const expectedDigest = document.statement.subject.digest.value;
  const hash = createHash("sha256");
  let observedSizeBytes = 0;

  for await (const chunk of artifactBytes) {
    if (!(chunk instanceof Uint8Array)) {
      throw new TypeError("artifact stream chunks must be Uint8Array values");
    }

    const buffer = Reflect.apply(typedArrayBuffer, chunk, []);
    const byteOffset = Reflect.apply(typedArrayByteOffset, chunk, []);
    const byteLength = Reflect.apply(typedArrayByteLength, chunk, []);
    const bytes = new Uint8Array(buffer, byteOffset, byteLength);
    observedSizeBytes += byteLength;
    if (observedSizeBytes > expectedSizeBytes) {
      throw new AttestationSizeError(expectedSizeBytes, observedSizeBytes);
    }
    hash.update(bytes);
  }

  if (observedSizeBytes !== expectedSizeBytes) {
    throw new AttestationSizeError(expectedSizeBytes, observedSizeBytes);
  }

  const observedDigest = hash.digest("hex");
  if (observedDigest !== expectedDigest) {
    throw new AttestationDigestError(expectedDigest, observedDigest);
  }

  return Object.freeze({
    sizeBytes: observedSizeBytes,
    digest: Object.freeze({ algorithm: "sha256", value: observedDigest }),
  });
}

export { schema };
