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
const arrayBufferByteLength = Object.getOwnPropertyDescriptor(
  ArrayBuffer.prototype,
  "byteLength",
).get;
const dataViewBuffer = Object.getOwnPropertyDescriptor(
  DataView.prototype,
  "buffer",
).get;
const dataViewByteLength = Object.getOwnPropertyDescriptor(
  DataView.prototype,
  "byteLength",
).get;
const dataViewByteOffset = Object.getOwnPropertyDescriptor(
  DataView.prototype,
  "byteOffset",
).get;
const maxAttestationSnapshotDepth = 64;
const maxAttestationSnapshotNodes = 100_000;
const maxAttestationSnapshotArrayLength = 1_000;
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
  constructor(errors, options = undefined) {
    super("attestation does not satisfy schema v1", errors, options);
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

function snapshotSchemaError(instancePath, reason, message, cause = undefined) {
  return new AttestationSchemaError(
    [
      {
        instancePath,
        schemaPath: "#/jsonDataSnapshot",
        keyword: "jsonDataSnapshot",
        params: { reason },
        message,
      },
    ],
    cause === undefined ? undefined : { cause },
  );
}

function snapshotPropertyValue(value, key, instancePath) {
  try {
    return Reflect.get(value, key);
  } catch (cause) {
    throw snapshotSchemaError(
      instancePath,
      "read",
      "must be readable as JSON data",
      cause,
    );
  }
}

function snapshotOwnKeys(value, instancePath) {
  try {
    return Reflect.ownKeys(value);
  } catch (cause) {
    throw snapshotSchemaError(
      instancePath,
      "read",
      "must expose stable JSON object properties",
      cause,
    );
  }
}

function snapshotPropertyDescriptor(value, key, instancePath) {
  try {
    return Reflect.getOwnPropertyDescriptor(value, key);
  } catch (cause) {
    throw snapshotSchemaError(
      instancePath,
      "read",
      "must expose stable JSON property descriptors",
      cause,
    );
  }
}

function snapshotIsArray(value, instancePath) {
  try {
    return Array.isArray(value);
  } catch (cause) {
    throw snapshotSchemaError(
      instancePath,
      "read",
      "must expose a readable JSON container shape",
      cause,
    );
  }
}

function snapshotJsonValue(value, instancePath, depth, state) {
  state.nodes += 1;
  if (state.nodes > maxAttestationSnapshotNodes) {
    throw snapshotSchemaError(
      instancePath,
      "size",
      `must contain at most ${maxAttestationSnapshotNodes} JSON values`,
    );
  }
  if (depth > maxAttestationSnapshotDepth) {
    throw snapshotSchemaError(
      instancePath,
      "depth",
      `must be nested at most ${maxAttestationSnapshotDepth} levels deep`,
    );
  }

  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw snapshotSchemaError(
        instancePath,
        "type",
        "must contain only finite JSON numbers",
      );
    }
    return value;
  }
  if (typeof value !== "object") {
    throw snapshotSchemaError(
      instancePath,
      "type",
      "must contain only JSON data values",
    );
  }
  if (state.ancestors.has(value)) {
    throw snapshotSchemaError(
      instancePath,
      "cycle",
      "must not contain cyclic references",
    );
  }

  state.ancestors.add(value);
  try {
    if (snapshotIsArray(value, instancePath)) {
      const length = snapshotPropertyValue(value, "length", instancePath);
      if (
        !Number.isSafeInteger(length) ||
        length < 0 ||
        length > maxAttestationSnapshotArrayLength
      ) {
        throw snapshotSchemaError(
          instancePath,
          "size",
          `arrays must contain at most ${maxAttestationSnapshotArrayLength} items`,
        );
      }
      const snapshot = new Array(length);
      for (let index = 0; index < length; index += 1) {
        const memberPath = `${instancePath}/${index}`;
        snapshot[index] = snapshotJsonValue(
          snapshotPropertyValue(value, String(index), memberPath),
          memberPath,
          depth + 1,
          state,
        );
      }
      return Object.freeze(snapshot);
    }

    const keys = snapshotOwnKeys(value, instancePath);
    if (state.nodes + keys.length > maxAttestationSnapshotNodes) {
      throw snapshotSchemaError(
        instancePath,
        "size",
        `must contain at most ${maxAttestationSnapshotNodes} JSON values`,
      );
    }
    const snapshot = {};
    for (const key of keys) {
      if (typeof key !== "string") {
        continue;
      }
      const memberPath = `${instancePath}/${jsonPointerToken(key)}`;
      const descriptor = snapshotPropertyDescriptor(value, key, memberPath);
      if (descriptor === undefined) {
        throw snapshotSchemaError(
          memberPath,
          "read",
          "must remain present while its JSON value is read",
        );
      }
      if (!descriptor.enumerable) {
        continue;
      }
      Object.defineProperty(snapshot, key, {
        configurable: true,
        enumerable: true,
        value: snapshotJsonValue(
          snapshotPropertyValue(value, key, memberPath),
          memberPath,
          depth + 1,
          state,
        ),
        writable: true,
      });
    }
    return Object.freeze(snapshot);
  } finally {
    state.ancestors.delete(value);
  }
}

function snapshotAttestation(document) {
  return snapshotJsonValue(document, "", 0, {
    ancestors: new WeakSet(),
    nodes: 0,
  });
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

function copyTypedArrayBytes(value) {
  const buffer = Reflect.apply(typedArrayBuffer, value, []);
  const byteOffset = Reflect.apply(typedArrayByteOffset, value, []);
  const byteLength = Reflect.apply(typedArrayByteLength, value, []);
  return Buffer.from(new Uint8Array(buffer, byteOffset, byteLength));
}

function copyKeyBytes(value) {
  if (ArrayBuffer.isView(value)) {
    if (value instanceof DataView) {
      const buffer = Reflect.apply(dataViewBuffer, value, []);
      const byteOffset = Reflect.apply(dataViewByteOffset, value, []);
      const byteLength = Reflect.apply(dataViewByteLength, value, []);
      return Buffer.from(new Uint8Array(buffer, byteOffset, byteLength));
    }
    return copyTypedArrayBytes(value);
  }
  if (value instanceof ArrayBuffer) {
    const byteLength = Reflect.apply(arrayBufferByteLength, value, []);
    return Buffer.from(new Uint8Array(value, 0, byteLength));
  }
  throw new TypeError("encoded key material must be bytes");
}

function snapshotJwk(value) {
  if (value === null || typeof value !== "object") {
    throw new TypeError("a JWK key must be an object");
  }
  const kty = Reflect.get(value, "kty");
  const crv = Reflect.get(value, "crv");
  const x = Reflect.get(value, "x");
  const d = Reflect.get(value, "d");
  const keyOps = Reflect.get(value, "key_ops");
  const ext = Reflect.get(value, "ext");
  if (d !== undefined) {
    throw new TypeError("the supplied JWK contains private key material");
  }
  const key = { kty, crv, x };
  if (keyOps !== undefined) {
    if (
      !Array.isArray(keyOps) ||
      !keyOps.every((item) => typeof item === "string")
    ) {
      throw new TypeError("JWK key operations must be an array of strings");
    }
    key.key_ops = [...keyOps];
  }
  if (ext !== undefined) {
    key.ext = ext;
  }
  return Object.freeze(key);
}

function snapshotKeyDescriptor(value) {
  const keyValue = Reflect.get(value, "key");
  const format = Reflect.get(value, "format");
  const type = Reflect.get(value, "type");
  const encoding = Reflect.get(value, "encoding");
  const passphraseValue = Reflect.get(value, "passphrase");
  const key =
    format === "jwk"
      ? snapshotJwk(keyValue)
      : typeof keyValue === "string"
        ? keyValue
        : copyKeyBytes(keyValue);
  const descriptor = { key };
  if (format !== undefined) {
    descriptor.format = format;
  }
  if (type !== undefined) {
    descriptor.type = type;
  }
  if (encoding !== undefined) {
    descriptor.encoding = encoding;
  }
  if (passphraseValue !== undefined) {
    descriptor.passphrase =
      typeof passphraseValue === "string"
        ? passphraseValue
        : copyKeyBytes(passphraseValue);
  }
  return Object.freeze(descriptor);
}

function containsPrivatePem(value) {
  const key = typeof value === "string" ? value : value.key;
  if (typeof key !== "string" && !Buffer.isBuffer(key)) {
    return false;
  }
  const pem = typeof key === "string" ? key : key.toString("ascii");
  return /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/.test(pem);
}

function publicKeyObject(publicKey) {
  try {
    let key;
    if (Buffer.isBuffer(publicKey) || publicKey instanceof Uint8Array) {
      const bytes = copyTypedArrayBytes(publicKey);
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
    } else if (publicKey instanceof CryptoKey) {
      key = KeyObject.from(publicKey);
      if (key.type !== "public") {
        throw new TypeError("the supplied key is not a public key");
      }
    } else {
      const input =
        typeof publicKey === "string"
          ? publicKey
          : snapshotKeyDescriptor(publicKey);
      if (containsPrivatePem(input)) {
        throw new TypeError("the supplied key contains private key material");
      }
      if (input.format === "der" && input.type !== "spki") {
        throw new TypeError("a DER public key must use SPKI encoding");
      }
      let containsPrivateMaterial = true;
      try {
        createPrivateKey(input);
      } catch {
        containsPrivateMaterial = false;
      }
      if (containsPrivateMaterial) {
        throw new TypeError("the supplied key contains private key material");
      }
      key = createPublicKey(input);
      if (input.format === "der") {
        const canonical = key.export({ format: "der", type: "spki" });
        if (!input.key.equals(canonical)) {
          throw new TypeError(
            "the DER public key must contain exactly one canonical SPKI value",
          );
        }
      }
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
  const attestation = snapshotAttestation(document);
  try {
    validateAttestation(attestation);
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

  if (!verifyAttestationSignature(attestation, publicKey)) {
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

  const expectedSizeBytes = attestation.statement.subject.sizeBytes;
  const expectedDigest = attestation.statement.subject.digest.value;
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
