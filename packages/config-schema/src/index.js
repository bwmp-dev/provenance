import { createHash } from "node:crypto";

import Ajv2020 from "ajv/dist/2020.js";
import { isAlias, isMap, isScalar, isSeq, parseDocument } from "yaml";

import schema from "./schema.json" with { type: "json" };

const ajv = new Ajv2020({ allErrors: true, strict: true });
ajv.addFormat("regex", {
  type: "string",
  validate(value) {
    try {
      new RegExp(value, "u");
      return true;
    } catch {
      return false;
    }
  },
});

const validate = ajv.compile(schema);

export class ConfigurationError extends Error {
  constructor(message, errors = []) {
    super(message);
    this.name = "ConfigurationError";
    this.errors = errors;
  }
}

function assertUnicodeScalarValue(value) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw new ConfigurationError(
          "strings must not contain lone Unicode surrogates",
        );
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new ConfigurationError(
        "strings must not contain lone Unicode surrogates",
      );
    }
  }
}

function scalarValue(node) {
  const value = node.value;
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    if (typeof value === "string") {
      assertUnicodeScalarValue(value);
    }
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  throw new ConfigurationError(
    "configuration values must use the JSON data model",
  );
}

function convertYamlNode(node) {
  if (node === null) {
    return null;
  }
  if (isAlias(node)) {
    throw new ConfigurationError("YAML aliases are not permitted");
  }
  if (isScalar(node)) {
    if (node.tag && !node.tag.startsWith("tag:yaml.org,2002:")) {
      throw new ConfigurationError(`YAML tag ${node.tag} is not permitted`);
    }
    return scalarValue(node);
  }
  if (isSeq(node)) {
    return node.items.map(convertYamlNode);
  }
  if (isMap(node)) {
    const result = {};
    for (const pair of node.items) {
      if (!isScalar(pair.key) || typeof pair.key.value !== "string") {
        throw new ConfigurationError(
          "configuration mapping keys must be strings",
        );
      }
      const key = pair.key.value;
      assertUnicodeScalarValue(key);
      if (Object.hasOwn(result, key)) {
        throw new ConfigurationError(`duplicate configuration key: ${key}`);
      }
      Object.defineProperty(result, key, {
        configurable: true,
        enumerable: true,
        value: convertYamlNode(pair.value),
        writable: true,
      });
    }
    return result;
  }
  throw new ConfigurationError("unsupported YAML node");
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
    if (!Number.isFinite(value)) {
      throw new ConfigurationError("numbers must be finite");
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
  throw new ConfigurationError(
    "configuration values must use the JSON data model",
  );
}

export function validateConfiguration(value) {
  if (!validate(value)) {
    throw new ConfigurationError("configuration does not satisfy schema v1", [
      ...validate.errors,
    ]);
  }
  return value;
}

export function parseConfiguration(source) {
  const document = parseDocument(source, {
    logLevel: "silent",
    schema: "core",
    strict: true,
    uniqueKeys: true,
    version: "1.2",
  });
  if (document.errors.length > 0 || document.warnings.length > 0) {
    const issues = [...document.errors, ...document.warnings];
    throw new ConfigurationError(issues[0].message, issues);
  }
  return validateConfiguration(convertYamlNode(document.contents));
}

export function normalizeConfiguration(value) {
  validateConfiguration(value);
  return canonicalize(value);
}

export function hashConfiguration(value) {
  return createHash("sha256")
    .update(normalizeConfiguration(value))
    .digest("hex");
}

export { schema };
