import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  ConfigurationError,
  hashConfiguration,
  normalizeConfiguration,
  parseConfiguration,
  validateConfiguration,
} from "../dist/index.js";

const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fixtures = resolve(packageDirectory, "../../schemas/fixtures/config");

async function read(path) {
  return readFile(resolve(fixtures, path), "utf8");
}

function setPath(document, path, value) {
  let target = document;
  for (const part of path.slice(0, -1)) {
    target = target[part];
  }
  target[path.at(-1)] = value;
}

test("valid YAML normalizes and hashes to the golden JSON", async () => {
  const value = parseConfiguration(await read("valid/hosted.yml"));
  const normalized = normalizeConfiguration(value);
  const golden = JSON.parse(await read("valid/hosted.normalized.json"));
  const expectedHash = (await read("valid/hosted.normalized.sha256")).trim();

  assert.deepEqual(value, golden);
  assert.equal(normalized.includes("\n"), false);
  assert.equal(hashConfiguration(value), expectedHash);
});

test("the self-hosted unrestricted fixture is schema-valid", async () => {
  const source = await read("valid/self-hosted-unrestricted.yml");
  assert.doesNotThrow(() => parseConfiguration(source));
});

test("invalid golden mutations fail with the expected keyword and path", async () => {
  const original = JSON.parse(await read("valid/hosted.normalized.json"));
  const cases = JSON.parse(await read("invalid/cases.json"));

  for (const fixture of cases) {
    const value = structuredClone(original);
    setPath(value, fixture.path, fixture.value);
    assert.throws(
      () => validateConfiguration(value),
      (error) =>
        error instanceof ConfigurationError &&
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

test("unsafe YAML and incomplete timestamp input are rejected", async () => {
  const names = [
    "alias.yml",
    "custom-tag.yml",
    "duplicate-key.yml",
    "non-finite.yml",
    "non-json-key.yml",
    "timestamp.yml",
  ];

  for (const name of names) {
    const source = await read(`invalid-yaml/${name}`);
    assert.throws(() => parseConfiguration(source), ConfigurationError, name);
  }
});

test("modern Paper config preserves 26.x matrix and API floor identities", async () => {
  const value = parseConfiguration(await read("valid/paper-26.yml"));
  assert.equal(value.paper.matrix[0].minecraftVersion, "26.1.2");
  assert.equal(value.paper.matrix[0].javaVersion, 25);
  assert.equal(value.paper.recommendations.apiFloor, "26.1");
  assert.deepEqual(JSON.parse(normalizeConfiguration(value)), value);
});

test("test-secret selection pins versions and rejects unsafe names or values", async () => {
  const original = JSON.parse(await read("valid/hosted.normalized.json"));
  for (const secrets of [{}, { token: 1, "api.token": 9007199254740991 }]) {
    const value = structuredClone(original);
    value.tests.secrets = secrets;
    assert.doesNotThrow(() => validateConfiguration(value));
    assert.deepEqual(
      JSON.parse(normalizeConfiguration(value)).tests.secrets,
      secrets,
    );
    assert.notEqual(hashConfiguration(value), hashConfiguration(original));
  }
  for (const secrets of [
    { token: "latest" },
    { token: "private-value" },
    { token: 0 },
    { token: -1 },
    { token: 1.5 },
    { token: 9007199254740992 },
    { "../token": 1 },
    { TOKEN: 1 },
    { "a/b": 1 },
    { "a\\b": 1 },
    { "a..b": 1 },
    { "": 1 },
    { ["a".repeat(64)]: 1 },
    Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`token-${i}`, 1])),
    null,
    [],
  ]) {
    const value = structuredClone(original);
    value.tests.secrets = secrets;
    assert.throws(() => validateConfiguration(value), ConfigurationError);
  }
});
