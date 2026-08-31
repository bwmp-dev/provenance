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
