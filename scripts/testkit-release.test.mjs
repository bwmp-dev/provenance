import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  checksumFilename,
  manifestFilename,
  testkitManifest,
  testkitMatrix,
  testkitSourceCommit,
  validateTestkitIdentity,
} from "./testkit-release.mjs";

const tag = "testkit-v0.1.0-alpha.3";

test("audited testkit matrix has the expected immutable identity", () => {
  assert.equal(testkitSourceCommit.length, 40);
  assert.equal(testkitMatrix.length, 15);
  assert.deepEqual(
    testkitMatrix.map(({ type }) => type),
    ["probe", ...Array(6).fill("benign"), ...Array(8).fill("hostile")],
  );
  assert.deepEqual(testkitMatrix[0], {
    id: "paper-probe",
    type: "probe",
    source: "plugins/paper-probe/build/libs/paper-probe-0.1.0.jar",
    sha256: "abbccf45831ef998466542b19169731b9ec4f8a6c3525fce4d7a2c0b5f4b4b43",
    sizeBytes: 478837,
  });
});

test("release identity is a dedicated testkit SemVer tag and audited source", () => {
  assert.deepEqual(validateTestkitIdentity(tag, testkitSourceCommit), {
    sourceCommit: testkitSourceCommit,
    tag,
  });
  for (const invalidTag of [
    "v0.1.0-alpha.3",
    "testkit-latest",
    "testkit-v01.0.0",
    "testkit-v1.0",
  ]) {
    assert.throws(() =>
      validateTestkitIdentity(invalidTag, testkitSourceCommit),
    );
  }
  assert.throws(() =>
    validateTestkitIdentity(tag, testkitSourceCommit.slice(0, 12)),
  );
  assert.throws(() => validateTestkitIdentity(tag, "0".repeat(40)));
});

test("manifest and asset names bind tag and source identity", () => {
  const manifest = testkitManifest(tag, testkitSourceCommit);
  const prefix = `provenance-${tag}-${testkitSourceCommit}`;
  assert.equal(manifest.release.sourceCommit, testkitSourceCommit);
  assert.equal(manifest.release.tag, tag);
  assert.equal(manifest.artifacts.length, 15);
  assert.equal(
    new Set(manifest.artifacts.map(({ filename }) => filename)).size,
    15,
  );
  assert.ok(
    manifest.artifacts.every(({ filename }) => filename.startsWith(prefix)),
  );
  assert.equal(
    manifestFilename(tag, testkitSourceCommit),
    `${prefix}.manifest.json`,
  );
  assert.equal(checksumFilename(tag, testkitSourceCommit), `${prefix}.sha256`);
});

test("release workflow is pinned, build-only, and fail-closed", async () => {
  const workflow = await readFile(
    new URL("../.github/workflows/release-testkit.yml", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(workflow, /uses: [^\n]+@v\d/);
  assert.doesNotMatch(workflow, /--clobber/);
  assert.doesNotMatch(workflow, /java\s+-jar/);
  assert.match(workflow, /hostileFixtures/);
  assert.match(workflow, /verifyHostileFixtureArtifacts/);
  assert.match(workflow, /A tag or release already exists for/);
  assert.match(workflow, /contents: write/);
});
