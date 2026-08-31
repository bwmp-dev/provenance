import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFile, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { buildContractRelease } from "./contract-release.mjs";
import { verifyContractRelease } from "./verify-contract-release.mjs";

const version = "0.0.0-contract-test.1";
const sourceCommit = "0".repeat(40);
const createdAt = "2000-01-01T00:00:00Z";

function digest(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

test("contract release is reproducible and its consumers compile", async (t) => {
  const firstDirectory = await mkdtemp(
    join(tmpdir(), "provenance-release-first-"),
  );
  const secondDirectory = await mkdtemp(
    join(tmpdir(), "provenance-release-second-"),
  );
  try {
    const options = { createdAt, sourceCommit, version };
    await buildContractRelease({
      ...options,
      outputDirectory: firstDirectory,
    });
    await buildContractRelease({
      ...options,
      outputDirectory: secondDirectory,
    });
    const manifest = await verifyContractRelease({
      consumers: true,
      directory: firstDirectory,
      version,
    });
    const sbom = JSON.parse(
      await readFile(resolve(firstDirectory, manifest.sbom.filename), "utf8"),
    );
    assert.equal(sbom.packages.length, 5);
    assert.equal(
      sbom.relationships.length,
      sbom.packages.length + sbom.files.length,
    );
    t.diagnostic(
      `SPDX 2.3 SBOM covers ${sbom.packages.length} packages and ${sbom.files.length} archived files`,
    );

    const firstFiles = (await readdir(firstDirectory)).sort();
    const secondFiles = (await readdir(secondDirectory)).sort();
    assert.deepEqual(secondFiles, firstFiles);
    for (const filename of firstFiles) {
      const first = await readFile(resolve(firstDirectory, filename));
      const second = await readFile(resolve(secondDirectory, filename));
      assert.deepEqual(second, first, `${filename} is not reproducible`);
      t.diagnostic(`${digest(first)}  ${filename}`);
    }

    const tamperedArchive = manifest.artifacts[0].filename;
    await appendFile(resolve(secondDirectory, tamperedArchive), "tampered");
    await assert.rejects(
      verifyContractRelease({
        directory: secondDirectory,
        version,
      }),
      new RegExp(`${tamperedArchive} (?:size|digest) differs`),
    );
  } finally {
    await rm(firstDirectory, { force: true, recursive: true });
    await rm(secondDirectory, { force: true, recursive: true });
  }
});

test("contract release rejects invalid identities and non-empty output", async () => {
  const outputDirectory = await mkdtemp(
    join(tmpdir(), "provenance-release-nonempty-"),
  );
  try {
    await assert.rejects(
      buildContractRelease({
        createdAt,
        outputDirectory,
        sourceCommit,
        version: "not-semver",
      }),
      /not valid SemVer/,
    );
    await assert.rejects(
      buildContractRelease({
        createdAt,
        outputDirectory,
        sourceCommit: "short",
        version,
      }),
      /40-character Git SHA/,
    );
    await assert.rejects(
      buildContractRelease({
        createdAt: "2000-01-01",
        outputDirectory,
        sourceCommit,
        version,
      }),
      /RFC 3339 UTC timestamp/,
    );

    await appendFile(resolve(outputDirectory, "existing"), "content");
    await assert.rejects(
      buildContractRelease({
        createdAt,
        outputDirectory,
        sourceCommit,
        version,
      }),
      /output directory is not empty/,
    );
  } finally {
    await rm(outputDirectory, { force: true, recursive: true });
  }
});
