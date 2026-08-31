import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  appendFile,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { Header } from "tar";
import { gzipSync } from "node:zlib";

import {
  buildContractRelease,
  checksumName,
  releaseManifestName,
  sbomName,
} from "./contract-release.mjs";
import {
  archiveEntries,
  verifyContractRelease,
} from "./verify-contract-release.mjs";

const version = "0.0.0-contract-test.1";
const sourceCommit = "0".repeat(40);
const createdAt = "2000-01-01T00:00:00Z";

function digest(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

function json(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function runWorkspaceBuild() {
  const windows = process.platform === "win32";
  const result = spawnSync(
    windows ? (process.env.ComSpec ?? "cmd.exe") : "pnpm",
    windows ? ["/d", "/s", "/c", "pnpm build"] : ["build"],
    { cwd: resolve(import.meta.dirname, ".."), encoding: "utf8", shell: false },
  );
  assert.equal(
    result.status,
    0,
    `workspace build failed\n${result.stdout}\n${result.stderr}`,
  );
  const gradle = spawnSync(
    process.execPath,
    [
      resolve(import.meta.dirname, "run-gradle.mjs"),
      ":paper-probe:jar",
      ":fixture-success:jar",
    ],
    { cwd: resolve(import.meta.dirname, ".."), encoding: "utf8", shell: false },
  );
  assert.equal(
    gradle.status,
    0,
    `Paper metadata release build failed\n${gradle.stdout}\n${gradle.stderr}`,
  );
}

function runGradleBuild(...tasks) {
  const result = spawnSync(
    process.execPath,
    [resolve(import.meta.dirname, "run-gradle.mjs"), ...tasks],
    { cwd: resolve(import.meta.dirname, ".."), encoding: "utf8", shell: false },
  );
  assert.equal(
    result.status,
    0,
    `Gradle build failed\n${result.stdout}\n${result.stderr}`,
  );
}

function privilegedBoundaryVerification(directory) {
  return spawnSync(
    process.platform === "win32" ? "python" : "python3",
    [
      resolve(import.meta.dirname, "verify-release-bundle.py"),
      "--directory",
      directory,
      "--source-sha",
      sourceCommit,
      "--version",
      version,
    ],
    { cwd: resolve(import.meta.dirname, ".."), encoding: "utf8", shell: false },
  );
}

function runPrivilegedBoundaryVerifier(directory) {
  const result = privilegedBoundaryVerification(directory);
  assert.equal(
    result.status,
    0,
    `stdlib release verifier failed\n${result.stdout}\n${result.stderr}`,
  );
}

function assertPrivilegedBoundaryRejects(directory) {
  const result = privilegedBoundaryVerification(directory);
  assert.notEqual(
    result.status,
    0,
    `stdlib release verifier accepted a tampered bundle\n${result.stdout}\n${result.stderr}`,
  );
}

async function replaceChecksum(directory, filename, contents) {
  const checksumPath = resolve(directory, checksumName(version));
  const lines = (await readFile(checksumPath, "utf8")).trimEnd().split("\n");
  const replacement = `${digest(contents)}  ${filename}`;
  const index = lines.findIndex((line) => line.endsWith(`  ${filename}`));
  assert.notEqual(index, -1, `checksum entry is missing: ${filename}`);
  lines[index] = replacement;
  await writeFile(checksumPath, `${lines.join("\n")}\n`);
}

async function mutateManifest(directory, mutate) {
  const filename = releaseManifestName(version);
  const path = resolve(directory, filename);
  const manifest = JSON.parse(await readFile(path, "utf8"));
  mutate(manifest);
  const contents = Buffer.from(json(manifest));
  await writeFile(path, contents);
  await replaceChecksum(directory, filename, contents);
}

async function mutationDirectory(source, parent, name) {
  const destination = resolve(parent, name);
  await cp(source, destination, { recursive: true });
  return destination;
}

function tarFixture(entries) {
  const blocks = [];
  for (const entry of entries) {
    const contents = Buffer.from(entry.contents ?? "");
    const header = new Header({
      gid: 0,
      linkpath: entry.linkpath,
      mode: 0o644,
      mtime: new Date(0),
      path: entry.path,
      size: contents.byteLength,
      type: entry.type ?? "File",
      uid: 0,
    });
    const headerBlock = Buffer.alloc(512);
    header.encode(headerBlock);
    blocks.push(headerBlock, contents);
    if (contents.byteLength % 512 !== 0) {
      blocks.push(Buffer.alloc(512 - (contents.byteLength % 512)));
    }
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

function unsafeArchiveCases(root) {
  return [
    {
      entries: [{ path: `${root}/../escape`, contents: "escape" }],
      message: /not normalized/,
      name: "traversal",
    },
    {
      entries: [
        {
          path: `${root}/link`,
          type: "SymbolicLink",
          linkpath: "../../escape",
        },
      ],
      message: /not a file/,
      name: "symbolic-link",
    },
    {
      entries: [
        { path: `${root}/link`, type: "Link", linkpath: `${root}/target` },
      ],
      message: /not a file/,
      name: "hard-link",
    },
    {
      entries: [
        { path: `${root}/duplicate`, contents: "same" },
        { path: `${root}/duplicate`, contents: "same" },
      ],
      message: /duplicate entries/,
      name: "duplicate",
    },
  ];
}

test("contract release is reproducible and its consumers compile", async (t) => {
  const firstDirectory = await mkdtemp(
    join(tmpdir(), "provenance-release-first-"),
  );
  const secondDirectory = await mkdtemp(
    join(tmpdir(), "provenance-release-second-"),
  );
  const mutationsDirectory = await mkdtemp(
    join(tmpdir(), "provenance-release-mutations-"),
  );
  const staleFiles = [
    resolve(import.meta.dirname, "../packages/api-client/dist/stale-output.js"),
    resolve(
      import.meta.dirname,
      "../packages/runner-protocol/dist/stale-output.js",
    ),
  ];
  try {
    for (const staleFile of staleFiles) {
      await mkdir(resolve(staleFile, ".."), { recursive: true });
      await writeFile(staleFile, "stale");
    }
    runWorkspaceBuild();
    const inspectorJar = resolve(
      import.meta.dirname,
      "../plugins/paper-probe/build/libs/paper-probe-0.1.0.jar",
    );
    const firstInspector = await readFile(inspectorJar);
    runGradleBuild(":paper-probe:clean", ":paper-probe:jar");
    assert.deepEqual(
      await readFile(inspectorJar),
      firstInspector,
      "Paper metadata inspector JAR is not reproducible",
    );
    for (const staleFile of staleFiles) {
      await assert.rejects(access(staleFile), { code: "ENOENT" });
    }

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
    runPrivilegedBoundaryVerifier(firstDirectory);
    const sbom = JSON.parse(
      await readFile(resolve(firstDirectory, manifest.sbom.filename), "utf8"),
    );
    assert.equal(sbom.packages.length, 24);
    assert.equal(
      sbom.packages.filter(({ filesAnalyzed }) => !filesAnalyzed).length,
      18,
    );
    assert(
      sbom.relationships.some(
        ({ relationshipType }) => relationshipType === "DEPENDS_ON",
      ),
    );
    assert(sbom.packages.every(({ checksums }) => checksums?.length > 0));
    t.diagnostic(
      `SPDX 2.3 SBOM covers ${sbom.packages.length} packages, including 18 runtime dependencies, and ${sbom.files.length} archived files`,
    );
    assert.deepEqual(manifest.compatibility, {
      action: "not-released",
      attestationSchema: "v1",
      cli: "not-released",
      configSchema: "v1",
      openapi: "v1",
      paperMetadata: {
        inspector: version,
        schema: "v1",
      },
      runnerProtocol: "v1",
      sdk: { typescriptClient: version },
    });

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
    assertPrivilegedBoundaryRejects(secondDirectory);

    const checksumMutation = await mutationDirectory(
      firstDirectory,
      mutationsDirectory,
      "checksum",
    );
    const checksumPath = resolve(checksumMutation, checksumName(version));
    const checksumContents = await readFile(checksumPath, "utf8");
    await writeFile(
      checksumPath,
      checksumContents.replace(/^[0-9a-f]{64}/, "0".repeat(64)),
    );
    await assert.rejects(
      verifyContractRelease({ directory: checksumMutation, version }),
      /checksum file differs/,
    );
    assertPrivilegedBoundaryRejects(checksumMutation);

    const manifestMutation = await mutationDirectory(
      firstDirectory,
      mutationsDirectory,
      "manifest",
    );
    await mutateManifest(manifestMutation, (document) => {
      document.compatibility.cli = "any";
    });
    await assert.rejects(
      verifyContractRelease({ directory: manifestMutation, version }),
      /compatibility declaration differs/,
    );
    assertPrivilegedBoundaryRejects(manifestMutation);

    const sbomMutation = await mutationDirectory(
      firstDirectory,
      mutationsDirectory,
      "sbom",
    );
    const sbomFilename = sbomName(version);
    const sbomPath = resolve(sbomMutation, sbomFilename);
    const tamperedSbom = JSON.parse(await readFile(sbomPath, "utf8"));
    const removedDependency = tamperedSbom.packages.find(
      ({ filesAnalyzed }) => !filesAnalyzed,
    ).SPDXID;
    tamperedSbom.packages = tamperedSbom.packages.filter(
      ({ SPDXID }) => SPDXID !== removedDependency,
    );
    tamperedSbom.relationships = tamperedSbom.relationships.filter(
      ({ relatedSpdxElement, spdxElementId }) =>
        relatedSpdxElement !== removedDependency &&
        spdxElementId !== removedDependency,
    );
    const tamperedSbomContents = Buffer.from(json(tamperedSbom));
    await writeFile(sbomPath, tamperedSbomContents);
    await mutateManifest(sbomMutation, (document) => {
      document.sbom.sha256 = digest(tamperedSbomContents);
      document.sbom.size = tamperedSbomContents.byteLength;
    });
    await replaceChecksum(sbomMutation, sbomFilename, tamperedSbomContents);
    await assert.rejects(
      verifyContractRelease({ directory: sbomMutation, version }),
      /SPDX (?:dependency|package inventory) differs/,
    );
    assertPrivilegedBoundaryRejects(sbomMutation);

    const unsafeArtifact = manifest.artifacts.find(
      ({ bundle }) => bundle === "config-schema",
    );
    const unsafeRoot = unsafeArtifact.filename.slice(0, -".tar.gz".length);
    for (const fixture of unsafeArchiveCases(unsafeRoot)) {
      const unsafeMutation = await mutationDirectory(
        firstDirectory,
        mutationsDirectory,
        `privileged-${fixture.name}`,
      );
      const unsafeContents = gzipSync(tarFixture(fixture.entries), {
        mtime: 0,
      });
      await writeFile(
        resolve(unsafeMutation, unsafeArtifact.filename),
        unsafeContents,
      );
      await mutateManifest(unsafeMutation, (document) => {
        const artifact = document.artifacts.find(
          ({ bundle }) => bundle === "config-schema",
        );
        artifact.sha256 = digest(unsafeContents);
        artifact.size = unsafeContents.byteLength;
      });
      await replaceChecksum(
        unsafeMutation,
        unsafeArtifact.filename,
        unsafeContents,
      );
      assertPrivilegedBoundaryRejects(unsafeMutation);
    }
  } finally {
    await rm(firstDirectory, { force: true, recursive: true });
    await rm(secondDirectory, { force: true, recursive: true });
    await rm(mutationsDirectory, { force: true, recursive: true });
    for (const staleFile of staleFiles) {
      await rm(staleFile, { force: true });
    }
  }
});

test("archive inspection rejects traversal, links, and duplicate entries", async () => {
  const directory = await mkdtemp(
    join(tmpdir(), "provenance-release-archive-safety-"),
  );
  const root = "provenance-config-schema-1.2.3";
  try {
    for (const fixture of unsafeArchiveCases(root)) {
      const path = resolve(directory, `${fixture.name}.tar`);
      await writeFile(path, tarFixture(fixture.entries));
      await assert.rejects(archiveEntries(path, root), fixture.message);
    }
  } finally {
    await rm(directory, { force: true, recursive: true });
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

test("release workflow reconciles a verified draft without overwriting assets", async () => {
  const workflow = await readFile(
    resolve(import.meta.dirname, "../.github/workflows/release-contracts.yml"),
    "utf8",
  );

  assert.match(workflow, /verify_release_assets false/);
  assert.match(workflow, /verify_release_assets true/);
  assert.match(workflow, /--field draft=true/);
  assert.match(workflow, /--field draft=false/);
  assert.match(
    workflow,
    /Release asset digest conflicts with the verified bundle/,
  );
  assert.match(workflow, /Paper metadata schema: v1/);
  assert.match(workflow, /Paper metadata inspector: \$VERSION/);
  assert.match(workflow, /expected_paths\[@\]\}" -ne 9/);
  assert.match(
    workflow,
    /Published release \$TAG already matches the verified bundle/,
  );
  assert.doesNotMatch(workflow, /gh release upload[^\n]*--clobber/);
  assert.doesNotMatch(workflow, /gh release create/);
  assert.match(workflow, /pnpm run release:contracts\n/);
  assert.match(workflow, /pnpm run release:verify\n/);
  assert.doesNotMatch(
    workflow,
    /pnpm (?:run )?release:(?:contracts|verify) --/,
  );
});

test("release workflow resumes from an immutable tag with trusted verifier code", async () => {
  const workflow = await readFile(
    resolve(import.meta.dirname, "../.github/workflows/release-contracts.yml"),
    "utf8",
  );

  assert.match(
    workflow,
    /policy_sha: \$\{\{ steps\.release\.outputs\.policy_sha \}\}/,
  );
  assert.match(workflow, /source_sha="\$tagged_sha"/);
  assert.match(
    workflow,
    /ref: \$\{\{ needs\.validate\.outputs\.policy_sha \}\}/,
  );
  assert.match(workflow, /ref: \$\{\{ github\.sha \}\}/);
  assert.match(workflow, /"\$policy_sha" != "\$GITHUB_SHA"/);
  assert.match(
    workflow,
    /Reviewed release commit is no longer the current main tip before tag creation/,
  );

  const identityFunction = workflow.slice(
    workflow.indexOf("          verify_release_identity() {"),
    workflow.indexOf("          validate_release_metadata() {"),
  );
  assert.notEqual(identityFunction.length, 0);
  assert.match(
    identityFunction,
    /git merge-base --is-ancestor "\$SOURCE_SHA" "\$POLICY_SHA"/,
  );
  assert.doesNotMatch(identityFunction, /origin\/main/);
});
