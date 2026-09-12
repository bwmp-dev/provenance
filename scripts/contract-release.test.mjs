import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  appendFile,
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { Header, extract as extractTar } from "tar";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { gzipSync } from "node:zlib";

import {
  buildContractRelease,
  checksumName,
  releaseManifestName,
  sbomName,
} from "./contract-release.mjs";
import {
  archiveEntries,
  projectNodeConsumerLock,
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

async function exercisePublishReconciliation(bundle, schemaVersion) {
  const repository = resolve(import.meta.dirname, "..");
  const workflow = parseYaml(
    await readFile(
      resolve(repository, ".github/workflows/release-contracts.yml"),
      "utf8",
    ),
  );
  const step = workflow.jobs.release.steps.find(
    ({ name }) => name === "Reconcile and publish GitHub release",
  );
  // Execute the entire deployed shell; only GitHub and ancestry discovery are
  // simulated. The independent Python byte/inventory/SPDX verifier stays real.
  const script = step.run.replaceAll(
    "python3 scripts/verify-release-bundle.py",
    `python3 '${resolve(repository, "scripts/verify-release-bundle.py")}'`,
  );
  const compatibility = [
    "## Compatibility declaration",
    "- Configuration schema: v1",
    "- Attestation schema: v1",
    "- Public OpenAPI: v1",
    "- Paper metadata schema: v1",
    `- Paper metadata inspector: ${version}`,
    "- Runner protocol: v1",
    "- CLI: not released",
    "- GitHub Action: not released",
    `- TypeScript SDK client: ${version}`,
    ...(schemaVersion === 2
      ? [
          `- TypeScript SDK facade: ${version} (archive-only; no npm publication)`,
        ]
      : []),
  ].join("\n");
  for (const scenario of [
    "same",
    "newer-policy",
    "fresh",
    "draft-missing",
    "unknown-schema",
    "string-schema",
    "missing-schema",
    "malformed-manifest",
    "missing-local",
    "extra-local",
    "substituted-local",
    "remote-extra",
    "remote-incomplete",
    "remote-digest",
    "metadata",
    "tag-conflict",
    "lightweight-tag",
    "unrelated-policy",
    "discovery",
  ]) {
    const directory = await mkdtemp(
      join(tmpdir(), "provenance-publish-inventory-"),
    );
    try {
      const local = join(directory, "dist/contracts");
      await mkdir(join(directory, "dist"));
      await cp(bundle, local, { recursive: true });
      const bin = join(directory, "bin");
      await mkdir(bin);
      await cp(
        resolve(repository, "scripts/fixtures/contract-release/gh-repeat.py"),
        join(bin, "gh"),
      );
      await chmod(join(bin, "gh"), 0o755);
      await writeFile(
        join(bin, "git"),
        `#!/usr/bin/env bash\nset -euo pipefail\n[[ "$#" == 4 && "$1" == merge-base && "$2" == --is-ancestor && "$3" == "$SOURCE_SHA" && "$4" == "$POLICY_SHA" ]]\n[[ "$CONTRACT_UNRELATED" != 1 ]]\n`,
        { mode: 0o755 },
      );
      const filenames = (await readdir(bundle)).sort();
      assert.equal(filenames.length, schemaVersion === 1 ? 9 : 10);
      const state = {
        tag: `v${version}`,
        source: sourceCommit,
        directory: bundle,
        release: {
          id: 1,
          tag_name: `v${version}`,
          name: `Provenance contracts v${version}`,
          body: compatibility,
          prerelease: true,
          draft: false,
        },
        assets: await Promise.all(
          filenames.map(async (name, index) => ({
            id: index + 1,
            name,
            size: (await readFile(join(bundle, name))).length,
            state: "uploaded",
          })),
        ),
      };
      const manifestPath = join(local, releaseManifestName(version));
      const mutating = ["fresh", "draft-missing"].includes(scenario);
      if (mutating) {
        state.allowMutations = true;
        state.release.draft = true;
        state.releaseExists = scenario !== "fresh";
        state.assets = scenario === "fresh" ? [] : state.assets.slice(0, 2);
      }
      if (
        ["unknown-schema", "string-schema", "missing-schema"].includes(scenario)
      ) {
        const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
        if (scenario === "missing-schema") delete manifest.schemaVersion;
        else
          manifest.schemaVersion =
            scenario === "unknown-schema" ? 3 : String(schemaVersion);
        await writeFile(manifestPath, json(manifest));
      }
      if (scenario === "malformed-manifest") await writeFile(manifestPath, "{");
      if (scenario === "missing-local" || scenario === "substituted-local")
        await rm(join(local, filenames[0]));
      if (scenario === "extra-local" || scenario === "substituted-local")
        await writeFile(join(local, "unexpected.tar.gz"), "not an archive");
      if (scenario === "remote-extra")
        state.assets.push({
          id: 99,
          name: "unexpected",
          size: 1,
          state: "uploaded",
        });
      if (scenario === "remote-incomplete") state.assets.pop();
      if (scenario === "remote-digest") state.tamper = filenames[0];
      if (scenario === "metadata") state.release.name = "different";
      if (scenario === "tag-conflict") state.source = "b".repeat(40);
      if (scenario === "lightweight-tag") state.tagType = "commit";
      if (scenario === "discovery") state.discoveryError = true;
      const statePath = join(directory, "state.json"),
        log = join(directory, "calls.jsonl");
      await writeFile(statePath, json(state));
      await writeFile(log, "");
      const execution = spawnSync("bash", ["-euo", "pipefail", "-c", script], {
        cwd: directory,
        encoding: "utf8",
        timeout: 30000,
        env: {
          ...process.env,
          PATH: `${bin}:${process.env.PATH}`,
          CONTRACT_REPEAT_STATE: statePath,
          CONTRACT_REPEAT_LOG: log,
          CONTRACT_UNRELATED: scenario === "unrelated-policy" ? "1" : "0",
          RUNNER_TEMP: directory,
          GITHUB_REPOSITORY: "bwmp-dev/provenance",
          TAG: `v${version}`,
          VERSION: version,
          SOURCE_SHA: sourceCommit,
          POLICY_SHA:
            scenario === "newer-policy" || scenario === "unrelated-policy"
              ? "1".repeat(40)
              : sourceCommit,
          PRERELEASE: "true",
        },
      });
      assert.ifError(execution.error);
      assert.equal(
        execution.status === 0,
        ["same", "newer-policy", "fresh", "draft-missing"].includes(scenario),
        `schema${schemaVersion}/${scenario}: ${execution.stdout}${execution.stderr}`,
      );
      const calls = (await readFile(log, "utf8"))
        .trim()
        .split("\n")
        .filter(Boolean)
        .map(JSON.parse);
      if (mutating) {
        const writes = calls.filter(
          (args) => args[0] === "release" || args.includes("--method"),
        );
        const uploads = writes.filter((args) => args[0] === "release");
        assert.deepEqual(
          uploads.map((args) => args[3].split("/").at(-1)).sort(),
          filenames.slice(scenario === "fresh" ? 0 : 2),
        );
        assert.ok(
          uploads.every(
            (args) =>
              args[1] === "upload" &&
              args[2] === `v${version}` &&
              !args.includes("--clobber"),
          ),
        );
        assert.equal(
          writes.length,
          uploads.length + (scenario === "fresh" ? 2 : 1),
        );
        const final = JSON.parse(await readFile(statePath, "utf8"));
        assert.equal(final.release.draft, false);
        assert.deepEqual(
          final.assets.map(({ name }) => name).sort(),
          filenames,
        );
      } else
        assert.ok(
          calls.every(
            (args) => args[0] === "api" && !args.includes("--method"),
          ),
          `unexpected mutation in ${scenario}`,
        );
      if (
        [
          "unknown-schema",
          "string-schema",
          "missing-schema",
          "malformed-manifest",
          "missing-local",
          "extra-local",
          "substituted-local",
        ].includes(scenario)
      )
        assert.equal(calls.length, 0, "invalid local inventory reached GitHub");
      console.info(
        `Actual publication shell schema${schemaVersion}/${scenario}: ${execution.status === 0 ? "accepted" : "rejected"}; ${mutating ? "exact mocked uploads and publish" : "no mutations"}`,
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
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
      ":fixture-matrix-compatibility:jar",
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
  return result;
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

test("released Node consumers use the exact audited dependency graph offline", async () => {
  const repositoryRoot = resolve(import.meta.dirname, "..");
  const rootLockContents = await readFile(
    resolve(repositoryRoot, "pnpm-lock.yaml"),
    "utf8",
  );
  const packageContents = await readFile(
    resolve(repositoryRoot, "packages/config-schema/package.json"),
    "utf8",
  );
  const registryNewerFixture = parseYaml(rootLockContents);
  registryNewerFixture.packages["fast-uri@3.1.7"] = {
    resolution: structuredClone(
      registryNewerFixture.packages["fast-uri@3.1.6"].resolution,
    ),
  };
  registryNewerFixture.snapshots["fast-uri@3.1.7"] = {};
  const inputs = {
    lockfileContents: stringifyYaml(registryNewerFixture, { lineWidth: 0 }),
    nodeImporter: "packages/config-schema",
    packageContents,
  };

  const firstLock = projectNodeConsumerLock(inputs);
  const secondLock = projectNodeConsumerLock(inputs);
  assert.equal(secondLock, firstLock, "consumer lock projection is not stable");
  const projected = parseYaml(firstLock);
  assert.equal(
    projected.snapshots["ajv@8.20.0"].dependencies["fast-uri"],
    "3.1.6",
  );
  assert(projected.packages["fast-uri@3.1.6"]);
  assert.equal(projected.packages["fast-uri@3.1.7"], undefined);
  assert.deepEqual(Object.keys(projected.importers), ["."]);

  const consumerDirectory = await mkdtemp(
    join(tmpdir(), "provenance-locked-consumer-"),
  );
  try {
    await writeFile(
      resolve(consumerDirectory, "package.json"),
      packageContents,
    );
    await writeFile(resolve(consumerDirectory, "pnpm-lock.yaml"), firstLock);
    const storePaths = [repositoryRoot, consumerDirectory].map((cwd) => {
      const versionResult = spawnSync("pnpm", ["--version"], {
        cwd,
        encoding: "utf8",
        env: process.env,
        shell: false,
      });
      assert.equal(versionResult.status, 0, versionResult.stderr);
      assert.equal(versionResult.stdout.trim(), "11.20.0");
      const result = spawnSync("pnpm", ["store", "path", "--silent"], {
        cwd,
        encoding: "utf8",
        env: process.env,
        shell: false,
      });
      assert.equal(result.status, 0, result.stderr);
      return result.stdout.trim();
    });
    assert.equal(
      storePaths[1],
      storePaths[0],
      "isolated consumer store differs",
    );
    if (process.env.pnpm_config_store_dir) {
      assert.equal(
        storePaths[0],
        resolve(process.env.pnpm_config_store_dir, "v11"),
        "pnpm did not use the explicitly populated store",
      );
    }
    const installation = spawnSync(
      "pnpm",
      ["install", "--offline", "--ignore-scripts", "--frozen-lockfile"],
      {
        cwd: consumerDirectory,
        encoding: "utf8",
        env: {
          ...process.env,
          CI: "true",
          npm_config_offline: "true",
          npm_config_registry: "http://127.0.0.1:9/",
        },
        shell: false,
      },
    );
    assert.equal(
      installation.status,
      0,
      `locked offline install failed\n${installation.stdout}\n${installation.stderr}`,
    );
    const ajvRealPath = await realpath(
      resolve(consumerDirectory, "node_modules/ajv/package.json"),
    );
    const installedFastUri = JSON.parse(
      await readFile(
        resolve(dirname(ajvRealPath), "../fast-uri/package.json"),
        "utf8",
      ),
    );
    assert.equal(installedFastUri.version, "3.1.6");
  } finally {
    await rm(consumerDirectory, { force: true, recursive: true });
  }
});

test("locked consumer projection rejects missing cache and tampered inputs", async () => {
  const repositoryRoot = resolve(import.meta.dirname, "..");
  const rootLockContents = await readFile(
    resolve(repositoryRoot, "pnpm-lock.yaml"),
    "utf8",
  );
  const packageContents = await readFile(
    resolve(repositoryRoot, "packages/config-schema/package.json"),
    "utf8",
  );
  const rootLock = parseYaml(rootLockContents);

  const missingSnapshot = structuredClone(rootLock);
  delete missingSnapshot.snapshots["fast-uri@3.1.6"];
  assert.throws(
    () =>
      projectNodeConsumerLock({
        lockfileContents: stringifyYaml(missingSnapshot),
        nodeImporter: "packages/config-schema",
        packageContents,
      }),
    /missing runtime snapshot: fast-uri@3\.1\.6/,
  );

  const tamperedManifest = JSON.parse(packageContents);
  tamperedManifest.dependencies.ajv = "8.20.1";
  assert.throws(
    () =>
      projectNodeConsumerLock({
        lockfileContents: rootLockContents,
        nodeImporter: "packages/config-schema",
        packageContents: json(tamperedManifest),
      }),
    /dependencies differs from the audited pnpm importer/,
  );
  assert.throws(
    () =>
      projectNodeConsumerLock({
        lockfileContents: `${rootLockContents}\nimporters: {}\n`,
        nodeImporter: "packages/config-schema",
        packageContents,
      }),
    /invalid or ambiguous/,
  );

  const exactPackage = rootLock.packages["fast-uri@3.1.6"];
  const missingStoreLock = stringifyYaml({
    lockfileVersion: "9.0",
    settings: rootLock.settings,
    importers: {
      fixture: {
        dependencies: {
          "fast-uri": { specifier: "3.1.6", version: "3.1.6" },
        },
      },
    },
    packages: { "fast-uri@3.1.6": exactPackage },
    snapshots: { "fast-uri@3.1.6": {} },
  });
  const missingStorePackage = json({
    name: "locked-missing-store-fixture",
    version: "1.0.0",
    dependencies: { "fast-uri": "3.1.6" },
  });
  const projectedMissingStoreLock = projectNodeConsumerLock({
    lockfileContents: missingStoreLock,
    nodeImporter: "fixture",
    packageContents: missingStorePackage,
  });
  const consumerDirectory = await mkdtemp(
    join(tmpdir(), "provenance-missing-locked-tarball-"),
  );
  const emptyStore = await mkdtemp(
    join(tmpdir(), "provenance-empty-pnpm-store-"),
  );
  try {
    await writeFile(
      resolve(consumerDirectory, "package.json"),
      missingStorePackage,
    );
    await writeFile(
      resolve(consumerDirectory, "pnpm-lock.yaml"),
      projectedMissingStoreLock,
    );
    const installation = spawnSync(
      "pnpm",
      [
        "install",
        "--offline",
        "--ignore-scripts",
        "--frozen-lockfile",
        "--store-dir",
        emptyStore,
      ],
      {
        cwd: consumerDirectory,
        encoding: "utf8",
        env: {
          ...process.env,
          CI: "true",
          npm_config_offline: "true",
          npm_config_registry: "http://127.0.0.1:9/",
        },
        shell: false,
      },
    );
    assert.notEqual(installation.status, 0);
    assert.match(
      `${installation.stdout}\n${installation.stderr}`,
      /(?:offline|store|tarball|package).*(?:fast-uri|3\.1\.6)|(?:fast-uri|3\.1\.6).*(?:offline|store|tarball|package)/is,
    );
  } finally {
    await rm(consumerDirectory, { force: true, recursive: true });
    await rm(emptyStore, { force: true, recursive: true });
  }
});

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
    resolve(
      import.meta.dirname,
      "../packages/typescript-sdk/dist/stale-output.js",
    ),
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
      "../plugins/paper-probe/build/libs/paper-probe-0.2.0.jar",
    );
    const firstInspector = await readFile(inspectorJar);
    const inspectorRebuild = runGradleBuild(
      ":paper-probe:clean",
      ":paper-probe:jar",
      "--no-build-cache",
      "--rerun-tasks",
    );
    assert.doesNotMatch(
      `${inspectorRebuild.stdout}\n${inspectorRebuild.stderr}`,
      /FROM-CACHE/,
      "Paper metadata inspector reproducibility rebuild used cached task output",
    );
    assert.deepEqual(
      await readFile(inspectorJar),
      firstInspector,
      "Paper metadata inspector JAR is not reproducible",
    );
    for (const staleFile of staleFiles) {
      await assert.rejects(access(staleFile), { code: "ENOENT" });
    }

    // Historical six-archive inventory remains fully verifiable.
    const options = { createdAt, sourceCommit, version, schemaVersion: 1 };
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
    await exercisePublishReconciliation(firstDirectory, 1);
    const sbom = JSON.parse(
      await readFile(resolve(firstDirectory, manifest.sbom.filename), "utf8"),
    );
    const attestation = manifest.artifacts.find(
      (artifact) => artifact.bundle === "attestation-schema",
    );
    const attestationRoot = attestation.filename.slice(0, -".tar.gz".length);
    const attestationEntries = await archiveEntries(
      resolve(firstDirectory, attestation.filename),
      attestationRoot,
    );
    assert.ok(
      !attestationEntries.some((path) => path.endsWith(".py")),
      "repository-only discovery validator must not become an undeclared runtime dependency",
    );
    for (const path of [
      "key-discovery/schema.json",
      "key-discovery/semantics.md",
      "key-discovery-fixtures/valid/initial.json",
      "key-discovery-fixtures/valid/rotated.json",
      "key-discovery-fixtures/invalid/cases.json",
    ]) {
      assert.ok(
        attestationEntries.includes(`${attestationRoot}/${path}`),
        path,
      );
    }
    assert.deepEqual(
      attestationEntries
        .filter((path) => path.startsWith(`${attestationRoot}/go/`))
        .sort(),
      [
        "LICENSE",
        "README.md",
        "go.mod",
        "go.sum",
        "json.go",
        "schema.json",
        "schema-v2.json",
        "verification.go",
      ]
        .map((name) => `${attestationRoot}/go/${name}`)
        .sort(),
    );
    for (const name of [
      "github.com/dlclark/regexp2",
      "github.com/santhosh-tekuri/jsonschema/v6",
      "golang.org/x/text",
    ]) {
      const dependency = sbom.packages.find((entry) => entry.name === name);
      assert.ok(dependency, `Go verifier dependency missing: ${name}`);
      assert.ok(
        sbom.relationships.some(
          (entry) =>
            entry.spdxElementId === "SPDXRef-Package-attestation-schema" &&
            entry.relatedSpdxElement === dependency.SPDXID &&
            entry.relationshipType === "DEPENDS_ON",
        ),
        `Go verifier SBOM relationship missing: ${name}`,
      );
    }
    assert.equal(sbom.packages.length, 26);
    assert.equal(
      sbom.packages.filter(({ filesAnalyzed }) => !filesAnalyzed).length,
      20,
    );
    assert(
      sbom.relationships.some(
        ({ relationshipType }) => relationshipType === "DEPENDS_ON",
      ),
    );
    assert(sbom.packages.every(({ checksums }) => checksums?.length > 0));
    t.diagnostic(
      `SPDX 2.3 SBOM covers ${sbom.packages.length} packages, including 20 runtime dependencies, and ${sbom.files.length} archived files`,
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

    const sdkFirst = resolve(mutationsDirectory, "sdk-first");
    const sdkSecond = resolve(mutationsDirectory, "sdk-second");
    const sdkManifest = await buildContractRelease({
      createdAt,
      sourceCommit,
      version,
      outputDirectory: sdkFirst,
    });
    await buildContractRelease({
      createdAt,
      sourceCommit,
      version,
      outputDirectory: sdkSecond,
    });
    assert.equal(sdkManifest.schemaVersion, 2);
    assert.equal(sdkManifest.artifacts.length, 7);
    assert.equal((await readdir(sdkFirst)).length, 10);
    assert.equal(sdkManifest.compatibility.sdk.typescriptSDK, version);
    assert.equal(
      (await readFile(resolve(sdkFirst, checksumName(version)), "utf8"))
        .trim()
        .split("\n").length,
      9,
    );
    for (const filename of await readdir(sdkFirst))
      assert.deepEqual(
        await readFile(resolve(sdkFirst, filename)),
        await readFile(resolve(sdkSecond, filename)),
        `new SDK inventory is not deterministic: ${filename}`,
      );
    await verifyContractRelease({
      directory: sdkFirst,
      version,
      consumers: true,
    });
    runPrivilegedBoundaryVerifier(sdkFirst);
    await exercisePublishReconciliation(sdkFirst, 2);
    const sdkSpdx = JSON.parse(
      await readFile(resolve(sdkFirst, sdkManifest.sbom.filename), "utf8"),
    );
    assert.equal(sdkSpdx.documentDescribes.length, 7);
    for (const name of ["openapi-fetch", "ajv", "ajv-formats", "yaml"]) {
      const dependency = sdkSpdx.packages.find((item) => item.name === name);
      assert.ok(
        sdkSpdx.relationships.some(
          (item) =>
            item.spdxElementId === "SPDXRef-Package-typescript-sdk" &&
            item.relatedSpdxElement === dependency.SPDXID &&
            item.relationshipType === "DEPENDS_ON",
        ),
        `SDK runtime dependency missing: ${name}`,
      );
    }
    const downgradedSDK = await mutationDirectory(
      sdkFirst,
      mutationsDirectory,
      "sdk-downgrade",
    );
    await mutateManifest(downgradedSDK, (document) => {
      document.schemaVersion = 1;
      delete document.compatibility.sdk.typescriptSDK;
    });
    await assert.rejects(
      verifyContractRelease({ directory: downgradedSDK, version }),
      /bundle inventory differs/,
    );
    assertPrivilegedBoundaryRejects(downgradedSDK);

    const sdkArtifact = sdkManifest.artifacts.find(
      ({ bundle }) => bundle === "typescript-sdk",
    );
    const sdkExtracted = resolve(mutationsDirectory, "sdk-extracted");
    await mkdir(sdkExtracted);
    await extractTar({
      file: resolve(sdkFirst, sdkArtifact.filename),
      cwd: sdkExtracted,
    });
    const sdkRoot = sdkArtifact.filename.slice(0, -7);
    const sdkEntries = await archiveEntries(
      resolve(sdkFirst, sdkArtifact.filename),
      sdkRoot,
    );
    for (const [name, omitted, changed] of [
      ["sdk-missing-implementation", "package/dist/index.js", null],
      ["sdk-missing-license", "package/vendor/verification/LICENSE", null],
      [
        "sdk-tampered-schema",
        null,
        "package/vendor/verification/dist/schema.json",
      ],
      [
        "sdk-tampered-dependency",
        null,
        "package/vendor/api-client/package.json",
      ],
    ]) {
      const directory = await mutationDirectory(
        sdkFirst,
        mutationsDirectory,
        name,
      );
      const entries = [];
      for (const path of sdkEntries) {
        if (path === `${sdkRoot}/${omitted}`) continue;
        entries.push({
          path,
          contents:
            path === `${sdkRoot}/${changed}`
              ? Buffer.from("tampered")
              : await readFile(resolve(sdkExtracted, path)),
        });
      }
      const contents = gzipSync(tarFixture(entries), { mtime: 0 });
      await writeFile(resolve(directory, sdkArtifact.filename), contents);
      await mutateManifest(directory, (document) => {
        const artifact = document.artifacts.find(
          (item) => item.bundle === "typescript-sdk",
        );
        artifact.sha256 = digest(contents);
        artifact.size = contents.length;
      });
      await replaceChecksum(directory, sdkArtifact.filename, contents);
      await assert.rejects(
        verifyContractRelease({ directory, version }),
        /entries differ|SDK copied source differs|bundle (?:size|digest) differs/,
      );
      assertPrivilegedBoundaryRejects(directory);
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
      ({ name }) => name === "github.com/dlclark/regexp2",
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

    const extracted = resolve(mutationsDirectory, "go-source-extracted");
    await mkdir(extracted);
    await extractTar({
      file: resolve(firstDirectory, attestation.filename),
      cwd: extracted,
    });
    for (const [name, omitted, changed] of [
      ["missing-go-source", "go/verification.go", null],
      ["missing-discovery-schema", "key-discovery/schema.json", null],
      ["missing-discovery-semantics", "key-discovery/semantics.md", null],
      ["tampered-discovery-schema", null, "key-discovery/schema.json"],
      ["missing-go-schema", "go/schema.json", null],
      ["missing-go-v2-schema", "go/schema-v2.json", null],
      ["missing-v2-authority", "schema-v2/schema.json", null],
      ["missing-js-v2-schema", "package/dist/schema-v2.json", null],
      ["missing-v2-golden", "fixtures/interop/small-artifact-v2.json", null],
      ["tampered-go-v2-schema", null, "go/schema-v2.json"],
      ["tampered-go-schema", null, "go/schema.json"],
      ["tampered-go-module", null, "go/go.mod"],
    ]) {
      const directory = await mutationDirectory(
        firstDirectory,
        mutationsDirectory,
        name,
      );
      const entries = [];
      for (const path of attestationEntries) {
        if (path === `${attestationRoot}/${omitted}`) continue;
        entries.push({
          path,
          contents:
            path === `${attestationRoot}/${changed}`
              ? Buffer.from("tampered")
              : await readFile(resolve(extracted, path)),
        });
      }
      const contents = gzipSync(tarFixture(entries), { mtime: 0 });
      await writeFile(resolve(directory, attestation.filename), contents);
      await mutateManifest(directory, (document) => {
        const artifact = document.artifacts.find(
          (entry) => entry.bundle === "attestation-schema",
        );
        artifact.sha256 = digest(contents);
        artifact.size = contents.length;
      });
      await replaceChecksum(directory, attestation.filename, contents);
      await assert.rejects(
        verifyContractRelease({ directory, version }),
        /entries differ|bundle (?:size|digest) differs/,
      );
      assertPrivilegedBoundaryRejects(directory);
    }

    const runnerArtifact = manifest.artifacts.find(
      ({ bundle }) => bundle === "runner-protocol",
    );
    const runnerExtracted = resolve(mutationsDirectory, "runner-extracted");
    await mkdir(runnerExtracted);
    await extractTar({
      file: resolve(firstDirectory, runnerArtifact.filename),
      cwd: runnerExtracted,
    });
    const runnerRoot = runnerArtifact.filename.slice(0, -".tar.gz".length);
    const runnerEntries = await archiveEntries(
      resolve(firstDirectory, runnerArtifact.filename),
      runnerRoot,
    );
    for (const [name, omitted, changed] of [
      ["missing-terminal-schema", "proto/terminal-evidence/schema.json", null],
      ["missing-terminal-vector", "proto/terminal-evidence/vectors.json", null],
      [
        "missing-terminal-v2-schema",
        "proto/terminal-evidence-v2/schema.json",
        null,
      ],
      [
        "missing-terminal-v2-vector",
        "proto/terminal-evidence-v2/vectors.json",
        null,
      ],
      [
        "tampered-terminal-v2-vector",
        null,
        "proto/terminal-evidence-v2/vectors.json",
      ],
      ["tampered-terminal-schema", null, "proto/terminal-evidence/schema.json"],
      [
        "tampered-terminal-vector",
        null,
        "proto/terminal-evidence/vectors.json",
      ],
    ]) {
      const directory = await mutationDirectory(
        firstDirectory,
        mutationsDirectory,
        name,
      );
      // Preserve the actual embedded manifest and all files, except the exact
      // owned mutation; outer hashes are updated so inner verification must act.
      const entries = [];
      for (const path of runnerEntries) {
        if (path === `${runnerRoot}/${omitted}`) continue;
        entries.push({
          path,
          contents:
            path === `${runnerRoot}/${changed}`
              ? Buffer.from("tampered")
              : await readFile(resolve(runnerExtracted, path)),
        });
      }
      const contents = gzipSync(tarFixture(entries), { mtime: 0 });
      await writeFile(resolve(directory, runnerArtifact.filename), contents);
      await mutateManifest(directory, (document) => {
        const artifact = document.artifacts.find(
          (entry) => entry.bundle === "runner-protocol",
        );
        artifact.sha256 = digest(contents);
        artifact.size = contents.length;
      });
      await replaceChecksum(directory, runnerArtifact.filename, contents);
      await assert.rejects(
        verifyContractRelease({ directory, version }),
        /entries differ|bundle (?:size|digest) differs/,
      );
      assertPrivilegedBoundaryRejects(directory);
    }

    const deviceArtifact = manifest.artifacts.find(
      ({ bundle }) => bundle === "openapi",
    );
    const deviceExtracted = resolve(mutationsDirectory, "device-extracted");
    await mkdir(deviceExtracted);
    await extractTar({
      file: resolve(firstDirectory, deviceArtifact.filename),
      cwd: deviceExtracted,
    });
    const deviceRoot = deviceArtifact.filename.slice(0, -".tar.gz".length);
    const deviceEntries = await archiveEntries(
      resolve(firstDirectory, deviceArtifact.filename),
      deviceRoot,
    );
    for (const file of [
      "device-login-semantics.md",
      "device-login-states.json",
      "actions-grant-semantics.md",
      "actions-grant-vectors.json",
      "alpha-administration-semantics.md",
      "alpha-administration-vectors.json",
      "publication-result-semantics.md",
      "publication-result-vectors.json",
      "execution-evidence-v1.json",
      "execution-evidence-v2.json",
      "release-rejection-semantics.md",
      "release-rejection-vectors.json",
    ]) {
      assert.ok(deviceEntries.includes(`${deviceRoot}/${file}`));
      for (const mutation of ["missing", "tampered"]) {
        const directory = await mutationDirectory(
          firstDirectory,
          mutationsDirectory,
          `device-${mutation}-${file}`,
        );
        const entries = [];
        for (const path of deviceEntries) {
          if (path === `${deviceRoot}/${file}` && mutation === "missing")
            continue;
          entries.push({
            path,
            contents:
              path === `${deviceRoot}/${file}`
                ? Buffer.from("tampered")
                : await readFile(resolve(deviceExtracted, path)),
          });
        }
        const contents = gzipSync(tarFixture(entries), { mtime: 0 });
        await writeFile(resolve(directory, deviceArtifact.filename), contents);
        await mutateManifest(directory, (document) => {
          const artifact = document.artifacts.find(
            ({ filename }) => filename === deviceArtifact.filename,
          );
          artifact.sha256 = digest(contents);
          artifact.size = contents.length;
        });
        await replaceChecksum(directory, deviceArtifact.filename, contents);
        await assert.rejects(
          verifyContractRelease({ directory, version }),
          /entries differ|bundle (?:size|digest) differs/,
        );
        assertPrivilegedBoundaryRejects(directory);
      }
    }

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

test("release bootstraps Node before pnpm and enables its cache only afterward", async () => {
  const workflow = parseYaml(
    await readFile(
      resolve(
        import.meta.dirname,
        "../.github/workflows/release-contracts.yml",
      ),
      "utf8",
    ),
  );
  const steps = workflow.jobs.build.steps;
  const checkout = steps.findIndex((step) =>
    step.uses?.startsWith("actions/checkout@"),
  );
  const pnpm = steps.findIndex((step) => step.uses === "pnpm/action-setup@v6");
  const nodeSteps = steps
    .map((step, index) => ({ step, index }))
    .filter(({ step }) => step.uses?.startsWith("actions/setup-node@"));
  assert.equal(nodeSteps.length, 2);
  const [bootstrap, cache] = nodeSteps;
  assert.ok(checkout >= 0 && checkout < bootstrap.index);
  assert.ok(bootstrap.index < pnpm && pnpm < cache.index);
  assert.equal(bootstrap.step.uses, "actions/setup-node@v7");
  assert.equal(bootstrap.step.with["node-version-file"], ".node-version");
  assert.equal(bootstrap.step.with["package-manager-cache"], false);
  assert.equal(bootstrap.step.with.cache, undefined);
  assert.equal(cache.step.uses, "actions/setup-node@v7");
  assert.equal(cache.step.with["node-version-file"], ".node-version");
  assert.equal(cache.step.with.cache, "pnpm");
  assert.equal(steps[pnpm].with.version, "11.20.0");
  assert.equal(steps[pnpm].with.run_install, false);
  for (const step of steps.slice(0, pnpm))
    assert.notEqual(step.with?.cache, "pnpm");
});

test("contract release provisions the audited GitHub CLI before API calls", async () => {
  const workflow = parseYaml(
    await readFile(
      resolve(
        import.meta.dirname,
        "../.github/workflows/release-contracts.yml",
      ),
      "utf8",
    ),
  );
  for (const name of ["validate", "release"]) {
    const steps = workflow.jobs[name].steps;
    const install = steps.findIndex(
      (step) => step.run === "bash scripts/install-github-cli.sh",
    );
    const checkout = steps.findIndex((step) =>
      step.uses?.startsWith("actions/checkout@"),
    );
    assert.ok(
      checkout >= 0 && install > checkout,
      `${name} installs from checked-out policy`,
    );
    const calls = steps
      .map((step, index) =>
        /\bgh (?:api|release)\b/.test(step.run ?? "") ? index : -1,
      )
      .filter((index) => index >= 0);
    assert.ok(calls.length > 0, `${name} actually invokes GitHub CLI`);
    assert.ok(
      install < calls[0],
      `${name} installs before its first GitHub CLI call`,
    );
    const firstRun = steps[calls[0]].run;
    assert.match(
      firstRun,
      /expected_gh="\$RUNNER_TEMP\/gh_2\.96\.0_linux_amd64\/bin\/gh"/,
    );
    const guard = firstRun.indexOf(
      'if [[ "$(command -v gh)" != "$expected_gh" ]]; then',
    );
    const firstCall = firstRun.search(/\bgh (?:api|release)\b/);
    assert.ok(
      guard >= 0 && guard < firstCall,
      `${name} rejects an unpinned CLI before use`,
    );
    assert.match(firstRun.slice(guard, firstCall), /exit 1/);
  }
});

test("release discovery reuses drafts and rejects ambiguity before creation", async () => {
  const workflow = parseYaml(
    await readFile(
      resolve(
        import.meta.dirname,
        "../.github/workflows/release-contracts.yml",
      ),
      "utf8",
    ),
  );
  const run = workflow.jobs.release.steps.find(
    (step) => step.name === "Reconcile and publish GitHub release",
  ).run;
  const discovery = run.slice(
    run.indexOf("find_release() {"),
    run.indexOf('release_id="$(jq'),
  );
  assert.ok(discovery.startsWith("find_release() {"));
  const draft = { id: 123, tag_name: "v0.1.0-alpha.11", draft: true };
  const published = { ...draft, draft: false };
  const cases = [
    { name: "existing draft", pages: [[draft]], expected: draft },
    { name: "published release", pages: [[published]], expected: published },
    {
      name: "later page",
      pages: [[{ tag_name: "other" }], [draft]],
      expected: draft,
    },
    { name: "absent", pages: [[]], creates: true, expected: draft },
    { name: "ambiguous", pages: [[draft], [published]], fails: true },
    { name: "API error", pages: [[]], apiError: true, fails: true },
    { name: "malformed", pages: "invalid", fails: true },
    {
      name: "creation race",
      pages: [[]],
      creates: true,
      createError: true,
      fallback: [[draft]],
      expected: draft,
    },
    {
      name: "ambiguous creation race",
      pages: [[]],
      creates: true,
      createError: true,
      fallback: [[draft, published]],
      fails: true,
    },
  ];
  for (const entry of cases) {
    const directory = await mkdtemp(join(tmpdir(), "release-discovery-"));
    try {
      const result = spawnSync(
        "bash",
        [
          "-euo",
          "pipefail",
          "-c",
          `
        verify_release_identity() { :; }
        validate_release_metadata() { :; }
        gh() {
          if [[ " $* " == *" --method POST "* ]]; then
            touch "$RUNNER_TEMP/created"
            printf '%s' "$CREATED_JSON"
            return "$CREATE_ERROR"
          fi
          [[ "$*" == "api --paginate repos/example/repo/releases?per_page=100 --slurp" ]] || return 99
          if [[ -f "$RUNNER_TEMP/created" ]]; then
            printf '%s' "$FALLBACK_PAGES"
          else
            printf '%s' "$RELEASE_PAGES"
          fi
          return "$API_ERROR"
        }
        ${discovery}
        printf '%s' "$release_json"
      `,
        ],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            RUNNER_TEMP: directory,
            GITHUB_REPOSITORY: "example/repo",
            TAG: draft.tag_name,
            SOURCE_SHA: "source",
            title: "title",
            compatibility: "body",
            PRERELEASE: "true",
            RELEASE_PAGES:
              typeof entry.pages === "string"
                ? entry.pages
                : JSON.stringify(entry.pages),
            FALLBACK_PAGES: JSON.stringify(entry.fallback ?? [[]]),
            CREATED_JSON: JSON.stringify(draft),
            API_ERROR: entry.apiError ? "1" : "0",
            CREATE_ERROR: entry.createError ? "1" : "0",
          },
        },
      );
      assert.ifError(result.error);
      if (entry.fails) assert.notEqual(result.status, 0, entry.name);
      else {
        assert.equal(result.status, 0, `${entry.name}: ${result.stderr}`);
        assert.deepEqual(JSON.parse(result.stdout), entry.expected, entry.name);
      }
      const created = await access(join(directory, "created")).then(
        () => true,
        () => false,
      );
      assert.equal(created, entry.creates ?? false, entry.name);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
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
  assert.match(workflow, /expected_paths\[@\]\}" -ne "\$expected_asset_count"/);
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
