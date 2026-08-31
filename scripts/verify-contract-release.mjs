import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, posix, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { extract as extractTar, list as listTar } from "tar";
import { parse as parseYaml } from "yaml";

import {
  archiveName,
  checksumName,
  contractBundles,
  releaseManifestName,
  releaseRepository,
  repositoryDirectory,
  toolchainManifest,
  validateReleaseIdentity,
} from "./contract-release.mjs";

function invariant(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function digest(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

function sorted(values) {
  return [...values].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
}

function equalStringSets(actual, expected, message) {
  invariant(
    JSON.stringify(sorted(actual)) === JSON.stringify(sorted(expected)),
    `${message}\nexpected: ${JSON.stringify(sorted(expected))}\nactual: ${JSON.stringify(sorted(actual))}`,
  );
}

function filesystemPath(root, portablePath) {
  return join(root, ...portablePath.split("/"));
}

function assertSafeArchivePath(path, root) {
  invariant(path.length > 0, "archive contains an empty path");
  invariant(!path.includes("\\"), `archive path uses a backslash: ${path}`);
  invariant(!posix.isAbsolute(path), `archive path is absolute: ${path}`);
  invariant(
    posix.normalize(path) === path,
    `archive path is not normalized: ${path}`,
  );
  invariant(
    path === root || path.startsWith(`${root}/`),
    `archive path leaves its release root: ${path}`,
  );
  invariant(
    !path.split("/").includes(".."),
    `archive path contains traversal: ${path}`,
  );
}

async function archiveEntries(archivePath, archiveRoot) {
  const entries = [];
  await listTar({
    file: archivePath,
    strict: true,
    onReadEntry(entry) {
      assertSafeArchivePath(entry.path, archiveRoot);
      invariant(
        entry.type === "File",
        `archive entry is not a file: ${entry.path}`,
      );
      entries.push(entry.path);
      entry.resume();
    },
  });
  equalStringSets(
    entries,
    new Set(entries),
    "archive contains duplicate entries",
  );
  return entries;
}

async function extractCheckedArchive(archivePath, destination, archiveRoot) {
  const entries = await archiveEntries(archivePath, archiveRoot);
  await mkdir(destination, { recursive: true });
  await extractTar({
    cwd: destination,
    file: archivePath,
    strict: true,
    filter(path, entry) {
      assertSafeArchivePath(path, archiveRoot);
      invariant(entry.type === "File", `archive entry is not a file: ${path}`);
      return true;
    },
  });
  return entries;
}

async function readJson(path, description) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    throw new Error(`${description} is not valid JSON: ${error.message}`);
  }
}

async function verifyArchive({
  archive,
  directory,
  releaseSourceCommit,
  version,
  verificationDirectory,
}) {
  const expectedFilename = archiveName(archive.bundle, version);
  invariant(
    archive.filename === expectedFilename,
    `unexpected archive filename for ${archive.bundle}`,
  );
  const archivePath = resolve(directory, archive.filename);
  const contents = await readFile(archivePath);
  invariant(
    contents.byteLength === archive.size,
    `${archive.filename} size differs`,
  );
  invariant(
    digest(contents) === archive.sha256,
    `${archive.filename} digest differs`,
  );

  const archiveRoot = archive.filename.slice(0, -".tar.gz".length);
  const entries = await extractCheckedArchive(
    archivePath,
    verificationDirectory,
    archiveRoot,
  );
  const extractedRoot = resolve(verificationDirectory, archiveRoot);
  const embeddedManifest = await readJson(
    resolve(extractedRoot, "RELEASE-MANIFEST.json"),
    `${archive.filename} embedded manifest`,
  );
  invariant(
    embeddedManifest.schemaVersion === 1,
    "unsupported bundle manifest",
  );
  invariant(embeddedManifest.bundle === archive.bundle, "bundle ID differs");
  invariant(
    embeddedManifest.releaseVersion === version,
    "bundle version differs",
  );
  invariant(
    embeddedManifest.sourceCommit === releaseSourceCommit,
    "bundle source commit differs",
  );
  invariant(Array.isArray(embeddedManifest.files), "bundle files are missing");

  const expectedEntries = [
    `${archiveRoot}/RELEASE-MANIFEST.json`,
    ...embeddedManifest.files.map((file) => `${archiveRoot}/${file.path}`),
  ];
  equalStringSets(
    entries,
    expectedEntries,
    `${archive.filename} entries differ`,
  );

  for (const file of embeddedManifest.files) {
    assertSafeArchivePath(`${archiveRoot}/${file.path}`, archiveRoot);
    invariant(
      typeof file.source === "string" &&
        !file.source.startsWith("../") &&
        !file.source.includes("\\"),
      `bundle source is invalid: ${file.source}`,
    );
    const filePath = filesystemPath(extractedRoot, file.path);
    const fileStat = await stat(filePath);
    invariant(fileStat.isFile(), `bundle entry is not a file: ${file.path}`);
    const fileContents = await readFile(filePath);
    invariant(
      fileContents.byteLength === file.size,
      `bundle size differs: ${file.path}`,
    );
    invariant(
      digest(fileContents) === file.sha256,
      `bundle digest differs: ${file.path}`,
    );
    if (file.transform === "release-version") {
      const packageDocument = JSON.parse(fileContents.toString("utf8"));
      invariant(
        packageDocument.version === version,
        `package version differs: ${file.path}`,
      );
    } else {
      invariant(
        file.transform === undefined,
        `unknown bundle transform: ${file.transform}`,
      );
    }
  }
}

function run(command, arguments_, workingDirectory, description) {
  const result = spawnSync(command, arguments_, {
    cwd: workingDirectory,
    encoding: "utf8",
    shell: false,
  });
  invariant(
    result.error === undefined,
    `${description} failed to start: ${result.error?.message}`,
  );
  invariant(
    result.status === 0,
    `${description} failed\n${[result.stdout, result.stderr].filter(Boolean).join("\n")}`,
  );
}

async function withConsumerArchive(directory, bundle, version, callback) {
  const cacheDirectory = resolve(
    repositoryDirectory,
    bundle === "config-schema"
      ? "packages/config-schema/.cache"
      : bundle === "attestation-schema"
        ? "packages/verification/.cache"
        : bundle === "runner-protocol"
          ? "packages/runner-protocol/.cache"
          : bundle === "typescript-client"
            ? "packages/api-client/.cache"
            : ".cache",
  );
  await mkdir(cacheDirectory, { recursive: true });
  const temporaryDirectory = await mkdtemp(
    join(cacheDirectory, `release-${bundle}-`),
  );
  const filename = archiveName(bundle, version);
  const archiveRoot = filename.slice(0, -".tar.gz".length);
  try {
    await extractCheckedArchive(
      resolve(directory, filename),
      temporaryDirectory,
      archiveRoot,
    );
    await callback(resolve(temporaryDirectory, archiveRoot));
  } finally {
    await rm(temporaryDirectory, { force: true, recursive: true });
  }
}

async function verifyConsumers(directory, version) {
  await withConsumerArchive(
    directory,
    "config-schema",
    version,
    async (root) => {
      const configuration = await import(
        `${pathToFileURL(resolve(root, "package/dist/index.js")).href}?release=${version}`
      );
      const source = await readFile(
        resolve(root, "fixtures/valid/hosted.yml"),
        "utf8",
      );
      const expectedHash = (
        await readFile(
          resolve(root, "fixtures/valid/hosted.normalized.sha256"),
          "utf8",
        )
      ).trim();
      invariant(
        configuration.hashConfiguration(
          configuration.parseConfiguration(source),
        ) === expectedHash,
        "released configuration consumer normalized the fixture differently",
      );
    },
  );

  await withConsumerArchive(
    directory,
    "attestation-schema",
    version,
    async (root) => {
      const verification = await import(
        `${pathToFileURL(resolve(root, "package/dist/index.js")).href}?release=${version}`
      );
      const document = await readJson(
        resolve(root, "fixtures/valid/hosted.json"),
        "released hosted attestation",
      );
      const vector = await readJson(
        resolve(root, "fixtures/vectors/hosted.json"),
        "released hosted vector",
      );
      verification.validateAttestation(document);
      invariant(
        verification.verifyAttestationSignature(
          document,
          Buffer.from(vector.publicKeyHex, "hex"),
        ),
        "released attestation consumer rejected the hosted signature vector",
      );
    },
  );

  await withConsumerArchive(
    directory,
    "runner-protocol",
    version,
    async (root) => {
      const protocol = await import(
        `${pathToFileURL(resolve(root, "typescript/dist/index.js")).href}?release=${version}`
      );
      invariant(
        protocol.RunnerMessageSchema,
        "released runner message schema is missing",
      );
      invariant(
        protocol.GatewayMessageSchema,
        "released gateway message schema is missing",
      );
      run("go", ["test", "./..."], resolve(root, "go"), "released Go bindings");
    },
  );

  await withConsumerArchive(directory, "openapi", version, async (root) => {
    const specification = parseYaml(
      await readFile(resolve(root, "provenance.v1.yaml"), "utf8"),
    );
    const inventory = await readJson(
      resolve(root, "operation-inventory.json"),
      "released OpenAPI inventory",
    );
    invariant(
      specification.openapi === "3.1.1",
      "released OpenAPI version differs",
    );
    invariant(
      Array.isArray(inventory) && inventory.length > 0,
      "released API inventory is empty",
    );
  });

  await withConsumerArchive(
    directory,
    "typescript-client",
    version,
    async (root) => {
      const clientModule = await import(
        `${pathToFileURL(resolve(root, "package/dist/index.js")).href}?release=${version}`
      );
      const client = clientModule.createProvenanceClient({
        baseUrl: "https://api.example.test",
      });
      invariant(
        typeof client.GET === "function",
        "released API client is not executable",
      );

      await writeFile(
        resolve(root, "consumer.mts"),
        [
          'import { createProvenanceClient, type paths } from "./package/dist/index.js";',
          'const path: keyof paths = "/v1/organizations";',
          'const client = createProvenanceClient({ baseUrl: "https://api.example.test" });',
          "void client.GET(path);",
          "",
        ].join("\n"),
      );
      await writeFile(
        resolve(root, "tsconfig.json"),
        JSON.stringify(
          {
            compilerOptions: {
              module: "NodeNext",
              moduleResolution: "NodeNext",
              noEmit: true,
              strict: true,
              target: "ES2023",
            },
            include: ["consumer.mts"],
          },
          null,
          2,
        ),
      );
      run(
        process.execPath,
        [
          resolve(
            repositoryDirectory,
            "packages/api-client/node_modules/typescript/bin/tsc",
          ),
          "--project",
          resolve(root, "tsconfig.json"),
        ],
        root,
        "released TypeScript client declarations",
      );
    },
  );
}

export async function verifyContractRelease({
  directory,
  consumers = false,
  version,
}) {
  const resolvedDirectory = resolve(directory);
  const manifestFilename = releaseManifestName(version);
  const manifestContents = await readFile(
    resolve(resolvedDirectory, manifestFilename),
  );
  const manifest = JSON.parse(manifestContents.toString("utf8"));
  invariant(manifest.schemaVersion === 1, "unsupported release manifest");
  invariant(manifest.release?.version === version, "release version differs");
  invariant(manifest.release?.tag === `v${version}`, "release tag differs");
  invariant(
    manifest.release?.repository === releaseRepository,
    "release repository differs",
  );
  const identity = validateReleaseIdentity(
    version,
    manifest.release?.sourceCommit ?? "",
  );
  invariant(
    JSON.stringify(manifest.toolchain) ===
      JSON.stringify(await toolchainManifest()),
    "release toolchain differs",
  );
  invariant(Array.isArray(manifest.artifacts), "release artifacts are missing");
  equalStringSets(
    manifest.artifacts.map((artifact) => artifact.bundle),
    contractBundles.map((bundle) => bundle.id),
    "release bundle inventory differs",
  );

  const checksumFilename = checksumName(version);
  const checksumLines = (
    await readFile(resolve(resolvedDirectory, checksumFilename), "utf8")
  )
    .trimEnd()
    .split("\n");
  const checksums = new Map();
  for (const line of checksumLines) {
    const match = /^([0-9a-f]{64})  ([^/\\]+)$/.exec(line);
    invariant(match, `invalid checksum line: ${line}`);
    invariant(!checksums.has(match[2]), `duplicate checksum: ${match[2]}`);
    checksums.set(match[2], match[1]);
  }
  const expectedChecksums = [
    ...manifest.artifacts.map((artifact) => artifact.filename),
    manifestFilename,
  ];
  equalStringSets(
    checksums.keys(),
    expectedChecksums,
    "checksum inventory differs",
  );
  invariant(
    checksums.get(manifestFilename) === digest(manifestContents),
    "release manifest checksum differs",
  );

  const verificationDirectory = await mkdtemp(
    join(tmpdir(), "provenance-contract-verify-"),
  );
  try {
    for (const archive of manifest.artifacts) {
      invariant(
        checksums.get(archive.filename) === archive.sha256,
        `${archive.filename} checksum file differs`,
      );
      await verifyArchive({
        archive,
        directory: resolvedDirectory,
        releaseSourceCommit: identity.sourceCommit,
        version,
        verificationDirectory,
      });
    }
    if (consumers) {
      await verifyConsumers(resolvedDirectory, version);
    }
  } finally {
    await rm(verificationDirectory, { force: true, recursive: true });
  }
  return manifest;
}

function parseArguments(arguments_) {
  const values = { consumers: false };
  for (let index = 0; index < arguments_.length; index += 1) {
    const name = arguments_[index];
    if (name === "--consumers") {
      values.consumers = true;
      continue;
    }
    if (!["--directory", "--version"].includes(name)) {
      throw new Error(`invalid verification argument: ${name ?? "<missing>"}`);
    }
    const value = arguments_[index + 1];
    if (!value) {
      throw new Error(`missing value for ${name}`);
    }
    values[name.slice(2)] = value;
    index += 1;
  }
  if (!values.version) {
    throw new Error("--version is required");
  }
  return {
    consumers: values.consumers,
    directory:
      values.directory ?? resolve(repositoryDirectory, "dist/contracts"),
    version: values.version,
  };
}

if (
  process.argv[1] &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url
) {
  const options = parseArguments(process.argv.slice(2));
  const manifest = await verifyContractRelease(options);
  console.info(
    `Verified ${manifest.artifacts.length} contract archives for ${manifest.release.tag}`,
  );
}
