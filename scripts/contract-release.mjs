import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, parse, posix, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { create as createTar } from "tar";

export const repositoryDirectory = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
);
export const releaseRepository = "https://github.com/bwmp-dev/provenance";

export const contractBundles = [
  {
    id: "config-schema",
    entries: [
      { source: "LICENSE", destination: "LICENSE" },
      {
        source: "packages/config-schema/package.json",
        destination: "package/package.json",
        packageVersion: true,
      },
      {
        source: "packages/config-schema/dist",
        destination: "package/dist",
      },
      { source: "schemas/config/v1", destination: "schema" },
      { source: "schemas/fixtures/config", destination: "fixtures" },
    ],
  },
  {
    id: "attestation-schema",
    entries: [
      { source: "LICENSE", destination: "LICENSE" },
      {
        source: "packages/verification/package.json",
        destination: "package/package.json",
        packageVersion: true,
      },
      {
        source: "packages/verification/dist",
        destination: "package/dist",
      },
      { source: "schemas/attestation/v1", destination: "schema" },
      { source: "schemas/fixtures/attestation", destination: "fixtures" },
    ],
  },
  {
    id: "runner-protocol",
    entries: [
      { source: "LICENSE", destination: "LICENSE" },
      {
        source: "packages/runner-protocol/package.json",
        destination: "typescript/package.json",
        packageVersion: true,
      },
      {
        source: "packages/runner-protocol/dist",
        destination: "typescript/dist",
      },
      { source: "proto/provenance/runner/v1", destination: "proto" },
      { source: "gen/proto", destination: "go" },
    ],
  },
  {
    id: "openapi",
    entries: [
      { source: "LICENSE", destination: "LICENSE" },
      {
        source: "openapi/provenance.v1.yaml",
        destination: "provenance.v1.yaml",
      },
      {
        source: "openapi/operation-inventory.json",
        destination: "operation-inventory.json",
      },
      { source: "openapi/redocly.yaml", destination: "redocly.yaml" },
    ],
  },
  {
    id: "typescript-client",
    entries: [
      { source: "LICENSE", destination: "LICENSE" },
      {
        source: "packages/api-client/package.json",
        destination: "package/package.json",
        packageVersion: true,
      },
      {
        source: "packages/api-client/dist",
        destination: "package/dist",
      },
    ],
  },
];

const semverPattern =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function validateReleaseIdentity(version, sourceCommit) {
  if (!semverPattern.test(version)) {
    throw new Error(`release version is not valid SemVer: ${version}`);
  }
  if (!/^[0-9a-fA-F]{40}$/.test(sourceCommit)) {
    throw new Error("source commit must be a 40-character Git SHA");
  }
  return { sourceCommit: sourceCommit.toLowerCase(), version };
}

export function validateSpdxTimestamp(createdAt) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(createdAt)) {
    throw new Error("SBOM creation time must be an RFC 3339 UTC timestamp");
  }
  const parsed = new Date(createdAt);
  if (
    Number.isNaN(parsed.valueOf()) ||
    parsed.toISOString().replace(".000Z", "Z") !== createdAt
  ) {
    throw new Error("SBOM creation time is invalid");
  }
  return createdAt;
}

export function archiveName(bundleId, version) {
  return `provenance-${bundleId}-${version}.tar.gz`;
}

export function releaseManifestName(version) {
  return `provenance-contracts-${version}.manifest.json`;
}

export function checksumName(version) {
  return `provenance-contracts-${version}.sha256`;
}

export function sbomName(version) {
  return `provenance-contracts-${version}.spdx.json`;
}

function digest(contents, algorithm = "sha256") {
  return createHash(algorithm).update(contents).digest("hex");
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function json(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function filesystemPath(root, portablePath) {
  return join(root, ...portablePath.split("/"));
}

function assertSafeDestination(destination) {
  if (
    !destination ||
    destination.startsWith("/") ||
    destination.includes("\\") ||
    posix.normalize(destination) !== destination ||
    destination.split("/").includes("..")
  ) {
    throw new Error(`unsafe archive destination: ${destination}`);
  }
}

async function packageContents(sourcePath, version) {
  const document = JSON.parse(await readFile(sourcePath, "utf8"));
  document.version = version;
  return Buffer.from(json(document), "utf8");
}

async function stageEntry({
  destination,
  files,
  packageVersion,
  source,
  stagingDirectory,
  version,
}) {
  assertSafeDestination(destination);
  const sourcePath = resolve(repositoryDirectory, source);
  const sourceRelative = relative(repositoryDirectory, sourcePath).replaceAll(
    "\\",
    "/",
  );
  if (sourceRelative.startsWith("../") || sourceRelative === "..") {
    throw new Error(`release source leaves the repository: ${source}`);
  }

  const sourceStat = await lstat(sourcePath);
  if (sourceStat.isSymbolicLink()) {
    throw new Error(`release sources must not be symbolic links: ${source}`);
  }
  if (sourceStat.isDirectory()) {
    if (packageVersion) {
      throw new Error(`package version transforms require a file: ${source}`);
    }
    const children = (await readdir(sourcePath)).sort();
    for (const child of children) {
      await stageEntry({
        destination: posix.join(destination, child),
        files,
        packageVersion: false,
        source: posix.join(source, child),
        stagingDirectory,
        version,
      });
    }
    return;
  }
  if (!sourceStat.isFile()) {
    throw new Error(`release sources must be regular files: ${source}`);
  }

  const contents = packageVersion
    ? await packageContents(sourcePath, version)
    : await readFile(sourcePath);
  const destinationPath = filesystemPath(stagingDirectory, destination);
  await mkdir(dirname(destinationPath), { recursive: true });
  await writeFile(destinationPath, contents, { mode: 0o644 });
  files.push({
    path: destination,
    sha1: digest(contents, "sha1"),
    sha256: digest(contents),
    size: contents.byteLength,
    source: sourceRelative,
    ...(packageVersion ? { transform: "release-version" } : {}),
  });
}

async function assertEmptyOutputDirectory(outputDirectory) {
  const root = parse(outputDirectory).root;
  if (outputDirectory === root || outputDirectory === repositoryDirectory) {
    throw new Error(
      "release output must not be a filesystem or repository root",
    );
  }
  try {
    const entries = await readdir(outputDirectory);
    if (entries.length > 0) {
      throw new Error(
        `release output directory is not empty: ${outputDirectory}`,
      );
    }
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
    await mkdir(outputDirectory, { recursive: true });
  }
}

export async function toolchainManifest() {
  const workspace = JSON.parse(
    await readFile(resolve(repositoryDirectory, "package.json"), "utf8"),
  );
  const requirements = await readFile(
    resolve(repositoryDirectory, "requirements-contracts.txt"),
    "utf8",
  );
  const spdxTools = /^spdx-tools==([^\r\n]+)$/m.exec(requirements)?.[1];
  if (!spdxTools) {
    throw new Error("spdx-tools must be pinned in requirements-contracts.txt");
  }
  return {
    buf: workspace.devDependencies["@bufbuild/buf"],
    go: (
      await readFile(resolve(repositoryDirectory, ".go-version"), "utf8")
    ).trim(),
    node: (
      await readFile(resolve(repositoryDirectory, ".node-version"), "utf8")
    ).trim(),
    openapiTypescript: JSON.parse(
      await readFile(
        resolve(repositoryDirectory, "packages/api-client/package.json"),
        "utf8",
      ),
    ).devDependencies["openapi-typescript"],
    pnpm: workspace.packageManager,
    protocGenEs: workspace.devDependencies["@bufbuild/protoc-gen-es"],
    spdxTools,
    tar: workspace.devDependencies.tar,
  };
}

function packageVerificationCode(files) {
  const checksums = files
    .map((file) => file.sha1)
    .sort(compareText)
    .join("");
  return digest(Buffer.from(checksums, "ascii"), "sha1");
}

export function createSpdxDocument({
  artifacts,
  bundleContents,
  createdAt,
  sourceCommit,
  version,
}) {
  validateSpdxTimestamp(createdAt);
  const artifactsByBundle = new Map(
    artifacts.map((artifact) => [artifact.bundle, artifact]),
  );
  const contentsByBundle = new Map(
    bundleContents.map((contents) => [contents.bundle, contents.files]),
  );
  const packages = [];
  const files = [];
  const relationships = [];
  const documentDescribes = [];

  for (const bundle of contractBundles) {
    const artifact = artifactsByBundle.get(bundle.id);
    const bundleFiles = contentsByBundle.get(bundle.id);
    if (!artifact || !bundleFiles) {
      throw new Error(`SBOM input is missing bundle: ${bundle.id}`);
    }
    const packageId = `SPDXRef-Package-${bundle.id}`;
    documentDescribes.push(packageId);
    packages.push({
      SPDXID: packageId,
      checksums: [{ algorithm: "SHA256", checksumValue: artifact.sha256 }],
      copyrightText: "NOASSERTION",
      downloadLocation: "NOASSERTION",
      filesAnalyzed: true,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "Apache-2.0",
      name: `provenance-${bundle.id}`,
      packageFileName: artifact.filename,
      packageVerificationCode: {
        packageVerificationCodeValue: packageVerificationCode(bundleFiles),
      },
      primaryPackagePurpose: "LIBRARY",
      versionInfo: version,
    });
    relationships.push({
      relatedSpdxElement: packageId,
      relationshipType: "DESCRIBES",
      spdxElementId: "SPDXRef-DOCUMENT",
    });

    for (const [index, file] of bundleFiles.entries()) {
      const fileId = `SPDXRef-File-${bundle.id}-${String(index + 1).padStart(4, "0")}`;
      files.push({
        SPDXID: fileId,
        checksums: [
          { algorithm: "SHA1", checksumValue: file.sha1 },
          { algorithm: "SHA256", checksumValue: file.sha256 },
        ],
        copyrightText: "NOASSERTION",
        fileName: `./${artifact.filename.slice(0, -".tar.gz".length)}/${file.path}`,
        licenseConcluded: "NOASSERTION",
        licenseInfoInFiles: ["NOASSERTION"],
      });
      relationships.push({
        relatedSpdxElement: fileId,
        relationshipType: "CONTAINS",
        spdxElementId: packageId,
      });
    }
  }

  return {
    SPDXID: "SPDXRef-DOCUMENT",
    creationInfo: {
      created: createdAt,
      creators: ["Tool: @bwmp-dev/provenance-contract-release"],
    },
    dataLicense: "CC0-1.0",
    documentDescribes,
    documentNamespace: `${releaseRepository}/releases/tag/v${encodeURIComponent(version)}/spdx/${sourceCommit}`,
    files,
    name: `provenance-contracts-${version}`,
    packages,
    relationships,
    spdxVersion: "SPDX-2.3",
  };
}

export async function buildContractRelease({
  createdAt,
  outputDirectory,
  sourceCommit,
  version,
}) {
  const identity = validateReleaseIdentity(version, sourceCommit);
  const sbomCreatedAt = validateSpdxTimestamp(createdAt);
  const resolvedOutput = resolve(outputDirectory);
  await assertEmptyOutputDirectory(resolvedOutput);

  const temporaryDirectory = await mkdtemp(
    join(tmpdir(), "provenance-contract-release-"),
  );
  const artifacts = [];
  const bundleContents = [];
  try {
    for (const bundle of contractBundles) {
      const stagingDirectory = resolve(temporaryDirectory, bundle.id);
      await mkdir(stagingDirectory, { recursive: true });
      const files = [];
      for (const entry of bundle.entries) {
        await stageEntry({
          ...entry,
          files,
          stagingDirectory,
          version: identity.version,
        });
      }
      files.sort((left, right) => compareText(left.path, right.path));

      const archiveRoot = `provenance-${bundle.id}-${identity.version}`;
      const embeddedManifest = {
        schemaVersion: 1,
        bundle: bundle.id,
        releaseVersion: identity.version,
        sourceCommit: identity.sourceCommit,
        files,
      };
      const embeddedManifestContents = Buffer.from(
        json(embeddedManifest),
        "utf8",
      );
      await writeFile(
        resolve(stagingDirectory, "RELEASE-MANIFEST.json"),
        embeddedManifestContents,
        { mode: 0o644 },
      );
      bundleContents.push({
        bundle: bundle.id,
        files: [
          ...files,
          {
            path: "RELEASE-MANIFEST.json",
            sha1: digest(embeddedManifestContents, "sha1"),
            sha256: digest(embeddedManifestContents),
            size: embeddedManifestContents.byteLength,
          },
        ].sort((left, right) => compareText(left.path, right.path)),
      });

      const filename = archiveName(bundle.id, identity.version);
      const archivePath = resolve(resolvedOutput, filename);
      const stagedFiles = [
        "RELEASE-MANIFEST.json",
        ...files.map((file) => file.path),
      ].sort();
      await createTar(
        {
          cwd: stagingDirectory,
          file: archivePath,
          gzip: { level: 9, mtime: 0, portable: true },
          mtime: new Date(0),
          portable: true,
          prefix: archiveRoot,
          strict: true,
        },
        stagedFiles,
      );
      const contents = await readFile(archivePath);
      artifacts.push({
        bundle: bundle.id,
        filename,
        sha256: digest(contents),
        size: contents.byteLength,
      });
    }

    artifacts.sort((left, right) => compareText(left.filename, right.filename));
    const sbomFilename = sbomName(identity.version);
    const sbomContents = Buffer.from(
      json(
        createSpdxDocument({
          artifacts,
          bundleContents,
          createdAt: sbomCreatedAt,
          sourceCommit: identity.sourceCommit,
          version: identity.version,
        }),
      ),
      "utf8",
    );
    const sbom = {
      filename: sbomFilename,
      format: "SPDX-2.3",
      sha256: digest(sbomContents),
      size: sbomContents.byteLength,
    };
    await writeFile(resolve(resolvedOutput, sbomFilename), sbomContents, {
      mode: 0o644,
    });

    const manifest = {
      schemaVersion: 1,
      release: {
        createdAt: sbomCreatedAt,
        repository: releaseRepository,
        sourceCommit: identity.sourceCommit,
        tag: `v${identity.version}`,
        version: identity.version,
      },
      toolchain: await toolchainManifest(),
      artifacts,
      sbom,
    };
    const manifestFilename = releaseManifestName(identity.version);
    const manifestContents = Buffer.from(json(manifest), "utf8");
    await writeFile(
      resolve(resolvedOutput, manifestFilename),
      manifestContents,
      { mode: 0o644 },
    );

    const checksums = [
      ...artifacts.map(({ filename, sha256 }) => ({ filename, sha256 })),
      { filename: manifestFilename, sha256: digest(manifestContents) },
      { filename: sbomFilename, sha256: digest(sbomContents) },
    ]
      .sort((left, right) => compareText(left.filename, right.filename))
      .map(({ filename, sha256 }) => `${sha256}  ${filename}`)
      .join("\n");
    await writeFile(
      resolve(resolvedOutput, checksumName(identity.version)),
      `${checksums}\n`,
      { mode: 0o644 },
    );
    return manifest;
  } finally {
    await rm(temporaryDirectory, { force: true, recursive: true });
  }
}

function parseArguments(arguments_) {
  const values = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const name = arguments_[index];
    const value = arguments_[index + 1];
    if (
      !["--created-at", "--output", "--source-commit", "--version"].includes(
        name,
      ) ||
      !value
    ) {
      throw new Error(`invalid release argument: ${name ?? "<missing>"}`);
    }
    values[name.slice(2)] = value;
  }
  if (!values.version || !values["source-commit"] || !values["created-at"]) {
    throw new Error(
      "--version, --source-commit, and --created-at are required",
    );
  }
  return {
    createdAt: values["created-at"],
    outputDirectory:
      values.output ?? resolve(repositoryDirectory, "dist/contracts"),
    sourceCommit: values["source-commit"],
    version: values.version,
  };
}

if (
  process.argv[1] &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url
) {
  const options = parseArguments(process.argv.slice(2));
  const manifest = await buildContractRelease(options);
  console.info(
    `Built ${manifest.artifacts.length} contract archives for ${manifest.release.tag}`,
  );
}
