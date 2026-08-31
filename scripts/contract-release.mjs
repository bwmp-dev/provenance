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
import { parse as parseYaml } from "yaml";

export const repositoryDirectory = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
);
export const releaseRepository = "https://github.com/bwmp-dev/provenance";

export const contractBundles = [
  {
    id: "config-schema",
    nodeImporter: "packages/config-schema",
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
    nodeImporter: "packages/verification",
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
    goModule: "gen/proto",
    nodeImporter: "packages/runner-protocol",
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
        source: "openapi/provenance.v1.yaml",
        destination: "openapi.json",
        openapiJson: true,
      },
      {
        source: "openapi/operation-inventory.json",
        destination: "operation-inventory.json",
      },
      { source: "openapi/redocly.yaml", destination: "redocly.yaml" },
    ],
  },
  {
    id: "paper-metadata",
    entries: [
      { source: "LICENSE", destination: "LICENSE" },
      {
        source: "schemas/paper-metadata/v1/schema.json",
        destination: "schema/schema.json",
      },
      {
        source: "plugins/paper-probe/build/libs/paper-probe-0.1.0.jar",
        destination: "paper-metadata-inspector.jar",
      },
      {
        source: "plugins/paper-probe/runtime-dependencies.json",
        destination: "runtime-dependencies.json",
      },
      {
        source:
          "packages/test-fixtures/benign/success/build/libs/success-1.0.0.jar",
        destination: "fixtures/success.jar",
      },
    ],
  },
  {
    id: "typescript-client",
    nodeImporter: "packages/api-client",
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

export function compatibilityDeclaration(version) {
  return {
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
    sdk: {
      typescriptClient: version,
    },
  };
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
  openapiJson,
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
    if (packageVersion || openapiJson) {
      throw new Error(`release transforms require a file: ${source}`);
    }
    const children = (await readdir(sourcePath)).sort();
    for (const child of children) {
      await stageEntry({
        destination: posix.join(destination, child),
        files,
        openapiJson: false,
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

  if (packageVersion && openapiJson) {
    throw new Error(`release source has conflicting transforms: ${source}`);
  }
  const contents = packageVersion
    ? await packageContents(sourcePath, version)
    : openapiJson
      ? Buffer.from(json(parseYaml(await readFile(sourcePath, "utf8"))), "utf8")
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
    ...(packageVersion
      ? { transform: "release-version" }
      : openapiJson
        ? { transform: "openapi-json" }
        : {}),
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
    java: "21",
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

function dependencySpdxId(ecosystem, name, version) {
  const key = `${ecosystem}:${name}@${version}`;
  const readable = key.replaceAll(/[^A-Za-z0-9.-]/g, "-");
  return `SPDXRef-Dependency-${readable}-${digest(Buffer.from(key)).slice(0, 12)}`;
}

function packageUrl(ecosystem, name, version) {
  if (ecosystem === "npm" && name.startsWith("@")) {
    const [scope, packageName] = name.slice(1).split("/");
    return `pkg:npm/%40${scope}/${packageName}@${version}`;
  }
  if (ecosystem === "maven") {
    return `pkg:maven/${name.replace(":", "/")}@${version}`;
  }
  return `pkg:${ecosystem}/${name}@${version}`;
}

function checksumFromIntegrity(integrity) {
  const match = /^(sha512|sha256|sha1)-(.+)$/.exec(integrity ?? "");
  if (!match) {
    throw new Error(`unsupported dependency integrity: ${integrity}`);
  }
  return {
    algorithm: match[1].toUpperCase(),
    checksumValue: Buffer.from(match[2], "base64").toString("hex"),
  };
}

async function installedNodeLicense(name, version) {
  const virtualStore = resolve(repositoryDirectory, "node_modules/.pnpm");
  const prefix = `${name.replace("/", "+")}@${version}`;
  const candidates = (await readdir(virtualStore))
    .filter((entry) => entry === prefix || entry.startsWith(`${prefix}_`))
    .sort(compareText);
  for (const candidate of candidates) {
    try {
      const packageDocument = JSON.parse(
        await readFile(
          resolve(
            virtualStore,
            candidate,
            "node_modules",
            ...name.split("/"),
            "package.json",
          ),
          "utf8",
        ),
      );
      if (
        packageDocument.name === name &&
        packageDocument.version === version
      ) {
        return packageDocument.license || "NOASSERTION";
      }
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw error;
      }
    }
  }
  throw new Error(
    `installed package is missing license evidence: ${name}@${version}`,
  );
}

async function nodeDependencyRecord(name, reference, lockfile) {
  const snapshotKey = `${name}@${reference}`;
  const snapshot = lockfile.snapshots?.[snapshotKey];
  if (!snapshot) {
    throw new Error(
      `pnpm lockfile is missing runtime snapshot: ${snapshotKey}`,
    );
  }
  const version = reference.replace(/\(.+$/, "");
  const packageKey = `${name}@${version}`;
  const metadata = lockfile.packages?.[packageKey];
  if (!metadata?.resolution?.integrity) {
    throw new Error(
      `pnpm lockfile is missing integrity evidence: ${packageKey}`,
    );
  }
  return {
    checksum: checksumFromIntegrity(metadata.resolution.integrity),
    ecosystem: "npm",
    key: `npm:${packageKey}`,
    license: await installedNodeLicense(name, version),
    name,
    reference,
    snapshot,
    version,
  };
}

async function runtimeDependencyInventory() {
  const lockfile = parseYaml(
    await readFile(resolve(repositoryDirectory, "pnpm-lock.yaml"), "utf8"),
  );
  const components = new Map();
  const dependenciesByBundle = new Map();

  for (const bundle of contractBundles.filter(
    ({ nodeImporter }) => nodeImporter,
  )) {
    const importer = lockfile.importers?.[bundle.nodeImporter];
    if (!importer) {
      throw new Error(
        `pnpm lockfile is missing importer: ${bundle.nodeImporter}`,
      );
    }
    const queue = Object.entries(importer.dependencies ?? {});
    const bundleDependencies = new Set();
    while (queue.length > 0) {
      const [name, dependency] = queue.shift();
      const record = await nodeDependencyRecord(
        name,
        dependency.version ?? dependency,
        lockfile,
      );
      if (bundleDependencies.has(record.key)) {
        continue;
      }
      bundleDependencies.add(record.key);
      components.set(record.key, record);
      for (const child of Object.entries({
        ...(record.snapshot.dependencies ?? {}),
        ...(record.snapshot.optionalDependencies ?? {}),
      })) {
        queue.push(child);
      }
    }
    dependenciesByBundle.set(bundle.id, bundleDependencies);
  }

  const goMod = await readFile(
    resolve(repositoryDirectory, "gen/proto/go.mod"),
    "utf8",
  );
  const goSum = await readFile(
    resolve(repositoryDirectory, "gen/proto/go.sum"),
    "utf8",
  );
  const sums = new Map();
  for (const line of goSum.trimEnd().split("\n")) {
    const match = /^(\S+) (\S+) h1:(\S+)$/.exec(line.trim());
    if (match && !match[2].endsWith("/go.mod")) {
      sums.set(`${match[1]}@${match[2]}`, match[3]);
    }
  }
  const goRequirements = [];
  for (const block of goMod.matchAll(/require\s*\(([^)]*)\)/g)) {
    for (const line of block[1].trim().split("\n")) {
      const match = /^(\S+)\s+(\S+)/.exec(line.trim());
      if (match) {
        goRequirements.push({ name: match[1], version: match[2] });
      }
    }
  }
  const goDependencies = new Set();
  for (const requirement of goRequirements) {
    const packageKey = `${requirement.name}@${requirement.version}`;
    const sum = sums.get(packageKey);
    if (!sum) {
      throw new Error(`go.sum is missing module checksum: ${packageKey}`);
    }
    const key = `golang:${packageKey}`;
    components.set(key, {
      checksum: {
        algorithm: "SHA256",
        checksumValue: Buffer.from(sum, "base64").toString("hex"),
      },
      ecosystem: "golang",
      key,
      license: "NOASSERTION",
      name: requirement.name,
      version: requirement.version,
    });
    goDependencies.add(key);
  }
  dependenciesByBundle.set(
    "runner-protocol",
    new Set([
      ...(dependenciesByBundle.get("runner-protocol") ?? []),
      ...goDependencies,
    ]),
  );

  const javaDependencies = JSON.parse(
    await readFile(
      resolve(
        repositoryDirectory,
        "plugins/paper-probe/runtime-dependencies.json",
      ),
      "utf8",
    ),
  );
  const paperProbeLock = await readFile(
    resolve(repositoryDirectory, "plugins/paper-probe/gradle.lockfile"),
    "utf8",
  );
  const paperProbeBuild = await readFile(
    resolve(repositoryDirectory, "build.gradle"),
    "utf8",
  );
  const expectedJavaCoordinates = new Set(
    [...paperProbeBuild.matchAll(/\bimplementation\("([^"\r\n]+)"\)/g)].map(
      (match) => match[1],
    ),
  );
  const paperMetadataDependencies = new Set();
  if (!Array.isArray(javaDependencies)) {
    throw new Error(
      "paper metadata runtime dependency inventory must be an array",
    );
  }
  for (const dependency of javaDependencies) {
    const name = `${dependency.group}:${dependency.artifact}`;
    const key = `maven:${name}@${dependency.version}`;
    if (
      Object.keys(dependency).sort().join(",") !==
        "artifact,checksum,group,license,version" ||
      !/^[0-9a-f]{64}$/.test(dependency.checksum) ||
      !dependency.license ||
      !paperProbeLock
        .split("\n")
        .some((line) => line.startsWith(`${name}:${dependency.version}=`))
    ) {
      throw new Error(`invalid paper metadata runtime dependency: ${key}`);
    }
    components.set(key, {
      checksum: {
        algorithm: "SHA256",
        checksumValue: dependency.checksum,
      },
      ecosystem: "maven",
      key,
      license: dependency.license,
      name,
      version: dependency.version,
    });
    if (!paperMetadataDependencies.add(key)) {
      throw new Error(`duplicate paper metadata runtime dependency: ${key}`);
    }
  }
  const declaredJavaCoordinates = new Set(
    javaDependencies.map(
      (dependency) =>
        `${dependency.group}:${dependency.artifact}:${dependency.version}`,
    ),
  );
  if (
    expectedJavaCoordinates.size !== declaredJavaCoordinates.size ||
    [...expectedJavaCoordinates].some(
      (coordinate) => !declaredJavaCoordinates.has(coordinate),
    )
  ) {
    throw new Error(
      "paper metadata runtime dependency inventory differs from Gradle",
    );
  }
  dependenciesByBundle.set("paper-metadata", paperMetadataDependencies);

  return {
    components: [...components.values()].sort((left, right) =>
      compareText(left.key, right.key),
    ),
    dependenciesByBundle,
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
  runtimeDependencies,
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

  for (const dependency of runtimeDependencies.components) {
    const packageId = dependencySpdxId(
      dependency.ecosystem,
      dependency.name,
      dependency.version,
    );
    packages.push({
      SPDXID: packageId,
      checksums: [dependency.checksum],
      copyrightText: "NOASSERTION",
      downloadLocation: "NOASSERTION",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceLocator: packageUrl(
            dependency.ecosystem,
            dependency.name,
            dependency.version,
          ),
          referenceType: "purl",
        },
      ],
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: dependency.license,
      name: dependency.name,
      primaryPackagePurpose: "LIBRARY",
      versionInfo: dependency.version,
    });
  }
  for (const bundle of contractBundles) {
    const dependencies = [
      ...(runtimeDependencies.dependenciesByBundle.get(bundle.id) ?? []),
    ].sort(compareText);
    for (const dependencyKey of dependencies) {
      const dependency = runtimeDependencies.components.find(
        ({ key }) => key === dependencyKey,
      );
      if (!dependency) {
        throw new Error(`SBOM dependency is missing: ${dependencyKey}`);
      }
      relationships.push({
        relatedSpdxElement: dependencySpdxId(
          dependency.ecosystem,
          dependency.name,
          dependency.version,
        ),
        relationshipType: "DEPENDS_ON",
        spdxElementId: `SPDXRef-Package-${bundle.id}`,
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
    const runtimeDependencies = await runtimeDependencyInventory();
    const sbomFilename = sbomName(identity.version);
    const sbomContents = Buffer.from(
      json(
        createSpdxDocument({
          artifacts,
          bundleContents,
          createdAt: sbomCreatedAt,
          runtimeDependencies,
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
      compatibility: compatibilityDeclaration(identity.version),
      dependencies: runtimeDependencies.components.map((dependency) => ({
        bundles: contractBundles
          .filter((bundle) =>
            runtimeDependencies.dependenciesByBundle
              .get(bundle.id)
              ?.has(dependency.key),
          )
          .map(({ id }) => id),
        checksum: dependency.checksum,
        ecosystem: dependency.ecosystem,
        license: dependency.license,
        name: dependency.name,
        version: dependency.version,
      })),
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
