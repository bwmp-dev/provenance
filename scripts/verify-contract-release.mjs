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
import { isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { extract as extractTar, list as listTar } from "tar";
import {
  parse as parseYaml,
  parseDocument as parseYamlDocument,
  stringify as stringifyYaml,
} from "yaml";

import {
  archiveName,
  checksumName,
  contractBundles,
  releaseManifestName,
  releaseRepository,
  repositoryDirectory,
  sbomName,
  toolchainManifest,
  validateReleaseIdentity,
  validateSpdxTimestamp,
} from "./contract-release.mjs";

const maximumArchiveEntries = 1000;
const maximumArchiveEntrySize = 20 * 1024 * 1024;
const maximumUnpackedArchiveSize = 100 * 1024 * 1024;

function invariant(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function digest(contents, algorithm = "sha256") {
  return createHash(algorithm).update(contents).digest("hex");
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
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
  invariant(match, `unsupported dependency integrity: ${integrity}`);
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

async function expectedRuntimeDependencies() {
  const lockfile = parseYaml(
    await readFile(resolve(repositoryDirectory, "pnpm-lock.yaml"), "utf8"),
  );
  const components = new Map();
  const dependenciesByBundle = new Map();
  for (const bundle of contractBundles.filter(
    ({ nodeImporter }) => nodeImporter,
  )) {
    const importer = lockfile.importers?.[bundle.nodeImporter];
    invariant(
      importer,
      `pnpm lockfile is missing importer: ${bundle.nodeImporter}`,
    );
    const queue = Object.entries(importer.dependencies ?? {});
    const bundleDependencies = new Set();
    while (queue.length > 0) {
      const [name, dependency] = queue.shift();
      const reference = dependency.version ?? dependency;
      const snapshot = lockfile.snapshots?.[`${name}@${reference}`];
      invariant(
        snapshot,
        `pnpm lockfile is missing runtime snapshot: ${name}@${reference}`,
      );
      const version = reference.replace(/\(.+$/, "");
      const packageKey = `${name}@${version}`;
      const metadata = lockfile.packages?.[packageKey];
      invariant(
        metadata?.resolution?.integrity,
        `pnpm lockfile is missing integrity evidence: ${packageKey}`,
      );
      const key = `npm:${packageKey}`;
      if (bundleDependencies.has(key)) {
        continue;
      }
      bundleDependencies.add(key);
      components.set(key, {
        checksum: checksumFromIntegrity(metadata.resolution.integrity),
        ecosystem: "npm",
        key,
        license: await installedNodeLicense(name, version),
        name,
        version,
      });
      for (const child of Object.entries({
        ...(snapshot.dependencies ?? {}),
        ...(snapshot.optionalDependencies ?? {}),
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
  const runnerDependencies = new Set(
    dependenciesByBundle.get("runner-protocol") ?? [],
  );
  for (const block of goMod.matchAll(/require\s*\(([^)]*)\)/g)) {
    for (const line of block[1].trim().split("\n")) {
      const match = /^(\S+)\s+(\S+)/.exec(line.trim());
      if (!match) {
        continue;
      }
      const packageKey = `${match[1]}@${match[2]}`;
      const sum = sums.get(packageKey);
      invariant(sum, `go.sum is missing module checksum: ${packageKey}`);
      const key = `golang:${packageKey}`;
      components.set(key, {
        checksum: {
          algorithm: "SHA256",
          checksumValue: Buffer.from(sum, "base64").toString("hex"),
        },
        ecosystem: "golang",
        key,
        license: "NOASSERTION",
        name: match[1],
        version: match[2],
      });
      runnerDependencies.add(key);
    }
  }
  dependenciesByBundle.set("runner-protocol", runnerDependencies);

  const javaDependencies = await readJson(
    resolve(
      repositoryDirectory,
      "plugins/paper-probe/runtime-dependencies.json",
    ),
    "paper metadata runtime dependencies",
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
  invariant(
    Array.isArray(javaDependencies),
    "paper metadata runtime dependency inventory must be an array",
  );
  for (const dependency of javaDependencies) {
    const name = `${dependency.group}:${dependency.artifact}`;
    const key = `maven:${name}@${dependency.version}`;
    invariant(
      Object.keys(dependency).sort().join(",") ===
        "artifact,checksum,group,license,version" &&
        /^[0-9a-f]{64}$/.test(dependency.checksum) &&
        dependency.license &&
        paperProbeLock
          .split("\n")
          .some((line) => line.startsWith(`${name}:${dependency.version}=`)),
      `invalid paper metadata runtime dependency: ${key}`,
    );
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
    invariant(
      !paperMetadataDependencies.has(key),
      `duplicate paper metadata runtime dependency: ${key}`,
    );
    paperMetadataDependencies.add(key);
  }
  const declaredJavaCoordinates = new Set(
    javaDependencies.map(
      (dependency) =>
        `${dependency.group}:${dependency.artifact}:${dependency.version}`,
    ),
  );
  invariant(
    expectedJavaCoordinates.size === declaredJavaCoordinates.size &&
      [...expectedJavaCoordinates].every((coordinate) =>
        declaredJavaCoordinates.has(coordinate),
      ),
    "paper metadata runtime dependency inventory differs from Gradle",
  );
  dependenciesByBundle.set("paper-metadata", paperMetadataDependencies);
  return { components, dependenciesByBundle };
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

export async function archiveEntries(archivePath, archiveRoot) {
  const entries = [];
  let unpackedSize = 0;
  let validationError;
  await listTar({
    file: archivePath,
    strict: true,
    onReadEntry(entry) {
      try {
        assertSafeArchivePath(entry.path, archiveRoot);
        invariant(
          entry.type === "File",
          `archive entry is not a file: ${entry.path}`,
        );
        invariant(
          Number.isSafeInteger(entry.size) &&
            entry.size >= 0 &&
            entry.size <= maximumArchiveEntrySize,
          `archive entry is too large: ${entry.path}`,
        );
        invariant(
          entries.length < maximumArchiveEntries,
          "archive contains too many entries",
        );
        unpackedSize += entry.size;
        invariant(
          unpackedSize <= maximumUnpackedArchiveSize,
          "archive unpacked size is too large",
        );
        entries.push(entry.path);
      } catch (error) {
        validationError ??= error;
      }
      entry.resume();
    },
  });
  if (validationError) {
    throw validationError;
  }
  equalStringSets(
    entries,
    new Set(entries),
    "archive contains duplicate entries",
  );
  return entries;
}

export async function extractCheckedArchive(
  archivePath,
  destination,
  archiveRoot,
) {
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

  const verifiedArchivePath = resolve(
    verificationDirectory,
    `.verified-${expectedFilename}`,
  );
  await writeFile(verifiedArchivePath, contents, { flag: "wx", mode: 0o400 });
  const archiveRoot = archive.filename.slice(0, -".tar.gz".length);
  const entries = await extractCheckedArchive(
    verifiedArchivePath,
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
    invariant(
      digest(fileContents, "sha1") === file.sha1,
      `bundle SHA-1 differs: ${file.path}`,
    );
    if (file.transform === "release-version") {
      const packageDocument = JSON.parse(fileContents.toString("utf8"));
      invariant(
        packageDocument.version === version,
        `package version differs: ${file.path}`,
      );
    } else if (file.transform === "openapi-json") {
      const openapiDocument = JSON.parse(fileContents.toString("utf8"));
      invariant(
        openapiDocument.openapi === "3.1.1",
        `generated OpenAPI JSON differs: ${file.path}`,
      );
    } else {
      invariant(
        file.transform === undefined,
        `unknown bundle transform: ${file.transform}`,
      );
    }
  }
  const embeddedManifestContents = await readFile(
    resolve(extractedRoot, "RELEASE-MANIFEST.json"),
  );
  return {
    bundle: archive.bundle,
    files: [
      ...embeddedManifest.files,
      {
        path: "RELEASE-MANIFEST.json",
        sha1: digest(embeddedManifestContents, "sha1"),
        sha256: digest(embeddedManifestContents),
        size: embeddedManifestContents.byteLength,
      },
    ].sort((left, right) =>
      left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
    ),
    root: extractedRoot,
  };
}

function packageVerificationCode(files) {
  const checksums = files
    .map((file) => file.sha1)
    .sort(compareText)
    .join("");
  return digest(Buffer.from(checksums, "ascii"), "sha1");
}

function exactObject(actual, expected, message) {
  invariant(
    JSON.stringify(actual) === JSON.stringify(expected),
    `${message}\nexpected: ${JSON.stringify(expected)}\nactual: ${JSON.stringify(actual)}`,
  );
}

const nodeDependencySections = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
];

function dependencyReference(dependency, description) {
  const reference = dependency?.version ?? dependency;
  invariant(
    typeof reference === "string" && reference.length > 0,
    `audited pnpm lockfile has an invalid ${description} reference`,
  );
  invariant(
    !/^(?:file|link|workspace):/.test(reference),
    `released consumer dependency is not registry-locked: ${description}`,
  );
  return reference;
}

function sortedObject(entries) {
  return Object.fromEntries(
    [...entries].sort(([left], [right]) => compareText(left, right)),
  );
}

export function projectNodeConsumerLock({
  lockfileContents,
  nodeImporter,
  packageContents,
}) {
  const document = parseYamlDocument(lockfileContents, {
    strict: true,
    uniqueKeys: true,
  });
  invariant(
    document.errors.length === 0 && document.warnings.length === 0,
    "audited pnpm lockfile is invalid or ambiguous",
  );
  let lockfile;
  try {
    lockfile = document.toJS({ maxAliasCount: 0 });
  } catch {
    throw new Error("audited pnpm lockfile is invalid or ambiguous");
  }
  invariant(
    lockfile?.lockfileVersion === "9.0" &&
      lockfile.settings &&
      typeof lockfile.settings === "object" &&
      lockfile.importers &&
      typeof lockfile.importers === "object" &&
      lockfile.packages &&
      typeof lockfile.packages === "object" &&
      lockfile.snapshots &&
      typeof lockfile.snapshots === "object",
    "audited pnpm lockfile structure is unsupported",
  );
  const importer = lockfile.importers[nodeImporter];
  invariant(importer, `pnpm lockfile is missing importer: ${nodeImporter}`);

  let packageDocument;
  try {
    packageDocument = JSON.parse(packageContents);
  } catch {
    throw new Error("released consumer package manifest is not valid JSON");
  }
  for (const section of nodeDependencySections) {
    const manifestDependencies = packageDocument[section] ?? {};
    const lockedDependencies = importer[section] ?? {};
    invariant(
      manifestDependencies &&
        typeof manifestDependencies === "object" &&
        !Array.isArray(manifestDependencies),
      `released consumer package has an invalid ${section} declaration`,
    );
    invariant(
      lockedDependencies &&
        typeof lockedDependencies === "object" &&
        !Array.isArray(lockedDependencies),
      `audited pnpm importer has an invalid ${section} declaration`,
    );
    exactObject(
      sortedObject(
        Object.entries(lockedDependencies).map(([name, dependency]) => [
          name,
          dependency?.specifier,
        ]),
      ),
      sortedObject(Object.entries(manifestDependencies)),
      `released consumer ${section} differs from the audited pnpm importer`,
    );
  }

  const snapshotEntries = new Map();
  const packageEntries = new Map();
  const queue = nodeDependencySections.flatMap((section) =>
    Object.entries(importer[section] ?? {}),
  );
  while (queue.length > 0) {
    const [name, dependency] = queue.shift();
    const reference = dependencyReference(dependency, name);
    const snapshotKey = `${name}@${reference}`;
    if (snapshotEntries.has(snapshotKey)) {
      continue;
    }
    const snapshot = lockfile.snapshots[snapshotKey];
    invariant(
      snapshot && typeof snapshot === "object",
      `audited pnpm lockfile is missing runtime snapshot: ${snapshotKey}`,
    );
    const version = reference.replace(/\(.+$/, "");
    const packageKey = `${name}@${version}`;
    const metadata = lockfile.packages[packageKey];
    invariant(
      metadata?.resolution?.integrity,
      `audited pnpm lockfile is missing integrity evidence: ${packageKey}`,
    );
    checksumFromIntegrity(metadata.resolution.integrity);
    snapshotEntries.set(snapshotKey, snapshot);
    packageEntries.set(packageKey, metadata);
    for (const child of Object.entries({
      ...(snapshot.dependencies ?? {}),
      ...(snapshot.optionalDependencies ?? {}),
    })) {
      queue.push(child);
    }
  }

  return stringifyYaml(
    {
      lockfileVersion: lockfile.lockfileVersion,
      settings: lockfile.settings,
      importers: { ".": importer },
      packages: sortedObject(packageEntries),
      snapshots: sortedObject(snapshotEntries),
    },
    { lineWidth: 0 },
  );
}

async function verifySpdxSemantics({
  artifacts,
  bundleContents,
  createdAt,
  dependencyManifest,
  sbom,
  sourceCommit,
  version,
}) {
  exactObject(
    {
      SPDXID: sbom.SPDXID,
      creationInfo: sbom.creationInfo,
      dataLicense: sbom.dataLicense,
      documentNamespace: sbom.documentNamespace,
      name: sbom.name,
      spdxVersion: sbom.spdxVersion,
    },
    {
      SPDXID: "SPDXRef-DOCUMENT",
      creationInfo: {
        created: createdAt,
        creators: ["Tool: @bwmp-dev/provenance-contract-release"],
      },
      dataLicense: "CC0-1.0",
      documentNamespace: `${releaseRepository}/releases/tag/v${encodeURIComponent(version)}/spdx/${sourceCommit}`,
      name: `provenance-contracts-${version}`,
      spdxVersion: "SPDX-2.3",
    },
    "release SPDX document metadata differs",
  );

  const runtimeDependencies = await expectedRuntimeDependencies();
  exactObject(
    dependencyManifest,
    [...runtimeDependencies.components.values()]
      .sort((left, right) => compareText(left.key, right.key))
      .map((dependency) => ({
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
    "release dependency manifest differs",
  );
  const artifactsByBundle = new Map(
    artifacts.map((artifact) => [artifact.bundle, artifact]),
  );
  const contentsByBundle = new Map(
    bundleContents.map((contents) => [contents.bundle, contents.files]),
  );
  const packagesById = new Map();
  for (const packageDocument of sbom.packages ?? []) {
    invariant(
      !packagesById.has(packageDocument.SPDXID),
      `duplicate SPDX package: ${packageDocument.SPDXID}`,
    );
    packagesById.set(packageDocument.SPDXID, packageDocument);
  }
  const filesById = new Map();
  for (const file of sbom.files ?? []) {
    invariant(
      !filesById.has(file.SPDXID),
      `duplicate SPDX file: ${file.SPDXID}`,
    );
    filesById.set(file.SPDXID, file);
  }

  const expectedPackageIds = [];
  const expectedFileIds = [];
  const expectedRelationships = [];
  const describedPackages = [];
  for (const bundle of contractBundles) {
    const packageId = `SPDXRef-Package-${bundle.id}`;
    const artifact = artifactsByBundle.get(bundle.id);
    const bundleFiles = contentsByBundle.get(bundle.id);
    invariant(
      artifact && bundleFiles,
      `SPDX source bundle is missing: ${bundle.id}`,
    );
    expectedPackageIds.push(packageId);
    describedPackages.push(packageId);
    exactObject(
      packagesById.get(packageId),
      {
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
      },
      `SPDX package differs: ${bundle.id}`,
    );
    expectedRelationships.push(
      JSON.stringify({
        relatedSpdxElement: packageId,
        relationshipType: "DESCRIBES",
        spdxElementId: "SPDXRef-DOCUMENT",
      }),
    );
    for (const [index, file] of bundleFiles.entries()) {
      const fileId = `SPDXRef-File-${bundle.id}-${String(index + 1).padStart(4, "0")}`;
      expectedFileIds.push(fileId);
      exactObject(
        filesById.get(fileId),
        {
          SPDXID: fileId,
          checksums: [
            { algorithm: "SHA1", checksumValue: file.sha1 },
            { algorithm: "SHA256", checksumValue: file.sha256 },
          ],
          copyrightText: "NOASSERTION",
          fileName: `./${artifact.filename.slice(0, -".tar.gz".length)}/${file.path}`,
          licenseConcluded: "NOASSERTION",
          licenseInfoInFiles: ["NOASSERTION"],
        },
        `SPDX file differs: ${bundle.id}/${file.path}`,
      );
      expectedRelationships.push(
        JSON.stringify({
          relatedSpdxElement: fileId,
          relationshipType: "CONTAINS",
          spdxElementId: packageId,
        }),
      );
    }
  }

  for (const dependency of [...runtimeDependencies.components.values()].sort(
    (left, right) => compareText(left.key, right.key),
  )) {
    const packageId = dependencySpdxId(
      dependency.ecosystem,
      dependency.name,
      dependency.version,
    );
    expectedPackageIds.push(packageId);
    exactObject(
      packagesById.get(packageId),
      {
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
      },
      `SPDX dependency differs: ${dependency.key}`,
    );
  }
  for (const bundle of contractBundles) {
    for (const dependencyKey of [
      ...(runtimeDependencies.dependenciesByBundle.get(bundle.id) ?? []),
    ].sort(compareText)) {
      const dependency = runtimeDependencies.components.get(dependencyKey);
      invariant(dependency, `expected dependency is missing: ${dependencyKey}`);
      expectedRelationships.push(
        JSON.stringify({
          relatedSpdxElement: dependencySpdxId(
            dependency.ecosystem,
            dependency.name,
            dependency.version,
          ),
          relationshipType: "DEPENDS_ON",
          spdxElementId: `SPDXRef-Package-${bundle.id}`,
        }),
      );
    }
  }

  equalStringSets(
    packagesById.keys(),
    expectedPackageIds,
    "SPDX package inventory differs",
  );
  equalStringSets(
    filesById.keys(),
    expectedFileIds,
    "SPDX file inventory differs",
  );
  equalStringSets(
    sbom.documentDescribes ?? [],
    describedPackages,
    "SPDX described package inventory differs",
  );
  equalStringSets(
    (sbom.relationships ?? []).map((relationship) =>
      JSON.stringify(relationship),
    ),
    expectedRelationships,
    "SPDX relationship inventory differs",
  );
}

function run(
  command,
  arguments_,
  workingDirectory,
  description,
  environment = {},
  shell = false,
) {
  const result = spawnSync(command, arguments_, {
    cwd: workingDirectory,
    encoding: "utf8",
    env: { ...process.env, ...environment },
    shell,
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

async function installNodeConsumer(
  packageDirectory,
  nodeImporter,
  description,
) {
  const consumerLock = projectNodeConsumerLock({
    lockfileContents: await readFile(
      resolve(repositoryDirectory, "pnpm-lock.yaml"),
      "utf8",
    ),
    nodeImporter,
    packageContents: await readFile(
      resolve(packageDirectory, "package.json"),
      "utf8",
    ),
  });
  await writeFile(resolve(packageDirectory, "pnpm-lock.yaml"), consumerLock, {
    flag: "wx",
    mode: 0o400,
  });
  const windows = process.platform === "win32";
  run(
    windows ? (process.env.ComSpec ?? "cmd.exe") : "pnpm",
    windows
      ? [
          "/d",
          "/s",
          "/c",
          "pnpm install --offline --ignore-scripts --frozen-lockfile",
        ]
      : ["install", "--offline", "--ignore-scripts", "--frozen-lockfile"],
    packageDirectory,
    description,
    {
      CI: "true",
      npm_config_offline: "true",
    },
  );
}

async function verifyConsumers(bundleRoots, version) {
  const rootFor = (bundle) => {
    const root = bundleRoots.get(bundle);
    invariant(root, `verified consumer bundle is missing: ${bundle}`);
    const repositoryRelative = relative(repositoryDirectory, root);
    invariant(
      isAbsolute(repositoryRelative) ||
        repositoryRelative === ".." ||
        repositoryRelative.startsWith(`..${sep}`),
      `consumer bundle must be isolated from repository caches: ${bundle}`,
    );
    return root;
  };

  {
    const root = rootFor("paper-metadata");
    const inspector = resolve(root, "paper-metadata-inspector.jar");
    const schema = resolve(root, "schema/schema.json");
    const java =
      process.platform === "win32" && process.env.JAVA_HOME
        ? resolve(process.env.JAVA_HOME, "bin/java.exe")
        : process.env.JAVA_HOME
          ? resolve(process.env.JAVA_HOME, "bin/java")
          : "java";
    const inspect = async (artifact) => {
      const expectedHash = digest(await readFile(artifact));
      const result = spawnSync(
        java,
        ["-jar", inspector, "--expected-sha256", expectedHash, artifact],
        { cwd: root, encoding: "utf8", shell: false },
      );
      invariant(
        result.error === undefined && result.status === 0,
        `released Paper metadata inspector failed\n${[result.stdout, result.stderr].filter(Boolean).join("\n")}`,
      );
      invariant(
        result.stderr === "",
        "released Paper metadata inspector emitted diagnostics for a handled result",
      );
      const python = process.platform === "win32" ? "python" : "python3";
      const validation = spawnSync(
        python,
        [
          resolve(
            repositoryDirectory,
            "schemas/paper-metadata/test_contract.py",
          ),
          "--validate-result",
          schema,
        ],
        { encoding: "utf8", input: result.stdout, shell: false },
      );
      invariant(
        validation.error === undefined && validation.status === 0,
        `released Paper metadata inspector output violates the shipped schema\n${[validation.stdout, validation.stderr].filter(Boolean).join("\n")}`,
      );
      return { document: JSON.parse(result.stdout), expectedHash };
    };

    const artifact = resolve(root, "fixtures/success.jar");
    const { document, expectedHash } = await inspect(artifact);
    exactObject(
      document,
      {
        schemaVersion: "provenance.paper-metadata/v1",
        artifactSha256: expectedHash,
        status: "valid",
        issues: [],
        plugin: {
          name: "ProvenanceSuccess",
          version: "1.0.0",
          mainClass: "dev.provenance.fixtures.SuccessPlugin",
          apiVersion: "1.21",
          requiredDependencies: [],
          softDependencies: [],
          loadBeforeDependencies: [],
          permissions: [],
          commands: [],
        },
      },
      "released Paper metadata inspector result differs",
    );

    const fixtureDirectory = await mkdtemp(
      join(tmpdir(), "provenance-paper-metadata-results-"),
    );
    try {
      const jar =
        process.platform === "win32" && process.env.JAVA_HOME
          ? resolve(process.env.JAVA_HOME, "bin/jar.exe")
          : process.env.JAVA_HOME
            ? resolve(process.env.JAVA_HOME, "bin/jar")
            : "jar";
      const missingSource = resolve(fixtureDirectory, "missing-source");
      const invalidSource = resolve(fixtureDirectory, "invalid-source");
      await mkdir(missingSource);
      await mkdir(invalidSource);
      await writeFile(resolve(missingSource, "README.txt"), "no metadata\n");
      await writeFile(
        resolve(invalidSource, "plugin.yml"),
        Buffer.from([0xc3, 0x28]),
      );
      const missingArtifact = resolve(fixtureDirectory, "missing.jar");
      const invalidArtifact = resolve(fixtureDirectory, "invalid.jar");
      run(
        jar,
        ["--create", "--file", missingArtifact, "-C", missingSource, "."],
        fixtureDirectory,
        "Paper missing-metadata fixture build",
      );
      run(
        jar,
        ["--create", "--file", invalidArtifact, "-C", invalidSource, "."],
        fixtureDirectory,
        "Paper invalid-metadata fixture build",
      );
      exactObject(
        (await inspect(missingArtifact)).document,
        {
          schemaVersion: "provenance.paper-metadata/v1",
          artifactSha256: digest(await readFile(missingArtifact)),
          status: "missing",
          issues: ["plugin_metadata_missing"],
        },
        "released Paper missing-metadata result differs",
      );
      exactObject(
        (await inspect(invalidArtifact)).document,
        {
          schemaVersion: "provenance.paper-metadata/v1",
          artifactSha256: digest(await readFile(invalidArtifact)),
          status: "invalid",
          issues: ["plugin_metadata_utf8_invalid"],
        },
        "released Paper invalid-metadata result differs",
      );
    } finally {
      await rm(fixtureDirectory, { force: true, recursive: true });
    }
  }

  {
    const root = rootFor("config-schema");
    await installNodeConsumer(
      resolve(root, "package"),
      "packages/config-schema",
      "released configuration dependency installation",
    );
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
  }

  {
    const root = rootFor("attestation-schema");
    await installNodeConsumer(
      resolve(root, "package"),
      "packages/verification",
      "released attestation dependency installation",
    );
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
  }

  {
    const root = rootFor("runner-protocol");
    await installNodeConsumer(
      resolve(root, "typescript"),
      "packages/runner-protocol",
      "released runner TypeScript dependency installation",
    );
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
    await writeFile(
      resolve(root, "typescript/consumer.mts"),
      [
        'import { GatewayMessageSchema, RunnerMessageSchema } from "./dist/index.js";',
        "void GatewayMessageSchema;",
        "void RunnerMessageSchema;",
        "",
      ].join("\n"),
    );
    await writeFile(
      resolve(root, "typescript/consumer-tsconfig.json"),
      JSON.stringify(
        {
          compilerOptions: {
            module: "NodeNext",
            moduleResolution: "NodeNext",
            noEmit: true,
            strict: true,
            target: "ES2022",
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
        resolve(root, "typescript/node_modules/typescript/bin/tsc"),
        "--project",
        resolve(root, "typescript/consumer-tsconfig.json"),
      ],
      resolve(root, "typescript"),
      "released runner TypeScript declarations",
    );
    run("go", ["test", "./..."], resolve(root, "go"), "released Go bindings", {
      GOPROXY: "off",
    });
  }

  {
    const root = rootFor("openapi");
    const specification = parseYaml(
      await readFile(resolve(root, "provenance.v1.yaml"), "utf8"),
    );
    const jsonSpecification = await readJson(
      resolve(root, "openapi.json"),
      "released OpenAPI JSON",
    );
    exactObject(
      jsonSpecification,
      specification,
      "released OpenAPI JSON differs from YAML",
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
    const methods = new Set([
      "delete",
      "get",
      "head",
      "options",
      "patch",
      "post",
      "put",
    ]);
    const operations = Object.entries(specification.paths ?? {}).flatMap(
      ([path, pathItem]) =>
        Object.entries(pathItem)
          .filter(([method]) => methods.has(method))
          .map(([method, operation]) => ({
            method,
            operationId: operation.operationId,
            path,
            tag: operation.tags?.[0],
          })),
    );
    const compareInventory = (left, right) =>
      compareText(left.path, right.path) ||
      compareText(left.method, right.method) ||
      compareText(left.operationId, right.operationId);
    exactObject(
      operations.sort(compareInventory),
      inventory.sort(compareInventory),
      "released OpenAPI operation inventory differs",
    );
  }

  {
    const root = rootFor("typescript-client");
    await installNodeConsumer(
      resolve(root, "package"),
      "packages/api-client",
      "released API client dependency installation",
    );
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
        resolve(root, "package/node_modules/typescript/bin/tsc"),
        "--project",
        resolve(root, "tsconfig.json"),
      ],
      root,
      "released TypeScript client declarations",
    );
  }
}

export async function verifyContractRelease({
  directory,
  consumers = false,
  version,
}) {
  validateReleaseIdentity(version, "0".repeat(40));
  const resolvedDirectory = resolve(directory);
  const manifestFilename = releaseManifestName(version);
  const manifestContents = await readFile(
    resolve(resolvedDirectory, manifestFilename),
  );
  const manifest = JSON.parse(manifestContents.toString("utf8"));
  invariant(manifest.schemaVersion === 1, "unsupported release manifest");
  exactObject(
    manifest.compatibility,
    {
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
    },
    "release compatibility declaration differs",
  );
  invariant(manifest.release?.version === version, "release version differs");
  invariant(manifest.release?.tag === `v${version}`, "release tag differs");
  invariant(
    manifest.release?.repository === releaseRepository,
    "release repository differs",
  );
  const createdAt = validateSpdxTimestamp(manifest.release?.createdAt ?? "");
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

  const expectedSbomFilename = sbomName(version);
  invariant(
    manifest.sbom?.filename === expectedSbomFilename,
    "release SBOM filename differs",
  );
  invariant(
    manifest.sbom?.format === "SPDX-2.3",
    "release SBOM format differs",
  );
  const sbomContents = await readFile(
    resolve(resolvedDirectory, expectedSbomFilename),
  );
  invariant(
    sbomContents.byteLength === manifest.sbom?.size,
    "release SBOM size differs",
  );
  invariant(
    digest(sbomContents) === manifest.sbom?.sha256,
    "release SBOM digest differs",
  );
  const sbom = await readJson(
    resolve(resolvedDirectory, expectedSbomFilename),
    "release SPDX SBOM",
  );
  run(
    "python",
    [
      "-m",
      "spdx_tools.spdx.clitools.pyspdxtools",
      "-i",
      resolve(resolvedDirectory, expectedSbomFilename),
    ],
    repositoryDirectory,
    "official SPDX 2.3 validation",
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
    expectedSbomFilename,
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
  invariant(
    checksums.get(expectedSbomFilename) === manifest.sbom.sha256,
    "release SBOM checksum differs",
  );

  const verificationDirectory = await mkdtemp(
    join(tmpdir(), "provenance-contract-verify-"),
  );
  try {
    const bundleContents = [];
    for (const archive of manifest.artifacts) {
      invariant(
        checksums.get(archive.filename) === archive.sha256,
        `${archive.filename} checksum file differs`,
      );
      bundleContents.push(
        await verifyArchive({
          archive,
          directory: resolvedDirectory,
          releaseSourceCommit: identity.sourceCommit,
          version,
          verificationDirectory,
        }),
      );
    }
    await verifySpdxSemantics({
      artifacts: manifest.artifacts,
      bundleContents,
      createdAt,
      dependencyManifest: manifest.dependencies,
      sbom,
      sourceCommit: identity.sourceCommit,
      version,
    });
    if (consumers) {
      await verifyConsumers(
        new Map(bundleContents.map(({ bundle, root }) => [bundle, root])),
        version,
      );
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
