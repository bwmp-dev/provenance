import { createHash } from "node:crypto";
import {
  constants,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { basename, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

export const testkitSourceCommit = "98d5f07f173a9e3f1b365add24b81c934d7e3c61";

export const testkitMatrix = Object.freeze([
  artifact(
    "paper-probe",
    "probe",
    "plugins/paper-probe/build/libs/paper-probe-0.1.0.jar",
    "abbccf45831ef998466542b19169731b9ec4f8a6c3525fce4d7a2c0b5f4b4b43",
    478837,
  ),
  artifact(
    "success",
    "benign",
    "packages/test-fixtures/benign/success/build/libs/success-1.0.0.jar",
    "b4a4d3786ffe84b2b6be9789f9dc4171b8870c570b821e4521ea963771ecd69d",
    1069,
  ),
  artifact(
    "on-load-failure",
    "benign",
    "packages/test-fixtures/benign/on-load-failure/build/libs/on-load-failure-1.0.0.jar",
    "35106732c959756bd4d7e1b9a41a69c774cad0ce015e9b5b38b4981b7491be1a",
    1186,
  ),
  artifact(
    "on-enable-failure",
    "benign",
    "packages/test-fixtures/benign/on-enable-failure/build/libs/on-enable-failure-1.0.0.jar",
    "2bca398ff8f30e505a3f92ed8204f9d52874f537d6ab94fb221b3ea6f00074d3",
    1192,
  ),
  artifact(
    "missing-dependency",
    "benign",
    "packages/test-fixtures/benign/missing-dependency/build/libs/missing-dependency-1.0.0.jar",
    "3b4468125deca2b84ea000229a7cda40be298cd4b7f7e032ba26e0b97f5d84b8",
    1127,
  ),
  artifact(
    "command-success",
    "benign",
    "packages/test-fixtures/benign/command-success/build/libs/command-success-1.0.0.jar",
    "977d74e6e3f9c959f58de6f12960d02ba78bd32ae0e02f7db1a3844f5a18d706",
    1281,
  ),
  artifact(
    "command-assertion-failure",
    "benign",
    "packages/test-fixtures/benign/command-assertion-failure/build/libs/command-assertion-failure-1.0.0.jar",
    "7d472b106122a994d07cf193484b50f747913efbbf41b3b18124681680d27b0e",
    1333,
  ),
  artifact(
    "enable-hang",
    "hostile",
    "packages/test-fixtures/hostile/enable-hang/build/libs/enable-hang-1.0.0.jar",
    "fe0fd91fa5622123c07ccda1f687c4a2eae39658d926526d9b60d8497154a517",
    1618,
  ),
  artifact(
    "process-exit",
    "hostile",
    "packages/test-fixtures/hostile/process-exit/build/libs/process-exit-1.0.0.jar",
    "56628987638e11ebda447a2348da87189de22882248e5584745d6e6ac840dcea",
    1530,
  ),
  artifact(
    "memory-bomb",
    "hostile",
    "packages/test-fixtures/hostile/memory-bomb/build/libs/memory-bomb-1.0.0.jar",
    "3014412fe9247cc4f2eda6fd69abb36d14da2b0076fa2469586f674efd843b78",
    1840,
  ),
  artifact(
    "fork-pid-bomb",
    "hostile",
    "packages/test-fixtures/hostile/fork-pid-bomb/build/libs/fork-pid-bomb-1.0.0.jar",
    "35159ca9338e5d5aa12f8167b3ce9e63a14030011b8632679ac4ab2c274e0ca6",
    2778,
  ),
  artifact(
    "disk-fill",
    "hostile",
    "packages/test-fixtures/hostile/disk-fill/build/libs/disk-fill-1.0.0.jar",
    "a9be4461514ec0a81b6b0b4744871e286f3047563b494af16f89428a72345780",
    2271,
  ),
  artifact(
    "network-scan",
    "hostile",
    "packages/test-fixtures/hostile/network-scan/build/libs/network-scan-1.0.0.jar",
    "7d87b753d8ad1ef1946314e7add20afc242dc1304dd00d433c1568fc5ffa5e4d",
    2234,
  ),
  artifact(
    "metadata-endpoint",
    "hostile",
    "packages/test-fixtures/hostile/metadata-endpoint/build/libs/metadata-endpoint-1.0.0.jar",
    "5ab1b9821ddcd204da292367c58bf830d5393527f39c212fef9dbd0ceea3fc9b",
    1796,
  ),
  artifact(
    "log-flood",
    "hostile",
    "packages/test-fixtures/hostile/log-flood/build/libs/log-flood-1.0.0.jar",
    "baab294f640dfa02787f0bf94e6fbba45f936344517c52a5d2dc67754345fcbf",
    1945,
  ),
]);

const repository = "https://github.com/bwmp-dev/provenance";
const tagPattern =
  /^testkit-v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/;

export function validateTestkitIdentity(tag, sourceCommit) {
  if (!tagPattern.test(tag)) {
    throw new Error(`testkit release tag is invalid: ${tag}`);
  }
  if (sourceCommit !== testkitSourceCommit) {
    throw new Error(
      `source commit has no audited testkit matrix: ${sourceCommit}`,
    );
  }
  return { sourceCommit, tag };
}

export function testkitManifest(tag, sourceCommit) {
  const identity = validateTestkitIdentity(tag, sourceCommit);
  return {
    schemaVersion: 1,
    release: {
      repository,
      sourceCommit: identity.sourceCommit,
      tag: identity.tag,
    },
    artifacts: testkitMatrix.map((entry) => ({
      id: entry.id,
      type: entry.type,
      filename: releaseAssetName(identity, entry.source),
      sha256: entry.sha256,
      sizeBytes: entry.sizeBytes,
    })),
  };
}

export function manifestFilename(tag, sourceCommit) {
  const identity = validateTestkitIdentity(tag, sourceCommit);
  return `${releasePrefix(identity)}.manifest.json`;
}

export function checksumFilename(tag, sourceCommit) {
  const identity = validateTestkitIdentity(tag, sourceCommit);
  return `${releasePrefix(identity)}.sha256`;
}

function artifact(id, type, source, sha256, sizeBytes) {
  return Object.freeze({ id, type, source, sha256, sizeBytes });
}

function releasePrefix(identity) {
  return `provenance-${identity.tag}-${identity.sourceCommit}`;
}

function releaseAssetName(identity, source) {
  return `${releasePrefix(identity)}-${basename(source)}`;
}

function digest(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

function canonicalManifest(tag, sourceCommit) {
  return Buffer.from(
    `${JSON.stringify(testkitManifest(tag, sourceCommit), null, 2)}\n`,
  );
}

function expectedChecksumContents(tag, sourceCommit, manifestContents) {
  const manifest = testkitManifest(tag, sourceCommit);
  return Buffer.from(
    [
      ...manifest.artifacts.map(({ filename, sha256 }) => ({
        filename,
        sha256,
      })),
      {
        filename: manifestFilename(tag, sourceCommit),
        sha256: digest(manifestContents),
      },
    ]
      .sort((left, right) =>
        left.filename < right.filename
          ? -1
          : left.filename > right.filename
            ? 1
            : 0,
      )
      .map(({ filename, sha256 }) => `${sha256}  ${filename}`)
      .join("\n") + "\n",
  );
}

function stage(sourceDirectory, outputDirectory, tag, sourceCommit) {
  const identity = validateTestkitIdentity(tag, sourceCommit);
  const sourceRoot = realpathSync(resolve(sourceDirectory));
  const output = resolve(outputDirectory);
  ensureEmptyOutput(output);

  for (const entry of testkitMatrix) {
    const path = resolve(sourceRoot, entry.source);
    if (relative(sourceRoot, path).startsWith(`..${sep}`)) {
      throw new Error(`testkit source leaves repository: ${entry.source}`);
    }
    const status = lstatSync(path);
    if (!status.isFile() || status.isSymbolicLink()) {
      throw new Error(`testkit source is not a regular file: ${entry.source}`);
    }
    const contents = readFileSync(path);
    verifyBytes(entry, contents, entry.source);
    copyFileSync(
      path,
      resolve(output, releaseAssetName(identity, entry.source)),
      constants.COPYFILE_EXCL,
    );
  }

  const manifestContents = canonicalManifest(tag, sourceCommit);
  writeFileSync(
    resolve(output, manifestFilename(tag, sourceCommit)),
    manifestContents,
    { flag: "wx" },
  );
  writeFileSync(
    resolve(output, checksumFilename(tag, sourceCommit)),
    expectedChecksumContents(tag, sourceCommit, manifestContents),
    { flag: "wx" },
  );
  verify(output, tag, sourceCommit);
}

function verify(directory, tag, sourceCommit) {
  validateTestkitIdentity(tag, sourceCommit);
  const root = realpathSync(resolve(directory));
  const manifestName = manifestFilename(tag, sourceCommit);
  const checksumName = checksumFilename(tag, sourceCommit);
  const manifestContents = canonicalManifest(tag, sourceCommit);
  const expectedNames = [
    ...testkitManifest(tag, sourceCommit).artifacts.map(
      (entry) => entry.filename,
    ),
    manifestName,
    checksumName,
  ].sort();
  const actualNames = readdirSync(root).sort();
  if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) {
    throw new Error("testkit release asset inventory differs");
  }

  for (const name of actualNames) {
    const status = lstatSync(resolve(root, name));
    if (!status.isFile() || status.isSymbolicLink()) {
      throw new Error(`testkit release asset is not a regular file: ${name}`);
    }
  }

  const actualManifest = readFileSync(resolve(root, manifestName));
  if (!actualManifest.equals(manifestContents)) {
    throw new Error("testkit release manifest is not canonical");
  }
  const expectedManifest = testkitManifest(tag, sourceCommit);
  for (let index = 0; index < testkitMatrix.length; index += 1) {
    const entry = testkitMatrix[index];
    const releaseEntry = expectedManifest.artifacts[index];
    verifyBytes(
      entry,
      readFileSync(resolve(root, releaseEntry.filename)),
      releaseEntry.filename,
    );
  }

  const expectedChecksums = expectedChecksumContents(
    tag,
    sourceCommit,
    manifestContents,
  );
  const actualChecksums = readFileSync(resolve(root, checksumName));
  if (!actualChecksums.equals(expectedChecksums)) {
    throw new Error("testkit release checksums differ");
  }
}

function compare(leftDirectory, rightDirectory, tag, sourceCommit) {
  verify(leftDirectory, tag, sourceCommit);
  verify(rightDirectory, tag, sourceCommit);
  const left = realpathSync(resolve(leftDirectory));
  const right = realpathSync(resolve(rightDirectory));
  for (const name of readdirSync(left).sort()) {
    if (
      !readFileSync(resolve(left, name)).equals(
        readFileSync(resolve(right, name)),
      )
    ) {
      throw new Error(`testkit rebuild differs: ${name}`);
    }
  }
}

function ensureEmptyOutput(directory) {
  if (existsSync(directory)) {
    const status = lstatSync(directory);
    if (!status.isDirectory() || status.isSymbolicLink()) {
      throw new Error("testkit output is not a regular directory");
    }
    if (readdirSync(directory).length !== 0) {
      throw new Error("testkit output directory is not empty");
    }
    return;
  }
  mkdirSync(directory, { recursive: true });
}

function verifyBytes(entry, contents, label) {
  if (contents.length !== entry.sizeBytes) {
    throw new Error(
      `${label} size differs: expected ${entry.sizeBytes}, got ${contents.length}`,
    );
  }
  const actual = digest(contents);
  if (actual !== entry.sha256) {
    throw new Error(
      `${label} SHA-256 differs: expected ${entry.sha256}, got ${actual}`,
    );
  }
}

function argumentsFor(command, values) {
  const result = {};
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (!name?.startsWith("--") || value === undefined) {
      throw new Error(`invalid ${command} argument: ${name ?? "<missing>"}`);
    }
    result[name.slice(2)] = value;
  }
  return result;
}

function required(arguments_, name) {
  const value = arguments_[name];
  if (!value) throw new Error(`missing --${name}`);
  return value;
}

function main() {
  const command = process.argv[2];
  const arguments_ = argumentsFor(command, process.argv.slice(3));
  const tag = required(arguments_, "tag");
  const sourceCommit = required(arguments_, "source-commit");
  if (command === "identity") {
    process.stdout.write(
      `${JSON.stringify(validateTestkitIdentity(tag, sourceCommit))}\n`,
    );
    return;
  }
  if (command === "stage") {
    stage(
      required(arguments_, "source"),
      required(arguments_, "directory"),
      tag,
      sourceCommit,
    );
    return;
  }
  if (command === "verify") {
    verify(required(arguments_, "directory"), tag, sourceCommit);
    return;
  }
  if (command === "compare") {
    compare(
      required(arguments_, "left"),
      required(arguments_, "right"),
      tag,
      sourceCommit,
    );
    return;
  }
  throw new Error(`unknown testkit release command: ${command ?? "<missing>"}`);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  main();
}
