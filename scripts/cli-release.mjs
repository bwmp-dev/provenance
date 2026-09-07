import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { create as createTar } from "tar";
import {
  validateReleaseIdentity,
  validateSpdxTimestamp,
} from "./contract-release.mjs";

export const repository = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
);
export const goVersion = "go1.25.13";
export const digest = (b) => createHash("sha256").update(b).digest("hex");
const json = (v) => Buffer.from(JSON.stringify(v, null, 2) + "\n");
const requireThat = (v, m) => {
  if (!v) throw new Error(m);
};
function run(command, args, cwd, env = {}) {
  return execFileSync(command, args, {
    cwd,
    env: { ...process.env, ...env },
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    timeout: 180000,
  });
}
function git(root, ...args) {
  return run("git", args, root).trim();
}
export function names(version) {
  requireThat(
    typeof version === "string" && version.length <= 64,
    "CLI version bound",
  );
  validateReleaseIdentity(version, "0".repeat(40));
  requireThat(
    !version.includes("+"),
    "CLI release versions cannot contain build metadata",
  );
  const prefix = `provenance-cli-${version}`;
  return {
    tag: `cli-v${version}`,
    root: `${prefix}-linux-amd64`,
    archive: `${prefix}-linux-amd64.tar.gz`,
    manifest: `${prefix}.manifest.json`,
    sbom: `${prefix}.spdx.json`,
    checksums: `${prefix}.sha256`,
  };
}
function regular(path, max = 64 * 1024 * 1024) {
  const st = lstatSync(path);
  requireThat(
    st.isFile() && !st.isSymbolicLink() && st.size <= max,
    "not a bounded regular input",
  );
  return readFileSync(path);
}
function sourceInventory(root, source) {
  const files = git(
    root,
    "ls-tree",
    "-r",
    "--name-only",
    source,
    "--",
    "packages/cli-go",
    "packages/verification-go",
    "LICENSE",
  )
    .split("\n")
    .filter(Boolean)
    .sort();
  requireThat(
    files.length > 10 && files.length <= 1000,
    "source inventory bound",
  );
  return files.map((path) => {
    const line = git(root, "ls-tree", source, "--", path);
    requireThat(/^100644 |^100755 /.test(line), "source links are forbidden");
    const bytes = Buffer.from(
      execFileSync("git", ["show", `${source}:${path}`], {
        cwd: root,
        maxBuffer: 8 * 1024 * 1024,
      }),
    );
    return { path, sizeBytes: bytes.length, sha256: digest(bytes) };
  });
}
function licenseFiles(root) {
  const result = [];
  function visit(dir) {
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name.localeCompare(b.name, "en"),
    )) {
      if (entry.name === ".git" || entry.name === "testdata") continue;
      const path = join(dir, entry.name);
      requireThat(
        !entry.isSymbolicLink(),
        "dependency tree contains a symlink",
      );
      if (entry.isDirectory()) visit(path);
      else if (
        entry.isFile() &&
        /^(license|licence|copying|notice|patents)([._-].*)?$/i.test(entry.name)
      )
        result.push({
          path: relative(root, path).split("\\").join("/"),
          bytes: regular(path, 1024 * 1024),
        });
    }
  }
  visit(root);
  requireThat(result.length > 0, "dependency license evidence missing");
  return result;
}
function parseStream(text) {
  const results = [];
  let start = 0,
    depth = 0,
    string = false,
    escape = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (string) {
      if (escape) escape = false;
      else if (c === "\\") escape = true;
      else if (c === '"') string = false;
    } else if (c === '"') string = true;
    else if (c === "{") {
      if (depth++ === 0) start = i;
    } else if (c === "}" && --depth === 0)
      results.push(JSON.parse(text.slice(start, i + 1)));
  }
  requireThat(depth === 0 && !string, "invalid Go JSON stream");
  return results;
}
function buildOne(checkout, output, go, cache, source, createdAt) {
  const env = {
    GOTOOLCHAIN: "local",
    GOROOT: "",
    GOWORK: "off",
    GOENV: "off",
    GOFLAGS: "",
    GOEXPERIMENT: "",
    GOFIPS140: "off",
    GOOS: "linux",
    GOARCH: "amd64",
    GOAMD64: "v1",
    CGO_ENABLED: "0",
    GOMODCACHE: join(cache, "modules"),
    GOCACHE: join(cache, "build"),
    GOPROXY: "https://proxy.golang.org",
    GOSUMDB: "sum.golang.org",
    GOPRIVATE: "",
    GONOPROXY: "",
    GONOSUMDB: "",
  };
  const module = join(checkout, "packages/cli-go");
  requireThat(
    run(go, ["version"], checkout, env).trim() ===
      `${goVersion} linux/amd64`.replace(/^/, "go version "),
    "Go toolchain identity differs",
  );
  run(go, ["mod", "download"], module, env);
  run(go, ["mod", "verify"], module, env);
  const offline = { ...env, GOPROXY: "off", GOSUMDB: "off" };
  mkdirSync(output, { recursive: true });
  const binary = join(output, "provenance");
  run(
    go,
    [
      "build",
      "-mod=readonly",
      "-trimpath",
      "-buildvcs=true",
      "-o",
      binary,
      "./cmd/provenance",
    ],
    module,
    offline,
  );
  const info =
    run(go, ["version", "-m", binary], module, offline)
      .split("\n")
      .slice(1)
      .join("\n")
      .trimEnd() + "\n";
  requireThat(
    info.includes(`vcs.revision=${source}`) &&
      info.includes("vcs.modified=false"),
    `binary source identity differs: ${info}; ${git(checkout, "status", "--porcelain")}`,
  );
  const packages = parseStream(
    run(
      go,
      ["list", "-mod=readonly", "-deps", "-json", "./cmd/provenance"],
      module,
      offline,
    ),
  );
  const modules = [
    ...new Map(
      packages.filter((p) => p.Module).map((p) => [p.Module.Path, p.Module]),
    ).values(),
  ].sort((a, b) => a.Path.localeCompare(b.Path, "en"));
  const components = [];
  const archiveFiles = new Map([
    ["provenance", { bytes: regular(binary), mode: 0o755 }],
    [
      "README.md",
      {
        bytes: regular(join(checkout, "packages/cli-go/README.md")),
        mode: 0o644,
      },
    ],
    ["LICENSE", { bytes: regular(join(checkout, "LICENSE")), mode: 0o644 }],
    ["build-info.txt", { bytes: Buffer.from(info), mode: 0o644 }],
  ]);
  for (const mod of modules) {
    const own =
      mod.Path === "github.com/bwmp-dev/provenance/packages/cli-go" ||
      mod.Path === "github.com/bwmp-dev/provenance/packages/verification-go";
    const id = `module-${digest(Buffer.from(mod.Path)).slice(0, 16)}`;
    let licenses;
    if (own)
      licenses = [
        { path: "LICENSE", bytes: regular(join(checkout, "LICENSE")) },
      ];
    else licenses = licenseFiles(mod.Dir);
    const record = {
      id,
      name: mod.Path,
      version: own ? source : mod.Version,
      kind: own ? "repository-source" : "go-module",
      sourceCommit: own ? source : null,
      goSum: own ? null : mod.Sum,
      licenses: [],
    };
    requireThat(
      own || (/^v/.test(mod.Version) && /^h1:/.test(mod.Sum)),
      "module has no verified identity",
    );
    if (mod.Replace)
      requireThat(
        own &&
          mod.Path.endsWith("/verification-go") &&
          mod.Replace.Path === "../verification-go",
        "unexpected module replacement",
      );
    for (const item of licenses) {
      const path = `licenses/${id}/${item.path}`;
      archiveFiles.set(path, { bytes: item.bytes, mode: 0o644 });
      record.licenses.push({ path, sha256: digest(item.bytes) });
    }
    components.push(record);
  }
  const goroot = run(go, ["env", "GOROOT"], checkout, env).trim();
  for (const path of ["LICENSE", "PATENTS"]) {
    archiveFiles.set(`licenses/go/${path}`, {
      bytes: regular(join(goroot, path)),
      mode: 0o644,
    });
  }
  components.push({
    id: "go-toolchain",
    name: "Go",
    version: goVersion,
    kind: "toolchain",
    sourceCommit: null,
    goSum: null,
    licenses: ["LICENSE", "PATENTS"].map((path) => ({
      path: `licenses/go/${path}`,
      sha256: digest(archiveFiles.get(`licenses/go/${path}`).bytes),
    })),
  });
  const regexRoot = join(checkout, "packages/cli-go/internal/config/regexpp");
  const regex = regular(join(regexRoot, "regexpp.cjs"));
  const license = regular(join(regexRoot, "LICENSE"));
  requireThat(
    digest(regex) ===
      "8f9526195a26cb0d47a48528e61f0083596d397092296a44fc1c1ac470aba336" &&
      digest(license) ===
        "fcf6eabf68ca96988a6b506b4fdc6cc32535d80eb2e11c79724af5ac6f50262b",
    "vendored regexpp pin differs",
  );
  archiveFiles.set("licenses/regexpp/LICENSE", { bytes: license, mode: 0o644 });
  components.push({
    id: "regexpp",
    name: "@eslint-community/regexpp",
    version: "4.12.2",
    kind: "vendored-javascript",
    sourceCommit: null,
    goSum: null,
    sourceSha256: digest(regex),
    licenses: [{ path: "licenses/regexpp/LICENSE", sha256: digest(license) }],
  });
  return { archiveFiles, components, buildInfo: info, createdAt };
}
function spdxDocument(manifest, files, archiveFiles) {
  // SPDX 2.3 mandates SHA1 for file verification codes. SHA256 remains the
  // security identity everywhere; SHA1 here is only SPDX bookkeeping.
  const fileSHA1 = new Map(
    files.map((f) => [
      f.path,
      createHash("sha1").update(archiveFiles.get(f.path).bytes).digest("hex"),
    ]),
  );
  const packages = manifest.components.map((c) => ({
    SPDXID: `SPDXRef-${c.id}`,
    name: c.name,
    versionInfo: c.version,
    downloadLocation:
      c.kind === "repository-source"
        ? `git+https://github.com/bwmp-dev/provenance@${manifest.sourceCommit}`
        : "NOASSERTION",
    filesAnalyzed: false,
    licenseConcluded: "NOASSERTION",
    licenseDeclared: "NOASSERTION",
    copyrightText: "NOASSERTION",
    comment: JSON.stringify({
      kind: c.kind,
      goSum: c.goSum,
      licenses: c.licenses,
      sourceCommit: c.sourceCommit,
      sourceSha256: c.sourceSha256,
    }),
  }));
  packages.unshift({
    SPDXID: "SPDXRef-CLI",
    name: "provenance-cli-linux-amd64",
    versionInfo: manifest.version,
    downloadLocation: "NOASSERTION",
    filesAnalyzed: true,
    packageVerificationCode: {
      packageVerificationCodeValue: createHash("sha1")
        .update([...fileSHA1.values()].sort().join(""))
        .digest("hex"),
    },
    licenseConcluded: "NOASSERTION",
    licenseDeclared: "Apache-2.0",
    copyrightText: "NOASSERTION",
  });
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `provenance-cli-${manifest.version}`,
    documentNamespace: `https://github.com/bwmp-dev/provenance/cli/${manifest.version}/${manifest.sourceCommit}`,
    creationInfo: {
      created: manifest.createdAt,
      creators: ["Tool: provenance-cli-release"],
    },
    packages,
    files: files.map((f, i) => ({
      SPDXID: `SPDXRef-File-${i}`,
      fileName: `./${manifest.archiveRoot}/${f.path}`,
      checksums: [
        { algorithm: "SHA256", checksumValue: f.sha256 },
        { algorithm: "SHA1", checksumValue: fileSHA1.get(f.path) },
      ],
      licenseConcluded: "NOASSERTION",
      licenseInfoInFiles: ["NOASSERTION"],
      copyrightText: "NOASSERTION",
    })),
    relationships: [
      {
        spdxElementId: "SPDXRef-DOCUMENT",
        relationshipType: "DESCRIBES",
        relatedSpdxElement: "SPDXRef-CLI",
      },
      ...packages.slice(1).map((p) => ({
        spdxElementId: "SPDXRef-CLI",
        relationshipType: "DEPENDS_ON",
        relatedSpdxElement: p.SPDXID,
      })),
      ...files.map((_, i) => ({
        spdxElementId: "SPDXRef-CLI",
        relationshipType: "CONTAINS",
        relatedSpdxElement: `SPDXRef-File-${i}`,
      })),
    ],
  };
}
async function packageOne(
  result,
  dir,
  n,
  source,
  version,
  createdAt,
  sourceFiles,
) {
  const staging = join(dir, "stage");
  mkdirSync(staging);
  const files = [];
  for (const [path, item] of [...result.archiveFiles].sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  )) {
    const target = join(staging, n.root, path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, item.bytes, { mode: item.mode });
    files.push({
      path,
      sizeBytes: item.bytes.length,
      sha256: digest(item.bytes),
      mode: item.mode,
    });
  }
  const manifest = {
    schemaVersion: 1,
    version,
    tag: n.tag,
    sourceCommit: source,
    createdAt,
    platform: "linux-amd64",
    goVersion,
    cgoEnabled: false,
    goAMD64: "v1",
    archiveRoot: n.root,
    archive: { filename: n.archive, sizeBytes: 0, sha256: "" },
    files,
    sourceFiles,
    components: result.components,
    buildInfo: result.buildInfo,
  };
  await createTar(
    {
      cwd: staging,
      file: join(dir, n.archive),
      gzip: { level: 9, mtime: 0 },
      portable: true,
      noPax: true,
      mtime: new Date(createdAt),
    },
    files.map((f) => `${n.root}/${f.path}`),
  );
  const archive = regular(join(dir, n.archive));
  manifest.archive.sizeBytes = archive.length;
  manifest.archive.sha256 = digest(archive);
  writeFileSync(join(dir, n.manifest), json(manifest));
  writeFileSync(
    join(dir, n.sbom),
    json(spdxDocument(manifest, files, result.archiveFiles)),
  );
  const checks = [n.archive, n.manifest, n.sbom]
    .sort()
    .map((name) => `${digest(regular(join(dir, name)))}  ${name}\n`)
    .join("");
  writeFileSync(join(dir, n.checksums), checks);
}
export async function buildCLI({
  version,
  sourceCommit,
  output,
  go = process.env.CLI_RELEASE_GO || "go",
  root = repository,
}) {
  validateReleaseIdentity(version, sourceCommit);
  const n = names(version);
  requireThat(!existsSync(output), "output destination already exists");
  requireThat(
    git(root, "rev-parse", `${sourceCommit}^{commit}`) === sourceCommit,
    "source commit missing",
  );
  const createdAt = new Date(
    Number(git(root, "show", "-s", "--format=%ct", sourceCommit)) * 1000,
  )
    .toISOString()
    .replace(".000Z", "Z");
  validateSpdxTimestamp(createdAt);
  const sourceFiles = sourceInventory(root, sourceCommit);
  const temporary = mkdtempSync(join(tmpdir(), "provenance-cli-build-"));
  try {
    for (const name of ["first", "second-different-absolute-path"]) {
      const checkout = join(temporary, name);
      run(
        "git",
        ["clone", "--quiet", "--no-hardlinks", "--no-checkout", root, checkout],
        root,
      );
      git(checkout, "checkout", "--quiet", "--detach", sourceCommit);
      requireThat(
        git(checkout, "status", "--porcelain") === "",
        "source checkout is dirty",
      );
      const dest = join(temporary, `${name}-output`);
      const result = buildOne(
        checkout,
        dest,
        go,
        join(temporary, "cache"),
        sourceCommit,
        createdAt,
      );
      await packageOne(
        result,
        dest,
        n,
        sourceCommit,
        version,
        createdAt,
        sourceFiles,
      );
    }
    const first = join(temporary, "first-output"),
      second = join(temporary, "second-different-absolute-path-output");
    for (const name of [
      "provenance",
      n.archive,
      n.manifest,
      n.sbom,
      n.checksums,
    ])
      requireThat(
        regular(join(first, name)).equals(regular(join(second, name))),
        "two-directory reproducibility mismatch",
      );
    mkdirSync(dirname(output), { recursive: true });
    // Do not make this recursive: the final destination must remain exclusive,
    // including when another invocation creates it after the initial check.
    mkdirSync(output);
    for (const name of [n.archive, n.manifest, n.sbom, n.checksums])
      cpSync(join(first, name), join(output, name), {
        errorOnExist: true,
        force: false,
      });
    return {
      version,
      sourceCommit,
      tag: n.tag,
      output,
      artifacts: [n.archive, n.manifest, n.sbom, n.checksums],
    };
  } finally {
    // Go intentionally makes downloaded module directories read-only. Only our
    // fresh owned temporary tree is made removable; never follow symlinks.
    function removable(path) {
      const st = lstatSync(path);
      if (!st.isDirectory() || st.isSymbolicLink()) return;
      chmodSync(path, 0o700);
      for (const entry of readdirSync(path)) removable(join(path, entry));
    }
    removable(temporary);
    rmSync(temporary, { recursive: true, force: true });
  }
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    const args = process.argv.slice(2);
    requireThat(args.shift() === "build", "expected build command");
    const options = {};
    while (args.length) {
      const key = args.shift();
      requireThat(
        ["--version", "--source-commit", "--output", "--go"].includes(key) &&
          args.length &&
          !options[key],
        "invalid arguments",
      );
      options[key] = args.shift();
    }
    const result = await buildCLI({
      version: options["--version"],
      sourceCommit: options["--source-commit"],
      output: resolve(options["--output"] || ""),
      go: options["--go"],
    });
    process.stdout.write(JSON.stringify(result) + "\n");
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
