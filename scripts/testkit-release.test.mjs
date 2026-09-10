import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

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
  assert.equal(testkitSourceCommit, "18400bb4a47d28c1d95c3f4067603af3f3409d5e");
  assert.equal(testkitMatrix.length, 15);
  assert.deepEqual(
    testkitMatrix.map(({ type }) => type),
    ["probe", ...Array(6).fill("benign"), ...Array(8).fill("hostile")],
  );
  assert.deepEqual(testkitMatrix[0], {
    id: "paper-probe",
    type: "probe",
    source: "plugins/paper-probe/build/libs/paper-probe-0.2.0.jar",
    sha256: "141a535d495a3afd5f413cab04618e75421390f0e14acba0707d1573c5a8c96b",
    sizeBytes: 480768,
  });
  const pidFixture = testkitMatrix.find(({ id }) => id === "fork-pid-bomb");
  assert.equal(
    pidFixture.sha256,
    "b4d936c12370892047839396786b6e65b1b5ccf65c6ddae70e283b43fe3e8e16",
  );
  assert.equal(pidFixture.sizeBytes, 7593);
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
  assert.throws(
    () =>
      validateTestkitIdentity(tag, "98d5f07f173a9e3f1b365add24b81c934d7e3c61"),
    /no audited testkit matrix/,
  );
});

test("staging rejects wrong bytes, source links, and occupied destinations", (t) => {
  const root = mkdtempSync(join(tmpdir(), "testkit-policy-negative-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const source = join(root, "source");
  const probe = join(source, testkitMatrix[0].source);
  mkdirSync(dirname(probe), { recursive: true });
  const script = fileURLToPath(
    new URL("./testkit-release.mjs", import.meta.url),
  );
  const run = (command, args) =>
    spawnSync(
      process.execPath,
      [
        script,
        command,
        "--tag",
        tag,
        "--source-commit",
        testkitSourceCommit,
        ...args,
      ],
      { encoding: "utf8" },
    );
  const stage = (suffix) =>
    run("stage", ["--source", source, "--directory", join(root, suffix)]);
  const rejects = (result, pattern) => {
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, pattern);
  };
  // Deliberately invalid bytes are rejection fixtures, never acceptance evidence.
  writeFileSync(probe, Buffer.alloc(1));
  rejects(stage("bad-size"), /size differs/);
  writeFileSync(probe, Buffer.alloc(testkitMatrix[0].sizeBytes));
  rejects(stage("bad-digest"), /SHA-256 differs/);
  rmSync(probe);
  symlinkSync(join(root, "missing"), probe);
  rejects(stage("source-link"), /not a regular file/);
  const occupied = join(root, "occupied");
  mkdirSync(occupied);
  writeFileSync(join(occupied, "retained"), "do not overwrite");
  rejects(stage("occupied"), /directory is not empty/);
  symlinkSync(occupied, join(root, "output-link"));
  rejects(stage("output-link"), /not a regular directory/);
  rejects(run("verify", ["--directory", occupied]), /inventory differs/);
  rejects(
    run("compare", ["--left", occupied, "--right", occupied]),
    /inventory differs/,
  );
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
  assert.equal(workflow.match(/Install pinned GitHub CLI/g)?.length, 2);
  assert.equal(workflow.match(/command -v gh/g)?.length, 2);
});

test("every release job provisions pinned Node before invoking it", async () => {
  const workflow = parse(
    await readFile(
      new URL("../.github/workflows/release-testkit.yml", import.meta.url),
      "utf8",
    ),
  );
  for (const [name, versionFile] of [
    ["validate", ".node-version"],
    ["build", "source/.node-version"],
    ["release", "policy/.node-version"],
  ]) {
    const steps = workflow.jobs[name].steps;
    const setup = steps.findIndex((step) =>
      step.uses?.startsWith("actions/setup-node@"),
    );
    assert.ok(setup >= 0, `${name} must provision Node explicitly`);
    assert.equal(
      steps[setup].uses,
      "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
    );
    assert.equal(steps[setup].with["node-version-file"], versionFile);
    const checkout = steps.findIndex(
      (step) =>
        step.uses?.startsWith("actions/checkout@") &&
        (step.with?.path ?? ".") ===
          (versionFile.includes("/") ? versionFile.split("/")[0] : "."),
    );
    assert.ok(
      checkout >= 0 && checkout < setup,
      `${name} must check out the version file first`,
    );
    const invocations = steps
      .map((step, index) => (/^\s*node\s/m.test(step.run ?? "") ? index : -1))
      .filter((index) => index >= 0);
    assert.ok(invocations.length > 0, `${name} must actually exercise Node`);
    for (const index of invocations)
      assert.ok(setup < index, `${name} invokes Node before setup`);
  }
});

test("release jobs bootstrap the reviewed GitHub CLI bytes", async () => {
  const installer = await readFile(
    new URL("./install-github-cli.sh", import.meta.url),
    "utf8",
  );
  assert.match(installer, /version="2\.96\.0"/);
  assert.match(installer, /b300f2ec7ec9dc9addc39b2ad88c54097ded7ca0/);
  assert.match(
    installer,
    /83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60/,
  );
  assert.match(installer, /archive_size="14652560"/);
  assert.match(installer, /sha256sum --check --strict/);
  assert.match(installer, /ELF 64-bit LSB executable, x86-64/);
  assert.match(installer, /reported_version/);
});
