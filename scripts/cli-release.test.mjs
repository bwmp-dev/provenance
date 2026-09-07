import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { parse as yaml } from "yaml";
import { create as createTar } from "tar";
import { buildCLI, digest, names, repository } from "./cli-release.mjs";

const version = "0.1.0-alpha.1";
const source = execFileSync("git", ["rev-parse", "HEAD"], {
  cwd: repository,
  encoding: "utf8",
}).trim();
const n = names(version);
const workflow = yaml(
  readFileSync(join(repository, ".github/workflows/release-cli.yml"), "utf8"),
);
const verify = (directory) =>
  spawnSync(
    "python3",
    [
      "scripts/verify-cli-release.py",
      "--directory",
      directory,
      "--version",
      version,
      "--source-sha",
      source,
    ],
    { cwd: repository, encoding: "utf8", timeout: 30000 },
  );
function rehash(directory) {
  writeFileSync(
    join(directory, n.checksums),
    [n.archive, n.manifest, n.sbom]
      .sort()
      .map(
        (name) => `${digest(readFileSync(join(directory, name)))}  ${name}\n`,
      )
      .join(""),
  );
}

test("CLI distribution workflow is separate and least privilege", () => {
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.equal(workflow.concurrency["cancel-in-progress"], false);
  for (const job of Object.values(workflow.jobs))
    assert.deepEqual(job["runs-on"], ["self-hosted", "linux", "x64"]);
  assert.deepEqual(workflow.jobs.build.permissions, { contents: "read" });
  assert.equal(workflow.jobs.release.permissions["id-token"], "write");
  assert.equal(workflow.jobs.release.permissions.contents, "write");
  const checks = workflow.jobs.release.steps.filter((s) =>
    s.uses?.startsWith("actions/attest@"),
  );
  assert.deepEqual(
    checks.map((s) => s.with["subject-path"]),
    ["dist/cli/*", "dist/cli/*.tar.gz"],
  );
  assert.match(checks[1].with["sbom-path"], /provenance-cli-/);
  assert(!JSON.stringify(workflow).includes("dist/contracts"));
  for (const job of Object.values(workflow.jobs))
    for (const step of job.steps)
      if (step.run) {
        const command = step.run.replace(/\$\{\{[^}]+\}\}/g, "fixture");
        assert.equal(
          spawnSync("bash", ["-n"], { input: command }).status,
          0,
          step.name,
        );
      }
  assert.throws(() => names("0.1.0+metadata"));
  assert.throws(() => names("../escape"));
  assert.throws(() => names("0.1.0-" + "a".repeat(65)));
});

test(
  "actual two-directory release, independent tamper checks, extracted native CLI and conflicting repeats",
  { timeout: 600000 },
  async (t) => {
    const temporary = mkdtempSync(
      join(tmpdir(), "provenance-cli-distribution-test-"),
    );
    t.after(() => rmSync(temporary, { recursive: true, force: true }));
    const bundle = join(temporary, "bundle");
    await buildCLI({ version, sourceCommit: source, output: bundle });
    assert.deepEqual(
      readdirSync(bundle).sort(),
      [n.archive, n.manifest, n.sbom, n.checksums].sort(),
    );
    const valid = verify(bundle);
    assert.equal(valid.status, 0, valid.stderr);
    const spdx = spawnSync(
      "python",
      [
        "-m",
        "spdx_tools.spdx.clitools.pyspdxtools",
        "-i",
        join(bundle, n.sbom),
      ],
      { encoding: "utf8", timeout: 30000 },
    );
    assert.equal(spdx.status, 0, spdx.stdout + spdx.stderr);
    const result = JSON.parse(valid.stdout);
    assert.equal(result.verified, true);
    assert.equal(result.components, 19);
    assert.equal(result.files, 31);
    await assert.rejects(
      buildCLI({ version, sourceCommit: source, output: bundle }),
      /already exists/,
    );
    await assert.rejects(
      buildCLI({
        version,
        sourceCommit: "0".repeat(40),
        output: join(temporary, "missing"),
      }),
    );
    async function reject(label, mutate) {
      const dir = join(temporary, label);
      cpSync(bundle, dir, { recursive: true });
      await mutate(dir);
      const checked = verify(dir);
      assert.notEqual(checked.status, 0, label);
      assert.match(checked.stderr, /verification failed/, label);
    }
    await reject("extra-asset", (dir) =>
      writeFileSync(join(dir, "unexpected"), "x"),
    );
    await reject("binary-tamper", (dir) => {
      const path = join(dir, n.archive);
      const bytes = readFileSync(path);
      bytes[bytes.length - 20] ^= 1;
      writeFileSync(path, bytes);
      rehash(dir);
    });
    await reject("missing-checksum", (dir) =>
      writeFileSync(join(dir, n.checksums), ""),
    );
    await reject("wrong-source", (dir) => {
      const path = join(dir, n.manifest);
      const m = JSON.parse(readFileSync(path));
      m.sourceCommit = "0".repeat(40);
      writeFileSync(path, JSON.stringify(m));
      rehash(dir);
    });
    await reject("missing-license", (dir) => {
      const path = join(dir, n.manifest);
      const m = JSON.parse(readFileSync(path));
      m.components
        .find((c) => c.name === "github.com/dop251/goja")
        .licenses.pop();
      writeFileSync(path, JSON.stringify(m));
      rehash(dir);
    });
    await reject("missing-linked-module", (dir) => {
      const path = join(dir, n.manifest);
      const m = JSON.parse(readFileSync(path));
      m.components.splice(0, 1);
      writeFileSync(path, JSON.stringify(m));
      rehash(dir);
    });
    await reject("false-sbom", (dir) => {
      const path = join(dir, n.sbom);
      const m = JSON.parse(readFileSync(path));
      m.packages[1].versionInfo = "false-version";
      writeFileSync(path, JSON.stringify(m));
      rehash(dir);
    });
    await reject("false-file-license", (dir) => {
      const path = join(dir, n.sbom);
      const m = JSON.parse(readFileSync(path));
      m.files[0].licenseConcluded = "MIT";
      writeFileSync(path, JSON.stringify(m));
      rehash(dir);
    });
    await reject("duplicate-json", (dir) => {
      const path = join(dir, n.manifest);
      writeFileSync(
        path,
        readFileSync(path, "utf8").replace("{", '{"schemaVersion":1,'),
      );
      rehash(dir);
    });
    await reject("unsafe-archive", async (dir) => {
      const stage = join(temporary, "unsafe-stage");
      mkdirSync(stage);
      writeFileSync(join(stage, "unexpected"), "x");
      await createTar({ cwd: stage, file: join(dir, n.archive), gzip: true }, [
        "unexpected",
      ]);
      const path = join(dir, n.manifest);
      const m = JSON.parse(readFileSync(path));
      const bytes = readFileSync(join(dir, n.archive));
      m.archive = {
        filename: n.archive,
        sizeBytes: bytes.length,
        sha256: digest(bytes),
      };
      writeFileSync(path, JSON.stringify(m));
      rehash(dir);
    });
    await t.test(
      "actual extracted binary, signed fixture and nonroot Secret Service",
      () => {
        const native = spawnSync(
          "bash",
          ["scripts/test-cli-release-native.sh", bundle, version, source],
          {
            cwd: repository,
            encoding: "utf8",
            timeout: 180000,
            maxBuffer: 8 * 1024 * 1024,
          },
        );
        assert.equal(native.status, 0, native.stdout + native.stderr);
        assert.match(native.stdout, /"storedSessionReadback": true/);
        assert.match(native.stdout, /"lockedStorePreIssuance": true/);
        console.log(
          native.stdout
            .split("\n")
            .filter((line) => line.startsWith("{"))
            .join("\n"),
        );
      },
    );
    await t.test(
      "actual publish script refuses conflicting repeats without mutation",
      () => {
        const dir = join(temporary, "repeat");
        mkdirSync(join(dir, "dist"), { recursive: true });
        cpSync(bundle, join(dir, "dist/cli"), { recursive: true });
        const bin = join(dir, "bin");
        mkdirSync(bin);
        cpSync(
          join(repository, "scripts/fixtures/cli-release/gh-repeat.py"),
          join(bin, "gh"),
        );
        chmodSync(join(bin, "gh"), 0o755);
        // Trusted verifier resolves source via the actual repository; its execution
        // remains real, only GitHub is simulated. No checkout mutation is required.
        const step = workflow.jobs.release.steps.find(
          (s) => s.name === "Reconcile and publish GitHub release",
        );
        let script = step.run
          .replaceAll(
            "python3 scripts/verify-cli-release.py",
            `python3 '${join(repository, "scripts/verify-cli-release.py")}' --repository '${repository}'`,
          )
          .replaceAll(
            "git merge-base --is-ancestor",
            `git -C '${repository}' merge-base --is-ancestor`,
          );
        const compatibility = [
          "## CLI distribution",
          "- Platform: Linux amd64 only",
          "- Native credential storage: Linux Secret Service; no plaintext fallback",
          "- Requires an explicitly trusted HTTPS platform origin and verification keys",
          "- No live platform, browser confirmation, macOS or Windows acceptance claimed",
          "- Separate CLI release; existing contract release assets are unchanged",
        ].join("\n");
        const state = {
          tag: n.tag,
          source,
          directory: bundle,
          release: {
            id: 1,
            tag_name: n.tag,
            name: `Provenance CLI ${n.tag}`,
            body: compatibility,
            prerelease: true,
            draft: false,
          },
          assets: readdirSync(bundle)
            .sort()
            .map((name, index) => ({
              id: index + 1,
              name,
              size: readFileSync(join(bundle, name)).length,
              state: "uploaded",
            })),
        };
        for (const scenario of [
          "same",
          "tag-conflict",
          "lightweight-tag",
          "digest",
          "metadata",
          "extra",
          "incomplete",
          "discovery",
        ]) {
          const current = structuredClone(state);
          if (scenario === "digest") current.tamper = n.archive;
          if (scenario === "metadata") current.release.name = "different";
          if (scenario === "extra")
            current.assets.push({
              id: 99,
              name: "extra",
              size: 1,
              state: "uploaded",
            });
          if (scenario === "incomplete") current.assets.pop();
          if (scenario === "discovery") current.discoveryError = true;
          if (scenario === "tag-conflict") current.source = "b".repeat(40);
          if (scenario === "lightweight-tag") current.tagType = "commit";
          const statePath = join(dir, scenario + ".json"),
            log = join(dir, scenario + ".log");
          writeFileSync(statePath, JSON.stringify(current));
          const execution = spawnSync(
            "bash",
            ["-euo", "pipefail", "-c", script],
            {
              cwd: dir,
              encoding: "utf8",
              timeout: 30000,
              env: {
                ...process.env,
                PATH: bin + ":" + process.env.PATH,
                CLI_REPEAT_STATE: statePath,
                CLI_REPEAT_LOG: log,
                RUNNER_TEMP: dir,
                GITHUB_REPOSITORY: "bwmp-dev/provenance",
                TAG: n.tag,
                VERSION: version,
                SOURCE_SHA: source,
                POLICY_SHA: source,
                PRERELEASE: "true",
              },
            },
          );
          assert.equal(
            execution.status === 0,
            scenario === "same",
            scenario + execution.stdout + execution.stderr,
          );
          const calls = readFileSync(log, "utf8")
            .trim()
            .split("\n")
            .map(JSON.parse);
          assert(calls.length > 0);
          assert(
            calls.every(
              (args) => args[0] === "api" && !args.includes("--method"),
            ),
            "repeat attempted mutation",
          );
        }
      },
    );
  },
);
