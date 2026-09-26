import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";

import { parse } from "yaml";

const workflowDirectory = new URL("../.github/workflows/", import.meta.url);

// The only GitHub-hosted exception: CI's test-only native CLI matrix.
const hostedJobs = new Map([["ci.yml", "cli-native"]]);

test("repository workflows use only trusted Linux x64 self-hosted jobs", async () => {
  const names = (await readdir(workflowDirectory))
    .filter((name) => name.endsWith(".yml") || name.endsWith(".yaml"))
    .sort();
  assert.deepEqual(names, [
    "ci.yml",
    "release-cli.yml",
    "release-contracts.yml",
    "release-testkit.yml",
  ]);

  for (const name of names) {
    const source = await readFile(new URL(name, workflowDirectory), "utf8");
    const workflow = parse(source);
    assert.ok(workflow && typeof workflow === "object", `${name} must parse`);
    assert.ok(
      workflow.jobs && typeof workflow.jobs === "object",
      `${name} jobs`,
    );
    assert.doesNotMatch(source, /runs-on:\s*ubuntu-/);
    assert.ok(!Object.hasOwn(workflow.on ?? {}, "pull_request"));
    assert.ok(!Object.hasOwn(workflow.on ?? {}, "pull_request_target"));
    for (const [jobName, job] of Object.entries(workflow.jobs)) {
      if (hostedJobs.get(name) === jobName) continue;
      assert.deepEqual(
        job["runs-on"],
        ["self-hosted", "linux", "x64"],
        `${name} ${jobName} runner selector`,
      );
    }
  }
});

test("CI runs for every trusted upstream branch and never for pull requests", async () => {
  const source = await readFile(new URL("ci.yml", workflowDirectory), "utf8");
  const workflow = parse(source);

  assert.deepEqual(Object.keys(workflow.on).sort(), [
    "push",
    "workflow_dispatch",
  ]);
  assert.deepEqual(workflow.on.push, { branches: ["**"] });
  assert.doesNotMatch(source, /github\.(?:base_ref|event\.pull_request)/);
});

test("release workflows remain manual-only", async () => {
  for (const name of [
    "release-cli.yml",
    "release-contracts.yml",
    "release-testkit.yml",
  ]) {
    const workflow = parse(
      await readFile(new URL(name, workflowDirectory), "utf8"),
    );
    assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  }
});

test("offline consumer jobs populate and share an explicit per-runner store", async () => {
  for (const [name, jobName] of [
    ["ci.yml", "contracts"],
    ["release-contracts.yml", "build"],
  ]) {
    const workflow = parse(
      await readFile(new URL(name, workflowDirectory), "utf8"),
    );
    const job = workflow.jobs[jobName];
    const storeIndex = job.steps.findIndex(
      (step) =>
        step.run ===
        'echo "pnpm_config_store_dir=$RUNNER_TEMP/provenance-pnpm-store" >> "$GITHUB_ENV"',
    );
    const setupIndex = job.steps.findIndex((step) =>
      step.uses?.startsWith("pnpm/action-setup@"),
    );
    assert.ok(storeIndex >= 0 && storeIndex < setupIndex);
    assert.equal(
      job.steps[setupIndex].with.dest,
      "${{ runner.temp }}/provenance-pnpm",
    );
    assert.equal(job.steps[setupIndex].with.version, "11.20.0");
    const fetchIndex = job.steps.findIndex(
      (step) => step.run === "pnpm fetch --frozen-lockfile --ignore-scripts",
    );
    const installIndex = job.steps.findIndex(
      (step) => step.run === "pnpm install --frozen-lockfile",
    );
    const checkIndex = job.steps.findIndex((step) => step.run === "pnpm check");
    assert.ok(fetchIndex >= 0 && fetchIndex < installIndex);
    assert.ok(installIndex < checkIndex);
  }
});

test("hosted native CLI matrix is test-only, secretless and SHA-pinned", async () => {
  const source = await readFile(new URL("ci.yml", workflowDirectory), "utf8");
  const job = parse(source).jobs["cli-native"];
  assert.equal(job["runs-on"], "${{ matrix.os }}");
  assert.deepEqual(job.strategy.matrix, {
    os: ["macos-latest", "windows-latest"],
  });
  assert.deepEqual(job.permissions, { contents: "read" });
  assert.ok(!Object.hasOwn(job, "environment"));
  assert.ok(!Object.hasOwn(job, "needs"));
  assert.ok(!Object.hasOwn(job, "env"));
  const text = JSON.stringify(job);
  assert.doesNotMatch(text, /secrets\.|github\.token|GITHUB_TOKEN|id-token/);
  assert.doesNotMatch(text, /upload-artifact|attest|release|docker/i);
  for (const step of job.steps) {
    assert.ok(
      !Object.hasOwn(step, "env") || !JSON.stringify(step.env).includes("${{"),
    );
    if (!step.uses) continue;
    assert.match(
      step.uses,
      /^(actions|pnpm)\/[a-z-]+@[0-9a-f]{40}$/,
      step.uses,
    );
    if (step.uses.startsWith("actions/checkout@"))
      assert.equal(step.with["persist-credentials"], false);
  }
});
