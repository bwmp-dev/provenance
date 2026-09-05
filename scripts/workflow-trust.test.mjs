import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";

import { parse } from "yaml";

const workflowDirectory = new URL("../.github/workflows/", import.meta.url);

test("repository workflows use only trusted Linux x64 self-hosted jobs", async () => {
  const names = (await readdir(workflowDirectory))
    .filter((name) => name.endsWith(".yml") || name.endsWith(".yaml"))
    .sort();
  assert.deepEqual(names, [
    "ci.yml",
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
  for (const name of ["release-contracts.yml", "release-testkit.yml"]) {
    const workflow = parse(
      await readFile(new URL(name, workflowDirectory), "utf8"),
    );
    assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  }
});
