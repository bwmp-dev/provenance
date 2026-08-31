import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import {
  evaluateFixtureEvidence,
  loadHarnessConfiguration,
  parseProbeNdjson,
  SAFE_FIXTURES,
} from "./paper-behavioral-lib.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const testData = resolve(import.meta.dirname, "../test-data");

test("accepts the package manager argument delimiter", () => {
  const packageManager = process.platform === "win32" ? "cmd.exe" : "pnpm";
  const arguments_ =
    process.platform === "win32"
      ? ["/d", "/s", "/c", "pnpm.cmd run paper:behavioral -- --help"]
      : ["run", "paper:behavioral", "--", "--help"];
  const result = spawnSync(packageManager, arguments_, {
    cwd: repositoryRoot,
    encoding: "utf8",
    timeout: 30_000,
    windowsHide: true,
  });

  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(
    `${result.stdout}\n${result.stderr}`,
    /Usage: pnpm run paper:behavioral/,
  );
});

test("loads the exact pinned Paper artifact and benign matrix", async () => {
  const configuration = await loadHarnessConfiguration(
    repositoryRoot,
    join(testData, "paper-development.json"),
    join(testData, "paper-behavioral-fixtures.json"),
  );

  assert.equal(configuration.paper.minecraftVersion, "1.21.8");
  assert.equal(configuration.paper.build, 60);
  assert.equal(
    configuration.paper.download.sha256,
    "8de7c52c3b02403503d16fac58003f1efef7dd7a0256786843927fa92ee57f1e",
  );
  assert.deepEqual(
    configuration.fixtures.map((fixture) => fixture.id),
    SAFE_FIXTURES,
  );
  assert.ok(
    configuration.fixtures.every((fixture) =>
      fixture.artifactPath.includes("/benign/"),
    ),
  );
});

test("rejects hostile or additional fixtures before resolving artifacts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "provenance-paper-harness-"));
  const validPaper = join(testData, "paper-development.json");
  const invalidFixtures = join(directory, "fixtures.json");
  await writeFile(
    invalidFixtures,
    JSON.stringify({
      schemaVersion: 1,
      fixtures: [
        {
          id: "process-exit",
          targetPlugin: "ProvenanceProcessExit",
          artifactPath:
            "packages/test-fixtures/hostile/process-exit/build/libs/process-exit-1.0.0.jar",
          testPlan: { console: [] },
          expectedClassifications: [],
          requiredEvents: [],
        },
      ],
    }),
  );

  await assert.rejects(
    loadHarnessConfiguration(repositoryRoot, validPaper, invalidFixtures),
    /not in the benign allowlist/,
  );
});

test("parses complete structured NDJSON and evaluates classifications", () => {
  const event = (type, data = {}) => ({
    timestamp: "2026-08-31T20:00:00Z",
    type,
    data,
  });
  const events = [
    event("PROBE_LOADED"),
    event("TEST_PLAN", { status: "LOADED", consoleTests: 0 }),
    event("METADATA_INSPECTION", {
      name: "ProvenanceSuccess",
      status: "VALID",
    }),
    event("SERVER_LOADED"),
    event("STABILIZATION_STARTED"),
    event("STABILIZATION_COMPLETED"),
    event("SERVER_READY", { requirementsSatisfied: true }),
    event("CLEAN_SHUTDOWN_REQUESTED"),
    event("SERVER_STOPPED"),
  ];
  const parsed = parseProbeNdjson(
    `${events.map((value) => JSON.stringify(value)).join("\n")}\n`,
  );
  const result = evaluateFixtureEvidence(
    {
      targetPlugin: "ProvenanceSuccess",
      testPlan: { console: [] },
      expectedClassifications: [],
      requiredEvents: [
        {
          type: "SERVER_READY",
          data: { requirementsSatisfied: true },
        },
      ],
    },
    parsed,
  );

  assert.equal(result.passed, true);
  assert.equal(result.eventCount, 9);
  assert.deepEqual(result.classifications, []);
});

test("fails closed on truncated, oversized, or malformed probe evidence", () => {
  const event = JSON.stringify({
    timestamp: "2026-08-31T20:00:00Z",
    type: "SERVER_READY",
    data: {},
  });
  assert.throws(() => parseProbeNdjson(event), /complete NDJSON line/);
  assert.throws(
    () => parseProbeNdjson(`${event}\n`, { maximumBytes: 4 }),
    /exceeds 4 bytes/,
  );
  assert.throws(
    () => parseProbeNdjson('{"timestamp":false}\n'),
    /invalid envelope/,
  );
});

test("reports missing stable events and unexpected classifications", () => {
  const result = evaluateFixtureEvidence(
    {
      targetPlugin: "ProvenanceSuccess",
      testPlan: { console: [] },
      expectedClassifications: [],
      requiredEvents: [{ type: "SERVER_READY", data: {} }],
    },
    [
      {
        timestamp: "2026-08-31T20:00:00Z",
        type: "CLASSIFICATION",
        data: { code: "infrastructure_failure" },
      },
    ],
  );

  assert.equal(result.passed, false);
  assert.match(result.failures.join("\n"), /infrastructure_failure/);
  assert.match(result.failures.join("\n"), /SERVER_READY/);
});
