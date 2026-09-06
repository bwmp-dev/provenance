import assert from "node:assert/strict";
import test from "node:test";
import { definition, matrix } from "./run-matrix-behavioral.mjs";
import { evaluateFixtureEvidence } from "./paper-behavioral-lib.mjs";

test("matrix requires two specific negative classifications and one pass", () => {
  assert.deepEqual(
    matrix.map((row) => [row.version, definition(row).expectedClassifications]),
    [
      ["1.20.6", ["on_enable_failure"]],
      ["1.21.4", ["on_enable_failure"]],
      ["1.21.8", []],
    ],
  );
  for (const row of matrix) {
    assert.match(row.paper, /^[0-9a-f]{64}$/);
    assert.match(row.runtime, /^[0-9a-f]{64}$/);
    assert.ok(evaluateFixtureEvidence(definition(row), []).failures.length > 0);
  }
});

test("synthetic incompatible and infrastructure outcomes cannot satisfy fixture", () => {
  for (const code of [
    "plugin_incompatible",
    "runner_restarted",
    "paper_lifecycle_failed",
  ]) {
    assert.ok(
      evaluateFixtureEvidence(definition(matrix[0]), [
        { type: "CLASSIFICATION", data: { code } },
      ]).failures.some((value) => value.startsWith("classifications:")),
    );
  }
});
