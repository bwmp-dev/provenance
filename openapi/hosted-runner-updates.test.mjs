import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "yaml";
const doc = parse(
  readFileSync(new URL("./provenance.v1.yaml", import.meta.url), "utf8"),
);
test("hosted updater credentials are separate from human administration", () => {
  const admin = doc.paths["/v1/admin/runner-updates"];
  for (const op of Object.values(admin))
    assert.deepEqual(op.security, [{ SessionCookie: [] }]);
  const poll = doc.paths["/v1/runner-updater/{runnerId}/poll"].post;
  assert.deepEqual(poll.security, [{ HostedRunnerUpdater: [] }]);
  assert.equal(
    poll.parameters.find((p) => p.name === "runnerId").required,
    true,
  );
  assert.equal(
    poll.parameters.some((p) => p.name === "Idempotency-Key"),
    false,
  );
  assert.equal(
    admin.post.parameters.find((p) => p.name === "Idempotency-Key").required,
    true,
  );
  for (const op of [admin.get, admin.post, poll]) {
    for (const status of ["400", "401", "403", "404", "503"])
      assert.ok(op.responses[status]);
    assert.ok(op.responses["200"].headers["Cache-Control"]);
  }
});
test("hosted update states and signed release identity remain bounded", () => {
  const s = doc.components.schemas;
  assert.deepEqual(s.HostedRunnerUpdate.properties.state.enum, [
    "draining",
    "installing",
    "verifying",
    "succeeded",
    "rolled_back",
    "failed",
    "cancelled",
  ]);
  assert.equal(s.HostedRunnerRelease.additionalProperties, false);
  assert.equal(s.HostedRunnerRelease.properties.sizeBytes.maximum, 536870912);
  assert.deepEqual(Object.keys(s.HostedRunnerRelease.properties).sort(), [
    "sha256",
    "signature",
    "sizeBytes",
    "url",
    "version",
  ]);
  assert.equal(
    s.HostedRunnerUpdateRequest.properties.organizationId,
    undefined,
  );
  assert.equal(s.HostedRunnerUpdateRequest.properties.credential, undefined);
});
