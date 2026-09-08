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
test("every hosted operation has closed non-reflective no-store failures", () => {
  const paths = [
    "/v1/admin/runner-updates",
    "/v1/runner-updater/{runnerId}/poll",
    "/v1/admin/hosted-runners",
    "/v1/admin/hosted-runners/install-profile",
    "/v1/runner-releases/{sha256}",
  ];
  let count = 0;
  for (const path of paths)
    for (const [method, op] of Object.entries(doc.paths[path])) {
      count++;
      assert.equal(
        op.responses[200].headers["Cache-Control"].schema.const,
        "no-store",
      );
      assert.ok(
        !(op.parameters ?? []).some((p) =>
          ["Authorization", "provenance_session"].includes(p.name),
        ),
      );
      assert.deepEqual(
        op.security,
        path.startsWith("/v1/admin/")
          ? [{ SessionCookie: [] }]
          : [{ HostedRunnerUpdater: [] }],
      );
      const statuses =
        path === "/v1/runner-releases/{sha256}"
          ? [401, 403, 429, 503]
          : method === "post"
            ? [400, 401, 403, 404, 409, 429, 503]
            : path === "/v1/admin/runner-updates"
              ? [400, 401, 403, 404, 429, 503]
              : [400, 401, 403, 429, 503];
      assert.deepEqual(
        Object.keys(op.responses)
          .filter((s) => s !== "200" && s !== "default")
          .map(Number),
        statuses,
      );
      for (const status of statuses) {
        const response =
          doc.components.responses[op.responses[status].$ref.split("/").at(-1)];
        assert.equal(
          response.headers["Cache-Control"].schema.const,
          "no-store",
        );
        assert.deepEqual(Object.keys(response.content), [
          "application/problem+json",
        ]);
        const schema =
          doc.components.schemas[
            response.content["application/problem+json"].schema.$ref
              .split("/")
              .at(-1)
          ];
        assert.equal(schema.additionalProperties, false);
        assert.deepEqual(schema.required, ["type", "title", "status", "code"]);
        assert.deepEqual(Object.keys(schema.properties), schema.required);
        assert.equal(schema.properties.status.const, status);
        const codes = {
          400: ["invalid_request"],
          401: ["authentication_required"],
          403: ["admin_required"],
          404: ["not_found"],
          409: ["idempotency_key_conflict", "runner_update_conflict"],
          429: ["rate_limited"],
          503: ["admin_unavailable"],
        };
        if (!path.startsWith("/v1/admin/")) {
          codes[403] = ["updater_forbidden"];
          codes[409] = ["runner_update_conflict"];
          codes[503] = ["updater_unavailable"];
        }
        assert.deepEqual(schema.properties.code.enum, codes[status]);
      }
    }
  assert.equal(count, 7);
});

test("release existence stays private and polling IDs are bounded", () => {
  assert.equal(
    doc.paths["/v1/runner-releases/{sha256}"].get.responses[404],
    undefined,
  );
  const id = doc.paths["/v1/runner-updater/{runnerId}/poll"].post.parameters[0];
  assert.equal(id.schema.format, "uuid");
  assert.equal(id.schema.maxLength, 36);
  assert.equal(
    doc.components.schemas.HostedRunnerNode.properties.name.maxLength,
    128,
  );
  assert.deepEqual(
    doc.components.schemas.HostedUpdaterCommand.properties.outcome.enum,
    ["", "succeeded", "rolled_back", "failed", "cancelled"],
  );
  for (const p of [
    "/v1/admin/hosted-runners",
    "/v1/admin/hosted-runners/install-profile",
  ])
    assert.deepEqual(doc.paths[p].get.parameters, []);
});

test("hosted fixed collections and privileged release URLs are bounded", () => {
  const s = doc.components.schemas;
  assert.equal(s.HostedRunnerList.properties.runners.maxItems, 200);
  for (const field of ["updates", "releases"])
    assert.equal(s.HostedRunnerUpdateView.properties[field].maxItems, 50);
  assert.equal(s.HostedRunnerRelease.properties.url.pattern, "^https://");
});
