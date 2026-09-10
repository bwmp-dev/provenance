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
  assert.equal(doc.components.parameters.IdempotencyKey.required, true);
  for (const op of [admin.get, admin.post, poll]) {
    for (const status of ["400", "401", "403", "503"])
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
    "/v1/admin/hosted-catalogs",
    "/v1/runner-catalogs/{runnerId}/poll",
    "/v1/runner-catalog-assets/{sha256}/{filename}",
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
      const statuses = [
        "/v1/runner-releases/{sha256}",
        "/v1/runner-catalog-assets/{sha256}/{filename}",
      ].includes(path)
        ? [401, 403, 429, 503]
        : path.startsWith("/v1/runner-updater/") ||
            path.startsWith("/v1/runner-catalogs/")
          ? [400, 401, 403, 409, 429, 503]
          : method === "post"
            ? [400, 401, 403, 404, 409, 429, 503]
            : [
                  "/v1/admin/runner-updates",
                  "/v1/admin/hosted-catalogs",
                ].includes(path)
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
  assert.equal(count, 11);
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

test("hosted polling preserves durable node-bound operation semantics", () => {
  const p = doc.components.schemas.HostedUpdaterPoll;
  assert.equal(p.additionalProperties, false);
  assert.deepEqual(Object.keys(p.properties).sort(), ["operationId", "report"]);
  assert.deepEqual(p.required, ["report"]);
  assert.match(
    p.description,
    /idle without operationId selects the node[’']s durable active operation/,
  );
  assert.match(p.description, /All non-idle reports require its operationId/);
  assert.match(
    p.description,
    /Repeating a report cannot select or mutate another node[’']s operation/,
  );
  const s = doc.components.schemas;
  assert.equal(
    s.HostedRunnerRelease.properties.signature.pattern,
    "^[A-Za-z0-9+/]{86}==$",
  );
  for (const type of [
    "HostedRunnerUpdateRequest",
    "HostedRunnerRequest",
    "HostedInstallProfile",
  ])
    assert.equal(
      s[type].properties.releasePublicKey.pattern,
      "^[A-Za-z0-9+/]{43}=$",
    );
});

test("hosted mutations retain canonical idempotency and bounded views signal truncation", () => {
  for (const p of ["/v1/admin/runner-updates", "/v1/admin/hosted-runners"])
    assert.deepEqual(doc.paths[p].post.parameters, [
      { $ref: "#/components/parameters/IdempotencyKey" },
    ]);
  for (const n of ["HostedRunnerList", "HostedRunnerUpdateView"]) {
    assert.equal(
      doc.components.schemas[n].properties.truncated.type,
      "boolean",
    );
    assert.ok(doc.components.schemas[n].required.includes("truncated"));
  }
  assert.equal(
    doc.paths["/v1/runner-updater/{runnerId}/poll"].post.responses[404],
    undefined,
  );
  const semantics = readFileSync(
    new URL("./hosted-runner-semantics.md", import.meta.url),
    "utf8",
  );
  assert.match(
    semantics,
    /unbound or unavailable runner.*403 updater_forbidden/,
  );
});

test("hosted install profiles accept either legacy pins or bounded complete Paper catalogs", async () => {
  const { createRequire } = await import("node:module");
  const require = createRequire(
    new URL("../packages/verification/package.json", import.meta.url),
  );
  const Ajv = require("ajv/dist/2020.js");
  const addFormats = require("ajv-formats");
  const ajv = new Ajv({ strict: false });
  addFormats(ajv);
  ajv.addSchema({ $id: "hosted", components: doc.components });
  const validate = ajv.compile({
    $ref: "hosted#/components/schemas/HostedInstallProfile",
  });
  const asset = {
    uri: "https://artifacts.example/asset",
    sha256: "a".repeat(64),
    sizeBytes: 100,
  };
  const artifact = { ...asset, filename: "paper.jar" };
  const catalog = {
    environmentId: "paper-1.21.11-42-java-21",
    paper: { gameVersion: "1.21.11", build: 42, artifact },
    java: {
      distribution: "eclipse-temurin",
      version: "21.0.8+9",
      os: "linux",
      architecture: "amd64",
      archiveRoot: "jdk-21.0.8+9-jre",
      artifact: { ...artifact, filename: "java.tar.gz" },
      maximumExpandedBytes: 1000,
    },
    probeVersion: "0.1.0",
    probeSourceCommit: "f82dcbf8244354059731ba533f73909ed5528bbd",
    probe: {
      ...artifact,
      filename: "paper-probe.jar",
      sha256:
        "040062e4ea15fdffe3c37e4402b978527dd4864870edefe2c662209e12d63868",
      sizeBytes: 478853,
    },
    preparedRuntime: {
      artifact: { ...artifact, filename: "runtime.tar.gz" },
      maximumExpandedBytes: 1000,
    },
  };
  {
    const validateCatalog = ajv.compile({
      $ref: "hosted#/components/schemas/HostedPaperCatalog",
    });
    const legacy = structuredClone(catalog);
    legacy.paper.gameVersion = "1.8.8";
    legacy.java.version = "8.0.504+1";
    assert.equal(
      validateCatalog(legacy),
      false,
      "old probe cannot authorize legacy Paper",
    );
    legacy.probeVersion = "0.2.0";
    legacy.probeSourceCommit = "18400bb4a47d28c1d95c3f4067603af3f3409d5e";
    legacy.probe.sha256 =
      "141a535d495a3afd5f413cab04618e75421390f0e14acba0707d1573c5a8c96b";
    legacy.probe.sizeBytes = 480768;
    assert.equal(
      validateCatalog(legacy),
      true,
      JSON.stringify(validateCatalog.errors),
    );
    legacy.probeSourceCommit = catalog.probeSourceCommit;
    assert.equal(
      validateCatalog(legacy),
      false,
      "mixed probe pins must be rejected",
    );
  }
  const profile = {
    gatewayAddress: "gateway.example:443",
    apiOrigin: "https://api.example",
    artifactHosts: ["artifacts.example"],
    bundle: asset,
    releasePublicKey: "A".repeat(43) + "=",
    resources: {
      cpuMillis: 2000,
      memoryBytes: 6442450944,
      diskBytes: 17179869184,
      processCount: 1024,
    },
    paperCatalogs: [catalog],
  };
  assert.equal(validate(profile), true, JSON.stringify(validate.errors));
  const modern = structuredClone(profile);
  modern.paperCatalogs[0].paper.gameVersion = "26.1.2";
  modern.paperCatalogs[0].java.version = "25.0.4.1+1";
  assert.equal(validate(modern), true, JSON.stringify(validate.errors));
  modern.paperCatalogs[0].paper.gameVersion = "26.0";
  assert.equal(validate(modern), false);
  const legacy = {
    ...profile,
    probe: asset,
    preparedRuntime: { ...asset, maximumExpandedBytes: 1000 },
  };
  delete legacy.paperCatalogs;
  assert.equal(validate(legacy), true, JSON.stringify(validate.errors));
  for (const invalid of [
    { ...profile, probe: asset },
    { ...profile, preparedRuntime: legacy.preparedRuntime },
    { ...legacy, paperCatalogs: [catalog] },
    { ...profile, paperCatalogs: [] },
    { ...profile, paperCatalogs: Array(33).fill(catalog) },
    { ...profile, paperCatalogs: [catalog, catalog] },
    { ...profile, paperCatalogs: null },
  ])
    assert.equal(validate(invalid), false, JSON.stringify(invalid));
  for (const mutate of [
    (c) => {
      c.paper.artifact.filename = "../paper.jar";
    },
    (c) => {
      c.paper.artifact.sizeBytes = 536870913;
    },
    (c) => {
      c.paper.build = 0;
    },
    (c) => {
      c.paper.gameVersion = "latest";
    },
    (c) => {
      c.paper.gameVersion = "1.19.4";
    },
    (c) => {
      c.java.version = "21";
    },
    (c) => {
      c.java.architecture = "arm64";
    },
    (c) => {
      c.java.archiveRoot = "../java";
    },
    (c) => {
      c.preparedRuntime.maximumExpandedBytes = 1073741825;
    },
    (c) => {
      c.probe.sha256 = "b".repeat(64);
    },
    (c) => {
      c.probeVersion = "latest";
    },
    (c) => {
      c.unknown = true;
    },
    (c) => {
      delete c.preparedRuntime;
    },
  ]) {
    const invalid = structuredClone(profile);
    mutate(invalid.paperCatalogs[0]);
    assert.equal(validate(invalid), false, JSON.stringify(invalid));
  }
});
