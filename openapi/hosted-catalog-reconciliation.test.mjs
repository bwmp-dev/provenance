import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "yaml";

const doc = parse(
  readFileSync(new URL("./provenance.v1.yaml", import.meta.url), "utf8"),
);

test("hosted catalog control and updater authorities stay separate", () => {
  const admin = doc.paths["/v1/admin/hosted-catalogs"];
  assert.deepEqual(admin.get.security, [{ SessionCookie: [] }]);
  assert.deepEqual(admin.post.security, [{ SessionCookie: [] }]);
  assert.equal(
    admin.post.parameters[0].$ref,
    "#/components/parameters/IdempotencyKey",
  );
  for (const path of [
    "/v1/runner-catalogs/{runnerId}/poll",
    "/v1/runner-catalog-assets/{sha256}/{filename}",
  ])
    assert.deepEqual(Object.values(doc.paths[path])[0].security, [
      { HostedRunnerUpdater: [] },
    ]);
});

test("signed catalog revisions and fleet requests are closed and bounded", () => {
  const schemas = doc.components.schemas;
  const revision = schemas.HostedCatalogRevision;
  assert.equal(revision.additionalProperties, false);
  assert.equal(
    revision.properties.schemaVersion.const,
    "provenance.hosted-paper-catalog/v1",
  );
  assert.equal(revision.properties.catalogs.maxItems, 32);
  assert.equal(revision.properties.artifactHosts.maxItems, 32);
  assert.equal(revision.properties.signature.maxLength, 88);
  assert.deepEqual(revision.required, [
    "schemaVersion",
    "artifactHosts",
    "catalogs",
    "sha256",
    "signature",
  ]);
  const request = schemas.HostedCatalogRequest;
  assert.equal(request.additionalProperties, false);
  assert.deepEqual(request.properties.action.enum, [
    "publish",
    "reconcile",
    "cancel",
  ]);
  assert.equal(request.properties.runnerIds.maxItems, 200);
  assert.equal(request.properties.runnerIds.uniqueItems, true);
  assert.equal(request.properties.credential, undefined);
  assert.equal(request.properties.organizationId, undefined);
});

test("catalog desired state, history, polling and downloads are bounded", () => {
  const schemas = doc.components.schemas;
  assert.equal(schemas.HostedCatalogView.properties.revisions.maxItems, 50);
  assert.equal(
    schemas.HostedCatalogView.properties.reconciliations.maxItems,
    50,
  );
  assert.equal(
    schemas.HostedCatalogMutationResult.properties.operationIds.maxItems,
    200,
  );
  assert.deepEqual(schemas.HostedCatalogCommand.properties.phase.enum, [
    "wait",
    "install",
    "verify",
    "complete",
  ]);
  const download =
    doc.paths["/v1/runner-catalog-assets/{sha256}/{filename}"].get;
  assert.equal(download.responses[404], undefined);
  assert.equal(download.parameters[0].schema.pattern, "^[a-f0-9]{64}$");
  assert.equal(
    download.parameters[1].schema.pattern,
    "^(?!.*\\.\\.)[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$",
  );
});
