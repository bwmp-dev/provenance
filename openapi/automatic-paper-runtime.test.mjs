import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "yaml";
import { createHash, createPublicKey, verify } from "node:crypto";
const doc = parse(
  readFileSync(new URL("./provenance.v1.yaml", import.meta.url), "utf8"),
);

test("public runtime vector binds exact bytes across producer and runner", () => {
  const v = JSON.parse(
    readFileSync(
      new URL("../schemas/paper-runtime/v1/vector.json", import.meta.url),
      "utf8",
    ),
  );
  const raw = Buffer.from(v.manifest.payload, "base64");
  const p = JSON.parse(raw);
  const c = p.catalog;
  const id = createHash("sha256")
    .update(
      "provenance.paper-runtime/v1\n" +
        [
          c.paper.gameVersion,
          String(c.paper.build),
          c.paper.artifact.sha256,
          c.java.distribution,
          c.java.version,
          c.java.os,
          c.java.architecture,
        ].join("\0"),
    )
    .digest("hex");
  assert.equal(id, v.runtimeId);
  assert.equal(p.runtimeId, id);
  const key = createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(v.publicKey, "hex"),
    ]),
    format: "der",
    type: "spki",
  });
  assert.ok(
    verify(
      null,
      Buffer.concat([Buffer.from("provenance.paper-runtime/v1\n"), raw]),
      key,
      Buffer.from(v.manifest.signature, "base64"),
    ),
  );
  for (const artifact of [
    c.paper.artifact,
    c.java.artifact,
    c.probe,
    c.preparedRuntime.artifact,
  ])
    assert.equal(
      artifact.uri,
      `${v.origin}/v1/paper-runtime-assets/${artifact.sha256}/${artifact.filename}`,
    );
});
test("automatic Paper discovery and delivery are read-only public operations", () => {
  for (const path of [
    "/v1/paper-runtimes/{runtimeId}",
    "/v1/paper-runtime-assets/{sha256}/{filename}",
    "/v1/paper-versions",
    "/v1/paper-versions/{version}/builds",
  ]) {
    assert.deepEqual(Object.keys(doc.paths[path]), ["get"]);
    assert.deepEqual(doc.paths[path].get.security, []);
  }
});
test("automatic runtime signature and artifact authority are bounded and explicit", () => {
  const s = doc.components.schemas;
  assert.equal(s.AutomaticPaperRuntimeManifest.additionalProperties, false);
  assert.deepEqual(s.AutomaticPaperRuntimeManifest.required, [
    "payload",
    "signature",
  ]);
  assert.equal(
    s.AutomaticPaperRuntimeManifest.properties.payload.maxLength,
    87384,
  );
  assert.match(
    s.AutomaticPaperRuntimeManifest.properties.signature.description,
    /separate from the runner release key/,
  );
  assert.match(
    s.AutomaticPaperRuntimePayload.description,
    /Verify signature, request identity and artifact authority/,
  );
  assert.equal(s.AutomaticPaperBuilds.properties.builds.maxItems, 2048);
  assert.ok(
    s.AutomaticPaperVersions.properties.versions.items.required.includes(
      "harnessSupported",
    ),
  );
});
