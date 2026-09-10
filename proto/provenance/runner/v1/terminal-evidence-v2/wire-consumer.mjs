// Isolated generated TypeScript wire consumer, runnable from a released bundle.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { sha256, validateWrapper } from "./reference.mjs";

const directory = process.argv[2];
const require = createRequire(resolve(directory, "package.json"));
const { create, toBinary, fromBinary } = require("@bufbuild/protobuf");
const p = await import(pathToFileURL(resolve(directory, "dist/index.js")));
const vector = JSON.parse(
  readFileSync(new URL("vectors.json", import.meta.url)),
);
const f = JSON.parse(readFileSync(new URL("fixtures.json", import.meta.url)));
assert.equal(p.ProtocolFeature.TERMINAL_EVIDENCE_V2, 7);
for (const [kind, schema] of [
  ["completed", p.JobCompletedSchema],
  ["failed", p.JobFailedSchema],
]) {
  assert.equal(
    schema.fields.find((field) => field.name === "execution_evidence").number,
    10,
  );
  const proof = create(p.ExecutionEvidenceSchema, {
    canonicalJson: Buffer.from(vector.canonical),
    digest: {
      algorithm: p.DigestAlgorithm.SHA256,
      value: Buffer.from(vector.sha256, "hex"),
    },
  });
  const message = create(p.RunnerMessageSchema, {
    messageId: "fixture-terminal",
    payload: {
      case: kind,
      value: create(schema, {
        lease: {
          leaseId: f.binding.leaseId,
          jobId: f.binding.jobId,
          executionId: f.binding.executionId,
        },
        attempt: {
          attemptId: f.binding.attemptId,
          attemptNumber: f.binding.attemptNumber,
          releaseCandidateId: f.binding.candidateId,
          matrixEntryId: f.binding.matrixEntryId,
        },
        executionEvidence: proof,
      }),
    },
  });
  const wire = toBinary(p.RunnerMessageSchema, message);
  const decoded = fromBinary(p.RunnerMessageSchema, wire);
  const evidence = decoded.payload.value.executionEvidence;
  assert.equal(evidence.digest.algorithm, p.DigestAlgorithm.SHA256);
  assert.equal(
    Buffer.from(evidence.digest.value).toString("hex"),
    sha256(evidence.canonicalJson),
  );
  assert.equal(
    Buffer.from(evidence.canonicalJson).toString(),
    vector.canonical,
  );
  const expected = {
    featureV2Enabled: true,
    wholeMessageBytes: wire.length,
    binding: f.binding,
    requested: f.requested,
    assertions: f.observations.map(([id, type, , selector]) => ({
      id,
      type,
      selector,
      supported: true,
    })),
  };
  validateWrapper(evidence, expected);
  const bad = fromBinary(p.RunnerMessageSchema, wire).payload.value
    .executionEvidence;
  bad.digest.algorithm = p.DigestAlgorithm.SHA512;
  assert.throws(() => validateWrapper(bad, expected));
  bad.digest.algorithm = p.DigestAlgorithm.SHA256;
  bad.digest.value = new Uint8Array(31);
  assert.throws(() => validateWrapper(bad, expected));
  bad.digest.value = new Uint8Array(32);
  assert.throws(() => validateWrapper(bad, expected));
  assert.throws(() =>
    validateWrapper(evidence, { ...expected, wholeMessageBytes: 65537 }),
  );
  assert.throws(() =>
    validateWrapper(evidence, { ...expected, featureV2Enabled: false }),
  );
  assert.deepEqual(toBinary(p.RunnerMessageSchema, decoded), wire);
  const legacy = create(schema, {});
  assert.equal(
    fromBinary(schema, toBinary(schema, legacy)).executionEvidence,
    undefined,
  );
}
