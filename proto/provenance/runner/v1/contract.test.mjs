import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const contractDirectory = dirname(fileURLToPath(import.meta.url));
const gatewaySource = readFileSync(
  join(contractDirectory, "runner_gateway.proto"),
  "utf8",
);
const commonSource = readFileSync(
  join(contractDirectory, "common.proto"),
  "utf8",
);
const snapshot = JSON.parse(
  readFileSync(join(contractDirectory, "contract.snapshot.json"), "utf8"),
);

const canonicalUuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const canonicalTraceparentPattern =
  /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;
const zeroUuid = "00000000-0000-0000-0000-000000000000";
const protocolFeature = Object.freeze({
  durableLeaseAcknowledgements: 1,
  credentialRotation: 2,
  jobCorrelationV1: 3,
  restartUploadRecovery: 4,
});

function validProtocolFeatures(features) {
  const known = new Set(Object.values(protocolFeature));
  return (
    Array.isArray(features) &&
    features.every(
      (feature, index) =>
        known.has(feature) && features.indexOf(feature) === index,
    )
  );
}

function validCorrelationUuid(value) {
  return (
    typeof value === "string" &&
    value !== zeroUuid &&
    canonicalUuidPattern.test(value)
  );
}

function validJobCorrelation(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !==
      "organizationId,projectId,traceparent,workflowId"
  ) {
    return false;
  }
  const traceparent = canonicalTraceparentPattern.exec(value.traceparent);
  return (
    traceparent !== null &&
    traceparent[1] !== "0".repeat(32) &&
    traceparent[2] !== "0".repeat(16) &&
    validCorrelationUuid(value.organizationId) &&
    validCorrelationUuid(value.projectId) &&
    value.workflowId === `release/${value.workflowId?.slice(8)}` &&
    value.workflowId.length === 44 &&
    validCorrelationUuid(value.workflowId.slice(8))
  );
}

function validJobCorrelationNegotiation(features, correlation) {
  if (!validProtocolFeatures(features)) {
    return false;
  }
  const advertised = features.includes(protocolFeature.jobCorrelationV1);
  return advertised ? validJobCorrelation(correlation) : correlation == null;
}

function exactIdentity(actual, expected, fields) {
  return (
    actual !== null &&
    typeof actual === "object" &&
    expected !== null &&
    typeof expected === "object" &&
    Object.keys(actual).sort().join(",") === [...fields].sort().join(",") &&
    Object.keys(expected).sort().join(",") === [...fields].sort().join(",") &&
    fields.every((field) => actual[field] === expected[field])
  );
}

function futureTimestamp(value, now) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && parsed > now.getTime();
}

function validObjectKey(value) {
  if (
    typeof value !== "string" ||
    Buffer.byteLength(value, "utf8") < 1 ||
    Buffer.byteLength(value, "utf8") > 1024 ||
    value.startsWith("/") ||
    value.includes("\\") ||
    [...value].some((character) => {
      const codePoint = character.codePointAt(0);
      return codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
    })
  ) {
    return false;
  }

  return value
    .split("/")
    .every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

function validRestartUploadRecovery(features, reconciliation, localJob, now) {
  if (!validProtocolFeatures(features)) {
    return false;
  }
  const upload = reconciliation?.completeLogUpload;
  if (upload == null) {
    return true;
  }
  return (
    features.includes(protocolFeature.restartUploadRecovery) &&
    reconciliation.status === 3 &&
    exactIdentity(reconciliation.lease, localJob?.lease, [
      "leaseId",
      "jobId",
      "executionId",
      "expiresAt",
    ]) &&
    exactIdentity(reconciliation.attempt, localJob?.attempt, [
      "attemptId",
      "attemptNumber",
      "releaseCandidateId",
      "matrixEntryId",
    ]) &&
    futureTimestamp(reconciliation.lease.expiresAt, now) &&
    upload.contentType === "application/gzip" &&
    futureTimestamp(upload.expiresAt, now) &&
    validObjectKey(upload.objectKey)
  );
}

function runBuf(arguments_) {
  const configuredCommand = process.env.BUF;
  const command = configuredCommand ?? process.execPath;
  const commandArguments = configuredCommand
    ? arguments_
    : [
        resolve(
          contractDirectory,
          "../../../../node_modules/@bufbuild/buf/bin/buf",
        ),
        ...arguments_,
      ];
  const result = spawnSync(command, commandArguments, {
    cwd: contractDirectory,
    encoding: "utf8",
    shell: false,
  });

  assert.equal(
    result.error,
    undefined,
    `could not run Buf at ${JSON.stringify(command)}: ${result.error?.message}`,
  );
  assert.equal(
    result.status,
    0,
    [result.stdout, result.stderr].filter(Boolean).join("\n"),
  );
}

function readVarint(buffer, cursor) {
  let value = 0;
  let shift = 0;

  while (cursor.offset < buffer.length) {
    const byte = buffer[cursor.offset++];
    value += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) {
      return value;
    }
    shift += 7;
    assert.ok(shift <= 63, "invalid descriptor varint");
  }

  assert.fail("truncated descriptor varint");
}

function decodeFields(buffer) {
  const fields = [];
  const cursor = { offset: 0 };

  while (cursor.offset < buffer.length) {
    const tag = readVarint(buffer, cursor);
    const number = Math.floor(tag / 8);
    const wireType = tag % 8;

    if (wireType === 0) {
      fields.push({ number, value: readVarint(buffer, cursor), wireType });
      continue;
    }

    if (wireType === 1) {
      cursor.offset += 8;
      continue;
    }

    if (wireType === 2) {
      const length = readVarint(buffer, cursor);
      const end = cursor.offset + length;
      assert.ok(end <= buffer.length, "truncated descriptor field");
      fields.push({
        bytes: buffer.subarray(cursor.offset, end),
        number,
        wireType,
      });
      cursor.offset = end;
      continue;
    }

    if (wireType === 5) {
      cursor.offset += 4;
      continue;
    }

    assert.fail(`unsupported descriptor wire type ${wireType}`);
  }

  return fields;
}

function bytes(fields, number) {
  return fields
    .filter((field) => field.number === number)
    .map((field) => field.bytes);
}

function text(fields, number) {
  const [value] = bytes(fields, number);
  return value?.toString("utf8");
}

function scalar(fields, number, fallback = 0) {
  return fields.find((field) => field.number === number)?.value ?? fallback;
}

function parseField(buffer) {
  const fields = decodeFields(buffer);
  return {
    name: text(fields, 1),
    number: scalar(fields, 3),
    oneofIndex: fields.some((field) => field.number === 9)
      ? scalar(fields, 9)
      : undefined,
  };
}

function parseMessage(buffer) {
  const fields = decodeFields(buffer);
  return {
    fields: bytes(fields, 2).map(parseField),
    name: text(fields, 1),
    reservedNames: bytes(fields, 10).map((value) => value.toString("utf8")),
    reservedRanges: bytes(fields, 9).map((rangeBuffer) => {
      const range = decodeFields(rangeBuffer);
      return [scalar(range, 1), scalar(range, 2)];
    }),
  };
}

function parseEnum(buffer) {
  const fields = decodeFields(buffer);
  return {
    name: text(fields, 1),
    values: Object.fromEntries(
      bytes(fields, 2).map((valueBuffer) => {
        const value = decodeFields(valueBuffer);
        return [String(scalar(value, 2)), text(value, 1)];
      }),
    ),
  };
}

function parseMethod(buffer) {
  const fields = decodeFields(buffer);
  return {
    clientStreaming: scalar(fields, 5) === 1,
    input: text(fields, 2).split(".").at(-1),
    name: text(fields, 1),
    output: text(fields, 3).split(".").at(-1),
    serverStreaming: scalar(fields, 6) === 1,
  };
}

function parseService(buffer) {
  const fields = decodeFields(buffer);
  return {
    methods: bytes(fields, 2).map(parseMethod),
    name: text(fields, 1),
  };
}

function parseContract(buffer) {
  const descriptorSet = decodeFields(buffer);
  const files = bytes(descriptorSet, 1)
    .map((fileBuffer) => {
      const fields = decodeFields(fileBuffer);
      return {
        enums: bytes(fields, 5).map(parseEnum),
        messages: bytes(fields, 4).map(parseMessage),
        package: text(fields, 2),
        services: bytes(fields, 6).map(parseService),
      };
    })
    .filter((file) => file.package === "provenance.runner.v1");

  return {
    enums: files.flatMap((file) => file.enums),
    messages: files.flatMap((file) => file.messages),
    services: files.flatMap((file) => file.services),
  };
}

function numberedFields(message) {
  return Object.fromEntries(
    message.fields.map((field) => [String(field.number), field.name]),
  );
}

test("runner v1 descriptor matches the compatibility snapshot", () => {
  const temporaryDirectory = mkdtempSync(
    join(tmpdir(), "provenance-runner-v1-"),
  );
  const descriptorPath = join(temporaryDirectory, "runner-v1.binpb");

  try {
    runBuf(["format", "--diff", "--exit-code", "."]);
    runBuf(["lint", "."]);
    runBuf(["build", ".", "--exclude-source-info", "-o", descriptorPath]);

    const descriptor = readFileSync(descriptorPath);
    assert.equal(
      createHash("sha256").update(descriptor).digest("hex"),
      snapshot.descriptorSha256,
      "wire descriptor changed; use `buf breaking` and review field reservations before accepting a new snapshot",
    );

    const contract = parseContract(descriptor);
    const service = contract.services.find(
      (candidate) => candidate.name === snapshot.service.name,
    );
    assert.ok(service, "RunnerGateway service is missing");
    assert.deepEqual(service.methods, [
      {
        clientStreaming: snapshot.service.clientStreaming,
        input: snapshot.service.input,
        name: snapshot.service.method,
        output: snapshot.service.output,
        serverStreaming: snapshot.service.serverStreaming,
      },
    ]);

    const messages = new Map(
      contract.messages.map((message) => [message.name, message]),
    );
    assert.deepEqual(
      [...messages.keys()].sort(),
      [...snapshot.messageNames].sort(),
    );
    const enums = new Map(
      contract.enums.map((enumeration) => [enumeration.name, enumeration]),
    );
    assert.deepEqual([...enums.keys()].sort(), [...snapshot.enumNames].sort());

    for (const [enumName, expectedValues] of Object.entries(
      snapshot.criticalEnums,
    )) {
      assert.deepEqual(enums.get(enumName).values, expectedValues);
    }

    const runnerMessage = messages.get("RunnerMessage");
    const gatewayMessage = messages.get("GatewayMessage");
    assert.deepEqual(
      Object.fromEntries(
        runnerMessage.fields
          .filter((field) => field.oneofIndex === 0)
          .map((field) => [String(field.number), field.name]),
      ),
      snapshot.runnerPayload,
    );
    assert.deepEqual(
      Object.fromEntries(
        gatewayMessage.fields
          .filter((field) => field.oneofIndex === 0)
          .map((field) => [String(field.number), field.name]),
      ),
      snapshot.gatewayPayload,
    );

    for (const [messageName, expectedFields] of Object.entries(
      snapshot.criticalFields,
    )) {
      assert.deepEqual(
        numberedFields(messages.get(messageName)),
        expectedFields,
      );
    }

    for (const [messageName, expectedRanges] of Object.entries(
      snapshot.reservedRanges,
    )) {
      assert.deepEqual(
        messages.get(messageName).reservedRanges,
        expectedRanges,
      );
    }

    for (const [messageName, expectedNames] of Object.entries(
      snapshot.reservedNames,
    )) {
      assert.deepEqual(messages.get(messageName).reservedNames, expectedNames);
    }
  } finally {
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
});

test("durable acknowledgement semantics remain normative", () => {
  for (const event of [
    "LeaseAccepted",
    "LeaseRejected",
    "LeaseRenewal",
    "JobPreparing",
    "JobStarted",
    "JobCompleted",
    "JobFailed",
    "JobCancelled",
  ]) {
    assert.match(
      gatewaySource,
      new RegExp(
        `MUST acknowledge[\\s\\S]{0,200}\\b${event}\\b|\\b${event}\\b[\\s\\S]{0,200}RunnerEventAcknowledgement`,
      ),
    );
  }
  assert.match(
    gatewaySource,
    /Authenticate, Capabilities, LogBatch, and(?:\s*\/\/)?\s*UsageReport do not(?:\s*\/\/)?\s*receive durability acknowledgements/,
  );
  assert.match(
    gatewaySource,
    /Every heartbeat receives a HeartbeatAcknowledgement after commit/,
  );
  assert.match(
    gatewaySource,
    /exactly one matching item per active_leases item and no extras/,
  );
  assert.match(gatewaySource, /not implicitly released/);
  assert.match(
    gatewaySource,
    /exact\s*\/\/ duplicate message ID and payload re-acks the same ID and sequence with ALREADY_APPLIED/,
  );
  assert.match(
    gatewaySource,
    /zero-lease acknowledgement confirms the prior commit/,
  );
  assert.match(
    gatewaySource,
    /sequence with another ID, is a transport conflict/,
  );
});

test("restart recovery upload is feature-gated, identity-bound, and ephemeral", () => {
  const reconciliationBlock = gatewaySource.slice(
    gatewaySource.indexOf("message LeaseReconciliation"),
    gatewaySource.indexOf("message RunnerEventAcknowledgement"),
  );
  const reconciliationNormative = reconciliationBlock
    .replaceAll("//", "")
    .replaceAll(/\s+/g, " ");

  assert.match(
    commonSource,
    /PROTOCOL_FEATURE_RESTART_UPLOAD_RECOVERY\s*=\s*4\s*;/,
  );
  assert.equal(
    snapshot.criticalEnums.ProtocolFeature["4"],
    "PROTOCOL_FEATURE_RESTART_UPLOAD_RECOVERY",
  );
  assert.equal(
    snapshot.criticalFields.LeaseReconciliation["16"],
    "complete_log_upload",
  );
  assert.equal(snapshot.criticalFields.ObjectUpload["10"], "object_key");
  assert.deepEqual(snapshot.reservedRanges.ObjectUpload, [[4, 10]]);
  const objectUploadBlock = commonSource.slice(
    commonSource.indexOf("message ObjectUpload"),
    commonSource.indexOf("message DependencyInput"),
  );
  const objectUploadNormative = objectUploadBlock
    .replaceAll("//", "")
    .replaceAll(/\s+/g, " ");
  assert.match(objectUploadBlock, /string object_key\s*=\s*10\s*;/);
  assert.match(objectUploadBlock, /reserved 4 to 9;/);
  assert.match(
    objectUploadNormative,
    /uri is an opaque, short-lived upload capability[\s\S]*MUST NOT derive durable object identity from any URI component/,
  );
  assert.match(
    objectUploadNormative,
    /object_key is the durable bucket-relative object identity[\s\S]*between 1 and 1024 bytes/,
  );
  assert.match(reconciliationBlock, /reserved 8 to 15;/);
  assert.match(
    reconciliationBlock,
    /ObjectUpload complete_log_upload\s*=\s*16\s*;/,
  );
  assert.match(
    reconciliationNormative,
    /MUST attach complete_log_upload only to a HeartbeatAcknowledgement[\s\S]*after reconnect/,
  );
  assert.match(
    reconciliationNormative,
    /only when[\s\S]*current[\s\S]*authenticated stream advertised PROTOCOL_FEATURE_RESTART_UPLOAD_RECOVERY/,
  );
  assert.match(
    reconciliationNormative,
    /MUST omit it from RunnerEventAcknowledgement[\s\S]*did not advertise/,
  );
  assert.match(
    reconciliationNormative,
    /does not create, replay,[\s\S]*or extend a LeaseOffer/,
  );
  assert.match(
    reconciliationNormative,
    /compare every LeaseIdentity and AttemptIdentity field against JobSpecification\.lease and[\s\S]*JobSpecification\.attempt/,
  );
  assert.match(
    reconciliationNormative,
    /LEASE_STATUS_ACTIVE and future lease and upload expiries/,
  );
  assert.match(
    reconciliationNormative,
    /receiving this field[\s\S]*did not advertise[\s\S]*MUST reject the acknowledgement/,
  );
  assert.match(
    reconciliationNormative,
    /reject a[\s\S]*stale, substituted, expired, terminal, cancelled,[\s\S]*mismatched capability/,
  );
  assert.match(
    reconciliationNormative,
    /Fields 1 through 7 are the committed reconciliation state; complete_log_upload is explicitly[\s\S]*excluded from that state, its payload hash, and replay reproducibility/,
  );
  assert.match(
    reconciliationNormative,
    /exact duplicate heartbeat replays the[\s\S]*same committed fields and committed_at but MAY mint a different URI and expiry/,
  );
  assert.match(
    reconciliationNormative,
    /neither peer may persist it in durable lease, attempt, event, log,[\s\S]*or audit state/,
  );
  assert.match(reconciliationNormative, /redact it from diagnostics/);
  assert.match(
    reconciliationNormative,
    /Absence remains valid for older[\s\S]*peers/,
  );

  const now = new Date("2030-01-02T03:04:05.000Z");
  const localJob = {
    lease: {
      leaseId: "lease-recovery",
      jobId: "job-recovery",
      executionId: "execution-recovery",
      expiresAt: "2030-01-02T04:00:00.000Z",
    },
    attempt: {
      attemptId: "attempt-recovery",
      attemptNumber: 2,
      releaseCandidateId: "candidate-recovery",
      matrixEntryId: "matrix-recovery",
    },
  };
  const reconciliation = {
    lease: structuredClone(localJob.lease),
    attempt: structuredClone(localJob.attempt),
    status: 3,
    completeLogUpload: {
      uri: "https://object.invalid/ephemeral-recovery-capability",
      contentType: "application/gzip",
      expiresAt: "2030-01-02T03:30:00.000Z",
      objectKey: "complete-logs/candidate-recovery/attempt-recovery.log.gz",
    },
  };
  const negotiated = [
    protocolFeature.durableLeaseAcknowledgements,
    protocolFeature.restartUploadRecovery,
  ];

  assert.equal(
    validRestartUploadRecovery(negotiated, reconciliation, localJob, now),
    true,
  );
  assert.equal(validObjectKey("x".repeat(1024)), true, "1024-byte key");
  assert.equal(
    validObjectKey("é".repeat(513)),
    false,
    "the key bound is measured in UTF-8 bytes",
  );
  assert.equal(
    validRestartUploadRecovery(
      negotiated,
      {
        ...reconciliation,
        completeLogUpload: {
          ...reconciliation.completeLogUpload,
          uri: "https://another.invalid/a-path-unrelated-to-the-object-key?signature=opaque",
        },
      },
      localJob,
      now,
    ),
    true,
    "object identity is explicit and must not be derived from the opaque URI",
  );
  assert.equal(
    validRestartUploadRecovery(
      [protocolFeature.durableLeaseAcknowledgements],
      reconciliation,
      localJob,
      now,
    ),
    false,
    "runner must reject an upload it did not advertise support for",
  );
  assert.equal(
    validRestartUploadRecovery(
      [
        protocolFeature.durableLeaseAcknowledgements,
        protocolFeature.restartUploadRecovery,
        protocolFeature.restartUploadRecovery,
      ],
      reconciliation,
      localJob,
      now,
    ),
    false,
    "duplicate feature",
  );
  assert.equal(
    validRestartUploadRecovery([1, 99], reconciliation, localJob, now),
    false,
    "unknown feature",
  );
  assert.equal(
    validRestartUploadRecovery(
      [protocolFeature.durableLeaseAcknowledgements],
      { ...reconciliation, completeLogUpload: undefined },
      localJob,
      now,
    ),
    true,
    "absence remains valid for a non-negotiating peer",
  );

  for (const [path, value] of [
    [["lease", "leaseId"], "substituted-lease"],
    [["lease", "jobId"], "substituted-job"],
    [["lease", "executionId"], "substituted-execution"],
    [["lease", "expiresAt"], "2030-01-02T05:00:00.000Z"],
    [["attempt", "attemptId"], "substituted-attempt"],
    [["attempt", "attemptNumber"], 3],
    [["attempt", "releaseCandidateId"], "substituted-candidate"],
    [["attempt", "matrixEntryId"], "substituted-matrix"],
  ]) {
    const substituted = structuredClone(reconciliation);
    substituted[path[0]][path[1]] = value;
    assert.equal(
      validRestartUploadRecovery(negotiated, substituted, localJob, now),
      false,
      `substituted ${path.join(".")}`,
    );
  }

  for (const invalid of [
    { ...reconciliation, status: 2 },
    {
      ...reconciliation,
      lease: { ...reconciliation.lease, expiresAt: now.toISOString() },
    },
    {
      ...reconciliation,
      completeLogUpload: {
        ...reconciliation.completeLogUpload,
        expiresAt: now.toISOString(),
      },
    },
    ...[
      "",
      "/complete-logs/attempt.log.gz",
      "complete-logs//attempt.log.gz",
      "complete-logs/./attempt.log.gz",
      "complete-logs/../attempt.log.gz",
      "complete-logs\\attempt.log.gz",
      "complete-logs/control\u0000.log.gz",
      "x".repeat(1025),
    ].map((objectKey) => ({
      ...reconciliation,
      completeLogUpload: {
        ...reconciliation.completeLogUpload,
        objectKey,
      },
    })),
  ]) {
    assert.equal(
      validRestartUploadRecovery(negotiated, invalid, localJob, now),
      false,
    );
  }
});

test("IFC-012 job correlation is bounded, negotiated, and replay-stable", () => {
  assert.match(commonSource, /v0\.1\.0-alpha\.7/);
  assert.match(commonSource, /PROTOCOL_FEATURE_JOB_CORRELATION_V1\s*=\s*3\s*;/);
  assert.match(commonSource, /JobCorrelation job_correlation\s*=\s*21\s*;/);
  assert.match(commonSource, /reserved 11 to 19;/);
  assert.match(
    commonSource,
    /MUST attach job_correlation only after[\s\S]*advertises[\s\S]*JOB_CORRELATION_V1/,
  );
  assert.match(
    commonSource,
    /advertising JOB_CORRELATION_V1 MUST require and validate[\s\S]*every offered job/,
  );
  assert.match(
    commonSource,
    /carrier without having advertised the feature MUST reject the offer/,
  );
  assert.match(
    commonSource,
    /Absence is valid only for[\s\S]*legacy, non-negotiated operation/,
  );
  assert.match(commonSource, /exactly 55 lowercase ASCII bytes/);
  assert.match(commonSource, /trace[\s\S]{0,20}and parent ids MUST be nonzero/);
  assert.match(
    commonSource,
    /organization_scope remains the sole job authorization scope/,
  );
  assert.match(
    commonSource,
    /AttemptIdentity\.matrix_entry_id is the alpha test-instance correlation/,
  );
  assert.match(
    commonSource,
    /suffix[\s\S]{0,20}MUST equal AttemptIdentity\.release_candidate_id/,
  );
  assert.match(
    commonSource,
    /sources organization_id and[\s\S]*project_id from the immutable candidate/,
  );
  assert.match(
    commonSource,
    /exact replay MUST preserve every[\s\S]*field byte-for-byte/,
  );

  const correlationBlock = commonSource.slice(
    commonSource.indexOf("message JobCorrelation"),
    commonSource.indexOf("message JobSpecification"),
  );
  assert.doesNotMatch(
    correlationBlock,
    /\b(map|metadata|baggage|tracestate|secret|plugin_output|authorization_scope)\s*</,
  );
  assert.doesNotMatch(correlationBlock, /test_id/);

  const valid = {
    traceparent: "00-0000000000000000000000000000aa11-000000000000bb22-01",
    organizationId: "a0000000-0000-0000-0000-000000000011",
    projectId: "b0000000-0000-0000-0000-000000000022",
    workflowId: "release/c0000000-0000-0000-0000-000000000033",
  };
  assert.equal(validJobCorrelationNegotiation([1, 3], valid), true);
  assert.equal(validJobCorrelationNegotiation([1], null), true);

  const invalidCorrelations = [
    null,
    {},
    { ...valid, traceparent: valid.traceparent.toUpperCase() },
    {
      ...valid,
      traceparent: "01-0000000000000000000000000000aa11-000000000000bb22-01",
    },
    {
      ...valid,
      traceparent: "00-00000000000000000000000000000000-000000000000bb22-01",
    },
    {
      ...valid,
      traceparent: "00-0000000000000000000000000000aa11-0000000000000000-01",
    },
    { ...valid, traceparent: `${valid.traceparent}0` },
    { ...valid, organizationId: zeroUuid },
    { ...valid, organizationId: valid.organizationId.toUpperCase() },
    { ...valid, organizationId: "not-a-uuid" },
    { ...valid, projectId: zeroUuid },
    { ...valid, projectId: `${valid.projectId}0` },
    { ...valid, workflowId: `other/${valid.workflowId.slice(8)}` },
    { ...valid, workflowId: `release/${zeroUuid}` },
    { ...valid, baggage: "private=value" },
    { ...valid, tracestate: "private=value" },
    { ...valid, metadata: { token: "private" } },
  ];
  for (const correlation of invalidCorrelations) {
    assert.equal(
      validJobCorrelationNegotiation([1, 3], correlation),
      false,
      JSON.stringify(correlation),
    );
  }

  assert.equal(
    validJobCorrelationNegotiation([1], valid),
    false,
    "carrier without feature",
  );
  assert.equal(
    validJobCorrelationNegotiation([1, 3], null),
    false,
    "feature without carrier",
  );
  assert.equal(
    validJobCorrelationNegotiation([1, 3, 3], valid),
    false,
    "duplicate feature",
  );
  assert.equal(
    validJobCorrelationNegotiation([1, 99], null),
    false,
    "unknown feature",
  );

  const replay = structuredClone(valid);
  assert.deepEqual(replay, valid);
  replay.traceparent = replay.traceparent.replace(/bb22-01$/, "bb23-01");
  assert.notDeepEqual(replay, valid);
});

test("credential rotation remains protocol-v1, feature-gated, and replay-safe", () => {
  assert.match(
    commonSource,
    /PROTOCOL_FEATURE_CREDENTIAL_ROTATION\s*=\s*2\s*;/,
  );
  assert.match(gatewaySource, /keeps protocol_version equal to literal "1"/);
  assert.match(
    gatewaySource,
    /MUST send RotateCredential only after the runner advertises CREDENTIAL_ROTATION/,
  );
  assert.match(
    gatewaySource,
    /non-advertising or mixed-version runner never receives rotation/,
  );
  assert.match(
    gatewaySource,
    /durably queue one rotation while the runner is offline/,
  );
  assert.match(
    gatewaySource,
    /MUST NOT attempt[\s\S]*current stream advertises CREDENTIAL_ROTATION/,
  );
  assert.match(
    gatewaySource,
    /Immediately before writing any[\s\S]*durably records delivery_attempted/,
  );
  assert.match(
    gatewaySource,
    /no delivery attempt[\s\S]*abandons the rotation[\s\S]*leaves the predecessor[\s\S]*unchanged/,
  );
  assert.match(gatewaySource, /mixed-version outcome/);
  assert.match(
    gatewaySource,
    /Disabling rollout stops new rotations[\s\S]*attempt[\s\S]*abandonment rules/,
  );
  assert.match(
    gatewaySource,
    /After delivery_attempted, receipt is potentially ambiguous/,
  );
  assert.match(
    gatewaySource,
    /atomically persist the[\s\S]{0,20}new[\s\S]*before[\s\S]{0,20}acknowledgement/,
  );
  assert.match(
    gatewaySource,
    /exact[\s\S]{0,20}duplicate[\s\S]{0,30}acknowledged again/,
  );
  assert.match(
    gatewaySource,
    /conflicting[\s\S]{0,20}duplicate[\s\S]{0,30}terminates the stream/,
  );
  assert.match(
    gatewaySource,
    /crash before persistence yields no acknowledgement/i,
  );
  assert.match(
    gatewaySource,
    /crash after persistence but before[\s\S]{0,20}acknowledgement/i,
  );
  assert.match(
    gatewaySource,
    /does not terminate the active predecessor-authenticated stream/,
  );
  assert.match(gatewaySource, /reconnects[\s\S]*before reconnect_before/);
  assert.match(gatewaySource, /revokes[\s\S]*predecessor immediately/);
  assert.match(
    gatewaySource,
    /revokes the predecessor at[\s\S]*reconnect_before/,
  );
  assert.match(
    gatewaySource,
    /unattempted[\s\S]{0,20}abandoned rotation never revokes it/,
  );
  assert.match(
    gatewaySource,
    /Explicit administrative revocation overrides every[\s\S]*rotation/,
  );
  assert.match(
    gatewaySource,
    /does not by itself[\s\S]*revoke the predecessor/,
  );
  assert.match(gatewaySource, /exactly 50 canonical ASCII bytes/);
  assert.match(
    gatewaySource,
    /\^prc_v1_\[A-Za-z0-9_-\]\{42\}\[AEIMQUYcgkosw048\]\$/,
  );
  assert.match(gatewaySource, /re-encode byte-for-byte/);
  assert.match(gatewaySource, /fingerprint is exactly 32 SHA-256 bytes/);

  const rotationBlock = gatewaySource.slice(
    gatewaySource.indexOf("message RotateCredential"),
    gatewaySource.indexOf("message ShutdownRunner"),
  );
  assert.doesNotMatch(rotationBlock, /private_key|storage_credential/);
});

test(
  "optional Buf breaking target remains compatible",
  { skip: !process.env.BUF_BREAKING_AGAINST },
  () => {
    runBuf(["breaking", ".", "--against", process.env.BUF_BREAKING_AGAINST]);
  },
);
