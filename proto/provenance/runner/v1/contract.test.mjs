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
  assert.match(gatewaySource, /while the\s*\/\/\s*runner is offline/);
  assert.match(
    gatewaySource,
    /atomically persist the new[\s\S]*before[\s\S]{0,20}acknowledgement/,
  );
  assert.match(gatewaySource, /exact duplicate[\s\S]*acknowledged again/);
  assert.match(gatewaySource, /conflicting duplicate terminates[\s\S]*stream/);
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
    /predecessor is revoked at[\s\S]*reconnect_before/,
  );
  assert.match(
    gatewaySource,
    /does not by itself[\s\S]*revoke the predecessor/,
  );
  assert.match(gatewaySource, /exactly 50 ASCII bytes/);
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
