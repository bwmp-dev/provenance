import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const contractDirectory = dirname(fileURLToPath(import.meta.url));
const snapshot = JSON.parse(
  readFileSync(join(contractDirectory, "contract.snapshot.json"), "utf8"),
);

function runBuf(arguments_) {
  const command = process.env.BUF ?? "buf";
  const result = spawnSync(command, arguments_, {
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
  return fields.filter((field) => field.number === number).map((field) => field.bytes);
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
  return text(decodeFields(buffer), 1);
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
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "provenance-runner-v1-"));
  const descriptorPath = join(temporaryDirectory, "runner-v1.binpb");

  try {
    runBuf(["format", "--diff", "--exit-code", "."]);
    runBuf(["lint", "."]);
    runBuf([
      "build",
      ".",
      "--exclude-source-info",
      "-o",
      descriptorPath,
    ]);

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
    assert.deepEqual([...contract.enums].sort(), [...snapshot.enumNames].sort());

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
      assert.deepEqual(numberedFields(messages.get(messageName)), expectedFields);
    }

    for (const [messageName, expectedRanges] of Object.entries(
      snapshot.reservedRanges,
    )) {
      assert.deepEqual(messages.get(messageName).reservedRanges, expectedRanges);
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

test("optional Buf breaking target remains compatible", { skip: !process.env.BUF_BREAKING_AGAINST }, () => {
  runBuf(["breaking", ".", "--against", process.env.BUF_BREAKING_AGAINST]);
});
