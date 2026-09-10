import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createSDKClient,
  SDKError,
  parseConfiguration,
  normalizeConfiguration,
  hashConfiguration,
  verifyAttestationSignature,
  verifyAttestedArtifact,
} from "../dist/index.js";

const options = (transport, extra = {}) => ({
  origin: "https://platform.example.invalid",
  transport,
  timeoutMs: 1000,
  maxResponseBytes: 1024,
  ...extra,
});
const request = (client, extra = {}) =>
  client.GET("/v1/release-candidates/{candidateId}", {
    params: { path: { candidateId: "00000000-0000-4000-8000-000000000001" } },
    ...extra,
  });
const rejects = (promise, code) =>
  assert.rejects(promise, (error) => {
    assert.ok(error instanceof SDKError);
    assert.equal(error.code, code);
    assert.equal(error.message, `Provenance SDK: ${code}`);
    assert.equal(error.cause, undefined);
    assert.doesNotMatch(JSON.stringify(error), /SECRET/);
    return true;
  });

test("actual generated methods preserve path, explicit credentials and typed successful data", async () => {
  let calls = 0;
  const client = createSDKClient(
    options(async (req) => {
      calls++;
      assert.equal(
        req.url,
        "https://platform.example.invalid/v1/release-candidates/00000000-0000-4000-8000-000000000001",
      );
      assert.equal(req.redirect, "manual");
      assert.equal(req.credentials, "omit");
      assert.equal(req.headers.get("authorization"), "Bearer SECRET");
      return Response.json(
        { status: "passed" },
        { headers: { "set-cookie": "SECRET" } },
      );
    }),
  );
  const result = await request(client, {
    headers: { authorization: "Bearer SECRET" },
  });
  assert.deepEqual(result.data, { status: "passed" });
  assert.equal(result.response.headers.has("set-cookie"), false);
  assert.equal(calls, 1);
  assert.ok(Object.isFrozen(client));
  assert.equal(client.use, undefined);
});

for (const origin of [
  "http://platform.example.invalid",
  "https://user:SECRET@platform.example.invalid",
  "https://platform.example.invalid/path",
  "https://platform.example.invalid/?SECRET",
  "https://platform.example.invalid/#SECRET",
  "not a url",
]) {
  test(`reject untrusted origin form ${origin.replaceAll("SECRET", "redacted")}`, () => {
    assert.throws(() => createSDKClient(options(fetch, { origin })), {
      code: "invalid_options",
    });
  });
}
for (const field of ["timeoutMs", "maxResponseBytes"])
  for (const value of [0, -1, Infinity, 1.5, Number.MAX_SAFE_INTEGER]) {
    test(`reject ${field} bound ${value}`, () =>
      assert.throws(() => createSDKClient(options(fetch, { [field]: value })), {
        code: "invalid_options",
      }));
  }
test("per-call base URL cannot redirect bearer authority", async () => {
  let calls = 0;
  const client = createSDKClient(
    options(async () => {
      calls++;
      return Response.json({});
    }),
  );
  await rejects(
    request(client, {
      baseUrl: "https://attacker.example.invalid",
      headers: { authorization: "SECRET" },
    }),
    "destination_denied",
  );
  assert.equal(calls, 0);
});
for (const status of [301, 302, 307, 308, 400, 401, 403, 404, 429, 500]) {
  test(`closed HTTP ${status} without automatic retry or body disclosure`, async () => {
    let calls = 0;
    const client = createSDKClient(
      options(async () => {
        calls++;
        return new Response("SECRET PRIVATE BODY", {
          status,
          statusText: "SECRET",
          headers: {
            location: "https://SECRET.invalid",
            "x-private": "SECRET",
          },
        });
      }),
    );
    await rejects(
      request(client),
      status < 400 ? "redirect_denied" : "request_failed",
    );
    assert.equal(calls, 1);
  });
}
test("transport exception is closed", async () => {
  await rejects(
    request(
      createSDKClient(
        options(async () => {
          throw new Error("SECRET");
        }),
      ),
    ),
    "transport_failed",
  );
});

for (const key of [
  "fetch",
  "Request",
  "middleware",
  "bodySerializer",
  "querySerializer",
  "pathSerializer",
])
  test(`generated ${key} override cannot bypass the transport boundary`, async () => {
    let calls = 0;
    const attack = () => {
      calls++;
      throw new Error("SECRET");
    };
    await rejects(
      request(createSDKClient(options(attack)), {
        [key]: key === "middleware" ? [{ onRequest: attack }] : attack,
      }),
      "invalid_options",
    );
    assert.equal(calls, 0);
  });
test("caller-created SDK errors cannot carry private messages or fields", async () => {
  const error = new SDKError("SECRET", "SECRET");
  error.message = "SECRET";
  error.privateBody = "SECRET";
  await rejects(
    request(
      createSDKClient(
        options(async () => {
          throw error;
        }),
      ),
    ),
    "transport_failed",
  );
});
test("malformed successful JSON is closed", async () => {
  await rejects(
    request(
      createSDKClient(
        options(
          async () =>
            new Response("SECRET", {
              headers: { "content-type": "application/json" },
            }),
        ),
      ),
    ),
    "transport_failed",
  );
});
test("response overflow cancels stream", async () => {
  let cancelled = false;
  const body = new ReadableStream({
    pull(c) {
      c.enqueue(new Uint8Array(9));
    },
    cancel() {
      cancelled = true;
    },
  });
  await rejects(
    request(
      createSDKClient(
        options(async () => new Response(body), { maxResponseBytes: 8 }),
      ),
    ),
    "response_limit",
  );
  assert.equal(cancelled, true);
});
test("timeout bounds stalled caller transport and stalled response body", async () => {
  // Keep the test process alive while AbortSignal.timeout's unref timer runs.
  const keepAlive = setInterval(() => {}, 100);
  try {
    await rejects(
      request(
        createSDKClient(
          options(() => new Promise(() => {}), { timeoutMs: 10 }),
        ),
      ),
      "timeout",
    );
    await rejects(
      request(
        createSDKClient(
          options(
            async () =>
              new Response(
                new ReadableStream({
                  pull() {
                    return new Promise(() => {});
                  },
                }),
              ),
            { timeoutMs: 10 },
          ),
        ),
      ),
      "timeout",
    );
  } finally {
    clearInterval(keepAlive);
  }
});
test("caller cancellation stays distinct", async () => {
  const controller = new AbortController();
  controller.abort("SECRET");
  await rejects(
    request(createSDKClient(options(fetch)), { signal: controller.signal }),
    "cancelled",
  );
});
test("existing configuration package remains authoritative", async () => {
  const source = await readFile(
    new URL(
      "../../../schemas/fixtures/config/valid/hosted.yml",
      import.meta.url,
    ),
    "utf8",
  );
  const parsed = parseConfiguration(source);
  assert.equal(hashConfiguration(parsed).length, 64);
  assert.deepEqual(JSON.parse(normalizeConfiguration(parsed)), parsed);
  assert.throws(
    () => parseConfiguration(source + "\nunknownSecret: SECRET\n"),
    { code: "configuration_invalid" },
  );
});
for (const name of ["small-artifact.json", "small-artifact-v2.json"]) {
  test(`verifier authenticates ${name} before reading artifact bytes`, async () => {
    const fixture = JSON.parse(
      await readFile(
        new URL(
          `../../../schemas/fixtures/attestation/interop/${name}`,
          import.meta.url,
        ),
        "utf8",
      ),
    );
    const key = Buffer.from(fixture.publicKeyHex, "hex");
    assert.equal(verifyAttestationSignature(fixture.document, key), true);
    const identity = await verifyAttestedArtifact(fixture.document, key, [
      Buffer.from(fixture.artifactHex, "hex"),
    ]);
    assert.equal(
      identity.digest.value,
      fixture.document.statement.subject.digest.value,
    );
    let read = false;
    const altered = structuredClone(fixture.document);
    altered.statement.subject.version = "SECRET";
    await rejects(
      verifyAttestedArtifact(altered, key, {
        *[Symbol.iterator]() {
          read = true;
          throw new Error("SECRET");
        },
      }),
      "verification_failed",
    );
    assert.equal(read, false);
    await rejects(
      verifyAttestedArtifact(fixture.document, key, [Buffer.from("SECRET")]),
      "verification_failed",
    );
  });
}
