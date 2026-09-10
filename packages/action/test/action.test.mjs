import assert from "node:assert/strict";
import test from "node:test";
import { createServer, request as httpsRequest } from "node:https";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { compile, notices } from "../scripts/build.mjs";
import { reportingState } from "../src/client.mjs";

const require = createRequire(import.meta.url);
const { execute } = require("../dist/index.cjs");
const id = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const commit = "a".repeat(40);
const grantToken = `pva_${Buffer.alloc(32, 1).toString("base64url")}`;
const assertion = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJmaXh0dXJlIn0.c2lnbmF0dXJl";
let fixtureRoot, key, cert;
test.before(async () => {
  fixtureRoot = await mkdtemp(resolve(tmpdir(), "provenance-action-test-"));
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      resolve(fixtureRoot, "key"),
      "-out",
      resolve(fixtureRoot, "cert"),
      "-subj",
      "/CN=localhost",
      "-addext",
      "subjectAltName=IP:127.0.0.1",
      "-days",
      "1",
    ],
    { stdio: "ignore" },
  );
  key = await readFile(resolve(fixtureRoot, "key"));
  cert = await readFile(resolve(fixtureRoot, "cert"));
});
test.after(async () => {
  await rm(fixtureRoot, { recursive: true, force: true });
});

async function scenario(t, opts = {}) {
  const dir = await mkdtemp(resolve(fixtureRoot, "case-"));
  const jar = Buffer.from("synthetic stable JAR bytes");
  await writeFile(resolve(dir, "plugin.jar"), jar);
  const yaml = await readFile(
    new URL(
      "../../../schemas/fixtures/config/valid/hosted.yml",
      import.meta.url,
    ),
    "utf8",
  );
  await writeFile(
    resolve(dir, "provenance.yml"),
    opts.invalidConfig ? `${yaml}\nunknownRoot: true\n` : yaml,
  );
  const calls = [],
    masks = [],
    reports = [];
  let snapshotBody,
    artifactBody,
    candidateBody,
    resourceAttempt = 0,
    candidateReads = 0;
  let origin;
  const response = (res, status, body) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };
  const artifact = () => ({
    id: id(3),
    projectId: id(1),
    fileName: "plugin.jar",
    sizeBytes: artifactBody.sizeBytes,
    sha256: artifactBody.sha256,
    state: opts.rejectArtifact ? "rejected" : "ready",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
  const candidate = () => ({
    id: id(4),
    projectId: id(1),
    artifactId: id(3),
    configurationHash: snapshotBody.configurationHash,
    version: "v1",
    state:
      opts.state ||
      (opts.wait ? (candidateReads ? "published" : "testing") : "pending"),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
  const server = createServer({ key, cert }, async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const bytes = Buffer.concat(chunks);
    const url = new URL(req.url, origin);
    let body;
    try {
      body = JSON.parse(bytes.toString());
    } catch {
      body = bytes;
    }
    calls.push({
      path: url.pathname,
      method: req.method,
      headers: req.headers,
      body,
    });
    if (url.pathname === "/oidc") {
      assert.equal(req.headers.authorization, "Bearer oidc-fixture-token");
      assert.equal(url.searchParams.get("audience"), "fixture-audience");
      return response(res, 200, { value: assertion });
    }
    if (url.pathname === "/v1/auth/github-actions/grants") {
      assert.equal(req.headers.authorization, undefined);
      assert.deepEqual(body, { assertion });
      if (opts.issueLoss) return req.socket.destroy();
      if (opts.issueExpected)
        return response(res, opts.issueExpected.status, {
          type: "about:blank",
          title: "Automation grant failed",
          ...opts.issueExpected,
        });
      if (opts.issueConflict)
        return response(res, 409, { code: "credential_not_replayable" });
      return response(res, 201, {
        grantId: id(9),
        principalType: "github-actions",
        accessToken: grantToken,
        tokenType: "Bearer",
        expiresAt: new Date(
          Date.now() + (opts.expiresIn ?? 60000),
        ).toISOString(),
        scope: {
          organizationId: id(8),
          projectId: id(1),
          appId: "10",
          installationId: "11",
          repositoryId: opts.substitute ? "999" : "12",
          repositoryOwnerId: "13",
          sourceCommit: opts.sourceMismatch ? "b".repeat(40) : commit,
          sourceRef: "refs/heads/main",
          workflowRef:
            "fixture/repo/.github/workflows/release.yml@refs/heads/main",
        },
      });
    }
    if (url.pathname.startsWith("/repos/")) {
      assert.equal(req.headers.authorization, "Bearer report-fixture-token");
      assert.equal(url.pathname, `/repos/fixture/repo/statuses/${commit}`);
      reports.push(body);
      return response(res, opts.reportFail ? 403 : 201, body);
    }
    if (url.pathname === "/storage") {
      assert.equal(req.headers.authorization, undefined);
      assert.equal(req.headers.cookie, undefined);
      assert.deepEqual(bytes, jar);
      if (opts.storageRedirect) {
        res.writeHead(307, { location: "https://127.0.0.1:9/steal" });
        return res.end();
      }
      return response(res, 200, {});
    }
    assert.equal(req.headers.authorization, `Bearer ${grantToken}`);
    if (opts.revoke) return response(res, 403, { code: "forbidden" });
    if (url.pathname.endsWith("/config-snapshots")) {
      if (opts.platformRedirect) {
        res.writeHead(307, { location: "https://127.0.0.1:9/steal" });
        return res.end();
      }
      if (opts.malformed) {
        res.writeHead(201, { "content-type": "application/json" });
        return res.end("{not valid private response");
      }
      if (opts.overflow)
        return response(res, 201, { private: "x".repeat(100001) });
      snapshotBody = body;
      assert.equal(body.sourceCommit, commit);
      assert.equal(body.sourceRef, "refs/heads/main");
      assert.equal(
        createHash("sha256").update(body.normalizedJson).digest("hex"),
        body.configurationHash,
      );
      assert.deepEqual(
        JSON.parse(body.normalizedJson),
        JSON.parse(
          await readFile(
            new URL(
              "../../../schemas/fixtures/config/valid/hosted.normalized.json",
              import.meta.url,
            ),
            "utf8",
          ),
        ),
      );
      if (opts.resourceLoss && resourceAttempt++ === 0)
        return req.socket.destroy();
      if (opts.foreignResource)
        return response(res, 404, { code: "not_found" });
      if (opts.mutateFile)
        await writeFile(
          resolve(dir, "plugin.jar"),
          Buffer.alloc(jar.length, 99),
        );
      return response(res, 201, {
        id: id(2),
        projectId: id(1),
        sourceCommit: commit,
        sourceRef: "refs/heads/main",
        schemaVersion: 1,
        configurationHash: body.configurationHash,
        createdAt: new Date().toISOString(),
      });
    }
    if (url.pathname.endsWith("/artifacts/uploads")) {
      artifactBody = body;
      assert.equal(body.sha256, createHash("sha256").update(jar).digest("hex"));
      return response(res, 201, {
        artifactId: id(3),
        uploadUrl: `${origin}/storage?fixture-private-signature`,
        expiresAt: new Date(Date.now() + 60000).toISOString(),
        requiredHeaders:
          opts.requiredHeaders ??
          (opts.unsafeHeader
            ? { Authorization: "private-provider-value" }
            : { "Content-Type": "application/java-archive" }),
      });
    }
    if (url.pathname.endsWith("/complete"))
      return response(res, 202, {
        ...artifact(),
        ...(opts.verifying ? { state: "verifying" } : {}),
        ...(opts.hashMismatch ? { sha256: "0".repeat(64) } : {}),
      });
    if (url.pathname === `/v1/artifacts/${id(3)}`)
      return response(res, 200, artifact());
    if (url.pathname.endsWith("/release-candidates")) {
      candidateBody = body;
      assert.equal(body.configurationSnapshotId, id(2));
      if (opts.candidateConflict)
        return response(res, 409, { code: "version_conflict" });
      return response(res, 201, candidate());
    }
    if (url.pathname.endsWith("/events")) {
      return response(res, 200, {
        items: [
          {
            id: id(20),
            candidateId: opts.eventSubstitution ? id(99) : id(4),
            sequence: 1,
            kind: "test_completed",
            occurredAt: "2026-09-07T00:00:00Z",
          },
        ],
        page: opts.paginationLoop
          ? { hasMore: true, nextCursor: "repeated" }
          : { hasMore: false },
      });
    }
    if (url.pathname === `/v1/release-candidates/${id(4)}`) {
      candidateReads++;
      return response(res, 200, candidate());
    }
    return response(res, 404, {});
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  origin = `https://127.0.0.1:${server.address().port}`;
  t.after(() => new Promise((r) => server.close(r)));
  // Actual TLS network, custom fixture CA trust only. No global TLS override.
  const fixtureFetch = (url, init) =>
    new Promise((resolve, reject) => {
      const request = httpsRequest(
        url,
        {
          method: init.method,
          headers: Object.fromEntries(new Headers(init.headers)),
          ca: cert,
          rejectUnauthorized: true,
          signal: init.signal,
        },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () =>
            resolve(
              new Response(Buffer.concat(chunks), {
                status: res.statusCode,
                headers: res.headers,
              }),
            ),
          );
        },
      );
      request.on("error", reject);
      request.end(init.body);
    });
  const result = await execute(
    {
      artifactPath: resolve(dir, "plugin.jar"),
      configPath: resolve(dir, "provenance.yml"),
      origin,
      project: id(1),
      commit,
      ref: "refs/heads/main",
      repository: "fixture/repo",
      repositoryId: "12",
      ownerId: "13",
      audience: "fixture-audience",
      version: "v1",
      changelog: "private fixture changelog",
      wait: !!opts.wait,
      report: opts.report ? "status" : "none",
      repositoryToken: "report-fixture-token",
      maxArtifactBytes: 1024,
      requestMs: opts.totalMs ? 50 : 1000,
      totalMs: opts.totalMs || 3000,
      pollMs: 10,
      attempts: 2,
      maxPages: 2,
      responseBytes: 100000,
    },
    {
      oidcURL: `${origin}/oidc`,
      oidcToken: "oidc-fixture-token",
      githubOrigin: origin,
      testEndpoints: true,
      fetch: fixtureFetch,
      mask: (v) => masks.push(v),
      signal: opts.signal,
    },
  );
  return { result, calls, masks, reports, candidateBody };
}

test("compiled distribution submits real normalized configuration and exact bytes", async (t) => {
  const s = await scenario(t);
  assert.deepEqual(s.result, {
    outcome: "submitted",
    candidateId: id(4),
    artifactId: id(3),
  });
  assert.ok(s.masks.includes(assertion));
  assert.ok(s.masks.includes(grantToken));
  assert.ok(!JSON.stringify(s.result).includes("private"));
});
for (const name of ["If-None-Match", "if-none-match", "IF-NONE-MATCH"]) {
  test(`immutable storage condition reaches PUT: ${name}`, async (t) => {
    const s = await scenario(t, { requiredHeaders: { [name]: "*" } });
    assert.equal(s.result.outcome, "submitted");
    const puts = s.calls.filter((c) => c.method === "PUT");
    assert.equal(puts.length, 1);
    assert.equal(puts[0].headers["if-none-match"], "*");
    assert.equal(puts[0].headers.authorization, undefined);
    assert.equal(puts[0].headers.cookie, undefined);
  });
}
for (const [name, requiredHeaders] of [
  ["arbitrary ETag", { "If-None-Match": '"etag"' }],
  ["empty condition", { "If-None-Match": "" }],
  ["whitespace condition", { "If-None-Match": " * " }],
  ["duplicate condition", { "If-None-Match": "*", "if-none-match": "*" }],
  ["overridden condition", { "If-None-Match": "*", "if-none-match": '"etag"' }],
  [
    "reverse overridden condition",
    { "if-none-match": '"etag"', "If-None-Match": "*" },
  ],
  ...[
    "Authorization",
    "Cookie",
    "Host",
    "Proxy-Authorization",
    "x-amz-security-token",
    "If-Match",
  ].map((name) => [name, { "If-None-Match": "*", [name]: "forbidden" }]),
]) {
  test(`storage condition refusal before PUT: ${name}`, async (t) => {
    const s = await scenario(t, { requiredHeaders });
    assert.equal(s.result.outcome, "incomplete");
    assert.equal(s.result.reason, "storage_headers_denied");
    assert.equal(s.calls.filter((c) => c.method === "PUT").length, 0);
  });
}
test("compiled optional wait does not interpret test_completed as publication", async (t) => {
  const s = await scenario(t, { wait: true, report: true });
  assert.equal(s.result.outcome, "published");
  assert.deepEqual(
    s.reports.map((r) => r.state),
    ["pending", "success"],
  );
  assert.ok(s.calls.some((c) => c.path.endsWith("/events")));
});
test("same-grant lost resource acknowledgement retries identical key/body", async (t) => {
  const s = await scenario(t, { resourceLoss: true });
  assert.equal(s.result.outcome, "submitted");
  const calls = s.calls.filter((c) => c.path.endsWith("/config-snapshots"));
  assert.equal(calls.length, 2);
  assert.equal(
    calls[0].headers["idempotency-key"],
    calls[1].headers["idempotency-key"],
  );
  assert.deepEqual(calls[0].body, calls[1].body);
});
for (const [name, opts, reason] of [
  ["lost issuance response", { issueLoss: true }, "unavailable"],
  ["consumed assertion", { issueConflict: true }, "credential_unrecoverable"],
  ["numeric substitution", { substitute: true }, "identity_mismatch"],
  ["source substitution", { sourceMismatch: true }, "identity_mismatch"],
  ["platform redirect", { platformRedirect: true }, "redirect_denied"],
  ["malformed success", { malformed: true }, "invalid_response"],
  ["response overflow", { overflow: true }, "invalid_response"],
  ["expired grant", { expiresIn: -1 }, "authority_expired"],
  ["revoked grant", { revoke: true }, "authority_denied"],
  ["foreign resource", { foreignResource: true }, "resource_not_owned"],
  ["existing candidate version", { candidateConflict: true }, "conflict"],
  ["file mutation", { mutateFile: true }, "file_changed"],
  ["storage redirect", { storageRedirect: true }, "redirect_denied"],
  [
    "storage credential header",
    { unsafeHeader: true },
    "storage_headers_denied",
  ],
  ["server hash mismatch", { hashMismatch: true }, "identity_mismatch"],
  ["rejected bytes", { rejectArtifact: true }, "artifact_rejected"],
  [
    "foreign event",
    { wait: true, eventSubstitution: true },
    "invalid_response",
  ],
  ["cursor loop", { wait: true, paginationLoop: true }, "invalid_response"],
  ["report permission", { report: true, reportFail: true }, "reporting_failed"],
])
  test(name, async (t) => {
    const s = await scenario(t, opts);
    assert.equal(s.result.outcome, "incomplete");
    assert.equal(s.result.reason, reason);
    assert.equal(
      s.calls.filter((c) => c.path === "/v1/auth/github-actions/grants").length,
      1,
    );
    assert.ok(
      !s.calls.some(
        (c) => c.path.includes("publication-result") || c.path === "/steal",
      ),
    );
  });
for (const [state, outcome, report] of [
  ["awaiting_approval", "approval_required", "pending"],
  ["failed", "failed", "failure"],
  ["canceled", "canceled", "error"],
])
  test(`truthful ${state}`, async (t) => {
    const s = await scenario(t, { wait: true, report: true, state });
    assert.equal(s.result.outcome, outcome);
    assert.equal(s.reports.at(-1).state, report);
  });
test("approved is not publication success and expiry ends waiting", async (t) => {
  const s = await scenario(t, {
    wait: true,
    state: "approved",
    expiresIn: 100,
  });
  assert.equal(s.result.outcome, "incomplete");
  assert.equal(s.result.reason, "authority_expired");
  assert.equal(
    s.calls.filter((c) => c.path === "/v1/auth/github-actions/grants").length,
    1,
  );
});
test("cancellation before submission is closed", async (t) => {
  const a = new AbortController();
  a.abort();
  const s = await scenario(t, { signal: a.signal });
  assert.equal(s.result.reason, "cancelled");
  assert.equal(s.calls.length, 0);
});
test("unknown config fails before any credentials leave", async (t) => {
  const s = await scenario(t, { invalidConfig: true });
  assert.equal(s.result.outcome, "incomplete");
  assert.equal(s.calls.length, 0);
});
test("deterministic bundle matches checked distribution", async () => {
  const a = await compile(),
    b = await compile();
  assert.deepEqual(a.outputFiles[0].contents, b.outputFiles[0].contents);
  assert.deepEqual(
    Buffer.from(a.outputFiles[0].contents),
    await readFile(new URL("../dist/index.cjs", import.meta.url)),
  );
});
test("closed reporter mapping never turns incomplete into success", () => {
  for (const key of ["incomplete", "unknown", "test_completed", "approved"])
    assert.notEqual(reportingState(key)[0], "success");
});

test("compiled flow exercises all seven resource operations", async (t) => {
  const s = await scenario(t, { wait: true, verifying: true });
  assert.equal(s.result.outcome, "published");
  for (const path of [
    "/config-snapshots",
    "/artifacts/uploads",
    `/artifacts/${id(3)}/complete`,
    `/artifacts/${id(3)}`,
    "/release-candidates",
    `/release-candidates/${id(4)}`,
    `/release-candidates/${id(4)}/events`,
  ])
    assert.ok(
      s.calls.some((c) => c.path.endsWith(path)),
      path,
    );
});
test("total timeout never becomes success or acquires another grant", async (t) => {
  const s = await scenario(t, { wait: true, state: "approved", totalMs: 150 });
  assert.equal(s.result.outcome, "incomplete");
  assert.equal(s.result.reason, "timeout");
  assert.equal(
    s.calls.filter((c) => c.path === "/v1/auth/github-actions/grants").length,
    1,
  );
});
test("bundle includes deterministic full third-party notices", async () => {
  const result = await compile();
  assert.equal(
    await notices(result),
    await readFile(
      new URL("../dist/THIRD_PARTY_NOTICES.txt", import.meta.url),
      "utf8",
    ),
  );
});
test("real executable rejects untrusted workflow context without diagnostic secrets", () => {
  const secret = "fixture%secret\n::error::injected";
  const result = spawnSync(
    process.execPath,
    [new URL("../dist/index.cjs", import.meta.url).pathname],
    {
      encoding: "utf8",
      env: {
        PATH: process.env.PATH,
        GITHUB_ACTIONS: "true",
        GITHUB_EVENT_NAME: "pull_request_target",
        GITHUB_SERVER_URL: "https://github.com",
        "INPUT_GITHUB-TOKEN": secret,
      },
    },
  );
  assert.equal(result.status, 1);
  const diagnostics =
    result.stdout
      .split("\n")
      .filter((l) => !l.startsWith("::add-mask::"))
      .join("\n") + result.stderr;
  assert.ok(!diagnostics.includes("fixture%secret"));
  assert.ok(!diagnostics.includes("injected"));
  assert.match(diagnostics, /verify explicit inputs/);
});

test("released IFC022 issuance-denial vectors never retry or request resources", async (t) => {
  const vectors = JSON.parse(
    await readFile(
      new URL("../../../openapi/actions-grant-vectors.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(vectors.contract, "IFC-022");
  for (const vector of vectors.issuance.filter(
    (v) => v.expected.status !== 201,
  ))
    await t.test(vector.id, async (t) => {
      const s = await scenario(t, { issueExpected: vector.expected });
      assert.equal(s.result.outcome, "incomplete");
      assert.equal(
        s.result.reason,
        vector.expected.status === 409
          ? "credential_unrecoverable"
          : "grant_denied",
      );
      assert.deepEqual(
        s.calls.map((c) => c.path),
        ["/oidc", "/v1/auth/github-actions/grants"],
      );
    });
});
