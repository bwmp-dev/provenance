import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { createServer, request as httpsRequest } from "node:https";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { createRequire } from "node:module";
import test from "node:test";
import { parse as parseYAML } from "yaml";
import {
  createSDKClient,
  parseConfiguration,
  normalizeConfiguration,
  hashConfiguration,
} from "../dist/index.js";

const { execute } = createRequire(import.meta.url)(
  "../../action/dist/index.cjs",
);
const root = resolve(import.meta.dirname, "../../..");
const example = resolve(root, "examples/consumption");
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const id = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
function run(command, args, cwd = root) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8" });
  assert.equal(
    result.status,
    0,
    `${command} failed\n${result.stdout}\n${result.stderr}`,
  );
}
let jar, temporary, key, cert;
test.before(async () => {
  run(process.execPath, [
    "scripts/run-gradle.mjs",
    ":paper-probe:verifyPaperApiArtifact",
  ]);
  const args = [
    "examples/consumption/plugin/build.mjs",
    "plugins/paper-probe/build/dependency-verification/paper-api",
  ];
  run(process.execPath, args);
  jar = await readFile(resolve(example, "plugin/build/example-plugin.jar"));
  run(process.execPath, args);
  assert.deepEqual(
    await readFile(resolve(example, "plugin/build/example-plugin.jar")),
    jar,
  );
  temporary = await mkdtemp(resolve(tmpdir(), "provenance-sdk-example-tls-"));
  run("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    resolve(temporary, "key"),
    "-out",
    resolve(temporary, "cert"),
    "-subj",
    "/CN=localhost",
    "-addext",
    "subjectAltName=IP:127.0.0.1",
    "-days",
    "1",
  ]);
  key = await readFile(resolve(temporary, "key"));
  cert = await readFile(resolve(temporary, "cert"));
});
test.after(async () => {
  if (temporary) await rm(temporary, { recursive: true, force: true });
});

for (const visibility of ["public", "private"])
  test(`complete ${visibility} example build, Action submission and same-grant SDK observation over TLS`, async (t) => {
    const workflow = parseYAML(
      await readFile(resolve(example, `${visibility}.workflow.yml`), "utf8"),
    );
    assert.deepEqual(Object.keys(workflow.on).sort(), [
      "push",
      "workflow_dispatch",
    ]);
    assert.deepEqual(
      workflow.permissions,
      visibility === "public"
        ? { contents: "read", "id-token": "write", statuses: "write" }
        : { contents: "read", "id-token": "write" },
    );
    assert.ok(
      workflow.jobs.submit.steps.every(
        (step) => !step.uses || /@[a-f0-9]{40}$/.test(step.uses),
      ),
    );
    const submission = workflow.jobs.submit.steps.at(-1);
    assert.equal(
      submission.uses,
      "bwmp-dev/provenance/packages/action@975a854b42f997a6b382b549b65f6e8b2be25158",
    );
    assert.equal(submission.with.wait, "false");
    const configuration = parseConfiguration(
      await readFile(resolve(example, "provenance.yml"), "utf8"),
    );
    assert.equal(configuration.release.mode, "test-only");
    const commit = "a".repeat(40),
      token = `pva_${Buffer.alloc(32, 1).toString("base64url")}`;
    const calls = [],
      reports = [],
      masks = [];
    let origin;
    const artifact = {
      id: id(3),
      projectId: id(1),
      fileName: "example-plugin.jar",
      sizeBytes: jar.length,
      sha256: hash(jar),
      state: "ready",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    const candidate = {
      id: id(4),
      projectId: id(1),
      artifactId: id(3),
      configurationHash: hashConfiguration(configuration),
      version: "1.0.0",
      state: "pending",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    const server = createServer({ key, cert }, async (req, res) => {
      try {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const bytes = Buffer.concat(chunks);
        const url = new URL(req.url, origin);
        calls.push(url.pathname);
        const respond = (status, value) => {
          res.writeHead(status, { "content-type": "application/json" });
          res.end(JSON.stringify(value));
        };
        if (url.pathname === "/oidc")
          return respond(200, { value: "fixture.assertion.signature" });
        if (url.pathname === "/v1/auth/github-actions/grants")
          return respond(201, {
            grantId: id(9),
            principalType: "github-actions",
            accessToken: token,
            tokenType: "Bearer",
            expiresAt: new Date(Date.now() + 60000).toISOString(),
            scope: {
              organizationId: id(8),
              projectId: id(1),
              appId: "10",
              installationId: "11",
              repositoryId: "12",
              repositoryOwnerId: "13",
              sourceCommit: commit,
              sourceRef: "refs/heads/main",
              workflowRef:
                "fixture/repo/.github/workflows/provenance.yml@refs/heads/main",
            },
          });
        if (url.pathname === "/storage") {
          assert.equal(req.headers.authorization, undefined);
          assert.deepEqual(bytes, jar);
          return respond(200, {});
        }
        if (url.pathname.startsWith("/repos/")) {
          assert.equal(req.headers.authorization, "Bearer fixture-report");
          reports.push(JSON.parse(bytes));
          return respond(201, reports.at(-1));
        }
        assert.equal(req.headers.authorization, `Bearer ${token}`);
        const body = bytes.length ? JSON.parse(bytes) : null;
        if (url.pathname.endsWith("/config-snapshots")) {
          assert.equal(
            body.normalizedJson,
            normalizeConfiguration(configuration),
          );
          assert.equal(
            body.configurationHash,
            hashConfiguration(configuration),
          );
          return respond(201, {
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
          assert.equal(body.sha256, hash(jar));
          assert.equal(body.sizeBytes, jar.length);
          return respond(201, {
            artifactId: id(3),
            uploadUrl: `${origin}/storage`,
            expiresAt: new Date(Date.now() + 60000).toISOString(),
            requiredHeaders: { "Content-Type": "application/java-archive" },
          });
        }
        if (url.pathname.endsWith("/complete")) return respond(202, artifact);
        if (url.pathname === `/v1/artifacts/${id(3)}`)
          return respond(200, artifact);
        if (url.pathname.endsWith("/release-candidates")) {
          assert.equal(body.artifactId, id(3));
          assert.equal(body.configurationSnapshotId, id(2));
          return respond(201, candidate);
        }
        if (url.pathname === `/v1/release-candidates/${id(4)}`)
          return respond(200, candidate);
        return respond(404, {});
      } catch (error) {
        res.destroy(error);
        t.assert.fail(error.message);
      }
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    origin = `https://127.0.0.1:${server.address().port}`;
    t.after(() => new Promise((r) => server.close(r)));
    const transport = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      return new Promise(async (resolveResponse, reject) => {
        const network = httpsRequest(
          req.url,
          {
            method: req.method,
            headers: Object.fromEntries(req.headers),
            ca: cert,
            rejectUnauthorized: true,
            signal: req.signal,
          },
          (response) => {
            const chunks = [];
            response.on("data", (chunk) => chunks.push(chunk));
            response.on("end", () =>
              resolveResponse(
                new Response(Buffer.concat(chunks), {
                  status: response.statusCode,
                  headers: response.headers,
                }),
              ),
            );
          },
        );
        network.on("error", reject);
        network.end(Buffer.from(await req.arrayBuffer()));
      });
    };
    const result = await execute(
      {
        artifactPath: resolve(root, submission.with.artifact),
        configPath: resolve(root, submission.with.configuration),
        origin,
        project: id(1),
        commit,
        ref: "refs/heads/main",
        repository: "fixture/repo",
        repositoryId: "12",
        ownerId: "13",
        audience: "fixture-audience",
        version: submission.with.version,
        changelog: "",
        wait: false,
        report: submission.with.report,
        repositoryToken: visibility === "public" ? "fixture-report" : "",
        maxArtifactBytes: Number(submission.with["max-artifact-bytes"]),
        requestMs: 1000,
        totalMs: 5000,
        pollMs: 10,
        attempts: 2,
        maxPages: 2,
        responseBytes: 100000,
      },
      {
        oidcURL: `${origin}/oidc`,
        oidcToken: "fixture-oidc",
        githubOrigin: origin,
        testEndpoints: true,
        fetch: transport,
        mask: (value) => masks.push(value),
      },
    );
    assert.equal(result.outcome, "submitted", JSON.stringify(result));
    const sdk = createSDKClient({
      origin,
      transport,
      timeoutMs: 1000,
      maxResponseBytes: 100000,
    });
    const observed = await sdk.GET("/v1/release-candidates/{candidateId}", {
      params: { path: { candidateId: id(4) } },
      headers: { authorization: `Bearer ${token}` },
    });
    assert.equal(observed.data.state, "pending");
    assert.equal(
      calls.filter((path) => path === "/v1/auth/github-actions/grants").length,
      1,
    );
    assert.equal(
      calls.some((path) => path.includes("publication-result")),
      false,
    );
    assert.ok(masks.includes(token));
    assert.equal(reports.length, visibility === "public" ? 1 : 0);
    if (reports.length) assert.equal(reports[0].state, "pending");
    assert.doesNotMatch(
      JSON.stringify(result),
      /pva_|fixture\.assertion|fixture-report|fixture-oidc/,
    );
    t.diagnostic(
      `actual example JAR SHA-256 ${hash(jar)}; ${calls.length} TLS requests; submission only`,
    );
  });
