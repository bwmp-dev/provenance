import { randomUUID } from "node:crypto";
import { basename } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { ActionError, fail, finite, https, uuid, numeric, sha, object, timestamp, exactKeys, stableFile, boundedResponse } from "./safety.mjs";

const states = new Set(["pending", "testing", "awaiting_approval", "approved", "canceled", "failed", "publishing", "published"]);
const eventKinds = new Set(["created", "testing_started", "test_completed", "approval_requested", "approved", "canceled", "retry_requested", "publication_started", "publication_completed", "failed"]);
const descriptions = {
  submitted: ["pending", "Submitted; verification/publication not yet established"],
  waiting: ["pending", "Waiting for an authoritative candidate outcome"],
  approval_required: ["pending", "Human approval required; publication not established"],
  published: ["success", "Platform reports candidate published"],
  failed: ["failure", "Platform reports candidate failed"],
  canceled: ["error", "Candidate canceled"],
  incomplete: ["error", "Observation incomplete; outcome unknown"],
};
export const reportingState = (outcome) => descriptions[outcome] || descriptions.incomplete;

export function validateInputs(c) {
  c.origin = https(c.origin, true).origin;
  if (!uuid(c.project) || !sha(c.commit) || typeof c.ref !== "string" || !/^refs\/[A-Za-z0-9._/+-]{1,500}$/.test(c.ref) ||
      typeof c.audience !== "string" || !c.audience || c.audience.length > 2048 ||
      typeof c.repository !== "string" || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(c.repository) ||
      !numeric(c.repositoryId) || !numeric(c.ownerId) || typeof c.version !== "string" || !c.version || c.version.length > 128 ||
      typeof c.changelog !== "string" || c.changelog.length > 65536 || !["none", "status"].includes(c.report) || typeof c.wait !== "boolean") fail("invalid_configuration");
  finite(c.maxArtifactBytes, 2147483647);
  finite(c.requestMs, 120000);
  finite(c.totalMs, 3600000);
  finite(c.pollMs, 60000);
  finite(c.attempts, 5);
  finite(c.maxPages, 100);
  finite(c.responseBytes, 1048576);
  if (c.requestMs > c.totalMs || (c.report === "status" && (typeof c.repositoryToken !== "string" || !c.repositoryToken))) fail("invalid_configuration");
  return c;
}

// The only production factory is the generated public API client. Injection is
// available to black-box fixtures, never from Action inputs or repository files.
export async function runAction(input, runtime) {
  let config, jar, source;
  let grant, candidateId, artifactId, outcome = "incomplete", reason;
  const started = Date.now();
  const signal = runtime.signal || new AbortController().signal;
  const mask = runtime.mask || (() => {});
  const fetcher = runtime.fetch || fetch;
  const now = () => Date.now();
  let operationDeadline;
  const check = (credential = true) => {
    if (signal.aborted) fail("cancelled");
    if (now() >= operationDeadline) fail("timeout");
    if (credential && grant && now() >= timestamp(grant.expiresAt)) fail("authority_expired");
  };
  const request = async (url, options = {}, credential = false) => {
    check(credential);
    const end = Math.min(operationDeadline, now() + config.requestMs, credential && grant ? timestamp(grant.expiresAt) : Infinity);
    const abort = AbortSignal.any([signal, AbortSignal.timeout(Math.max(1, end - now()))]);
    try {
      const r = await fetcher(url, { ...options, redirect: "manual", signal: abort });
      if (r.status >= 300 && r.status < 400) { await r.body?.cancel(); fail("redirect_denied"); }
      const bytes = await boundedResponse(r, config.responseBytes);
      check(credential);
      return new Response(bytes.length ? bytes : null, { status: r.status, headers: r.headers });
    } catch (e) {
      if (e instanceof ActionError) throw e;
      if (signal.aborted) fail("cancelled");
      if (now() >= end) fail(credential && grant && now() >= timestamp(grant.expiresAt) ? "authority_expired" : "timeout");
      fail("unavailable");
    }
  };
  const json = async (r) => {
    if (!(r.headers.get("content-type") || "").toLowerCase().includes("application/json")) fail("invalid_response");
    try { return await r.json(); } catch { fail("invalid_response"); }
  };
  const report = async (state) => {
    if (config.report === "none") return;
    const [value, description] = reportingState(state);
    const r = await request(`${runtime.githubOrigin || "https://api.github.com"}/repos/${config.repository}/statuses/${config.commit}`, {
      method: "POST", headers: { Authorization: `Bearer ${config.repositoryToken}`, Accept: "application/vnd.github+json", "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28" },
      body: JSON.stringify({ state: value, context: "provenance/action", description }),
    });
    if (r.status !== 201) fail("reporting_failed");
    const body = await json(r);
    if (!object(body) || body.state !== value || body.context !== "provenance/action") fail("reporting_failed");
  };
  try {
    config = validateInputs({ ...input });
    operationDeadline = started + config.totalMs;
    if (config.repositoryToken) mask(config.repositoryToken);
    jar = await stableFile(config.artifactPath, config.maxArtifactBytes);
    source = await stableFile(config.configPath, 1048576);
    const rawYaml = new TextDecoder("utf-8", { fatal: true }).decode(source.bytes);
    const parsed = runtime.parseConfiguration(rawYaml);
    const normalizedJson = runtime.normalizeConfiguration(parsed);
    const configurationHash = runtime.hashConfiguration(parsed);
    await source.check();
    await jar.check();
    const oidcURL = https(runtime.oidcURL);
    if (!runtime.testEndpoints && !oidcURL.hostname.endsWith(".actions.githubusercontent.com")) fail("unsupported_context");
    if (!runtime.oidcToken) fail("oidc_unavailable");
    mask(runtime.oidcToken);
    oidcURL.searchParams.set("audience", config.audience);
    const oidcResponse = await request(oidcURL, { headers: { Authorization: `Bearer ${runtime.oidcToken}`, Accept: "application/json" } });
    if (oidcResponse.status !== 200) fail("oidc_unavailable");
    const oidc = await json(oidcResponse);
    if (!object(oidc) || typeof oidc.value !== "string" || oidc.value.length < 16 || oidc.value.length > 16384 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(oidc.value)) fail("invalid_response");
    mask(oidc.value);
    // Issuance is deliberately not retried: successful response loss is not recoverable.
    const issued = await request(`${config.origin}/v1/auth/github-actions/grants`, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json", "Idempotency-Key": randomUUID() }, body: JSON.stringify({ assertion: oidc.value }) });
    if (issued.status !== 201) fail(issued.status === 409 ? "credential_unrecoverable" : "grant_denied");
    grant = await json(issued);
    if (typeof grant?.accessToken === "string") mask(grant.accessToken);
    exactKeys(grant, ["grantId", "principalType", "accessToken", "tokenType", "expiresAt", "scope"]);
    exactKeys(grant.scope, ["organizationId", "projectId", "appId", "installationId", "repositoryId", "repositoryOwnerId", "sourceCommit", "sourceRef", "workflowRef"]);
    if (!uuid(grant.grantId) || !uuid(grant.scope.organizationId) || grant.principalType !== "github-actions" || grant.tokenType !== "Bearer" || !/^pva_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(grant.accessToken) ||
        grant.scope.projectId !== config.project || grant.scope.repositoryId !== config.repositoryId || grant.scope.repositoryOwnerId !== config.ownerId ||
        grant.scope.sourceCommit !== config.commit || grant.scope.sourceRef !== config.ref || !numeric(grant.scope.appId) || !numeric(grant.scope.installationId) || typeof grant.scope.workflowRef !== "string" || !grant.scope.workflowRef || grant.scope.workflowRef.length > 1024) fail("identity_mismatch");
    check();
    const client = runtime.createClient({ baseUrl: config.origin, fetch: async (req) => {
      const url = new URL(req.url);
      if (url.origin !== config.origin || req.headers.has("cookie") || req.headers.has("origin")) fail("credential_destination");
      return request(req.url, { method: req.method, headers: req.headers, body: ["GET", "HEAD"].includes(req.method) ? undefined : await req.text() }, true);
    } });
    const call = async (method, path, params, body, expectedStatus) => {
      const key = randomUUID();
      for (let attempt = 1; ; attempt++) {
        check();
        await jar.check();
        await source.check();
        try {
          const result = await client[method](path, { params, body, headers: { Authorization: `Bearer ${grant.accessToken}`, Accept: "application/json", ...(method === "POST" ? { "Idempotency-Key": key } : {}) } });
          check();
          const status = result.response.status;
          if (status === 401 || status === 403) fail("authority_denied");
          if (status === 404) fail("resource_not_owned");
          if (status === 429 || status >= 500) fail("unavailable");
          if (status !== expectedStatus || !object(result.data)) fail("invalid_response");
          return result.data;
        } catch (e) {
          const error = e instanceof ActionError ? e : new ActionError("unavailable");
          if (error.code !== "unavailable" || attempt >= config.attempts) throw error;
          await delay(config.pollMs, undefined, { signal });
        }
      }
    };
    const project = { path: { projectId: config.project } };
    const snapshot = await call("POST", "/v1/projects/{projectId}/config-snapshots", project, { rawYaml, normalizedJson, schemaVersion: 1, configurationHash, sourceCommit: config.commit, sourceRef: config.ref }, 201);
    if (!uuid(snapshot.id) || snapshot.projectId !== config.project || snapshot.configurationHash !== configurationHash || snapshot.sourceCommit !== config.commit || snapshot.sourceRef !== config.ref || snapshot.schemaVersion !== 1) fail("identity_mismatch");
    const fileName = basename(config.artifactPath);
    if (!fileName || fileName.length > 255 || /[\r\n\x00]/.test(fileName)) fail("invalid_file");
    const upload = await call("POST", "/v1/projects/{projectId}/artifacts/uploads", project, { fileName, sizeBytes: jar.bytes.length, sha256: jar.digest }, 201);
    if (!uuid(upload.artifactId)) fail("invalid_response");
    artifactId = upload.artifactId;
    const uploadURL = https(upload.uploadUrl);
    mask(upload.uploadUrl);
    if (timestamp(upload.expiresAt) <= now()) fail("upload_expired");
    const headers = new Headers();
    if (upload.requiredHeaders !== undefined && !object(upload.requiredHeaders)) fail("invalid_response");
    for (const [name, value] of Object.entries(upload.requiredHeaders || {})) {
      // No credential-bearing or routing headers, including provider Authorization.
      if (!/^(content-type|content-md5|x-amz-checksum-sha256|x-amz-content-sha256|x-amz-meta-[a-z0-9-]+)$/i.test(name) || typeof value !== "string" || value.length > 2048 || /[\r\n\x00]/.test(value)) fail("storage_headers_denied");
      headers.set(name, value);
    }
    check();
    await jar.check();
    const stored = await request(uploadURL, { method: "PUT", headers, body: jar.bytes }, true);
    if (![200, 201, 204].includes(stored.status)) fail("upload_failed");
    await jar.check();
    const artifactParams = { path: { artifactId } };
    let artifact = await call("POST", "/v1/artifacts/{artifactId}/complete", artifactParams, { sizeBytes: jar.bytes.length, sha256: jar.digest }, 202);
    for (;;) {
      if (artifact.id !== artifactId || artifact.projectId !== config.project || artifact.sha256 !== jar.digest || artifact.sizeBytes !== jar.bytes.length) fail("identity_mismatch");
      if (artifact.state === "ready") break;
      if (!["pending", "uploaded", "verifying"].includes(artifact.state)) fail("artifact_rejected");
      await delay(config.pollMs, undefined, { signal });
      artifact = await call("GET", "/v1/artifacts/{artifactId}", artifactParams, undefined, 200);
    }
    let candidate = await call("POST", "/v1/projects/{projectId}/release-candidates", project, { artifactId, configurationSnapshotId: snapshot.id, configurationHash, version: config.version, changelog: config.changelog }, 201);
    const verifyCandidate = (v) => {
      if (!uuid(v.id) || (candidateId && v.id !== candidateId) || v.projectId !== config.project || v.artifactId !== artifactId || v.configurationHash !== configurationHash || v.version !== config.version || !states.has(v.state)) fail("identity_mismatch");
    };
    verifyCandidate(candidate);
    candidateId = candidate.id;
    if (!config.wait) outcome = "submitted";
    else {
      await report("waiting");
      let cursor, sequence = -1;
      const seen = new Set();
      for (;;) {
        verifyCandidate(candidate);
        if (["failed", "canceled", "published"].includes(candidate.state)) { outcome = candidate.state; break; }
        if (candidate.state === "awaiting_approval") { outcome = "approval_required"; break; }
        const cursors = new Set();
        for (let pageNo = 0; ; pageNo++) {
          if (pageNo >= config.maxPages) fail("observation_limit");
          const page = await call("GET", "/v1/release-candidates/{candidateId}/events", { path: { candidateId }, query: { limit: 100, ...(cursor ? { cursor } : {}) } }, undefined, 200);
          if (!Array.isArray(page.items) || page.items.length > 100 || !object(page.page) || typeof page.page.hasMore !== "boolean") fail("invalid_response");
          for (const event of page.items) {
            if (!object(event) || !uuid(event.id) || event.candidateId !== candidateId || !Number.isSafeInteger(event.sequence) || event.sequence < 0 || !eventKinds.has(event.kind)) fail("invalid_response");
            timestamp(event.occurredAt);
            if (seen.has(event.id)) continue;
            if (event.sequence <= sequence || seen.size >= 100 * config.maxPages) fail("observation_limit");
            seen.add(event.id); sequence = event.sequence;
          }
          if (page.page.nextCursor != null) {
            if (typeof page.page.nextCursor !== "string" || !page.page.nextCursor || page.page.nextCursor.length > 2048 || cursors.has(page.page.nextCursor)) fail("invalid_response");
            cursor = page.page.nextCursor;
            cursors.add(cursor);
          } else if (page.page.hasMore) fail("invalid_response");
          if (!page.page.hasMore) break;
        }
        await delay(config.pollMs, undefined, { signal });
        candidate = await call("GET", "/v1/release-candidates/{candidateId}", { path: { candidateId } }, undefined, 200);
      }
    }
    await report(outcome);
  } catch (e) {
    reason = e instanceof ActionError ? e.code : signal.aborted ? "cancelled" : "unavailable";
    outcome = "incomplete";
    if (config?.report === "status" && operationDeadline && now() < operationDeadline && !signal.aborted) {
      try { await report("incomplete"); } catch { reason = "reporting_failed"; }
    }
  } finally {
    await jar?.close().catch(() => {});
    await source?.close().catch(() => {});
  }
  return { outcome, ...(reason ? { reason } : {}), ...(candidateId ? { candidateId } : {}), ...(artifactId ? { artifactId } : {}) };
}
