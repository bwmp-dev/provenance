import { appendFile } from "node:fs/promises";
import { createProvenanceClient } from "@bwmp-dev/api-client";
import {
  parseConfiguration,
  normalizeConfiguration,
  hashConfiguration,
} from "@bwmp-dev/config-schema";
import { runAction } from "./client.mjs";
import { ActionError } from "./safety.mjs";

const escape = (s) =>
  String(s)
    .replaceAll("%", "%25")
    .replaceAll("\r", "%0D")
    .replaceAll("\n", "%0A");
const mask = (s) => process.stdout.write(`::add-mask::${escape(s)}\n`);
const input = (name) =>
  process.env[`INPUT_${name.replaceAll(" ", "_").toUpperCase()}`] || "";
const integer = (name, fallback) =>
  /^\d+$/.test(input(name) || fallback) ? Number(input(name) || fallback) : NaN;
const abort = new AbortController();
process.once("SIGINT", () => abort.abort());
process.once("SIGTERM", () => abort.abort());

// Exported for compiled-distribution HTTP fixtures. No Action input selects these
// seams; the executable always constructs the production runtime below.
export function execute(config, runtime) {
  return runAction(config, {
    createClient: createProvenanceClient,
    parseConfiguration,
    normalizeConfiguration,
    hashConfiguration,
    ...runtime,
  });
}

async function main() {
  const env = process.env;
  for (const secret of [
    env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
    input("github-token"),
  ])
    if (secret) mask(secret);
  if (
    env.GITHUB_ACTIONS !== "true" ||
    env.GITHUB_SERVER_URL !== "https://github.com" ||
    !["push", "workflow_dispatch"].includes(env.GITHUB_EVENT_NAME) ||
    input("repository") !== env.GITHUB_REPOSITORY ||
    input("source-commit") !== env.GITHUB_SHA ||
    input("source-ref") !== env.GITHUB_REF ||
    !["true", "false"].includes(input("wait"))
  )
    throw new ActionError("unsupported_context");
  const result = await execute(
    {
      artifactPath: input("artifact"),
      configPath: input("configuration"),
      version: input("version"),
      changelog: input("changelog"),
      project: input("project"),
      origin: input("platform-origin"),
      audience: input("audience"),
      commit: input("source-commit"),
      ref: input("source-ref"),
      repository: input("repository"),
      repositoryId: env.GITHUB_REPOSITORY_ID,
      ownerId: env.GITHUB_REPOSITORY_OWNER_ID,
      wait: input("wait") === "true",
      report: input("report"),
      repositoryToken: input("github-token"),
      maxArtifactBytes: integer("max-artifact-bytes", ""),
      requestMs: integer("request-timeout-ms", "30000"),
      totalMs: integer("timeout-ms", "600000"),
      pollMs: integer("poll-interval-ms", "2000"),
      attempts: integer("request-attempts", "2"),
      maxPages: integer("max-event-pages", "10"),
      responseBytes: 1048576,
    },
    {
      oidcURL: env.ACTIONS_ID_TOKEN_REQUEST_URL,
      oidcToken: env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
      mask,
      signal: abort.signal,
    },
  );
  // Only package-created enums and validated UUIDs reach runner commands/output.
  for (const [key, value] of Object.entries(result)) {
    if (env.GITHUB_OUTPUT)
      await appendFile(env.GITHUB_OUTPUT, `${key}=${value}\n`);
  }
  process.stdout.write(`Provenance Action: ${result.outcome}\n`);
  if (["incomplete", "failed", "canceled"].includes(result.outcome))
    process.exitCode = 1;
}
if (typeof require !== "undefined" && require.main === module)
  main().catch(() => {
    process.stdout.write(
      "::error::Provenance Action unavailable; verify explicit inputs and supported workflow context. No credentials were printed.\n",
    );
    process.exitCode = 1;
  });
