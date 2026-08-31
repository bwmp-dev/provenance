import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { once } from "node:events";
import {
  evaluateFixtureEvidence,
  identifyFile,
  loadHarnessConfiguration,
  parseProbeNdjson,
  sha256File,
} from "./paper-behavioral-lib.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const testData = resolve(import.meta.dirname, "../test-data");
const maximumProcessOutputBytes = 4 * 1_048_576;
const maximumProbeBytes = 1_048_576;
const maximumProbeEvents = 1_024;
const paperUserAgent =
  "bwmp-dev-provenance/0.1 (https://github.com/bwmp-dev/provenance)";

const options = parseArguments(process.argv.slice(2));
if (options.help) {
  process.stdout.write(`Usage: pnpm run paper:behavioral -- [options]

Runs exactly the six benign Plan 02 fixtures in separate real Paper processes.

Options:
  --java PATH                 Java executable (or PAPER_BEHAVIOR_JAVA)
  --timeout-seconds NUMBER    Per-process wall timeout, 60-600 (default: 180)
  --cache-directory PATH      Verified Paper download cache
  --evidence-directory PATH   Retained run directory and JSON summary
  --help                      Show this help
`);
  process.exit(0);
}

await main();

async function main() {
  const paperPath = join(testData, "paper-development.json");
  const fixturesPath = join(testData, "paper-behavioral-fixtures.json");
  const configuration = await loadHarnessConfiguration(
    repositoryRoot,
    paperPath,
    fixturesPath,
  );
  const runId = `${new Date().toISOString().replaceAll(":", "-")}-${process.pid}`;
  const evidenceRoot = resolve(
    repositoryRoot,
    options.evidenceDirectory ?? join("build", "paper-behavioral", runId),
  );
  const cacheRoot = resolve(
    repositoryRoot,
    options.cacheDirectory ?? join(".cache", "paper-behavioral"),
  );
  await mkdir(dirname(evidenceRoot), { recursive: true });
  await mkdir(evidenceRoot, { recursive: false });
  await mkdir(cacheRoot, { recursive: true });
  const summaryPath = join(evidenceRoot, "summary.json");
  const repository = repositoryIdentity();
  const summary = {
    schemaVersion: 1,
    runId,
    startedAt: new Date().toISOString(),
    completedAt: null,
    passed: false,
    repository,
    paper: configuration.paper,
    java: null,
    probe: null,
    limits: {
      processTimeoutSeconds: options.timeoutSeconds,
      maximumProcessOutputBytes,
      maximumProbeBytes,
      maximumProbeEvents,
    },
    fixtures: [],
    fatalError: null,
  };
  await writeSummary(summaryPath, summary);

  try {
    const javaExecutable = await resolveJavaExecutable(options.java);
    summary.java = await javaIdentity(javaExecutable);
    if (summary.java.majorVersion < configuration.paper.minimumJavaMajor) {
      throw new Error(
        `Java ${summary.java.majorVersion} is below Paper's pinned minimum ${configuration.paper.minimumJavaMajor}`,
      );
    }
    await writeSummary(summaryPath, summary);

    process.stdout.write(
      "Building and hash-verifying the six benign fixtures and probe...\n",
    );
    await runBuild(evidenceRoot);
    const fixtureHashes = await loadFixtureHashes();
    const probePath = resolve(
      repositoryRoot,
      "plugins/paper-probe/build/libs/paper-probe-0.1.0.jar",
    );
    summary.probe = {
      name: "ProvenanceProbe",
      version: "0.1.0",
      artifactPath: relative(repositoryRoot, probePath).replaceAll("\\", "/"),
      ...(await identifyFile(probePath)),
    };

    const paperJar = await acquirePaper(configuration.paper, cacheRoot);
    summary.paper.artifactPath = paperJar;
    summary.paper.verified = true;
    await writeSummary(summaryPath, summary);

    for (const fixture of configuration.fixtures) {
      process.stdout.write(`Running ${fixture.id}...\n`);
      const result = await runFixture({
        fixture,
        fixtureHashes,
        probePath,
        paperJar,
        javaExecutable,
        evidenceRoot,
      });
      summary.fixtures.push(result);
      await writeSummary(summaryPath, summary);
      process.stdout.write(
        `${fixture.id}: ${result.passed ? "PASS" : "FAIL"} (${result.durationMillis} ms, ${result.eventCount ?? 0} events)\n`,
      );
    }

    summary.completedAt = new Date().toISOString();
    summary.passed = summary.fixtures.every((fixture) => fixture.passed);
    await writeSummary(summaryPath, summary);
    process.stdout.write(`Evidence: ${summaryPath}\n`);
    if (!summary.passed) process.exitCode = 1;
  } catch (error) {
    summary.completedAt = new Date().toISOString();
    summary.fatalError = error instanceof Error ? error.message : String(error);
    await writeSummary(summaryPath, summary);
    process.stderr.write(`${summary.fatalError}\nEvidence: ${summaryPath}\n`);
    process.exitCode = 1;
  }
}

async function runFixture({
  fixture,
  fixtureHashes,
  probePath,
  paperJar,
  javaExecutable,
  evidenceRoot,
}) {
  const startedAt = new Date().toISOString();
  const caseRoot = join(evidenceRoot, "runs", fixture.id);
  const pluginsRoot = join(caseRoot, "plugins");
  await mkdir(pluginsRoot, { recursive: true });
  const fixturePath = resolve(repositoryRoot, fixture.artifactPath);
  const fixtureIdentity = await identifyFile(fixturePath);
  const fixtureName = basename(fixturePath);
  const expectedFixtureHash = fixtureHashes.get(fixtureName);
  if (!expectedFixtureHash || fixtureIdentity.sha256 !== expectedFixtureHash) {
    throw new Error(
      `${fixture.id} hash mismatch: expected ${expectedFixtureHash ?? "no manifest entry"}, observed ${fixtureIdentity.sha256}`,
    );
  }
  await Promise.all([
    copyFile(fixturePath, join(pluginsRoot, fixtureName)),
    copyFile(probePath, join(pluginsRoot, basename(probePath))),
    writeFile(join(caseRoot, "eula.txt"), "eula=true\n", "utf8"),
    writeFile(join(caseRoot, "server.properties"), serverProperties(), "utf8"),
    writeFile(
      join(caseRoot, "provenance-test-plan.json"),
      `${JSON.stringify(fixture.testPlan, null, 2)}\n`,
      "utf8",
    ),
  ]);

  const eventsPath = join(caseRoot, "provenance-probe-events.ndjson");
  const processResult = await runBoundedProcess(
    javaExecutable,
    [
      "-Xms256M",
      "-Xmx768M",
      `-Dprovenance.probe.target=${fixture.targetPlugin}`,
      `-Dprovenance.probe.events=${eventsPath}`,
      `-Dprovenance.probe.testPlan=${join(caseRoot, "provenance-test-plan.json")}`,
      "-Dprovenance.probe.stabilizationMillis=500",
      "-Dprovenance.probe.maximumCommandOutputBytes=4096",
      "-Dprovenance.probe.requestShutdown=true",
      "-jar",
      paperJar,
      "--nogui",
    ],
    caseRoot,
    options.timeoutSeconds * 1_000,
  );
  const [stdoutPath, stderrPath] = [
    join(caseRoot, "process.stdout.log"),
    join(caseRoot, "process.stderr.log"),
  ];
  await Promise.all([
    writeFile(stdoutPath, Buffer.concat(processResult.stdout)),
    writeFile(stderrPath, Buffer.concat(processResult.stderr)),
  ]);

  const failures = [];
  if (processResult.timedOut)
    failures.push("Paper process exceeded its wall timeout");
  if (processResult.outputLimitExceeded) {
    failures.push("Paper process exceeded its combined output limit");
  }
  if (processResult.code !== 0) {
    failures.push(
      `Paper process exited with code ${processResult.code} and signal ${processResult.signal}`,
    );
  }

  let evidence = null;
  let eventsIdentity = null;
  try {
    const eventSource = await readFile(eventsPath, "utf8");
    const events = parseProbeNdjson(eventSource, {
      maximumBytes: maximumProbeBytes,
      maximumEvents: maximumProbeEvents,
    });
    evidence = evaluateFixtureEvidence(fixture, events);
    failures.push(...evidence.failures);
    eventsIdentity = await identifyFile(eventsPath);
  } catch (error) {
    failures.push(
      `structured probe evidence is invalid: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const [stdoutSha256, stderrSha256] = await Promise.all([
    sha256File(stdoutPath),
    sha256File(stderrPath),
  ]);
  return {
    id: fixture.id,
    targetPlugin: fixture.targetPlugin,
    startedAt,
    completedAt: new Date().toISOString(),
    durationMillis: processResult.durationMillis,
    passed: failures.length === 0,
    failures,
    artifact: {
      path: fixture.artifactPath,
      expectedSha256: expectedFixtureHash,
      ...fixtureIdentity,
    },
    commandPlan: fixture.testPlan,
    expectedClassifications: fixture.expectedClassifications,
    observedClassifications: evidence?.classifications ?? [],
    eventCount: evidence?.eventCount ?? null,
    eventTypes: evidence?.eventTypes ?? {},
    process: {
      exitCode: processResult.code,
      signal: processResult.signal,
      timedOut: processResult.timedOut,
      outputLimitExceeded: processResult.outputLimitExceeded,
      observedOutputBytes: processResult.observedOutputBytes,
      stdout: {
        path: relative(evidenceRoot, stdoutPath).replaceAll("\\", "/"),
        retainedBytes: processResult.stdoutBytes,
        sha256: stdoutSha256,
      },
      stderr: {
        path: relative(evidenceRoot, stderrPath).replaceAll("\\", "/"),
        retainedBytes: processResult.stderrBytes,
        sha256: stderrSha256,
      },
    },
    events:
      eventsIdentity === null
        ? null
        : {
            path: relative(evidenceRoot, eventsPath).replaceAll("\\", "/"),
            ...eventsIdentity,
          },
  };
}

async function acquirePaper(paper, cacheRoot) {
  const destination = join(cacheRoot, paper.download.name);
  try {
    const identity = await identifyFile(destination);
    verifyPaperIdentity(paper, identity);
    process.stdout.write(`Using verified Paper cache entry ${destination}\n`);
    return destination;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }

  const temporary = `${destination}.partial-${process.pid}`;
  const response = await fetch(paper.download.url, {
    headers: { "User-Agent": paperUserAgent },
    redirect: "follow",
  });
  if (!response.ok || response.body === null) {
    throw new Error(`Paper download failed with HTTP ${response.status}`);
  }
  const output = await open(temporary, "wx");
  const digest = createHash("sha256");
  let sizeBytes = 0;
  try {
    for await (const chunk of response.body) {
      sizeBytes += chunk.byteLength;
      if (sizeBytes > paper.download.sizeBytes) {
        throw new Error("Paper download exceeded its pinned size");
      }
      digest.update(chunk);
      await output.write(chunk);
    }
  } catch (error) {
    await output.close();
    await rm(temporary, { force: true });
    throw error;
  }
  await output.close();
  const identity = { sizeBytes, sha256: digest.digest("hex") };
  try {
    verifyPaperIdentity(paper, identity);
    await rename(temporary, destination);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
  process.stdout.write(`Downloaded and verified ${paper.download.name}\n`);
  return destination;
}

function verifyPaperIdentity(paper, identity) {
  if (
    identity.sizeBytes !== paper.download.sizeBytes ||
    identity.sha256 !== paper.download.sha256
  ) {
    throw new Error(
      `Paper artifact identity mismatch: expected ${paper.download.sizeBytes}/${paper.download.sha256}, observed ${identity.sizeBytes}/${identity.sha256}`,
    );
  }
}

async function runBuild(evidenceRoot) {
  const result = spawnSync(
    process.execPath,
    [
      "scripts/run-gradle.mjs",
      ":paper-probe:jar",
      "verifySafeFixtureArtifacts",
    ],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      maxBuffer: 8 * 1_048_576,
      timeout: 600_000,
      windowsHide: true,
    },
  );
  const buildLog = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  await writeFile(join(evidenceRoot, "build.log"), buildLog, "utf8");
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`benign fixture/probe build exited with ${result.status}`);
  }
}

async function loadFixtureHashes() {
  const source = await readFile(join(testData, "fixture-jars.sha256"), "utf8");
  const hashes = new Map();
  for (const line of source.trim().split(/\r?\n/)) {
    const match = /^([a-f0-9]{64})\s+([^/\\]+\.jar)$/.exec(line);
    if (!match) throw new Error("fixture hash manifest has an invalid line");
    hashes.set(match[2], match[1]);
  }
  return hashes;
}

async function javaIdentity(executable) {
  const result = spawnSync(
    executable,
    ["-XshowSettings:properties", "-version"],
    {
      encoding: "utf8",
      maxBuffer: 1_048_576,
      timeout: 30_000,
      windowsHide: true,
    },
  );
  if (result.error) throw result.error;
  if (result.status !== 0)
    throw new Error(`Java identity command exited with ${result.status}`);
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  const property = (name) => {
    const match = new RegExp(
      `^\\s*${name.replaceAll(".", "\\.")} = (.+)$`,
      "m",
    ).exec(output);
    return match?.[1].trim() ?? null;
  };
  const version = property("java.version");
  const majorVersion = parseJavaMajor(version);
  return {
    executable,
    executableSha256: await sha256File(executable),
    version,
    majorVersion,
    vendor: property("java.vendor"),
    runtimeVersion: property("java.runtime.version"),
    vmName: property("java.vm.name"),
    vmVersion: property("java.vm.version"),
    javaHome: property("java.home"),
    osName: property("os.name"),
    osArchitecture: property("os.arch"),
    versionOutput: output.trim().split(/\r?\n/).filter(Boolean),
  };
}

function parseJavaMajor(version) {
  if (typeof version !== "string")
    throw new Error("Java did not report java.version");
  const match = /^(?:1\.)?(\d+)/.exec(version);
  if (!match) throw new Error(`could not parse Java version ${version}`);
  return Number.parseInt(match[1], 10);
}

async function resolveJavaExecutable(configured) {
  const requested =
    configured ?? process.env.PAPER_BEHAVIOR_JAVA ?? defaultJava();
  if (requested.includes("/") || requested.includes("\\")) {
    return realpath(resolve(requested));
  }
  const resolver = process.platform === "win32" ? "where.exe" : "which";
  const result = spawnSync(resolver, [requested], {
    encoding: "utf8",
    maxBuffer: 65_536,
    timeout: 10_000,
    windowsHide: true,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`could not resolve Java executable ${requested}`);
  }
  return realpath(result.stdout.trim().split(/\r?\n/)[0]);
}

function defaultJava() {
  if (process.env.JAVA_HOME) {
    return join(
      process.env.JAVA_HOME,
      "bin",
      process.platform === "win32" ? "java.exe" : "java",
    );
  }
  return "java";
}

async function runBoundedProcess(executable, arguments_, cwd, timeoutMillis) {
  const started = Date.now();
  const child = spawn(executable, arguments_, {
    cwd,
    env: process.env,
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  const stdout = [];
  const stderr = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let observedOutputBytes = 0;
  let timedOut = false;
  let outputLimitExceeded = false;
  let terminated = false;

  const terminate = () => {
    if (terminated) return;
    terminated = true;
    child.kill("SIGKILL");
  };
  const capture = (destination, chunk, stream) => {
    observedOutputBytes += chunk.byteLength;
    const retained = stdoutBytes + stderrBytes;
    const remaining = Math.max(0, maximumProcessOutputBytes - retained);
    if (remaining > 0) {
      const selected = chunk.subarray(0, remaining);
      destination.push(selected);
      if (stream === "stdout") stdoutBytes += selected.byteLength;
      else stderrBytes += selected.byteLength;
    }
    if (observedOutputBytes > maximumProcessOutputBytes) {
      outputLimitExceeded = true;
      terminate();
    }
  };
  child.stdout.on("data", (chunk) => capture(stdout, chunk, "stdout"));
  child.stderr.on("data", (chunk) => capture(stderr, chunk, "stderr"));
  child.on("error", terminate);
  const timeout = setTimeout(() => {
    timedOut = true;
    terminate();
  }, timeoutMillis);
  let code;
  let signal;
  try {
    [code, signal] = await once(child, "close");
  } finally {
    clearTimeout(timeout);
  }
  return {
    code,
    signal,
    timedOut,
    outputLimitExceeded,
    observedOutputBytes,
    stdout,
    stderr,
    stdoutBytes,
    stderrBytes,
    durationMillis: Date.now() - started,
  };
}

function serverProperties() {
  return [
    "accepts-transfers=false",
    "allow-flight=false",
    "enable-query=false",
    "enable-rcon=false",
    "enable-status=false",
    "enforce-secure-profile=false",
    "generate-structures=false",
    "level-name=fixture-world",
    "max-players=1",
    "motd=Provenance behavioral fixture",
    "online-mode=false",
    "server-ip=127.0.0.1",
    "server-port=0",
    "simulation-distance=2",
    "spawn-animals=false",
    "spawn-monsters=false",
    "spawn-npcs=false",
    "sync-chunk-writes=true",
    "view-distance=2",
    "white-list=true",
    "",
  ].join("\n");
}

function repositoryIdentity() {
  const commit = git(["rev-parse", "HEAD"]);
  const status = git(["status", "--short"]);
  return {
    commit,
    dirty: status.length > 0,
    changedPaths: status.length === 0 ? [] : status.split(/\r?\n/),
  };
}

function git(arguments_) {
  const result = spawnSync("git", arguments_, {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 1_048_576,
    timeout: 30_000,
    windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== 0)
    throw new Error(`git ${arguments_.join(" ")} failed`);
  return result.stdout.trim();
}

async function writeSummary(path, summary) {
  const temporary = `${path}.partial`;
  await writeFile(temporary, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  await rename(temporary, path);
}

function parseArguments(arguments_) {
  const result = {
    help: false,
    java: null,
    timeoutSeconds: 180,
    cacheDirectory: null,
    evidenceDirectory: null,
  };
  for (let index = 0; index < arguments_.length; index++) {
    const argument = arguments_[index];
    if (argument === "--") continue;
    if (argument === "--help") {
      result.help = true;
      continue;
    }
    if (
      argument !== "--java" &&
      argument !== "--timeout-seconds" &&
      argument !== "--cache-directory" &&
      argument !== "--evidence-directory"
    ) {
      throw new Error(`unknown argument ${argument}`);
    }
    const value = arguments_[++index];
    if (!value || value.startsWith("--")) {
      throw new Error(`${argument} requires a value`);
    }
    if (argument === "--java") result.java = value;
    if (argument === "--cache-directory") result.cacheDirectory = value;
    if (argument === "--evidence-directory") result.evidenceDirectory = value;
    if (argument === "--timeout-seconds") {
      result.timeoutSeconds = Number(value);
      if (
        !Number.isSafeInteger(result.timeoutSeconds) ||
        result.timeoutSeconds < 60 ||
        result.timeoutSeconds > 600
      ) {
        throw new Error("--timeout-seconds must be an integer from 60 to 600");
      }
    }
  }
  return result;
}
