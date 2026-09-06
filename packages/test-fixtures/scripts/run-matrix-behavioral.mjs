import { spawn, spawnSync } from "node:child_process";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  evaluateFixtureEvidence,
  identifyFile,
  parseProbeNdjson,
} from "./paper-behavioral-lib.mjs";

export const matrix = Object.freeze([
  {
    version: "1.20.6",
    build: 151,
    paper: "4b011f5adb5f6c72007686a223174fce82f31aeb4b34faf4652abc840b47e640",
    runtime: "17d5ef6f69ea92bb6b2e136ea572a150eb50f52fb005243228ef76e8ad0520e0",
    passed: false,
  },
  {
    version: "1.21.4",
    build: 232,
    paper: "5ee4f542f628a14c644410b08c94ea42e772ef4d29fe92973636b6813d4eaffc",
    runtime: "bc38b0397a3e2e53508e6341475bcf3aeb07c138996b9ce823b39a82e5b24110",
    passed: false,
  },
  {
    version: "1.21.8",
    build: 60,
    paper: "8de7c52c3b02403503d16fac58003f1efef7dd7a0256786843927fa92ee57f1e",
    runtime: "ba1434cfc3af6fe145660e82f5b07ce9cb46cbc76d23c68a767a3717e7e5ca57",
    passed: true,
  },
]);

export function definition(environment) {
  return {
    targetPlugin: "ProvenanceMatrixCompatibility",
    testPlan: { console: [] },
    expectedClassifications: environment.passed ? [] : ["on_enable_failure"],
    requiredEvents: [
      {
        type: "TARGET_REQUIREMENT",
        data: {
          name: "ProvenanceMatrixCompatibility",
          configured: true,
          loaded: true,
          enabled: environment.passed,
        },
      },
      {
        type: "SERVER_READY",
        data: { requirementsSatisfied: environment.passed },
      },
      ...(environment.passed
        ? []
        : [
            {
              type: "LIFECYCLE_EXCEPTION",
              data: {
                phase: "ENABLE",
                plugin: "ProvenanceMatrixCompatibility",
              },
            },
          ]),
    ],
  };
}

// This is an opt-in benign producer proof, not the hosted/sandbox exit gate.
// Inputs are already-downloaded immutable runtime archives; no host services,
// credentials, or network listeners outside loopback are used.
export async function main(args) {
  if (args[0] === "--") args = args.slice(1);
  if (args.length !== 3)
    throw new Error(
      "usage: run-matrix-behavioral.mjs <asset-directory> <java-executable> <new-evidence-directory>",
    );
  const [assets, java, evidence] = args.map((value) => resolve(value));
  await mkdir(evidence, { mode: 0o700 }); // Must be new; never reuse old evidence.
  const root = resolve(import.meta.dirname, "../../..");
  const fixture = join(
    root,
    "packages/test-fixtures/benign/matrix-compatibility/build/libs/matrix-compatibility-1.0.0.jar",
  );
  const probe = join(
    root,
    "plugins/paper-probe/build/libs/paper-probe-0.1.0.jar",
  );
  const fixtureIdentity = await identifyFile(fixture),
    probeIdentity = await identifyFile(probe);
  const manifest = await readFile(
    join(root, "packages/test-fixtures/test-data/fixture-jars.sha256"),
    "utf8",
  );
  if (
    !manifest
      .split("\n")
      .includes(`${fixtureIdentity.sha256}  matrix-compatibility-1.0.0.jar`)
  )
    throw new Error("fixture differs from reviewed manifest");
  const version = spawnSync(java, ["-XshowSettings:properties", "-version"], {
    encoding: "utf8",
    timeout: 10000,
    maxBuffer: 65536,
  });
  if (
    version.status !== 0 ||
    !version.stderr.includes("java.runtime.version = 21.0.8+9-LTS") ||
    !version.stderr.includes("java.vendor = Eclipse Adoptium")
  )
    throw new Error("requires exact Temurin21.0.8+9 runtime");
  const summary = {
    schemaVersion: "provenance.matrix-fixture-proof/v1",
    fixture: fixtureIdentity,
    probe: probeIdentity,
    java: {
      version: "21.0.8+9-LTS",
      vendor: "Eclipse Adoptium",
      executable: await identifyFile(java),
    },
    environments: [],
    passed: false,
  };
  try {
    for (const environment of matrix) {
      const archive = join(assets, `runtime-${environment.version}.tar.gz`);
      const paper = join(
        assets,
        `paper-${environment.version}-${environment.build}.jar`,
      );
      const archiveIdentity = await identifyFile(archive),
        paperIdentity = await identifyFile(paper);
      if (
        archiveIdentity.sha256 !== environment.runtime ||
        paperIdentity.sha256 !== environment.paper
      )
        throw new Error("prepared runtime or Paper identity mismatch");
      const caseRoot = join(evidence, environment.version);
      await mkdir(caseRoot, { mode: 0o700 });
      // Known digest archives are extracted only into a newly-created directory.
      const extracted = spawnSync(
        "tar",
        ["-xzf", archive, "-C", caseRoot, "--no-same-owner"],
        { timeout: 30000, maxBuffer: 65536 },
      );
      if (extracted.status !== 0)
        throw new Error("prepared runtime extraction failed");
      await mkdir(join(caseRoot, "plugins"));
      await copyFile(
        fixture,
        join(caseRoot, "plugins/matrix-compatibility.jar"),
      );
      await copyFile(probe, join(caseRoot, "plugins/paper-probe.jar"));
      await writeFile(join(caseRoot, "eula.txt"), "eula=true\n");
      await writeFile(
        join(caseRoot, "server.properties"),
        "server-ip=127.0.0.1\nserver-port=0\nonline-mode=false\nenable-query=false\nenable-rcon=false\nmax-players=1\nview-distance=2\nsimulation-distance=2\nspawn-protection=0\ngenerate-structures=false\nlevel-type=minecraft:flat\n",
      );
      await writeFile(join(caseRoot, "plan.json"), '{"console":[]}\n');
      const eventPath = join(caseRoot, "probe.ndjson");
      const started = Date.now();
      const execution = await run(
        java,
        [
          "-Xms256M",
          "-Xmx768M",
          "-Dprovenance.probe.target=ProvenanceMatrixCompatibility",
          `-Dprovenance.probe.events=${eventPath}`,
          `-Dprovenance.probe.testPlan=${join(caseRoot, "plan.json")}`,
          "-Dprovenance.probe.stabilizationMillis=10000",
          "-Dprovenance.probe.requestShutdown=true",
          "-jar",
          paper,
          "--nogui",
        ],
        caseRoot,
      );
      const events = parseProbeNdjson(await readFile(eventPath, "utf8"));
      const observed = evaluateFixtureEvidence(definition(environment), events);
      const row = {
        version: environment.version,
        build: environment.build,
        runtime: archiveIdentity,
        paper: paperIdentity,
        fixture: await identifyFile(
          join(caseRoot, "plugins/matrix-compatibility.jar"),
        ),
        probe: await identifyFile(join(caseRoot, "plugins/paper-probe.jar")),
        durationMillis: Date.now() - started,
        execution,
        classifications: events
          .filter((event) => event.type === "CLASSIFICATION")
          .map((event) => event.data.code),
        lifecycle: events
          .filter((event) =>
            [
              "PROBE_LOADED",
              "LIFECYCLE_EXCEPTION",
              "SERVER_READY",
              "SERVER_STOPPED",
            ].includes(event.type),
          )
          .map((event) => ({
            type: event.type,
            elapsedMillis: Date.parse(event.timestamp) - started,
          })),
        events: await identifyFile(eventPath),
        failures: observed.failures,
        passed:
          execution.code === 0 &&
          !execution.boundedFailure &&
          observed.failures.length === 0,
      };
      if (
        row.fixture.sha256 !== fixtureIdentity.sha256 ||
        row.probe.sha256 !== probeIdentity.sha256
      )
        throw new Error("artifact bytes changed across environments");
      summary.environments.push(row);
      process.stdout.write(
        `${environment.version}: ${row.passed ? "PASS" : "FAIL"} ${JSON.stringify(row.classifications)}\n`,
      );
    }
    summary.passed =
      summary.environments.length === 3 &&
      summary.environments.every((row) => row.passed);
  } finally {
    await writeFile(
      join(evidence, "summary.json"),
      JSON.stringify(summary, null, 2) + "\n",
      { mode: 0o600 },
    );
  }
  if (!summary.passed)
    throw new Error(
      "same-byte three-environment proof failed; inspect bounded summary",
    );
}

async function run(java, args, cwd) {
  const child = spawn(java, args, {
    cwd,
    env: { PATH: process.env.PATH, LANG: "C.UTF-8" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const output = [];
  let size = 0,
    boundedFailure = false;
  const stop = () => {
    boundedFailure = true;
    child.kill("SIGKILL");
  };
  const timer = setTimeout(stop, 180000);
  for (const stream of [child.stdout, child.stderr])
    stream.on("data", (chunk) => {
      size += chunk.length;
      if (size > 4 * 1048576) stop();
      else output.push(chunk);
    });
  try {
    const code = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", resolve);
    });
    await writeFile(join(cwd, "process.log"), Buffer.concat(output), {
      mode: 0o600,
    });
    return { code, boundedFailure, outputBytes: size };
  } finally {
    clearTimeout(timer);
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
