import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const includeHostile = process.argv.includes("--include-hostile");
const write = process.argv.includes("--write");

if (write && !includeHostile) {
  throw new Error(
    "--write requires --include-hostile so the manifest stays complete",
  );
}

const benign = [
  "success",
  "on-load-failure",
  "on-enable-failure",
  "missing-dependency",
  "command-success",
  "command-assertion-failure",
];
const hostile = [
  "enable-hang",
  "process-exit",
  "memory-bomb",
  "fork-pid-bomb",
  "disk-fill",
  "network-scan",
  "metadata-endpoint",
  "log-flood",
];

const manifestPath = join(root, "test-data", "fixture-jars.sha256");
const build = readFileSync(resolve(root, "..", "..", "build.gradle"), "utf8");
for (const name of hostile) {
  const sourceDir = join(root, "hostile", name, "src", "main", "java");
  const sourcePath = findJavaSource(sourceDir);
  const source = readFileSync(sourcePath, "utf8");
  if (
    !source.includes('Boolean.getBoolean("provenance.fixture.hostile.enabled")')
  ) {
    throw new Error(`${name} does not contain the runtime opt-in guard`);
  }
  if (name === "fork-pid-bomb") {
    verifyDeterministicForkPidFixture(source);
  }
}
if (!build.includes('tasks.register("hostileFixtures")')) {
  throw new Error(
    "hostile fixtures do not have an explicit opt-in Gradle task",
  );
}
const defaultCheck = build.slice(build.lastIndexOf('tasks.named("check")'));
const defaultCheckBody = defaultCheck.slice(0, defaultCheck.indexOf("}"));
for (const marker of [
  '":fixture-fork-pid-bomb:test"',
  '"verifyHostileFixtureArtifacts"',
]) {
  if (!defaultCheckBody.includes(marker)) {
    throw new Error(
      `default check is missing bounded hostile guard: ${marker}`,
    );
  }
}

const selected = [
  ...benign.map((name) => ["benign", name]),
  ...(includeHostile ? hostile.map((name) => ["hostile", name]) : []),
];
const actualHashes = new Map();
for (const [category, name] of selected) {
  const jar = join(root, category, name, "build", "libs", `${name}-1.0.0.jar`);
  if (!existsSync(jar)) {
    throw new Error(`missing fixture JAR: ${jar}`);
  }
  const actual = createHash("sha256").update(readFileSync(jar)).digest("hex");
  actualHashes.set(`${name}-1.0.0.jar`, actual);
  process.stdout.write(`${actual}  ${name}-1.0.0.jar\n`);
}

if (write) {
  const manifest = [...actualHashes]
    .map(([name, hash]) => `${hash}  ${name}`)
    .join("\n");
  writeFileSync(manifestPath, `${manifest}\n`);
  process.stdout.write(
    `wrote ${actualHashes.size} hashes to ${manifestPath}\n`,
  );
} else {
  const expectedHashes = new Map(
    readFileSync(manifestPath, "utf8")
      .trim()
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => {
        const [hash, name] = line.split(/\s+/, 2);
        return [name, hash];
      }),
  );
  for (const [name, actual] of actualHashes) {
    const expected = expectedHashes.get(name);
    if (actual !== expected) {
      throw new Error(
        `${name} hash mismatch: expected ${expected}, got ${actual}`,
      );
    }
  }
}

process.stdout.write(
  `verified ${selected.length} fixture JARs; hostile payload execution was not invoked\n`,
);

function findJavaSource(directory) {
  const stack = [directory];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) stack.push(path);
      if (entry.isFile() && entry.name.endsWith(".java")) return path;
    }
  }
  throw new Error(`no Java source under ${directory}`);
}

function verifyDeterministicForkPidFixture(source) {
  const onEnable = source.match(
    /public void onEnable\(\) \{(?<body>[\s\S]*?)\n  \}/,
  )?.groups?.body;
  if (
    !onEnable ||
    /ProcessBuilder|startOnce|childStarter\.start/.test(onEnable)
  ) {
    throw new Error("fork-pid-bomb must not create children during onEnable");
  }

  const required = [
    "@EventHandler(priority = EventPriority.MONITOR)",
    "ServerLoadEvent",
    "AtomicBoolean",
    "compareAndSet(false, true)",
    "retainedChildren.add",
    '": error=11,"',
    '": error=12,"',
    "SleeperPressureHold::sustain",
    "HOLD_MILLIS = 2_000",
    "Thread.sleep(HOLD_MILLIS)",
    "releaseAll",
    "terminateAndReap",
    "child.waitFor",
    "retainedChildren.clear()",
    'Path.of("/usr/bin/sleep")',
    'Path.of("/bin/sleep")',
    "builder.environment().clear()",
  ];
  for (const marker of required) {
    if (!source.includes(marker)) {
      throw new Error(
        `fork-pid-bomb is missing deterministic guard: ${marker}`,
      );
    }
  }

  const forbidden = [
    "ForkPidBombProcess",
    "java.home",
    "spawnChildren",
    "releaseAllButOne",
    "Process survivor",
  ];
  for (const marker of forbidden) {
    if (source.includes(marker)) {
      throw new Error(
        `fork-pid-bomb contains recursive child behavior: ${marker}`,
      );
    }
  }
}
