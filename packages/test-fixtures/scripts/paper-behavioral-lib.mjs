import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

export const SAFE_FIXTURES = Object.freeze([
  "success",
  "on-load-failure",
  "on-enable-failure",
  "missing-dependency",
  "command-success",
  "command-assertion-failure",
]);

const EVENT_SEQUENCE = [
  "PROBE_LOADED",
  "SERVER_LOADED",
  "STABILIZATION_STARTED",
  "STABILIZATION_COMPLETED",
  "SERVER_READY",
  "CLEAN_SHUTDOWN_REQUESTED",
  "SERVER_STOPPED",
];

const PAPER_FIELDS = new Set([
  "schemaVersion",
  "project",
  "minecraftVersion",
  "build",
  "channel",
  "minimumJavaMajor",
  "download",
]);
const DOWNLOAD_FIELDS = new Set(["name", "url", "sha256", "sizeBytes"]);
const FIXTURE_ROOT_FIELDS = new Set(["schemaVersion", "fixtures"]);
const FIXTURE_FIELDS = new Set([
  "id",
  "targetPlugin",
  "artifactPath",
  "testPlan",
  "expectedClassifications",
  "requiredEvents",
]);
const EVENT_FIELDS = new Set(["type", "data"]);

export async function loadHarnessConfiguration(
  repositoryRoot,
  paperPath,
  fixturesPath,
) {
  const [paperSource, fixturesSource] = await Promise.all([
    readFile(paperPath, "utf8"),
    readFile(fixturesPath, "utf8"),
  ]);
  const paper = parseJson(paperSource, "Paper development artifact");
  const fixtureDocument = parseJson(
    fixturesSource,
    "behavioral fixture matrix",
  );
  validatePaper(paper);
  validateFixtures(repositoryRoot, fixtureDocument);
  return { paper, fixtures: fixtureDocument.fixtures };
}

export function parseProbeNdjson(source, options = {}) {
  const maximumBytes = options.maximumBytes ?? 1_048_576;
  const maximumEvents = options.maximumEvents ?? 1_024;
  const bytes = Buffer.byteLength(source, "utf8");
  if (bytes === 0) throw new Error("probe event file is empty");
  if (bytes > maximumBytes) {
    throw new Error(`probe event file exceeds ${maximumBytes} bytes`);
  }
  if (!source.endsWith("\n")) {
    throw new Error(
      "probe event file does not end with a complete NDJSON line",
    );
  }
  const lines = source.slice(0, -1).split(/\r?\n/);
  if (lines.length > maximumEvents) {
    throw new Error(`probe event file exceeds ${maximumEvents} events`);
  }
  return lines.map((line, index) => {
    if (line.length === 0) {
      throw new Error(`probe event line ${index + 1} is empty`);
    }
    if (Buffer.byteLength(line, "utf8") > 131_072) {
      throw new Error(`probe event line ${index + 1} exceeds 131072 bytes`);
    }
    const event = parseJson(line, `probe event line ${index + 1}`);
    if (
      typeof event.timestamp !== "string" ||
      Number.isNaN(Date.parse(event.timestamp)) ||
      typeof event.type !== "string" ||
      !/^[A-Z][A-Z0-9_]*$/.test(event.type) ||
      !isPlainObject(event.data)
    ) {
      throw new Error(`probe event line ${index + 1} has an invalid envelope`);
    }
    return event;
  });
}

export function evaluateFixtureEvidence(definition, events) {
  const failures = [];
  const observedClassifications = events
    .filter((event) => event.type === "CLASSIFICATION")
    .map((event) => event.data.code);
  if (
    JSON.stringify(observedClassifications) !==
    JSON.stringify(definition.expectedClassifications)
  ) {
    failures.push(
      `classifications: expected ${JSON.stringify(definition.expectedClassifications)}, observed ${JSON.stringify(observedClassifications)}`,
    );
  }

  for (const required of definition.requiredEvents) {
    if (!events.some((event) => eventMatches(event, required))) {
      failures.push(`missing event ${JSON.stringify(required)}`);
    }
  }

  let previous = -1;
  for (const type of EVENT_SEQUENCE) {
    const index = events.findIndex((event, candidate) => {
      return candidate > previous && event.type === type;
    });
    if (index === -1) {
      failures.push(`missing ordered lifecycle event ${type}`);
    } else {
      previous = index;
    }
  }

  const metadata = events.find(
    (event) =>
      event.type === "METADATA_INSPECTION" &&
      event.data.name === definition.targetPlugin,
  );
  if (!metadata || metadata.data.status !== "VALID") {
    failures.push(
      `missing valid metadata inspection for ${definition.targetPlugin}`,
    );
  }

  const loadedPlan = events.find(
    (event) => event.type === "TEST_PLAN" && event.data.status === "LOADED",
  );
  const expectedConsoleTests = definition.testPlan.console.length;
  if (!loadedPlan || loadedPlan.data.consoleTests !== expectedConsoleTests) {
    failures.push(
      `missing loaded test plan with ${expectedConsoleTests} console tests`,
    );
  }

  return {
    passed: failures.length === 0,
    failures,
    eventCount: events.length,
    eventTypes: countValues(events.map((event) => event.type)),
    classifications: observedClassifications,
  };
}

export async function sha256File(path) {
  const source = await readFile(path);
  return createHash("sha256").update(source).digest("hex");
}

export async function identifyFile(path) {
  const [details, sha256] = await Promise.all([stat(path), sha256File(path)]);
  if (!details.isFile()) throw new Error(`not a regular file: ${path}`);
  return { sizeBytes: details.size, sha256 };
}

function validatePaper(paper) {
  requireExactFields(paper, PAPER_FIELDS, "Paper development artifact");
  if (
    paper.schemaVersion !== 1 ||
    paper.project !== "paper" ||
    typeof paper.minecraftVersion !== "string" ||
    !Number.isSafeInteger(paper.build) ||
    paper.build < 1 ||
    paper.channel !== "STABLE" ||
    !Number.isSafeInteger(paper.minimumJavaMajor) ||
    paper.minimumJavaMajor < 21 ||
    !isPlainObject(paper.download)
  ) {
    throw new Error("Paper development artifact has invalid identity fields");
  }
  requireExactFields(paper.download, DOWNLOAD_FIELDS, "Paper download");
  const expectedName = `paper-${paper.minecraftVersion}-${paper.build}.jar`;
  if (
    paper.download.name !== expectedName ||
    !paper.download.url.startsWith("https://fill-data.papermc.io/") ||
    !paper.download.url.endsWith(`/${expectedName}`) ||
    !/^[a-f0-9]{64}$/.test(paper.download.sha256) ||
    !paper.download.url.includes(paper.download.sha256) ||
    !Number.isSafeInteger(paper.download.sizeBytes) ||
    paper.download.sizeBytes < 1
  ) {
    throw new Error("Paper download pin is invalid");
  }
}

function validateFixtures(repositoryRoot, document) {
  requireExactFields(
    document,
    FIXTURE_ROOT_FIELDS,
    "behavioral fixture matrix",
  );
  if (document.schemaVersion !== 1 || !Array.isArray(document.fixtures)) {
    throw new Error("behavioral fixture matrix has an invalid envelope");
  }
  const observed = [];
  for (const fixture of document.fixtures) {
    requireExactFields(fixture, FIXTURE_FIELDS, "behavioral fixture");
    if (!SAFE_FIXTURES.includes(fixture.id)) {
      throw new Error(`fixture ${fixture.id} is not in the benign allowlist`);
    }
    observed.push(fixture.id);
    if (
      typeof fixture.targetPlugin !== "string" ||
      !/^Provenance[A-Za-z]+$/.test(fixture.targetPlugin) ||
      !isPlainObject(fixture.testPlan) ||
      !Array.isArray(fixture.testPlan.console) ||
      !Array.isArray(fixture.expectedClassifications) ||
      !fixture.expectedClassifications.every(
        (value) => typeof value === "string" && /^[a-z][a-z0-9_]*$/.test(value),
      ) ||
      !Array.isArray(fixture.requiredEvents)
    ) {
      throw new Error(`fixture ${fixture.id} has invalid expectations`);
    }
    const expectedArtifact = `packages/test-fixtures/benign/${fixture.id}/build/libs/${fixture.id}-1.0.0.jar`;
    if (fixture.artifactPath !== expectedArtifact) {
      throw new Error(
        `fixture ${fixture.id} does not use its fixed benign artifact`,
      );
    }
    const artifact = resolve(repositoryRoot, fixture.artifactPath);
    const benignRoot = resolve(repositoryRoot, "packages/test-fixtures/benign");
    const pathWithinBenign = relative(benignRoot, artifact);
    if (
      isAbsolute(pathWithinBenign) ||
      pathWithinBenign === ".." ||
      pathWithinBenign.startsWith(`..${sep}`)
    ) {
      throw new Error(
        `fixture ${fixture.id} escapes the benign fixture directory`,
      );
    }
    for (const expected of fixture.requiredEvents) {
      requireExactFields(expected, EVENT_FIELDS, `fixture ${fixture.id} event`);
      if (
        typeof expected.type !== "string" ||
        !/^[A-Z][A-Z0-9_]*$/.test(expected.type) ||
        !isPlainObject(expected.data)
      ) {
        throw new Error(
          `fixture ${fixture.id} has an invalid event expectation`,
        );
      }
    }
  }
  if (JSON.stringify(observed) !== JSON.stringify(SAFE_FIXTURES)) {
    throw new Error(
      "behavioral fixture matrix must contain the six benign fixtures once, in order",
    );
  }
}

function eventMatches(event, expected) {
  if (event.type !== expected.type) return false;
  return Object.entries(expected.data).every(
    ([key, value]) => JSON.stringify(event.data[key]) === JSON.stringify(value),
  );
}

function countValues(values) {
  const counts = {};
  for (const value of values) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
}

function parseJson(source, label) {
  try {
    const value = JSON.parse(source);
    if (!isPlainObject(value)) throw new Error("root must be an object");
    return value;
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`, {
      cause: error,
    });
  }
}

function requireExactFields(value, expected, label) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const actual = new Set(Object.keys(value));
  for (const field of expected) {
    if (!actual.has(field)) throw new Error(`${label} is missing ${field}`);
  }
  for (const field of actual) {
    if (!expected.has(field))
      throw new Error(`${label} has unknown field ${field}`);
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
