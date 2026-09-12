import {
  beforeAlphaAdmission,
  beforeFailureClassification,
} from "./alpha-compat.mjs";
const alphaPaths = [
  "/v1/admin/organizations",
  "/v1/account",
  "/v1/admin/users",
  "/v1/admin/invitations",
  "/v1/admin/runners",
  "/v1/admin/executions",
  "/v1/admin/usage",
  "/v1/admin/invitations/{invitationId}",
  "/v1/admin/users/{userId}/administrator",
];
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import test from "node:test";
import { parse, parseDocument } from "yaml";

const root = new URL("./", import.meta.url);
const doc = parse(await readFile(new URL("provenance.v1.yaml", root), "utf8"));
const baseline = JSON.parse(
  await readFile(new URL("alpha18-compat.hashes.json", root), "utf8"),
);
const vectors = JSON.parse(
  await readFile(new URL("publication-result-vectors.json", root), "utf8"),
);
const require = createRequire(
  new URL("../packages/verification/package.json", root),
);
const Ajv = require("ajv/dist/2020.js");
const ajv = new Ajv({ strict: false });
require("ajv-formats")(ajv);
ajv.addSchema({ $id: "publication", components: doc.components });
const valid = (name, value) =>
  ajv.validate({ $ref: `publication#/components/schemas/${name}` }, value);
const route = "/v1/release-candidates/{candidateId}/publication-result";

// Test/reference only: consumer implementations must enforce these semantics.
function coherent(value) {
  if (!valid("PublicationResult", value)) return false;
  const c = value.composition;
  if (!c) return true;
  if (
    new Set(c.targets.map((t) => t.identifier)).size !== c.targets.length ||
    new Set(c.targets.map((t) => t.type)).size !== c.targets.length
  )
    return false;
  const prior = new Map();
  for (const target of c.targets) {
    if (
      (target.disposition === "succeeded" ||
        target.remoteKnowledge === "confirmed") &&
      target.providerState !== "succeeded"
    )
      return false;
    if (
      target.disposition === "failed" &&
      !["permanent", "conflict"].includes(target.providerState)
    )
      return false;
    if (
      ["pending", "skipped"].includes(target.disposition) &&
      target.providerState !== null
    )
      return false;
    if (target.disposition === "active" && target.providerState === null)
      return false;
    if (
      target.remoteKnowledge === "conflict" &&
      target.providerState !== "conflict"
    )
      return false;
    if (
      target.requiredPrimaryTargets.some(
        (id) => !prior.has(id) || prior.get(id).type === "discord",
      )
    )
      return false;
    prior.set(target.identifier, target);
  }
  const primary = c.targets.filter((t) => t.type !== "discord");
  const secondary = c.targets.find((t) => t.type === "discord");
  if (!primary.length) return false;
  if (c.aggregate?.outcome === "succeeded") {
    if (primary.some((t) => t.disposition !== "succeeded")) return false;
    if (
      c.policy.secondaryFulfillment === "required_for_success" &&
      secondary &&
      secondary.disposition !== "succeeded"
    )
      return false;
  }
  if (
    c.aggregate?.outcome === "failed" &&
    !primary.some((t) => t.disposition === "failed")
  )
    return false;
  if (
    c.aggregate?.outcome === "requirement_unfulfilled" &&
    (c.policy.secondaryFulfillment !== "required_for_success" ||
      secondary?.disposition !== c.aggregate.code ||
      primary.some((t) => t.disposition !== "succeeded"))
  )
    return false;
  if (
    secondary?.disposition === "budget_exhausted" &&
    c.policy.waiting !== "finite"
  )
    return false;
  return true;
}

function strictReference(bytes) {
  assert.ok(bytes.length <= 16384);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const value = JSON.parse(text);
  assert.equal(parseDocument(text, { uniqueKeys: true }).errors.length, 0);
  assert.ok(coherent(value), JSON.stringify(ajv.errors));
  return value;
}

test("IFC021 leaves every alpha18 path/component and grant operation unchanged", async () => {
  const hash = (v) =>
    createHash("sha256").update(JSON.stringify(v)).digest("hex");
  assert.equal(baseline.source, "b8cd327dc477c5fcd5b96429c3840ad0ecdbe5fa");
  for (const [path, digest] of Object.entries(baseline.paths))
    assert.equal(
      hash(beforeAlphaAdmission(path, doc.paths[path])),
      digest,
      path,
    );
  for (const [family, entries] of Object.entries(baseline.components))
    for (const [name, digest] of Object.entries(entries))
      assert.equal(
        hash(
          beforeFailureClassification(
            family,
            name,
            doc.components[family][name],
          ),
        ),
        digest,
        name,
      );
  assert.deepEqual(
    Object.keys(doc.paths).filter(
      (p) =>
        !baseline.paths[p] &&
        !alphaPaths.includes(p) &&
        ![
          "/v1/admin/runner-updates",
          "/v1/admin/hosted-runners",
          "/v1/admin/hosted-runners/install-profile",
          "/v1/runner-releases/{sha256}",
          "/v1/runner-updater/{runnerId}/poll",
          "/v1/admin/hosted-catalogs",
          "/v1/paper-runtimes/{runtimeId}",
          "/v1/paper-runtime-assets/{sha256}/{filename}",
          "/v1/paper-versions",
          "/v1/paper-versions/{version}/builds",
          "/v1/runner-catalogs/{runnerId}/poll",
          "/v1/runner-catalog-assets/{sha256}/{filename}",
          "/v1/release-candidates/{candidateId}/matrix",
        ].includes(p),
    ),
    [route, "/v1/verifications/{verificationId}/attestations/v2"],
  );
  const op = doc.paths[route].get;
  assert.equal(op.operationId, "getReleaseCandidatePublicationResult");
  assert.deepEqual(op.security, [{ BearerAuth: [] }, { SessionCookie: [] }]);
  assert.equal(op.parameters[0].required, true);
  assert.equal(op.parameters[0].schema.minimum, 0);
  assert.deepEqual(Object.keys(op.responses), [
    "200",
    "400",
    "401",
    "403",
    "404",
    "405",
    "413",
    "429",
    "500",
    "503",
  ]);
  for (const response of Object.values(op.responses))
    assert.equal(response.headers["Cache-Control"].schema.const, "no-store");
  const generated = await readFile(
    new URL("../packages/api-client/src/gen/schema.d.ts", root),
    "utf8",
  );
  assert.match(generated, /getReleaseCandidatePublicationResult/);
  assert.match(generated, /PublicationTargetResult:/);
});

test("IFC021 coherent policy and late-knowledge vectors retain historical decisions", () => {
  assert.equal(vectors.contract, "IFC-021");
  assert.equal(vectors.runtimeEvidence, false);
  for (const c of vectors.cases)
    assert.deepEqual(
      strictReference(Buffer.from(JSON.stringify(c.response))),
      c.response,
      c.name,
    );
  const late = vectors.cases.filter((c) =>
    c.name.startsWith("finite exhaustion"),
  );
  assert.equal(late.length, 3);
  for (const c of late) {
    assert.deepEqual(
      c.response.composition.aggregate,
      late[0].response.composition.aggregate,
    );
    assert.equal(
      c.response.composition.targets[1].disposition,
      "budget_exhausted",
    );
  }
  assert.deepEqual(
    late.map((c) => c.response.composition.targets[1].remoteKnowledge),
    ["uncertain", "known", "confirmed"],
  );
  assert.equal(
    vectors.cases[1].response.composition.targets[0].remoteKnowledge,
    "not_observed",
  );
});

test("IFC021 knowledge precedence requires committed evidence, not a claim or retry", () => {
  // Vectors' optional event list describes the last target. Other targets use
  // their explicit committed terminal provider state as the qualifying fact.
  const knowledge = (target, events) => {
    if (target.providerState === "succeeded") return "confirmed";
    if (target.providerState === "conflict") return "conflict";
    if (target.type === "discord") {
      if (events.includes("confirmed")) return "confirmed";
      if (events.includes("message_known")) return "known";
      if (events.includes("send_intent")) return "uncertain";
    } else if (
      events.some((e) =>
        ["mutation_started", "mutation_returned", "uncertain"].includes(e),
      )
    )
      return "uncertain";
    return "not_observed";
  };
  for (const vector of vectors.cases) {
    const target = vector.response.composition?.targets.at(-1);
    if (target)
      assert.equal(
        knowledge(target, vector.evidence),
        target.remoteKnowledge,
        vector.name,
      );
  }
  for (const type of ["github", "discord"])
    assert.equal(
      knowledge({ type, providerState: "retryable" }, [
        "claimed",
        "lease_expired",
        "unavailable",
      ]),
      "not_observed",
    );
  assert.equal(
    knowledge({ type: "discord", providerState: "retryable" }, [
      "send_intent",
      "message_known",
      "uncertain",
    ]),
    "known",
  );
});

test("IFC021 rejects unknown fields, malformed bounded identities and contradictory facts", () => {
  const base = vectors.cases.find(
    (c) => c.name === "required secondary confirmed",
  ).response;
  for (const mutate of [
    (v) => {
      v.credentialId = "secret";
    },
    (v) => {
      v.composition.targets[0].remoteUrl = "https://private.invalid";
    },
    (v) => {
      v.composition.targets[1].remoteKnowledge = "absent";
    },
    (v) => {
      v.generation = 0.5;
    },
    (v) => {
      v.generation = -1;
    },
    (v) => {
      v.generation = 9007199254740992;
    },
    (v) => {
      v.artifactSha256 = "A".repeat(64);
    },
    (v) => {
      v.candidateId = "not-a-uuid";
    },
    (v) => {
      v.composition.targets[0].identifier = "a".repeat(64);
    },
    (v) => {
      v.composition.targets.push(
        ...v.composition.targets,
        ...v.composition.targets,
      );
    },
    (v) => {
      v.composition.targets[1].identifier = v.composition.targets[0].identifier;
    },
    (v) => {
      v.composition.targets[1].type = "github";
    },
    (v) => {
      v.composition.targets.reverse();
    },
    (v) => {
      v.composition.targets[1].requiredPrimaryTargets = ["missing"];
    },
    (v) => {
      v.composition.aggregate.code = "primary_failed";
    },
    (v) => {
      v.composition.targets[0].disposition = "failed";
    },
    (v) => {
      v.composition.targets[1].disposition = "budget_exhausted";
    },
    (v) => {
      v.status = "not_admitted";
    },
    (v) => {
      v.composition = null;
    },
    (v) => {
      v.composition.targets[0].providerState = null;
    },
    (v) => {
      v.composition.targets[0].providerState = "preflight";
    },
    (v) => {
      v.composition.targets[0].disposition = "skipped";
    },
  ]) {
    const value = structuredClone(base);
    mutate(value);
    assert.equal(coherent(value), false);
  }
  for (const key of Object.keys(base)) {
    const v = structuredClone(base);
    delete v[key];
    assert.equal(coherent(v), false, key);
  }
});

test("IFC021 reference raw JSON rejects duplicates, invalid bytes, trailing input and overflow", () => {
  const text = JSON.stringify(vectors.cases[0].response);
  for (const bytes of [
    Buffer.from(text.replace('"version":1', '"version":1,"version":1')),
    Buffer.from(text + "{}"),
    Buffer.concat([Buffer.from(text), Buffer.from([255])]),
    Buffer.from(" ".repeat(16385) + text),
  ])
    assert.throws(() => strictReference(bytes));
});

test("IFC021 closed errors bind exact status/title without dynamic leakage", () => {
  const error = {
    type: "about:blank",
    title: "Not found",
    status: 404,
    code: "not_found",
  };
  assert.equal(valid("PublicationResultProblem", error), true);
  for (const v of [
    { ...error, detail: "secret" },
    { ...error, status: 503 },
    { ...error, title: "foreign candidate" },
    { ...error, code: "unknown" },
  ])
    assert.equal(valid("PublicationResultProblem", v), false);
});

test("IFC021 generated client reads exact generation without network or mutation", async () => {
  const { createProvenanceClient } =
    await import("../packages/api-client/dist/index.js");
  const example = vectors.cases[0].response;
  const client = createProvenanceClient({
    baseUrl: "https://api.example.test",
    fetch: async (request) => {
      assert.equal(request.method, "GET");
      const url = new URL(request.url);
      assert.equal(
        url.pathname,
        `/v1/release-candidates/${example.candidateId}/publication-result`,
      );
      assert.equal(url.search, "?generation=0");
      assert.equal(
        request.headers.get("Authorization"),
        "Bearer synthetic-project-token",
      );
      return new Response(JSON.stringify(example), {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        },
      });
    },
  });
  const result = await client.GET(route, {
    params: {
      path: { candidateId: example.candidateId },
      query: { generation: 0 },
    },
    headers: { Authorization: "Bearer synthetic-project-token" },
  });
  assert.deepEqual(result.data, example);
  assert.equal(result.response.headers.get("Cache-Control"), "no-store");
});
