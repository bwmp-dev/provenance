import assert from "node:assert/strict";
// Project creation adds session authorization; alpha admission adds one refusal.
// Assert each exact additive change before projecting earlier release snapshots.
export function beforeAlphaAdmission(path, item) {
  if (path === "/v1/release-candidates/{candidateId}/executions") {
    const copy = structuredClone(item);
    const flag = copy.get.parameters.pop();
    assert.equal(flag.name, "includeFailureClassification");
    assert.equal(flag.in, "query");
    assert.equal(flag.required, false);
    assert.deepEqual(flag.schema, { type: "boolean", default: false });
    return copy;
  }
  if (path === "/v1/organizations/{organizationId}/projects") {
    const copy = structuredClone(item);
    assert.deepEqual(copy.post.security, [
      { BearerAuth: [] },
      { SessionCookie: [] },
    ]);
    copy.post.security = [{ BearerAuth: [] }];
    return copy;
  }
  if (path !== "/v1/auth/sessions") return item;
  const copy = structuredClone(item);
  assert.equal(
    copy.post.responses["403"].$ref,
    "#/components/responses/AlphaInvitationRequired",
  );
  delete copy.post.responses["403"];
  return copy;
}

// Only this explicitly opt-in field may differ from prior closed descriptors.
// The unchanged baseline hashes still protect every legacy field and constraint.
export function beforeFailureClassification(family, name, value) {
  if (family !== "schemas" || name !== "ExecutionLogDescriptor") return value;
  const copy = structuredClone(value);
  assert.deepEqual(copy.properties.failureCategory.type, ["string", "null"]);
  assert.deepEqual(copy.properties.failureCategory.enum, [
    "plugin",
    "infrastructure",
    "policy",
    null,
  ]);
  assert.equal(copy.required.includes("failureCategory"), false);
  delete copy.properties.failureCategory;
  return copy;
}

// The gate event was already emitted by the platform when the current event
// contract was corrected. Earlier releases retain their exact ten-kind enum.
export function beforePublicationGateEvent(family, name, value) {
  if (family !== "schemas" || name !== "ReleaseEvent") return value;
  const copy = structuredClone(value);
  const kinds = copy.properties.kind.enum;
  assert.equal(
    kinds.filter((kind) => kind === "publication_gate_passed").length,
    1,
  );
  kinds.splice(kinds.indexOf("publication_gate_passed"), 1);
  return copy;
}

export function beforePublicationGateEventDocument(document) {
  const copy = structuredClone(document);
  copy.components.schemas.ReleaseEvent = beforePublicationGateEvent(
    "schemas",
    "ReleaseEvent",
    copy.components.schemas.ReleaseEvent,
  );
  return copy;
}
