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
