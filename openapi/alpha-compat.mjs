import assert from "node:assert/strict";
// Project creation adds session authorization; alpha admission adds one refusal.
// Assert each exact additive change before projecting earlier release snapshots.
export function beforeAlphaAdmission(path, item) {
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
