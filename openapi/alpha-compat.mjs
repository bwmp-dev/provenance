import assert from "node:assert/strict";
// Only the newly specified admission refusal is excluded from earlier release
// snapshots. Its full shape is frozen by alpha-administration.test.mjs.
export function beforeAlphaAdmission(path, item) {
  if (path !== "/v1/auth/sessions") return item;
  const copy = structuredClone(item);
  assert.equal(
    copy.post.responses["403"].$ref,
    "#/components/responses/AlphaInvitationRequired",
  );
  delete copy.post.responses["403"];
  return copy;
}
