// WP-07D adds user-managed project API token issuance, listing and
// revocation. Earlier release snapshots are projected by removing exactly that
// additive surface; every other path and component must remain unchanged.
export const projectApiTokensPath = "/v1/projects/{projectId}/api-tokens";
export const projectApiTokenPath =
  "/v1/projects/{projectId}/api-tokens/{tokenId}";
export const projectApiTokenSchemas = [
  "ProjectApiTokenCapability",
  "CreateProjectApiTokenRequest",
  "ProjectApiToken",
  "CreatedProjectApiToken",
  "ProjectApiTokenList",
];

export function beforeProjectApiTokens(document) {
  const copy = structuredClone(document);
  delete copy.paths[projectApiTokensPath];
  delete copy.paths[projectApiTokenPath];
  delete copy.components.parameters.ProjectApiTokenId;
  delete copy.components.headers.ProjectApiTokenNoStore;
  for (const name of projectApiTokenSchemas)
    delete copy.components.schemas[name];
  return copy;
}
