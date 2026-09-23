// IFC-033 adds one project-qualified GitHub connection read and its page
// schema. Earlier release snapshots are projected by removing exactly that
// additive surface; every other path and component must remain unchanged.
export const githubConnectionReadPath =
  "/v1/projects/{projectId}/github-connections";

export function beforeGitHubConnectionRead(document) {
  const copy = structuredClone(document);
  delete copy.paths[githubConnectionReadPath];
  delete copy.components.schemas.GitHubConnectionPage;
  return copy;
}
