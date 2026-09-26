import { beforeGitHubConnectionRead } from "./github-connection-read-compat.mjs";
import { beforeProjectApiTokens } from "./project-api-tokens-compat.mjs";
export const publicVerificationPaths = [
  "/v1/public/{ownerSlug}",
  "/v1/public/{ownerSlug}/{projectSlug}",
  "/v1/public/{ownerSlug}/{projectSlug}/versions/{version}/attestation",
  "/v1/public/{ownerSlug}/{projectSlug}/versions/{version}/attestations/v2",
];
export function beforePublicVerification(document) {
  const copy = beforeGitHubConnectionRead(beforeProjectApiTokens(document));
  for (const path of publicVerificationPaths) delete copy.paths[path];
  delete copy.components.schemas.PublicVerificationPage;
  return copy;
}
