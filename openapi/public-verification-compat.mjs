export const publicVerificationPaths = [
  "/v1/public/{ownerSlug}",
  "/v1/public/{ownerSlug}/{projectSlug}",
  "/v1/public/{ownerSlug}/{projectSlug}/versions/{version}/attestation",
  "/v1/public/{ownerSlug}/{projectSlug}/versions/{version}/attestations/v2",
];
export function beforePublicVerification(document) {
  const copy = structuredClone(document);
  for (const path of publicVerificationPaths) delete copy.paths[path];
  delete copy.components.schemas.PublicVerificationPage;
  return copy;
}
