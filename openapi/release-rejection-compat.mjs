// Only the additive IFC-029 operations and schema are removed for older hashes.
// The rejection tests independently freeze the entire preceding alpha28 document.
export function beforeReleaseRejection(document) {
  const copy = structuredClone(document);
  delete copy.paths["/v1/release-candidates/{candidateId}/reject"];
  delete copy.paths["/v1/release-candidates/{candidateId}/rejection"];
  delete copy.components.schemas.ReleaseCandidateRejection;
  delete copy.components.responses.ReleaseCandidateRejectionConflict;
  return copy;
}
