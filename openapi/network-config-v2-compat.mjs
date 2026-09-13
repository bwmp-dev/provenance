// Only this explicitly versioned additive IFC-030 HTTP surface is projected
// away. Its own tests freeze the complete preceding alpha29 HTTP document.
export function beforeNetworkConfigV2(document) {
  const copy = structuredClone(document);
  delete copy.paths["/v2/projects/{projectId}/config-snapshots"];
  delete copy.paths["/v2/release-candidates/{candidateId}/inputs"];
  delete copy.components.responses.ConfigSnapshotV2Conflict;
  for (const name of [
    "CreateProjectConfigSnapshotRequestV2",
    "ProjectConfigSnapshotV2",
    "CandidateInputsV2",
    "CandidateInputConfigurationV2",
  ])
    delete copy.components.schemas[name];
  return copy;
}
