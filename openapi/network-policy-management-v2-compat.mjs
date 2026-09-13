// Project away only the registered additive tenant-management surface.
export const networkPolicyManagementOperations = [
  {
    method: "get",
    operationId: "getOrganizationNetworkPolicyV2",
    path: "/v2/organizations/{organizationId}/network-policy",
    tag: "organizations-projects",
  },
  {
    method: "post",
    operationId: "createOrganizationNetworkPolicyVersionV2",
    path: "/v2/organizations/{organizationId}/network-policy/versions",
    tag: "organizations-projects",
  },
  {
    method: "get",
    operationId: "getOrganizationNetworkPolicyVersionV2",
    path: "/v2/organizations/{organizationId}/network-policy/versions/{networkPolicyVersionId}",
    tag: "organizations-projects",
  },
  {
    method: "get",
    operationId: "getProjectNetworkPolicyV2",
    path: "/v2/projects/{projectId}/network-policy",
    tag: "organizations-projects",
  },
  {
    method: "post",
    operationId: "createProjectNetworkPolicyVersionV2",
    path: "/v2/projects/{projectId}/network-policy/versions",
    tag: "organizations-projects",
  },
  {
    method: "get",
    operationId: "getProjectNetworkPolicyVersionV2",
    path: "/v2/projects/{projectId}/network-policy/versions/{networkPolicyVersionId}",
    tag: "organizations-projects",
  },
];

export function beforeNetworkPolicyManagementV2(document) {
  const copy = structuredClone(document);
  for (const operation of networkPolicyManagementOperations)
    delete copy.paths[operation.path];
  delete copy.components.parameters.NetworkPolicyVersionId;
  delete copy.components.responses.NetworkPolicyVersionConflict;
  for (const name of [
    "NetworkPermissionV2",
    "NetworkPolicyV2",
    "CreateNetworkPolicyVersionRequestV2",
    "NetworkPolicyVersionV2",
  ])
    delete copy.components.schemas[name];
  return copy;
}
