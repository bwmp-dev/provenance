// Project away only the registered additive tenant-management surface.
export const networkPolicyManagementOperations = [
  {
    path: "/v2/organizations/{organizationId}/network-policy",
    method: "get",
    operationId: "getOrganizationNetworkPolicyV2",
    tag: "organizations-projects",
  },
  {
    path: "/v2/organizations/{organizationId}/network-policy/versions",
    method: "post",
    operationId: "createOrganizationNetworkPolicyVersionV2",
    tag: "organizations-projects",
  },
  {
    path: "/v2/organizations/{organizationId}/network-policy/versions/{networkPolicyVersionId}",
    method: "get",
    operationId: "getOrganizationNetworkPolicyVersionV2",
    tag: "organizations-projects",
  },
  {
    path: "/v2/projects/{projectId}/network-policy",
    method: "get",
    operationId: "getProjectNetworkPolicyV2",
    tag: "organizations-projects",
  },
  {
    path: "/v2/projects/{projectId}/network-policy/versions",
    method: "post",
    operationId: "createProjectNetworkPolicyVersionV2",
    tag: "organizations-projects",
  },
  {
    path: "/v2/projects/{projectId}/network-policy/versions/{networkPolicyVersionId}",
    method: "get",
    operationId: "getProjectNetworkPolicyVersionV2",
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
