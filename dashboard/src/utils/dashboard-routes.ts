const tenantRoutePattern = /^\/organizations\/([^/]+)\/tenants\/([^/]+)(?:\/|$)/;
const tenantLoginRoutePattern = /^\/organizations\/[^/]+\/tenants\/[^/]+\/login\/?$/;
const managedTenantRoutePattern = /^\/tenants\/([^/]+)(?:\/|$)/;
const tenantSubDetailRoutePattern =
  /^\/organizations\/[^/]+\/tenants\/[^/]+\/(crypto|settings|agents\/[^/]+)(?:\/|$)/;

export type TenantRouteContext = {
  orgSlug: string;
  tenantSlug: string;
};

export function getTenantRouteContext(pathname: string): TenantRouteContext | null {
  const match = pathname.match(tenantRoutePattern);

  if (!match) {
    return null;
  }

  return {
    orgSlug: decodeURIComponent(match[1]),
    tenantSlug: decodeURIComponent(match[2]),
  };
}

export function getManagedTenantSlug(pathname: string): string | null {
  const match = pathname.match(managedTenantRoutePattern);

  return match ? decodeURIComponent(match[1]) : null;
}

export function isTenantLoginRoute(pathname: string) {
  return tenantLoginRoutePattern.test(pathname);
}

export function isTenantSubDetailRoute(pathname: string) {
  return tenantSubDetailRoutePattern.test(pathname);
}

export function getTenantPath(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}`;
}

export function getTenantManagementPath(tenantSlug: string) {
  return `/tenants/${encodeURIComponent(tenantSlug)}`;
}

export function getTenantScopedPath(
  isTenantView: boolean,
  orgSlug: string | undefined,
  tenantSlug: string,
  tenantSegment?: string,
  managementSegment?: string,
) {
  if (isTenantView) {
    if (!orgSlug) {
      return '/tenants';
    }

    const basePath = getTenantPath(orgSlug, tenantSlug);

    return tenantSegment ? `${basePath}/${tenantSegment}` : basePath;
  }

  const basePath = getTenantManagementPath(tenantSlug);

  return managementSegment ? `${basePath}/${managementSegment}` : basePath;
}

export function getAgentPath(orgSlug: string, tenantSlug: string, agentId: string) {
  return `${getTenantPath(orgSlug, tenantSlug)}/agents/${encodeURIComponent(agentId)}`;
}

export function getAgentManagementPath(tenantSlug: string, agentId: string) {
  return `${getTenantManagementPath(tenantSlug)}/agents/${encodeURIComponent(agentId)}`;
}

export function getFlowPath(orgSlug: string, tenantSlug: string, flowId: string) {
  return `${getTenantPath(orgSlug, tenantSlug)}/flows/${encodeURIComponent(flowId)}`;
}

export function getFlowManagementPath(tenantSlug: string, flowId: string) {
  return `${getTenantManagementPath(tenantSlug)}/flows/${encodeURIComponent(flowId)}`;
}

export function getWorkflowRunPath(orgSlug: string, tenantSlug: string, runId: string) {
  return `${getTenantPath(orgSlug, tenantSlug)}/workflows/runs/${encodeURIComponent(runId)}`;
}

export function getWorkflowRunManagementPath(tenantSlug: string, runId: string) {
  return `${getTenantManagementPath(tenantSlug)}/workflows/runs/${encodeURIComponent(runId)}`;
}

export function getWorkflowApprovalPath(
  orgSlug: string,
  tenantSlug: string,
  runId: string,
  step: string,
) {
  return `${getWorkflowRunPath(orgSlug, tenantSlug, runId)}/approvals/${encodeURIComponent(step)}`;
}

export function getStreamPath(orgSlug: string, tenantSlug: string, streamId: string) {
  return `${getTenantPath(orgSlug, tenantSlug)}/streams/${encodeURIComponent(streamId)}`;
}

export function getStreamManagementPath(tenantSlug: string, streamId: string) {
  return `${getTenantManagementPath(tenantSlug)}/streams/${encodeURIComponent(streamId)}`;
}

export function getDomainPath(orgSlug: string, tenantSlug: string, domainId: string) {
  return `${getTenantPath(orgSlug, tenantSlug)}/domains/${encodeURIComponent(domainId)}`;
}

export function getDomainManagementPath(tenantSlug: string, domainId: string) {
  return `${getTenantManagementPath(tenantSlug)}/domains/${encodeURIComponent(domainId)}`;
}

export function getCreateRoutePath(orgSlug: string, tenantSlug: string) {
  return `${getTenantPath(orgSlug, tenantSlug)}/routes/create`;
}

export function getCreateRouteManagementPath(tenantSlug: string) {
  return `${getTenantManagementPath(tenantSlug)}/routes/create`;
}

export function getEditRoutePath(orgSlug: string, tenantSlug: string, routeId: string) {
  return `${getTenantPath(orgSlug, tenantSlug)}/routes/${encodeURIComponent(routeId)}/edit`;
}

export function getEditRouteManagementPath(tenantSlug: string, routeId: string) {
  return `${getTenantManagementPath(tenantSlug)}/routes/${encodeURIComponent(routeId)}/edit`;
}

export function getCreateStreamRoutePath(orgSlug: string, tenantSlug: string) {
  return `${getTenantPath(orgSlug, tenantSlug)}/stream-routes/create`;
}

export function getCreateStreamRouteManagementPath(tenantSlug: string) {
  return `${getTenantManagementPath(tenantSlug)}/stream-routes/create`;
}

export function getEditStreamRoutePath(orgSlug: string, tenantSlug: string, routeId: string) {
  return `${getTenantPath(orgSlug, tenantSlug)}/stream-routes/${encodeURIComponent(routeId)}/edit`;
}

export function getEditStreamRouteManagementPath(tenantSlug: string, routeId: string) {
  return `${getTenantManagementPath(tenantSlug)}/stream-routes/${encodeURIComponent(routeId)}/edit`;
}

export function getCreateServicePath(orgSlug: string, tenantSlug: string) {
  return `${getTenantPath(orgSlug, tenantSlug)}/services/create`;
}

export function getCreateServiceManagementPath(tenantSlug: string) {
  return `${getTenantManagementPath(tenantSlug)}/services/create`;
}

export function getEditServicePath(orgSlug: string, tenantSlug: string, serviceId: string) {
  return `${getTenantPath(orgSlug, tenantSlug)}/services/${encodeURIComponent(serviceId)}/edit`;
}

export function getEditServiceManagementPath(tenantSlug: string, serviceId: string) {
  return `${getTenantManagementPath(tenantSlug)}/services/${encodeURIComponent(serviceId)}/edit`;
}

export function getPipelinePath(orgSlug: string, tenantSlug: string, pipelineId: string) {
  return `${getTenantPath(orgSlug, tenantSlug)}/pipelines/${encodeURIComponent(pipelineId)}`;
}

export function getPipelineManagementPath(tenantSlug: string, pipelineId: string) {
  return `${getTenantManagementPath(tenantSlug)}/pipelines/${encodeURIComponent(pipelineId)}`;
}
