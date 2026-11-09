import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ orgSlug: string; tenantSlug: string; workflowId: string }>;
};

export async function POST(request: Request, routeContext: RouteContext) {
  const { workflowId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `workflows/${encodeURIComponent(workflowId)}/draft`,
    method: 'POST',
    request,
    routeContext,
  });
}

export async function PATCH(request: Request, routeContext: RouteContext) {
  const { workflowId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `workflows/${encodeURIComponent(workflowId)}/draft`,
    method: 'PATCH',
    request,
    routeContext,
  });
}
