import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ orgSlug: string; tenantSlug: string; workflowId: string }>;
};

export async function POST(request: Request, routeContext: RouteContext) {
  const { workflowId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `workflows/${encodeURIComponent(workflowId)}/trigger-secret`,
    method: 'POST',
    request,
    routeContext,
  });
}

export async function DELETE(request: Request, routeContext: RouteContext) {
  const { workflowId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `workflows/${encodeURIComponent(workflowId)}/trigger-secret`,
    method: 'DELETE',
    request,
    routeContext,
  });
}
