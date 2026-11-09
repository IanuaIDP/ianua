import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ orgSlug: string; riskId: string; tenantSlug: string }>;
};

export async function PATCH(request: Request, routeContext: RouteContext) {
  const { riskId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `workflows/risks/${encodeURIComponent(riskId)}`,
    method: 'PATCH',
    request,
    routeContext,
  });
}

export async function DELETE(request: Request, routeContext: RouteContext) {
  const { riskId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `workflows/risks/${encodeURIComponent(riskId)}`,
    method: 'DELETE',
    request,
    routeContext,
  });
}
