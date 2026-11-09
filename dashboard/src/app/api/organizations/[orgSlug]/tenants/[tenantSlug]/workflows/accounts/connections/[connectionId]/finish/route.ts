import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ connectionId: string; orgSlug: string; tenantSlug: string }>;
};

export async function POST(request: Request, routeContext: RouteContext) {
  const { connectionId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `workflows/accounts/connections/${encodeURIComponent(connectionId)}/finish`,
    method: 'POST',
    request,
    routeContext,
  });
}
