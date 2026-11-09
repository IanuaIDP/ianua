import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ orgSlug: string; routeId: string; tenantSlug: string }>;
};

export async function POST(request: Request, routeContext: RouteContext) {
  const { routeId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `routes/${encodeURIComponent(routeId)}/open-to-workflows`,
    method: 'POST',
    request,
    routeContext,
  });
}
