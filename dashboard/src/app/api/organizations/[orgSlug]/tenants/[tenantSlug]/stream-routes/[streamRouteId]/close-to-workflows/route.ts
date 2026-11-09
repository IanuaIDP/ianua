import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ orgSlug: string; streamRouteId: string; tenantSlug: string }>;
};

export async function POST(request: Request, routeContext: RouteContext) {
  const { streamRouteId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `stream-routes/${encodeURIComponent(streamRouteId)}/close-to-workflows`,
    method: 'POST',
    request,
    routeContext,
  });
}
