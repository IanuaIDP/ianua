import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ memoryId: string; orgSlug: string; tenantSlug: string }>;
};

export async function GET(request: Request, routeContext: RouteContext) {
  const { memoryId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `memories/${encodeURIComponent(memoryId)}/entries${new URL(request.url).search}`,
    method: 'GET',
    request,
    routeContext,
  });
}
