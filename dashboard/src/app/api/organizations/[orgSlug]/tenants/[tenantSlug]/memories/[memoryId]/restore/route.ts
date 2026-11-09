import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ memoryId: string; orgSlug: string; tenantSlug: string }>;
};

export async function POST(request: Request, routeContext: RouteContext) {
  const { memoryId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `memories/${encodeURIComponent(memoryId)}/restore`,
    method: 'POST',
    request,
    routeContext,
  });
}
