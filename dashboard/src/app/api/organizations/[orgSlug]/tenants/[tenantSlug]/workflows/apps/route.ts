import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ orgSlug: string; tenantSlug: string }>;
};

export async function GET(request: Request, routeContext: RouteContext) {
  return proxyTenantRequest({
    actionPath: 'workflows/apps',
    method: 'GET',
    request,
    routeContext,
  });
}
