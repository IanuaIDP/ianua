import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ orgSlug: string; tenantSlug: string }>;
};

export async function POST(request: Request, routeContext: RouteContext) {
  return proxyTenantRequest({
    actionPath: 'workflows/suggestions',
    method: 'POST',
    request,
    routeContext,
  });
}
