import {
  proxyTenantRequest,
  type TenantRouteContext as RouteContext,
} from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

export async function POST(request: Request, routeContext: RouteContext) {
  return proxyTenantRequest({
    actionPath: `workflows/accounts/connections`,
    method: 'POST',
    request,
    routeContext,
  });
}
