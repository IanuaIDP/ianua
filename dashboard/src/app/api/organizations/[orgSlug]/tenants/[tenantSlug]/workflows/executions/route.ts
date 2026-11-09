import {
  proxyTenantRequest,
  type TenantRouteContext as RouteContext,
} from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

export async function GET(request: Request, routeContext: RouteContext) {
  return proxyTenantRequest({
    actionPath: `workflows/executions${new URL(request.url).search}`,
    method: 'GET',
    request,
    routeContext,
  });
}
