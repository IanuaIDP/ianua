import {
  proxyTenantRequest,
  type TenantRouteContext as RouteContext,
} from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

export async function GET(request: Request, routeContext: RouteContext) {
  return proxyTenantRequest({
    actionPath: 'sandboxes/runtimes',
    method: 'GET',
    request,
    routeContext,
  });
}
