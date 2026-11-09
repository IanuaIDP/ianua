import {
  proxyTenantRequest,
  type TenantRouteContext as RouteContext,
} from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

export async function GET(request: Request, routeContext: RouteContext) {
  return proxyTenantRequest({
    actionPath: 'sandboxes/registries',
    method: 'GET',
    request,
    routeContext,
  });
}

export async function POST(request: Request, routeContext: RouteContext) {
  return proxyTenantRequest({
    actionPath: 'sandboxes/registries',
    method: 'POST',
    request,
    routeContext,
  });
}
