import {
  proxyTenantRequest,
  type TenantRouteContext as RouteContext,
} from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

export async function GET(request: Request, routeContext: RouteContext) {
  return proxyTenantRequest({
    actionPath: `workflows${new URL(request.url).search}`,
    method: 'GET',
    request,
    routeContext,
  });
}

export async function POST(request: Request, routeContext: RouteContext) {
  return proxyTenantRequest({
    actionPath: 'workflows',
    method: 'POST',
    request,
    routeContext,
  });
}
