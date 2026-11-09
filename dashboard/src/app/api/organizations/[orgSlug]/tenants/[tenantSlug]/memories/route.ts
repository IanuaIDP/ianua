import {
  proxyTenantRequest,
  type TenantRouteContext as RouteContext,
} from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

export async function GET(request: Request, routeContext: RouteContext) {
  return proxyTenantRequest({ actionPath: 'memories', method: 'GET', request, routeContext });
}

export async function POST(request: Request, routeContext: RouteContext) {
  return proxyTenantRequest({ actionPath: 'memories', method: 'POST', request, routeContext });
}
