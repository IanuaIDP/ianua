import {
  proxyTenantRequest,
  type TenantRouteContext,
} from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

export function POST(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({
    actionPath: 'agents/suspend-all',
    method: 'POST',
    request,
    routeContext,
  });
}
