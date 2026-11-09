import {
  proxyTenantRequest,
  type TenantRouteContext,
} from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

export async function POST(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({
    actionPath: 'auth/password/reset-code',
    method: 'POST',
    request,
    routeContext,
  });
}
