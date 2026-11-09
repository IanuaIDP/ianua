import {
  proxyTenantRequest,
  type TenantRouteContext,
} from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = TenantRouteContext & {
  params: Promise<{ orgSlug: string; tenantSlug: string; ruleName: string }>;
};

export async function PUT(request: Request, routeContext: RouteContext) {
  const { ruleName } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `authorization/policy/rules/${encodeURIComponent(ruleName)}/enabled`,
    method: 'PUT',
    request,
    routeContext,
  });
}
