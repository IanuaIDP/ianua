import {
  proxyTenantRequest,
  type TenantRouteContext,
} from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = TenantRouteContext & {
  params: Promise<{ orgSlug: string; tenantSlug: string; groupId: string }>;
};

export async function PUT(request: Request, routeContext: RouteContext) {
  const { groupId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `authorization/groups/${encodeURIComponent(groupId)}/parent`,
    method: 'PUT',
    request,
    routeContext,
  });
}
