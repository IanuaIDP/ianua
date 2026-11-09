import { proxyUserDetailRequest } from '../../proxy';

type TenantAccessRouteContext = {
  params: Promise<{
    orgSlug: string;
    tenantSlug: string;
    userId: string;
  }>;
};

export async function PUT(request: Request, routeContext: TenantAccessRouteContext) {
  const { tenantSlug } = await routeContext.params;

  return proxyUserDetailRequest({
    actionPath: `tenants/${encodeURIComponent(tenantSlug)}`,
    method: 'PUT',
    request,
    routeContext,
  });
}
