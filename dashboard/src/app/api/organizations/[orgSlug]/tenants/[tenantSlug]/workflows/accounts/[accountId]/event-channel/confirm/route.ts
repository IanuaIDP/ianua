import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ accountId: string; orgSlug: string; tenantSlug: string }>;
};

export async function POST(request: Request, routeContext: RouteContext) {
  const { accountId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `workflows/accounts/${encodeURIComponent(accountId)}/event-channel/confirm`,
    method: 'POST',
    request,
    routeContext,
  });
}
