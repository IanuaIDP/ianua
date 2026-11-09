import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ channelId: string; orgSlug: string; tenantSlug: string }>;
};

export async function POST(request: Request, routeContext: RouteContext) {
  const { channelId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `messaging/channels/${encodeURIComponent(channelId)}/close`,
    method: 'POST',
    request,
    routeContext,
  });
}
