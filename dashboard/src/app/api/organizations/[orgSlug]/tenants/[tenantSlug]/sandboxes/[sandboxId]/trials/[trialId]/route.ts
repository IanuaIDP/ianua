import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ orgSlug: string; sandboxId: string; tenantSlug: string; trialId: string }>;
};

export async function GET(request: Request, routeContext: RouteContext) {
  const { sandboxId, trialId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `sandboxes/${encodeURIComponent(sandboxId)}/trials/${encodeURIComponent(trialId)}`,
    method: 'GET',
    request,
    routeContext,
  });
}
