import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ orgSlug: string; sandboxId: string; tenantSlug: string }>;
};

export async function GET(request: Request, routeContext: RouteContext) {
  const { sandboxId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `sandboxes/${encodeURIComponent(sandboxId)}${new URL(request.url).search}`,
    method: 'GET',
    request,
    routeContext,
  });
}
