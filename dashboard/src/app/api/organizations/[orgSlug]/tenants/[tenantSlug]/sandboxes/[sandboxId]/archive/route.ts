import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ orgSlug: string; sandboxId: string; tenantSlug: string }>;
};

export async function POST(request: Request, routeContext: RouteContext) {
  const { sandboxId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `sandboxes/${encodeURIComponent(sandboxId)}/archive`,
    method: 'POST',
    request,
    routeContext,
  });
}
