import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ orgSlug: string; providerId: string; tenantSlug: string }>;
};

export async function PUT(request: Request, routeContext: RouteContext) {
  const { providerId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `model-providers/${encodeURIComponent(providerId)}/embeddings`,
    method: 'PUT',
    request,
    routeContext,
  });
}
