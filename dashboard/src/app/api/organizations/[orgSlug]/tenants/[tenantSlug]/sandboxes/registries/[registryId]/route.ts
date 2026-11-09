import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ orgSlug: string; registryId: string; tenantSlug: string }>;
};

export async function DELETE(request: Request, routeContext: RouteContext) {
  const { registryId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `sandboxes/registries/${encodeURIComponent(registryId)}`,
    method: 'DELETE',
    request,
    routeContext,
  });
}
