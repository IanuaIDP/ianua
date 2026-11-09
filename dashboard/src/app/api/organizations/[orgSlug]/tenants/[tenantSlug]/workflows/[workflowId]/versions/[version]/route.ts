import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ orgSlug: string; tenantSlug: string; version: string; workflowId: string }>;
};

export async function GET(request: Request, routeContext: RouteContext) {
  const { version, workflowId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `workflows/${encodeURIComponent(workflowId)}/versions/${encodeURIComponent(version)}`,
    method: 'GET',
    request,
    routeContext,
  });
}
