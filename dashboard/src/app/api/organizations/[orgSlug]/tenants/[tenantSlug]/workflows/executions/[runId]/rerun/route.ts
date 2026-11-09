import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ orgSlug: string; runId: string; tenantSlug: string }>;
};

export async function POST(request: Request, routeContext: RouteContext) {
  const { runId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `workflows/executions/${encodeURIComponent(runId)}/rerun`,
    method: 'POST',
    request,
    routeContext,
  });
}
