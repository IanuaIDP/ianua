import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ orgSlug: string; runId: string; step: string; tenantSlug: string }>;
};

export async function GET(request: Request, routeContext: RouteContext) {
  const { runId, step } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `workflows/executions/${encodeURIComponent(runId)}/approvals/${encodeURIComponent(step)}`,
    method: 'GET',
    request,
    routeContext,
  });
}
