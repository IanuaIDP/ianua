import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{
    evaluationId: string;
    orgSlug: string;
    tenantSlug: string;
    workflowId: string;
  }>;
};

export async function GET(request: Request, routeContext: RouteContext) {
  const { evaluationId, workflowId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `workflows/${encodeURIComponent(workflowId)}/evaluations/${encodeURIComponent(evaluationId)}`,
    method: 'GET',
    request,
    routeContext,
  });
}
