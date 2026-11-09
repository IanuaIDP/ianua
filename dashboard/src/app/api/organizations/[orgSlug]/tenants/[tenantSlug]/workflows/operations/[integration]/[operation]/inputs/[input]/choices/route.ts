import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{
    input: string;
    integration: string;
    operation: string;
    orgSlug: string;
    tenantSlug: string;
  }>;
};

export async function POST(request: Request, routeContext: RouteContext) {
  const { input, integration, operation } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `workflows/operations/${encodeURIComponent(integration)}/${encodeURIComponent(operation)}/inputs/${encodeURIComponent(input)}/choices`,
    method: 'POST',
    request,
    routeContext,
  });
}
