import { proxyTenantRequest } from '@/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy';

type RouteContext = {
  params: Promise<{ appId: string; orgSlug: string; tenantSlug: string }>;
};

export async function POST(request: Request, routeContext: RouteContext) {
  const { appId } = await routeContext.params;

  return proxyTenantRequest({
    actionPath: `saml/apps/${encodeURIComponent(appId)}/sign-in`,
    method: 'POST',
    request,
    routeContext,
  });
}
