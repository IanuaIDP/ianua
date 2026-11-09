import { proxyTenantRequest, type TenantRouteContext } from '../../../proxy';

export async function POST(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({
    actionPath: 'auth/magic-link/verify',
    method: 'POST',
    request,
    routeContext,
  });
}
