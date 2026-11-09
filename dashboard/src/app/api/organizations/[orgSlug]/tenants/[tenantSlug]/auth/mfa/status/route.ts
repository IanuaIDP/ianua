import { proxyTenantRequest, type TenantRouteContext } from '../../../proxy';

export async function GET(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({
    actionPath: 'auth/mfa/status',
    method: 'GET',
    request,
    routeContext,
  });
}
