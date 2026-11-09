import { proxyTenantRequest, type TenantRouteContext } from '../../../proxy';

export async function GET(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({
    actionPath: 'auth/device/trust',
    method: 'GET',
    request,
    routeContext,
  });
}
