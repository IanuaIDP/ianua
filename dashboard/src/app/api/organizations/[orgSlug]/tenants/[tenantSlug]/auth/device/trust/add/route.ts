import { proxyTenantRequest, type TenantRouteContext } from '../../../../proxy';

export async function POST(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({
    actionPath: 'auth/device/trust/add',
    method: 'POST',
    request,
    routeContext,
  });
}
