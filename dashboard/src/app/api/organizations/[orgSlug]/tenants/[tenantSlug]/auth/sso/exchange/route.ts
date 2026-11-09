import { proxyTenantRequest, type TenantRouteContext } from '../../../proxy';

export async function POST(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({
    actionPath: 'auth/sso/exchange',
    method: 'POST',
    request,
    routeContext,
  });
}
