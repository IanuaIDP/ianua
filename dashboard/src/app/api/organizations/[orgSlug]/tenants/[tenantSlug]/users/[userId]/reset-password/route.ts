import { proxyTenantUserDetailRequest, type TenantUserDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: TenantUserDetailRouteContext) {
  return proxyTenantUserDetailRequest({
    actionPath: 'reset-password',
    method: 'POST',
    request,
    routeContext,
  });
}
