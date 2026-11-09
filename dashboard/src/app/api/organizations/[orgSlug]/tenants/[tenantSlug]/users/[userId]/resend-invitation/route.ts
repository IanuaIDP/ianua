import { proxyTenantUserDetailRequest, type TenantUserDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: TenantUserDetailRouteContext) {
  return proxyTenantUserDetailRequest({
    actionPath: 'resend-invitation',
    method: 'POST',
    request,
    routeContext,
  });
}
