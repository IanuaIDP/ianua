import { proxyTenantRequest, type TenantRouteContext } from '../../../../proxy';

export async function POST(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({
    actionPath: 'auth/passkey/login/confirm',
    method: 'POST',
    request,
    routeContext,
  });
}
