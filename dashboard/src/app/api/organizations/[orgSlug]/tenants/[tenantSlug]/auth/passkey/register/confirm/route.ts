import { proxyTenantRequest, type TenantRouteContext } from '../../../../proxy';

export async function POST(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({
    actionPath: 'auth/passkey/register/confirm',
    method: 'POST',
    request,
    routeContext,
  });
}
