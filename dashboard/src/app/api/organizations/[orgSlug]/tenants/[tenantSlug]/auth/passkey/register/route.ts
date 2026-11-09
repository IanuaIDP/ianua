import { proxyTenantRequest, type TenantRouteContext } from '../../../proxy';

export async function POST(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({
    actionPath: 'auth/passkey/register',
    method: 'POST',
    request,
    routeContext,
  });
}
