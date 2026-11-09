import { proxyTenantRequest, type TenantRouteContext } from '../../../../proxy';

export async function POST(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({
    actionPath: 'auth/mfa/enroll/confirm',
    method: 'POST',
    request,
    routeContext,
  });
}
