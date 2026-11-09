import { proxyTenantRequest, type TenantRouteContext } from '../../../proxy';

export async function PUT(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({
    actionPath: 'federation/scim/settings',
    method: 'PUT',
    request,
    routeContext,
  });
}
