import { proxyTenantUserDetailRequest, type TenantUserDetailRouteContext } from './proxy';

export async function DELETE(request: Request, routeContext: TenantUserDetailRouteContext) {
  return proxyTenantUserDetailRequest({ method: 'DELETE', request, routeContext });
}

export async function PATCH(request: Request, routeContext: TenantUserDetailRouteContext) {
  return proxyTenantUserDetailRequest({ method: 'PATCH', request, routeContext });
}
