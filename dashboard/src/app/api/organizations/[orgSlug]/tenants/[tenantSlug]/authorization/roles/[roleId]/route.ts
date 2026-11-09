import { proxyRoleDetailRequest, type RoleDetailRouteContext } from './proxy';

export async function PATCH(request: Request, routeContext: RoleDetailRouteContext) {
  return proxyRoleDetailRequest({ method: 'PATCH', request, routeContext });
}

export async function DELETE(request: Request, routeContext: RoleDetailRouteContext) {
  return proxyRoleDetailRequest({ method: 'DELETE', request, routeContext });
}
