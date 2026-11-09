import { proxyUserDetailRequest, type UserDetailRouteContext } from './proxy';

export async function PATCH(request: Request, routeContext: UserDetailRouteContext) {
  return proxyUserDetailRequest({ method: 'PATCH', request, routeContext });
}

export async function DELETE(request: Request, routeContext: UserDetailRouteContext) {
  return proxyUserDetailRequest({ method: 'DELETE', request, routeContext });
}
