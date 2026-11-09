import { proxyUserAttributeRequest, type UserAttributeRouteContext } from './proxy';

export async function PATCH(request: Request, routeContext: UserAttributeRouteContext) {
  return proxyUserAttributeRequest({ method: 'PATCH', request, routeContext });
}

export async function DELETE(request: Request, routeContext: UserAttributeRouteContext) {
  return proxyUserAttributeRequest({ method: 'DELETE', request, routeContext });
}
