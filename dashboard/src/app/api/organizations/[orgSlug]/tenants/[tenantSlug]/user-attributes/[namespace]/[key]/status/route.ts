import { proxyUserAttributeRequest, type UserAttributeRouteContext } from '../proxy';

export async function PUT(request: Request, routeContext: UserAttributeRouteContext) {
  return proxyUserAttributeRequest({ actionPath: 'status', method: 'PUT', request, routeContext });
}
