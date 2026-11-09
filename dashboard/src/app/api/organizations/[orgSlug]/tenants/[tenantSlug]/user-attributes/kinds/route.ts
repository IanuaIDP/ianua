import { proxyUserAttributesRequest, type UserAttributesRouteContext } from '../proxy';

export async function GET(request: Request, routeContext: UserAttributesRouteContext) {
  return proxyUserAttributesRequest({ method: 'GET', request, routeContext, segments: ['kinds'] });
}
