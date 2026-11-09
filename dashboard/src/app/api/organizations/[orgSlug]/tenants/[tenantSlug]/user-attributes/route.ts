import { proxyUserAttributesRequest, type UserAttributesRouteContext } from './proxy';

export async function GET(request: Request, routeContext: UserAttributesRouteContext) {
  return proxyUserAttributesRequest({ method: 'GET', request, routeContext });
}

export async function POST(request: Request, routeContext: UserAttributesRouteContext) {
  return proxyUserAttributesRequest({ method: 'POST', request, routeContext });
}
