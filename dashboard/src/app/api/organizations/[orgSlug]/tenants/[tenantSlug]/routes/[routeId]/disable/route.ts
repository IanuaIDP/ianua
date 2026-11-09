import { proxyRouteDetailRequest, type RouteDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: RouteDetailRouteContext) {
  return proxyRouteDetailRequest({
    actionPath: 'disable',
    method: 'POST',
    request,
    routeContext,
  });
}
