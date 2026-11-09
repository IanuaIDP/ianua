import { proxyRouteDetailRequest, type RouteDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: RouteDetailRouteContext) {
  return proxyRouteDetailRequest({
    actionPath: 'activate',
    method: 'POST',
    request,
    routeContext,
  });
}
