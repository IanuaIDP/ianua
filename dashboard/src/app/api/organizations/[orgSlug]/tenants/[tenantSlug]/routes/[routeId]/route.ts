import { proxyRouteDetailRequest, type RouteDetailRouteContext } from './proxy';

export async function GET(request: Request, routeContext: RouteDetailRouteContext) {
  return proxyRouteDetailRequest({ method: 'GET', request, routeContext });
}

export async function PATCH(request: Request, routeContext: RouteDetailRouteContext) {
  return proxyRouteDetailRequest({ method: 'PATCH', request, routeContext });
}

export async function DELETE(request: Request, routeContext: RouteDetailRouteContext) {
  return proxyRouteDetailRequest({ method: 'DELETE', request, routeContext });
}
