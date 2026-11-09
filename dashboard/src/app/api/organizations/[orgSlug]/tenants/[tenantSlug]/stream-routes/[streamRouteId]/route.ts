import { proxyStreamRouteDetailRequest, type StreamRouteDetailRouteContext } from './proxy';

export async function GET(request: Request, routeContext: StreamRouteDetailRouteContext) {
  return proxyStreamRouteDetailRequest({ method: 'GET', request, routeContext });
}

export async function PATCH(request: Request, routeContext: StreamRouteDetailRouteContext) {
  return proxyStreamRouteDetailRequest({ method: 'PATCH', request, routeContext });
}

export async function DELETE(request: Request, routeContext: StreamRouteDetailRouteContext) {
  return proxyStreamRouteDetailRequest({ method: 'DELETE', request, routeContext });
}
