import { proxyStreamDetailRequest, type StreamDetailRouteContext } from './proxy';

export async function GET(request: Request, routeContext: StreamDetailRouteContext) {
  return proxyStreamDetailRequest({ method: 'GET', request, routeContext });
}

export async function PATCH(request: Request, routeContext: StreamDetailRouteContext) {
  return proxyStreamDetailRequest({ method: 'PATCH', request, routeContext });
}

export async function DELETE(request: Request, routeContext: StreamDetailRouteContext) {
  return proxyStreamDetailRequest({ method: 'DELETE', request, routeContext });
}
