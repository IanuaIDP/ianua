import { proxyGroupDetailRequest, type GroupDetailRouteContext } from './proxy';

export async function GET(request: Request, routeContext: GroupDetailRouteContext) {
  return proxyGroupDetailRequest({ method: 'GET', request, routeContext });
}

export async function DELETE(request: Request, routeContext: GroupDetailRouteContext) {
  return proxyGroupDetailRequest({ method: 'DELETE', request, routeContext });
}

export async function PATCH(request: Request, routeContext: GroupDetailRouteContext) {
  return proxyGroupDetailRequest({ method: 'PATCH', request, routeContext });
}
