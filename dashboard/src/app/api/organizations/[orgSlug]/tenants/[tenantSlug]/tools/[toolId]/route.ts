import { proxyToolDetailRequest, type ToolDetailRouteContext } from './proxy';

export async function DELETE(request: Request, routeContext: ToolDetailRouteContext) {
  return proxyToolDetailRequest({ method: 'DELETE', request, routeContext });
}

export async function PATCH(request: Request, routeContext: ToolDetailRouteContext) {
  return proxyToolDetailRequest({ method: 'PATCH', request, routeContext });
}
