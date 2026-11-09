import { proxyConnectionDetailRequest, type ConnectionDetailRouteContext } from './proxy';

export async function DELETE(request: Request, routeContext: ConnectionDetailRouteContext) {
  return proxyConnectionDetailRequest({ method: 'DELETE', request, routeContext });
}
