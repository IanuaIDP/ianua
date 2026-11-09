import { proxyConnectionDetailRequest, type ConnectionDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: ConnectionDetailRouteContext) {
  return proxyConnectionDetailRequest({
    actionPath: 'activate',
    method: 'POST',
    request,
    routeContext,
  });
}
