import { proxyStreamDetailRequest, type StreamDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: StreamDetailRouteContext) {
  return proxyStreamDetailRequest({
    actionPath: 'disable',
    method: 'POST',
    request,
    routeContext,
  });
}
