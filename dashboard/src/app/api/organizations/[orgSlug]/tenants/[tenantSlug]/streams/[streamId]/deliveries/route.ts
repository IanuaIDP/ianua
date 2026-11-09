import { proxyStreamDetailRequest, type StreamDetailRouteContext } from '../proxy';

export async function GET(request: Request, routeContext: StreamDetailRouteContext) {
  return proxyStreamDetailRequest({
    actionPath: 'deliveries',
    method: 'GET',
    request,
    routeContext,
  });
}
