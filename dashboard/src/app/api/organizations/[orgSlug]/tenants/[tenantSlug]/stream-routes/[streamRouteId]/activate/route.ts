import { proxyStreamRouteDetailRequest, type StreamRouteDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: StreamRouteDetailRouteContext) {
  return proxyStreamRouteDetailRequest({
    actionPath: 'activate',
    method: 'POST',
    request,
    routeContext,
  });
}
