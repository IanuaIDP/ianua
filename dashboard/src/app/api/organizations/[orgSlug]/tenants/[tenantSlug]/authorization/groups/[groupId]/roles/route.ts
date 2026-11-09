import { proxyGroupDetailRequest, type GroupDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: GroupDetailRouteContext) {
  return proxyGroupDetailRequest({ method: 'POST', request, routeContext, segments: ['roles'] });
}
