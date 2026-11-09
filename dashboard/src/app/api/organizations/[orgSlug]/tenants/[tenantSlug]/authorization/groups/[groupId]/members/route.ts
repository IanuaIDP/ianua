import { proxyGroupDetailRequest, type GroupDetailRouteContext } from '../proxy';

export async function GET(request: Request, routeContext: GroupDetailRouteContext) {
  return proxyGroupDetailRequest({ method: 'GET', request, routeContext, segments: ['members'] });
}

export async function POST(request: Request, routeContext: GroupDetailRouteContext) {
  return proxyGroupDetailRequest({ method: 'POST', request, routeContext, segments: ['members'] });
}
