import { proxyOAuthClientDetailRequest, type OAuthClientDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: OAuthClientDetailRouteContext) {
  return proxyOAuthClientDetailRequest({
    actionPath: 'rotate-secret',
    method: 'POST',
    request,
    routeContext,
  });
}
