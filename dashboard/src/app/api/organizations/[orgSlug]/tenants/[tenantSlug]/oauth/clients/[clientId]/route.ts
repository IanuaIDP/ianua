import { proxyOAuthClientDetailRequest, type OAuthClientDetailRouteContext } from './proxy';

export async function PATCH(request: Request, routeContext: OAuthClientDetailRouteContext) {
  return proxyOAuthClientDetailRequest({ method: 'PATCH', request, routeContext });
}
