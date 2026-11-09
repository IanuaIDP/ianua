import { proxyUserDetailRequest, type UserDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: UserDetailRouteContext) {
  return proxyUserDetailRequest({
    actionPath: 'revoke-invitation',
    method: 'POST',
    request,
    routeContext,
  });
}
