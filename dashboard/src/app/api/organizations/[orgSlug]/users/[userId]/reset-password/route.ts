import { proxyUserDetailRequest, type UserDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: UserDetailRouteContext) {
  return proxyUserDetailRequest({
    actionPath: 'reset-password',
    method: 'POST',
    request,
    routeContext,
  });
}
