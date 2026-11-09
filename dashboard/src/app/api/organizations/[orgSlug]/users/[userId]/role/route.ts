import { proxyUserDetailRequest, type UserDetailRouteContext } from '../proxy';

export async function PATCH(request: Request, routeContext: UserDetailRouteContext) {
  return proxyUserDetailRequest({
    actionPath: 'role',
    method: 'PATCH',
    request,
    routeContext,
  });
}
