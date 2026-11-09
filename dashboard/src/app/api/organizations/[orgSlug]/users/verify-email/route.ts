import { proxyUsersRequest, type UsersRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: UsersRouteContext) {
  return proxyUsersRequest({
    actionPath: 'verify-email',
    method: 'POST',
    request,
    routeContext,
  });
}
