import { proxyUsersRequest, type UsersRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: UsersRouteContext) {
  return proxyUsersRequest({
    actionPath: 'invitation-status',
    method: 'POST',
    request,
    routeContext,
  });
}
