import { proxyUsersRequest, type UsersRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: UsersRouteContext) {
  return proxyUsersRequest({
    actionPath: 'send-verification',
    method: 'POST',
    request,
    routeContext,
  });
}
