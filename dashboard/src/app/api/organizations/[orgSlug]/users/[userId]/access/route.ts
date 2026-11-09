import { proxyUserDetailRequest, type UserDetailRouteContext } from '../proxy';

export async function GET(request: Request, routeContext: UserDetailRouteContext) {
  return proxyUserDetailRequest({ actionPath: 'access', method: 'GET', request, routeContext });
}
