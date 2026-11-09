import { proxyUsersRequest, type UsersRouteContext } from './proxy';

export async function GET(request: Request, routeContext: UsersRouteContext) {
  return proxyUsersRequest({ method: 'GET', request, routeContext });
}

export async function POST(request: Request, routeContext: UsersRouteContext) {
  return proxyUsersRequest({ method: 'POST', request, routeContext });
}
