import { proxyRoleDetailRequest, type RoleDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: RoleDetailRouteContext) {
  return proxyRoleDetailRequest({
    actionPath: 'assignments',
    method: 'POST',
    request,
    routeContext,
  });
}
