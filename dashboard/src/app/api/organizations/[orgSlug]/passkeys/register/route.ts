import { proxyOrgPasskeysRequest, type OrgPasskeysRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: OrgPasskeysRouteContext) {
  return proxyOrgPasskeysRequest({
    actionPath: 'register',
    method: 'POST',
    request,
    routeContext,
  });
}
