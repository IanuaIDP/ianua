import { proxyOrgPasskeysRequest, type OrgPasskeysRouteContext } from './proxy';

export async function GET(request: Request, routeContext: OrgPasskeysRouteContext) {
  return proxyOrgPasskeysRequest({
    method: 'GET',
    request,
    routeContext,
  });
}
