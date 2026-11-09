import { proxyTenantRequest, type TenantRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({ actionPath: 'reactivate', method: 'POST', request, routeContext });
}
