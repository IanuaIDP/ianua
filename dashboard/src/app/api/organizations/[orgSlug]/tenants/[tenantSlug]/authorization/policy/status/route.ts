import { proxyTenantRequest, type TenantRouteContext } from '../../../proxy';

export async function POST(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({
    actionPath: 'authorization/policy/status',
    method: 'POST',
    request,
    routeContext,
  });
}
