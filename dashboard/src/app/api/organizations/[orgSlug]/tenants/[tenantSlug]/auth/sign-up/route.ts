import { proxyTenantRequest, type TenantRouteContext } from '../../proxy';

export async function GET(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({ actionPath: 'auth/sign-up', method: 'GET', request, routeContext });
}

export async function POST(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({ actionPath: 'auth/sign-up', method: 'POST', request, routeContext });
}
