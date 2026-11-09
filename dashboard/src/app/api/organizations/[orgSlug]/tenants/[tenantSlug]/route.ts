import { TENANT_DELETED_COOKIE_NAME } from '@/constants/auth';

import { proxyTenantRequest, type TenantRouteContext } from './proxy';

export async function GET(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({ method: 'GET', request, routeContext });
}

export async function PATCH(request: Request, routeContext: TenantRouteContext) {
  return proxyTenantRequest({ method: 'PATCH', request, routeContext });
}

export async function DELETE(request: Request, routeContext: TenantRouteContext) {
  const response = await proxyTenantRequest({ method: 'DELETE', request, routeContext });

  if (response.ok) {
    const secureCookie = new URL(request.url).protocol === 'https:' ? '; Secure' : '';

    response.headers.append(
      'Set-Cookie',
      `${TENANT_DELETED_COOKIE_NAME}=true; Path=/tenant-deleted; Max-Age=60; HttpOnly; SameSite=Lax${secureCookie}`,
    );
  }

  return response;
}
