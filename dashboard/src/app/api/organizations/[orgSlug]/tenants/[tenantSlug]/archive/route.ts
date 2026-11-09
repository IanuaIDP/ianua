import { TENANT_ARCHIVED_COOKIE_NAME } from '@/constants/auth';

import { proxyTenantRequest, type TenantRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: TenantRouteContext) {
  const response = await proxyTenantRequest({
    actionPath: 'archive',
    method: 'POST',
    request,
    routeContext,
  });

  if (response.ok) {
    const secureCookie = new URL(request.url).protocol === 'https:' ? '; Secure' : '';

    response.headers.append(
      'Set-Cookie',
      `${TENANT_ARCHIVED_COOKIE_NAME}=true; Path=/tenant-archived; Max-Age=60; HttpOnly; SameSite=Lax${secureCookie}`,
    );
  }

  return response;
}
