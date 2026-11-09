import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type RoleDetailRouteContext = {
  params: Promise<{
    orgSlug: string;
    roleId: string;
    tenantSlug: string;
  }>;
};

type ProxyRoleDetailRequestOptions = {
  actionPath?: string;
  method: 'DELETE' | 'PATCH' | 'POST';
  request: Request;
  routeContext: RoleDetailRouteContext;
};

export async function proxyRoleDetailRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyRoleDetailRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, roleId, tenantSlug } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendPath = [
    API_URL,
    'organizations',
    encodeURIComponent(orgSlug),
    'tenants',
    encodeURIComponent(tenantSlug),
    'authorization',
    'roles',
    encodeURIComponent(roleId),
    actionPath,
  ]
    .filter(Boolean)
    .join('/');
  const backendUrl = new URL(backendPath);
  const requestBody = await readOptionalRequestBody(request);

  const response = await fetch(backendUrl, {
    body: requestBody,
    cache: 'no-store',
    headers: {
      ...(authorization ? { Authorization: authorization } : {}),
      ...(requestBody && contentType ? { 'Content-Type': contentType } : {}),
    },
    method,
  });

  return createProxyResponse(response);
}
