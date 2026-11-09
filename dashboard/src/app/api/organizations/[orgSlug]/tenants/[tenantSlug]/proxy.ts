import { NextResponse } from 'next/server';

import {
  createProxyResponse,
  getForwardedClientHeaders,
  readOptionalRequestBody,
} from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type TenantRouteContext = {
  params: Promise<{
    orgSlug: string;
    tenantSlug: string;
  }>;
};

type ProxyTenantRequestOptions = {
  actionPath?: string;
  method: 'DELETE' | 'GET' | 'PATCH' | 'POST' | 'PUT';
  request: Request;
  routeContext: TenantRouteContext;
};

export async function proxyTenantRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyTenantRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, tenantSlug } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendPath = [
    API_URL,
    'organizations',
    encodeURIComponent(orgSlug),
    'tenants',
    encodeURIComponent(tenantSlug),
    actionPath,
  ]
    .filter(Boolean)
    .join('/');
  const backendUrl = new URL(backendPath);
  const requestBody =
    method === 'POST' || method === 'PATCH' || method === 'PUT'
      ? await readOptionalRequestBody(request)
      : undefined;

  const response = await fetch(backendUrl, {
    body: requestBody,
    cache: 'no-store',
    headers: {
      ...getForwardedClientHeaders(request),
      ...(authorization ? { Authorization: authorization } : {}),
      ...(requestBody && contentType ? { 'Content-Type': contentType } : {}),
    },
    method,
  });

  return createProxyResponse(response);
}
