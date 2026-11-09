import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type RouteDetailRouteContext = {
  params: Promise<{
    orgSlug: string;
    routeId: string;
    tenantSlug: string;
  }>;
};

type ProxyRouteDetailRequestOptions = {
  actionPath?: string;
  method: 'DELETE' | 'GET' | 'PATCH' | 'POST';
  request: Request;
  routeContext: RouteDetailRouteContext;
};

export async function proxyRouteDetailRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyRouteDetailRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, routeId, tenantSlug } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendPath = [
    API_URL,
    'organizations',
    encodeURIComponent(orgSlug),
    'tenants',
    encodeURIComponent(tenantSlug),
    'routes',
    encodeURIComponent(routeId),
    actionPath,
  ]
    .filter(Boolean)
    .join('/');
  const backendUrl = new URL(backendPath);
  const requestBody =
    method === 'PATCH' || method === 'POST' ? await readOptionalRequestBody(request) : undefined;

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
