import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type StreamDetailRouteContext = {
  params: Promise<{
    orgSlug: string;
    streamId: string;
    tenantSlug: string;
  }>;
};

type ProxyStreamDetailRequestOptions = {
  actionPath?: string;
  method: 'DELETE' | 'GET' | 'PATCH' | 'POST';
  request: Request;
  routeContext: StreamDetailRouteContext;
};

export async function proxyStreamDetailRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyStreamDetailRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, streamId, tenantSlug } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendPath = [
    API_URL,
    'organizations',
    encodeURIComponent(orgSlug),
    'tenants',
    encodeURIComponent(tenantSlug),
    'streams',
    encodeURIComponent(streamId),
    actionPath,
  ]
    .filter(Boolean)
    .join('/');
  const backendUrl = new URL(backendPath);
  backendUrl.search = new URL(request.url).search;
  const requestBody =
    method === 'DELETE' || method === 'GET' ? undefined : await readOptionalRequestBody(request);

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
