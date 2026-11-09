import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type ToolDetailRouteContext = {
  params: Promise<{
    orgSlug: string;
    tenantSlug: string;
    toolId: string;
  }>;
};

type ProxyToolDetailRequestOptions = {
  method: 'DELETE' | 'PATCH';
  request: Request;
  routeContext: ToolDetailRouteContext;
};

export async function proxyToolDetailRequest({
  method,
  request,
  routeContext,
}: ProxyToolDetailRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, tenantSlug, toolId } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendUrl = new URL(
    [
      API_URL,
      'organizations',
      encodeURIComponent(orgSlug),
      'tenants',
      encodeURIComponent(tenantSlug),
      'tools',
      encodeURIComponent(toolId),
    ].join('/'),
  );
  const requestBody = method !== 'DELETE' ? await readOptionalRequestBody(request) : undefined;

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
