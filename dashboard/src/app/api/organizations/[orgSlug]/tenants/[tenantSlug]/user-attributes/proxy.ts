import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type UserAttributesRouteContext = {
  params: Promise<{
    orgSlug: string;
    tenantSlug: string;
  }>;
};

type ProxyUserAttributesRequestOptions = {
  method: 'DELETE' | 'GET' | 'PATCH' | 'POST' | 'PUT';
  request: Request;
  routeContext: UserAttributesRouteContext;
  /** Path parts below `/user-attributes` — `['kinds']`, `[namespace, key]`. */
  segments?: string[];
};

export async function proxyUserAttributesRequest({
  method,
  request,
  routeContext,
  segments = [],
}: ProxyUserAttributesRequestOptions) {
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
    'user-attributes',
    ...segments.map((segment) => encodeURIComponent(segment)),
  ].join('/');
  const backendUrl = new URL(backendPath);
  backendUrl.search = new URL(request.url).search;
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
