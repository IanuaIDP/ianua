import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type UserAttributeRouteContext = {
  params: Promise<{
    key: string;
    namespace: string;
    orgSlug: string;
    tenantSlug: string;
  }>;
};

type ProxyUserAttributeRequestOptions = {
  actionPath?: string;
  method: 'DELETE' | 'PATCH' | 'PUT';
  request: Request;
  routeContext: UserAttributeRouteContext;
};

export async function proxyUserAttributeRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyUserAttributeRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { key, namespace, orgSlug, tenantSlug } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendPath = [
    API_URL,
    'organizations',
    encodeURIComponent(orgSlug),
    'tenants',
    encodeURIComponent(tenantSlug),
    'user-attributes',
    encodeURIComponent(namespace),
    encodeURIComponent(key),
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
