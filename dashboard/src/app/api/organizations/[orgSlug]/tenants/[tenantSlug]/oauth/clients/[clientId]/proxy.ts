import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type OAuthClientDetailRouteContext = {
  params: Promise<{
    clientId: string;
    orgSlug: string;
    tenantSlug: string;
  }>;
};

type ProxyOAuthClientDetailRequestOptions = {
  actionPath?: string;
  method: 'PATCH' | 'POST';
  request: Request;
  routeContext: OAuthClientDetailRouteContext;
};

export async function proxyOAuthClientDetailRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyOAuthClientDetailRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { clientId, orgSlug, tenantSlug } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendPath = [
    API_URL,
    'organizations',
    encodeURIComponent(orgSlug),
    'tenants',
    encodeURIComponent(tenantSlug),
    'oauth',
    'clients',
    encodeURIComponent(clientId),
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
