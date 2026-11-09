import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type OrgPasskeysRouteContext = {
  params: Promise<{
    orgSlug: string;
  }>;
};

type ProxyOrgPasskeysRequestOptions = {
  actionPath?: string;
  method: 'DELETE' | 'GET' | 'PATCH' | 'POST';
  request: Request;
  routeContext: OrgPasskeysRouteContext;
};

export async function proxyOrgPasskeysRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyOrgPasskeysRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendPath = [
    API_URL,
    'organizations',
    encodeURIComponent(orgSlug),
    'passkeys',
    actionPath,
  ]
    .filter(Boolean)
    .join('/');
  const backendUrl = new URL(backendPath);
  const requestBody =
    method === 'POST' || method === 'PATCH' ? await readOptionalRequestBody(request) : undefined;

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
