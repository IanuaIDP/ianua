import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type UserDetailRouteContext = {
  params: Promise<{
    orgSlug: string;
    userId: string;
  }>;
};

type ProxyUserDetailRequestOptions = {
  actionPath?: string;
  method: 'DELETE' | 'GET' | 'PATCH' | 'POST' | 'PUT';
  request: Request;
  routeContext: UserDetailRouteContext;
};

export async function proxyUserDetailRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyUserDetailRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, userId } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendPath = [
    API_URL,
    'organizations',
    encodeURIComponent(orgSlug),
    'users',
    encodeURIComponent(userId),
    actionPath,
  ]
    .filter(Boolean)
    .join('/');
  const backendUrl = new URL(backendPath);
  const requestBody =
    method !== 'DELETE' && method !== 'GET' ? await readOptionalRequestBody(request) : undefined;

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
