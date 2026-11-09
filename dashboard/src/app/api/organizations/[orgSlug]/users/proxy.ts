import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type UsersRouteContext = {
  params: Promise<{
    orgSlug: string;
  }>;
};

type ProxyUsersRequestOptions = {
  actionPath?: string;
  method: 'GET' | 'POST';
  request: Request;
  routeContext: UsersRouteContext;
};

export async function proxyUsersRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyUsersRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const requestUrl = new URL(request.url);
  const backendUrl = new URL(
    [API_URL, 'organizations', encodeURIComponent(orgSlug), 'users', actionPath]
      .filter(Boolean)
      .join('/'),
  );
  backendUrl.search = requestUrl.search;
  const requestBody = method === 'POST' ? await readOptionalRequestBody(request) : undefined;

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
