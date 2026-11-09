import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type GroupDetailRouteContext = {
  params: Promise<{
    groupId: string;
    orgSlug: string;
    tenantSlug: string;
  }>;
};

type ProxyGroupDetailRequestOptions = {
  method: 'DELETE' | 'GET' | 'PATCH' | 'POST';
  request: Request;
  routeContext: GroupDetailRouteContext;
  /** Path parts below the group itself — `['members']`, `['roles', roleId]`. */
  segments?: string[];
};

export async function proxyGroupDetailRequest({
  method,
  request,
  routeContext,
  segments = [],
}: ProxyGroupDetailRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { groupId, orgSlug, tenantSlug } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendPath = [
    API_URL,
    'organizations',
    encodeURIComponent(orgSlug),
    'tenants',
    encodeURIComponent(tenantSlug),
    'authorization',
    'groups',
    encodeURIComponent(groupId),
    ...segments.map((segment) => encodeURIComponent(segment)),
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
