import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

type RouteContext = {
  params: Promise<{
    orgSlug: string;
    passkeyId: string;
  }>;
};

async function proxyRequest(
  request: Request,
  { params }: RouteContext,
  method: 'DELETE' | 'PATCH',
) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, passkeyId } = await params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendUrl = new URL(
    `${API_URL}/organizations/${encodeURIComponent(orgSlug)}/passkeys/${encodeURIComponent(passkeyId)}`,
  );
  const requestBody = method === 'PATCH' ? await readOptionalRequestBody(request) : undefined;

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

export async function PATCH(request: Request, routeContext: RouteContext) {
  return proxyRequest(request, routeContext, 'PATCH');
}

export async function DELETE(request: Request, routeContext: RouteContext) {
  return proxyRequest(request, routeContext, 'DELETE');
}
