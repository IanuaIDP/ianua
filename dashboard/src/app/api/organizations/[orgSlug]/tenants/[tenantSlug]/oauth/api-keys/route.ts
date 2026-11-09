import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

type RouteContext = {
  params: Promise<{
    orgSlug: string;
    tenantSlug: string;
  }>;
};

export async function GET(request: Request, { params }: RouteContext) {
  return proxyTenantApiKeysRequest(request, { params }, 'GET');
}

export async function POST(request: Request, { params }: RouteContext) {
  return proxyTenantApiKeysRequest(request, { params }, 'POST');
}

async function proxyTenantApiKeysRequest(
  request: Request,
  { params }: RouteContext,
  method: 'GET' | 'POST',
) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, tenantSlug } = await params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const requestUrl = new URL(request.url);
  const backendUrl = new URL(
    `${API_URL}/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
      tenantSlug,
    )}/oauth/api-keys`,
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
