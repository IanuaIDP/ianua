import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

type RouteContext = {
  params: Promise<{
    orgSlug: string;
  }>;
};

export async function GET(request: Request, { params }: RouteContext) {
  return proxyOrgAuthConfigRequest(request, { params }, 'GET');
}

export async function PUT(request: Request, { params }: RouteContext) {
  return proxyOrgAuthConfigRequest(request, { params }, 'PUT');
}

async function proxyOrgAuthConfigRequest(
  request: Request,
  { params }: RouteContext,
  method: 'GET' | 'PUT',
) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug } = await params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendUrl = new URL(`${API_URL}/organizations/${encodeURIComponent(orgSlug)}/auth-config`);
  const requestBody = method === 'PUT' ? await readOptionalRequestBody(request) : undefined;

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
