import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

type RouteContext = {
  params: Promise<{
    orgSlug: string;
  }>;
};

export async function GET(request: Request, routeContext: RouteContext) {
  return proxySubscriptionRequest(request, routeContext, 'GET');
}

export async function PUT(request: Request, routeContext: RouteContext) {
  return proxySubscriptionRequest(request, routeContext, 'PUT');
}

async function proxySubscriptionRequest(
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
  const requestBody = method === 'PUT' ? await readOptionalRequestBody(request) : undefined;
  const response = await fetch(
    `${API_URL}/organizations/${encodeURIComponent(orgSlug)}/subscription`,
    {
      body: requestBody,
      cache: 'no-store',
      headers: {
        ...(authorization ? { Authorization: authorization } : {}),
        ...(requestBody ? { 'Content-Type': 'application/json' } : {}),
      },
      method,
    },
  );

  return createProxyResponse(response);
}
