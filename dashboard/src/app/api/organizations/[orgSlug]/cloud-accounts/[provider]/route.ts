import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

type RouteContext = {
  params: Promise<{
    orgSlug: string;
    provider: string;
  }>;
};

function getBackendUrl(orgSlug: string, provider: string) {
  return new URL(
    `${API_URL}/organizations/${encodeURIComponent(orgSlug)}/cloud-accounts/${encodeURIComponent(provider)}`,
  );
}

export async function POST(request: Request, { params }: RouteContext) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, provider } = await params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const requestBody = await readOptionalRequestBody(request);

  const response = await fetch(getBackendUrl(orgSlug, provider), {
    body: requestBody,
    cache: 'no-store',
    headers: {
      ...(authorization ? { Authorization: authorization } : {}),
      ...(requestBody && contentType ? { 'Content-Type': contentType } : {}),
    },
    method: 'POST',
  });

  return createProxyResponse(response);
}

export async function DELETE(request: Request, { params }: RouteContext) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, provider } = await params;
  const authorization = request.headers.get('authorization');

  const response = await fetch(getBackendUrl(orgSlug, provider), {
    cache: 'no-store',
    headers: {
      ...(authorization ? { Authorization: authorization } : {}),
    },
    method: 'DELETE',
  });

  return createProxyResponse(response);
}
