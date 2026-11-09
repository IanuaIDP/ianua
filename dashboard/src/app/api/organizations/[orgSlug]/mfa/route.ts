import { NextResponse } from 'next/server';

import {
  createProxyResponse,
  getForwardedClientHeaders,
  readOptionalRequestBody,
} from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

type RouteContext = {
  params: Promise<{
    orgSlug: string;
  }>;
};

export async function DELETE(request: Request, { params }: RouteContext) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug } = await params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const requestBody = await readOptionalRequestBody(request);
  const backendUrl = new URL(`${API_URL}/organizations/${encodeURIComponent(orgSlug)}/mfa`);

  const response = await fetch(backendUrl, {
    body: requestBody,
    cache: 'no-store',
    headers: {
      ...getForwardedClientHeaders(request),
      ...(authorization ? { Authorization: authorization } : {}),
      ...(requestBody && contentType ? { 'Content-Type': contentType } : {}),
    },
    method: 'DELETE',
  });

  return createProxyResponse(response);
}
