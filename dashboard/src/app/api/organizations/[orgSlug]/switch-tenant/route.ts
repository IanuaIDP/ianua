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

export async function POST(request: Request, { params }: RouteContext) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug } = await params;
  const authorization = request.headers.get('authorization');
  const backendUrl = new URL(
    `${API_URL}/organizations/${encodeURIComponent(orgSlug)}/switch-tenant`,
  );
  const body = await readOptionalRequestBody(request);

  const response = await fetch(backendUrl, {
    body,
    cache: 'no-store',
    headers: {
      ...getForwardedClientHeaders(request),
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(authorization ? { Authorization: authorization } : {}),
    },
    method: 'POST',
  });

  return createProxyResponse(response);
}
