import { NextResponse } from 'next/server';

import { createProxyResponse } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

type RouteContext = {
  params: Promise<{
    orgSlug: string;
    provider: string;
  }>;
};

export async function GET(request: Request, { params }: RouteContext) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, provider } = await params;
  const authorization = request.headers.get('authorization');
  const requestUrl = new URL(request.url);
  const backendUrl = new URL(
    `${API_URL}/organizations/${encodeURIComponent(orgSlug)}/cloud-accounts/${encodeURIComponent(
      provider,
    )}/networks`,
  );
  backendUrl.search = requestUrl.search;

  const response = await fetch(backendUrl, {
    cache: 'no-store',
    headers: {
      ...(authorization ? { Authorization: authorization } : {}),
    },
    method: 'GET',
  });

  return createProxyResponse(response);
}
