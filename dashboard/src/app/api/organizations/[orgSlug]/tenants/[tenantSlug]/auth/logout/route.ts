import { NextResponse } from 'next/server';

import { createProxyResponse, getForwardedClientHeaders } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

type RouteContext = {
  params: Promise<{
    orgSlug: string;
    tenantSlug: string;
  }>;
};

export async function POST(request: Request, { params }: RouteContext) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, tenantSlug } = await params;
  const authorization = request.headers.get('authorization');
  const backendUrl = new URL(
    `${API_URL}/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
      tenantSlug,
    )}/auth/logout`,
  );

  const response = await fetch(backendUrl, {
    cache: 'no-store',
    headers: {
      ...getForwardedClientHeaders(request),
      ...(authorization ? { Authorization: authorization } : {}),
    },
    method: 'POST',
  });

  return createProxyResponse(response);
}
