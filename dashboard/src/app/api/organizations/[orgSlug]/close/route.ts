import { NextResponse } from 'next/server';

import { createProxyResponse } from '@/app/api/_utils/proxy';
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
  const backendUrl = new URL(`${API_URL}/organizations/${encodeURIComponent(orgSlug)}/close`);

  const response = await fetch(backendUrl, {
    cache: 'no-store',
    headers: {
      ...(authorization ? { Authorization: authorization } : {}),
    },
    method: 'POST',
  });

  const proxyResponse = await createProxyResponse(response);

  if (response.ok) {
    const secureCookie = new URL(request.url).protocol === 'https:' ? '; Secure' : '';

    proxyResponse.headers.append(
      'Set-Cookie',
      `ianua-organization-closed=true; Path=/organization-closed; Max-Age=60; HttpOnly; SameSite=Lax${secureCookie}`,
    );
  }

  return proxyResponse;
}
