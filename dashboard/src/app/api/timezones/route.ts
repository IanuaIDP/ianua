import { NextResponse } from 'next/server';

import { createProxyResponse } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export async function GET(request: Request) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const authorization = request.headers.get('authorization');

  const response = await fetch(`${API_URL}/timezones`, {
    cache: 'no-store',
    headers: {
      ...(authorization ? { Authorization: authorization } : {}),
    },
    method: 'GET',
  });

  return createProxyResponse(response);
}
