import { NextResponse } from 'next/server';

import { createProxyResponse, getForwardedClientHeaders } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export async function POST(request: Request) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const body = await request.text();
  const response = await fetch(`${API_URL}/password/reset-resend`, {
    body,
    headers: {
      ...getForwardedClientHeaders(request),
      'Content-Type': 'application/json',
    },
    method: 'POST',
  });

  return createProxyResponse(response);
}
