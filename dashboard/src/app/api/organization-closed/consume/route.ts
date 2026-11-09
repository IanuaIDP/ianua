import { NextResponse } from 'next/server';

import { ORGANIZATION_CLOSED_COOKIE_NAME } from '@/constants/auth';

export async function POST() {
  const response = new NextResponse(null, { status: 204 });

  response.cookies.set({
    name: ORGANIZATION_CLOSED_COOKIE_NAME,
    value: '',
    maxAge: 0,
    path: '/organization-closed',
  });

  return response;
}
