import { NextResponse } from 'next/server';

import { TENANT_DELETED_COOKIE_NAME } from '@/constants/auth';

export async function POST() {
  const response = new NextResponse(null, { status: 204 });

  response.cookies.set({
    name: TENANT_DELETED_COOKIE_NAME,
    value: '',
    maxAge: 0,
    path: '/tenant-deleted',
  });

  return response;
}
