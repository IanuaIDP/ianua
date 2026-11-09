import { NextRequest, NextResponse } from 'next/server';

import {
  ORGANIZATION_CLOSED_COOKIE_NAME,
  ORGANIZATION_SUSPENDED_COOKIE_NAME,
  TENANT_ARCHIVED_COOKIE_NAME,
  TENANT_DELETED_COOKIE_NAME,
  TENANT_SUSPENDED_COOKIE_NAME,
} from '@/constants/auth';

const GATED_ROUTES: Record<string, string> = {
  '/organization-closed': ORGANIZATION_CLOSED_COOKIE_NAME,
  '/organization-suspended': ORGANIZATION_SUSPENDED_COOKIE_NAME,
  '/tenant-archived': TENANT_ARCHIVED_COOKIE_NAME,
  '/tenant-deleted': TENANT_DELETED_COOKIE_NAME,
  '/tenant-suspended': TENANT_SUSPENDED_COOKIE_NAME,
};

export function middleware(request: NextRequest) {
  const cookieName = GATED_ROUTES[request.nextUrl.pathname];

  if (!cookieName) {
    return NextResponse.next();
  }

  if (request.cookies.get(cookieName)?.value !== 'true') {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/organization-closed',
    '/organization-suspended',
    '/tenant-suspended',
    '/tenant-deleted',
    '/tenant-archived',
  ],
};
