import { NextResponse } from 'next/server';

import { createProxyResponse } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

type RouteContext = {
  params: Promise<{
    groupId: string;
    orgSlug: string;
    principalId: string;
    principalKind: string;
    tenantSlug: string;
  }>;
};

export async function DELETE(request: Request, { params }: RouteContext) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { groupId, orgSlug, principalId, principalKind, tenantSlug } = await params;
  const authorization = request.headers.get('authorization');
  const backendUrl = new URL(
    `${API_URL}/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
      tenantSlug,
    )}/authorization/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(
      principalKind,
    )}/${encodeURIComponent(principalId)}`,
  );

  const response = await fetch(backendUrl, {
    cache: 'no-store',
    headers: {
      ...(authorization ? { Authorization: authorization } : {}),
    },
    method: 'DELETE',
  });

  return createProxyResponse(response);
}
